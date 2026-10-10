//! Atomic native resource accounting. Revocation fences authority, not capacity:
//! reservations stay charged until the resource manager proves physical drainage.
use crate::{bundle, platform, tpm, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) const DIRECTORY: &str = "/var/lib/luma-broker/resources";
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVES: usize = 64;
const MAX_ARCHIVE_FILES: usize = 128;
pub(crate) mod checkpoint;
mod exclusion;
mod retention;

// Decimal strings preserve all 64 bits across JSON consumers, including JS.
pub(crate) mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
        let text = String::deserialize(d)?;
        let value = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical unsigned decimal"));
        }
        Ok(value)
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'.'))
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bundle::hex(&bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Domain {
    #[serde(with = "decimal")]
    pub capacity: u64,
    #[serde(with = "decimal")]
    pub reserve: u64,
    #[serde(with = "decimal")]
    pub pressure_enter: u64,
    #[serde(with = "decimal")]
    pub pressure_exit: u64,
    #[serde(with = "decimal")]
    pub observed: u64,
    #[serde(with = "decimal")]
    pub retained: u64,
    pub pressure: bool,
    pub quarantined: bool,
    #[serde(with = "decimal")]
    pub epoch: u64,
}

impl Domain {
    pub(crate) fn new(capacity: u64, reserve: u64, enter: u64, exit: u64) -> Result<Self> {
        let domain = Self {
            capacity,
            reserve,
            pressure_enter: enter,
            pressure_exit: exit,
            observed: 0,
            retained: 0,
            pressure: false,
            quarantined: false,
            epoch: 1,
        };
        domain.validate()?;
        Ok(domain)
    }
    fn validate(&self) -> Result<()> {
        if self.capacity == 0
            || self.reserve >= self.capacity
            || self.epoch == 0
            || self.pressure_enter > self.capacity
            || self.pressure_enter <= self.reserve
            || self.pressure_exit > self.pressure_enter
            || self.pressure_exit < self.reserve
        {
            return Err("invalid resource domain".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub domain: String,
    #[serde(with = "decimal")]
    pub loading: u64,
    #[serde(with = "decimal")]
    pub serving: u64,
}
impl Reservation {
    fn peak(&self) -> u64 {
        self.loading.max(self.serving)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Owner {
    pub uid: u32,
    pub pid: u32,
    #[serde(with = "decimal")]
    pub start_ticks: u64,
    pub boot: String,
    #[serde(with = "decimal")]
    pub cgroup_device: u64,
    #[serde(with = "decimal")]
    pub cgroup_inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Token {
    pub lease_id: String,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub manager_epoch: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    Active,
    Draining,
    Released,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub(crate) struct OutputEpoch(#[serde(with = "decimal")] pub u64);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lease {
    pub token: Token,
    pub owner: Owner,
    pub request: String,
    pub binding: String,
    pub reservations: Vec<Reservation>,
    #[serde(with = "decimal")]
    pub deadline_ms: u64,
    pub state: State,
    pub reason: String,
    // An immutable computation receipt is not a physical drainage receipt.
    // Omit absent values to preserve older canonical journals and archives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_domain_epochs: Option<BTreeMap<String, OutputEpoch>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub output_fenced: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Archive {
    #[serde(with = "decimal")]
    pub through_generation: u64,
    pub sha256: String,
}

impl Archive {
    fn name(&self) -> String {
        format!("archive-{}-{}.json", self.through_generation, self.sha256)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ledger {
    schema_version: u32,
    pub manager_epoch: String,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub domains: BTreeMap<String, Domain>,
    pub archives: Vec<Archive>,
    pub leases: Vec<Lease>,
}

impl Ledger {
    #[cfg(test)]
    pub(crate) fn fresh_for_test() -> Self {
        Self::empty()
    }
    fn empty() -> Self {
        Self {
            schema_version: 1,
            manager_epoch: String::new(),
            generation: 0,
            domains: BTreeMap::new(),
            archives: vec![],
            leases: vec![],
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.leases.len() > MAX_RECORDS
            || self.domains.len() > 16
            || self.archives.len() > MAX_ARCHIVES
        {
            return Err("unsupported or exhausted resource ledger".into());
        }
        if self.manager_epoch.is_empty() {
            if self.generation != 0
                || !self.domains.is_empty()
                || !self.leases.is_empty()
                || !self.archives.is_empty()
            {
                return Err("invalid uninitialized resource ledger".into());
            }
            return Ok(());
        }
        if !identifier(&self.manager_epoch) || self.domains.is_empty() {
            return Err("invalid resource manager epoch or inventory".into());
        }
        for (id, domain) in &self.domains {
            if !identifier(id) {
                return Err("invalid resource domain identity".into());
            }
            domain.validate()?;
        }
        let mut ids = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut previous = 0;
        for archive in &self.archives {
            if archive.through_generation <= previous
                || archive.through_generation > self.generation
                || archive.sha256.len() != 64
                || !archive
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid resource archive chain".into());
            }
            previous = archive.through_generation;
        }
        for lease in &self.leases {
            if !identifier(&lease.token.lease_id)
                || !ids.insert(&lease.token.lease_id)
                || !identifier(&lease.token.manager_epoch)
                || lease.token.generation <= previous
                || lease.token.generation > self.generation
                || !identifier(&lease.request)
                || !identifier(&lease.owner.boot)
                || lease.owner.pid == 0
                || lease.owner.start_ticks == 0
                || lease.owner.cgroup_inode == 0
                || lease.deadline_ms == 0
                || lease.binding.len() != 64
                || !lease.binding.bytes().all(|b| b.is_ascii_hexdigit())
                || !identifier(&lease.reason)
                || (lease.output_fenced
                    && (lease.output_sha256.is_none() || lease.state == State::Active))
                || lease.output_sha256.as_ref().map_or(false, |digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                || !requests.insert((lease.owner.clone_key(), &lease.request))
            {
                return Err("invalid resource lease or replay inventory".into());
            }
            previous = lease.token.generation;
            self.reservations_valid(&lease.reservations)?;
            if let Some(epochs) = &lease.output_domain_epochs {
                if lease.output_sha256.is_none()
                    || epochs
                        .keys()
                        .ne(lease.reservations.iter().map(|r| &r.domain))
                    || epochs.iter().any(|(id, epoch)| {
                        epoch.0 == 0
                            || epoch.0 > self.domains[id].epoch
                            || (lease.state == State::Active && epoch.0 != self.domains[id].epoch)
                    })
                {
                    return Err("invalid computation domain epoch snapshot".into());
                }
            }
            if lease.state == State::Active && lease.token.manager_epoch != self.manager_epoch {
                return Err("active lease belongs to a stale manager".into());
            }
        }
        for (id, domain) in &self.domains {
            if self.charged(id)? > domain.capacity - domain.reserve && !domain.quarantined {
                return Err("unquarantined resource overcommit".into());
            }
        }
        Ok(())
    }

    fn reservations_valid(&self, reservations: &[Reservation]) -> Result<()> {
        if reservations.is_empty() || reservations.len() > 16 {
            return Err("invalid resource plan".into());
        }
        let mut last = "";
        for r in reservations {
            if r.domain.as_str() <= last || r.peak() == 0 || !self.domains.contains_key(&r.domain) {
                return Err("unknown, duplicate, unordered or empty resource reservation".into());
            }
            last = &r.domain;
        }
        Ok(())
    }

    pub(crate) fn charged(&self, domain: &str) -> Result<u64> {
        let mut sum = self.domains.get(domain).ok_or("unknown domain")?.retained;
        for lease in self.leases.iter().filter(|l| l.state != State::Released) {
            for r in lease.reservations.iter().filter(|r| r.domain == domain) {
                sum = sum
                    .checked_add(r.peak())
                    .ok_or("resource byte accounting overflow")?;
            }
        }
        Ok(sum)
    }

    pub(crate) fn restart(
        &mut self,
        epoch: String,
        inventory: BTreeMap<String, Domain>,
    ) -> Result<()> {
        if !identifier(&epoch)
            || epoch == self.manager_epoch
            || inventory.is_empty()
            || inventory.len() > 16
        {
            return Err("invalid resource manager restart".into());
        }
        for (id, d) in &inventory {
            if !identifier(id) {
                return Err("invalid domain identity".into());
            }
            d.validate()?;
        }
        let mut next = self.clone();
        if next.domains.is_empty() {
            next.domains = inventory;
        } else {
            if next.domains.keys().ne(inventory.keys()) {
                return Err("resource inventory migration requires review".into());
            }
            for (id, d) in &mut next.domains {
                let live = &inventory[id];
                if (d.capacity, d.reserve, d.pressure_enter, d.pressure_exit)
                    != (
                        live.capacity,
                        live.reserve,
                        live.pressure_enter,
                        live.pressure_exit,
                    )
                {
                    d.quarantined = true;
                }
            }
        }
        next.manager_epoch = epoch;
        for lease in next.leases.iter_mut().filter(|l| l.state == State::Active) {
            lease.state = State::Draining;
            lease.reason = "manager-restart".into();
        }
        next.fence_outputs();
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn admit(
        &mut self,
        owner: Owner,
        request: String,
        binding: String,
        reservations: Vec<Reservation>,
        now: u64,
        deadline: u64,
    ) -> Result<Token> {
        self.validate()?;
        self.reservations_valid(&reservations)?;
        if !identifier(&request) || deadline <= now || deadline - now > 30_000 {
            return Err("invalid resource request or lease duration".into());
        }
        if let Some(old) = self
            .leases
            .iter()
            .find(|l| l.owner == owner && l.request == request)
        {
            if old.binding != binding || old.reservations != reservations {
                return Err("resource idempotency conflict".into());
            }
            self.assert_active(&old.token, &owner, now)?;
            return Ok(old.token.clone());
        }
        if self.leases.len() >= MAX_RECORDS {
            return Err("resource receipt capacity exhausted".into());
        }
        for r in &reservations {
            let domain = &self.domains[&r.domain];
            let required = self
                .charged(&r.domain)?
                .checked_add(r.peak())
                .ok_or("resource reservation overflow")?;
            if domain.quarantined || domain.pressure || required > domain.capacity - domain.reserve
            {
                return Err("resource domain unavailable or insufficient capacity".into());
            }
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("resource generation space exhausted")?;
        let token = Token {
            lease_id: random_id()?,
            generation,
            manager_epoch: self.manager_epoch.clone(),
        };
        if self
            .leases
            .iter()
            .any(|l| l.token.lease_id == token.lease_id)
        {
            return Err("resource identifier collision".into());
        }
        let mut next = self.clone();
        next.generation = generation;
        next.leases.push(Lease {
            token: token.clone(),
            owner,
            request,
            binding,
            reservations,
            deadline_ms: deadline,
            state: State::Active,
            reason: "admitted".into(),
            output_sha256: None,
            output_domain_epochs: None,
            output_fenced: false,
        });
        next.validate()?;
        *self = next;
        Ok(token)
    }

    pub(crate) fn admit_reusing_retained(
        &mut self,
        owner: Owner,
        request: String,
        binding: String,
        reservations: Vec<Reservation>,
        now: u64,
        deadline: u64,
        credits: &BTreeMap<String, u64>,
    ) -> Result<Token> {
        // Only the manager can transfer verified charges in its identical,
        // bounded physical cgroup. A client cannot supply allocation credits.
        if self
            .leases
            .iter()
            .any(|l| l.owner == owner && l.request == request)
        {
            return self.admit(owner, request, binding, reservations, now, deadline);
        }
        let mut next = self.clone();
        for (domain, credit) in credits {
            let plan = reservations
                .iter()
                .find(|r| &r.domain == domain)
                .ok_or("retained credit outside plan")?;
            let d = next
                .domains
                .get_mut(domain)
                .ok_or("unknown retained domain")?;
            if *credit > d.retained || *credit > plan.peak() {
                return Err("unproven retained allocation credit".into());
            }
            d.retained -= credit;
        }
        let token = next.admit(owner, request, binding, reservations, now, deadline)?;
        *self = next;
        Ok(token)
    }

    fn index(&self, token: &Token, owner: &Owner) -> Result<usize> {
        self.leases
            .iter()
            .position(|l| &l.token == token && &l.owner == owner)
            .ok_or_else(|| "unknown, forged or foreign resource lease".into())
    }

    pub(crate) fn assert_active(&self, token: &Token, owner: &Owner, now: u64) -> Result<&Lease> {
        let l = &self.leases[self.index(token, owner)?];
        if token.manager_epoch != self.manager_epoch
            || l.state != State::Active
            || now >= l.deadline_ms
            || l.reservations
                .iter()
                .any(|r| self.domains[&r.domain].quarantined)
        {
            return Err("expired, revoked or stale resource generation".into());
        }
        Ok(l)
    }

    pub(crate) fn renew(
        &mut self,
        token: &Token,
        owner: &Owner,
        now: u64,
        deadline: u64,
    ) -> Result<()> {
        self.assert_active(token, owner, now)?;
        if deadline <= now || deadline - now > 30_000 {
            return Err("invalid resource renewal duration".into());
        }
        let index = self.index(token, owner)?;
        self.leases[index].deadline_ms = deadline;
        Ok(())
    }

    pub(crate) fn complete_output(
        &mut self,
        token: &Token,
        owner: &Owner,
        now: u64,
        digest: &str,
    ) -> Result<()> {
        self.validate()?;
        self.assert_active(token, owner, now)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid computation output digest".into());
        }
        let index = self.index(token, owner)?;
        let epochs: BTreeMap<_, _> = self.leases[index]
            .reservations
            .iter()
            .map(|r| (r.domain.clone(), OutputEpoch(self.domains[&r.domain].epoch)))
            .collect();
        if let Some(previous) = &self.leases[index].output_sha256 {
            if previous != digest
                || self.leases[index].output_domain_epochs.as_ref() != Some(&epochs)
            {
                return Err("computation output replay or domain provenance differs; recompute in a fresh generation".into());
            }
        } else {
            self.leases[index].output_sha256 = Some(digest.into());
            self.leases[index].output_domain_epochs = Some(epochs);
        }
        // State, deadlines, reservations and domain observations are unchanged.
        Ok(())
    }

    pub(crate) fn revoke(&mut self, token: &Token, reason: &str) -> Result<()> {
        if !identifier(reason) {
            return Err("invalid resource revocation reason".into());
        }
        let l = self
            .leases
            .iter_mut()
            .find(|l| &l.token == token)
            .ok_or("unknown resource lease")?;
        if l.state == State::Active {
            l.state = State::Draining;
            l.reason = reason.into();
        }
        if reason != "owner-lost" && l.output_sha256.is_some() {
            l.output_fenced = true;
        }
        Ok(())
    }

    pub(crate) fn expire(&mut self, now: u64) {
        for l in self
            .leases
            .iter_mut()
            .filter(|l| l.state == State::Active && now >= l.deadline_ms)
        {
            l.state = State::Draining;
            l.reason = "expired".into();
            l.output_fenced = l.output_sha256.is_some();
        }
    }

    pub(crate) fn observe(&mut self, id: &str, used: u64, retained: u64) -> Result<()> {
        let charged = self.charged(id)?;
        let d = self.domains.get_mut(id).ok_or("unknown resource domain")?;
        let accounted = charged
            .checked_sub(d.retained)
            .ok_or("resource retained accounting underflow")?
            .checked_add(retained)
            .ok_or("resource retained accounting overflow")?;
        let load = used
            .max(accounted)
            .checked_add(d.reserve)
            .ok_or("resource observation overflow")?;
        d.observed = used;
        d.retained = retained;
        if load >= d.pressure_enter {
            d.pressure = true;
        } else if load <= d.pressure_exit {
            d.pressure = false;
        }
        Ok(())
    }

    pub(crate) fn quarantine(&mut self, id: &str, reason: &str) -> Result<()> {
        if !identifier(reason) {
            return Err("invalid resource quarantine reason".into());
        }
        let mut next = self.clone();
        let d = next.domains.get_mut(id).ok_or("unknown resource domain")?;
        if !d.quarantined {
            d.epoch = d
                .epoch
                .checked_add(1)
                .ok_or("resource domain epoch exhausted")?;
            d.quarantined = true;
        }
        for l in next
            .leases
            .iter_mut()
            .filter(|l| l.reservations.iter().any(|r| r.domain == id))
        {
            if l.state == State::Active {
                l.state = State::Draining;
                l.reason = reason.into();
            }
            l.output_fenced = l.output_sha256.is_some();
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    // Only the trusted resource-manager adapter calls this after re-observing
    // the exact cgroup inode, empty descendants and its remaining charged bytes.
    pub(crate) fn finish_draining(
        &mut self,
        token: &Token,
        retained: &BTreeMap<String, u64>,
    ) -> Result<()> {
        let index = self
            .leases
            .iter()
            .position(|l| &l.token == token)
            .ok_or("unknown drained lease")?;
        if self.leases[index].state != State::Draining {
            return Err("lease is not draining".into());
        }
        if retained
            .keys()
            .ne(self.leases[index].reservations.iter().map(|r| &r.domain))
        {
            return Err("incomplete resource drainage observation".into());
        }
        let mut next = self.clone();
        for (id, bytes) in retained {
            next.domains
                .get_mut(id)
                .ok_or("unknown drained domain")?
                .retained = *bytes;
        }
        next.leases[index].state = State::Released;
        next.leases[index].reason = "fenced-and-observed".into();
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn clear_quarantine(
        &mut self,
        review: &str,
        inventory: BTreeMap<String, Domain>,
    ) -> Result<()> {
        if self.review()? != review
            || self.leases.iter().any(|l| l.state != State::Released)
            || self.domains.keys().ne(inventory.keys())
        {
            return Err("stale resource review or incomplete drainage".into());
        }
        let mut next = self.clone();
        for (id, live) in inventory {
            live.validate()?;
            let old = &next.domains[&id];
            let mut domain = live;
            domain.epoch = old.epoch.checked_add(1).ok_or("resource epoch exhausted")?;
            domain.retained = old.retained;
            next.domains.insert(id, domain);
        }
        // A reviewed epoch cut restores admission, never old output authority.
        // All domains advance, so even already released results are fenced.
        next.fence_outputs();
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn review(&self) -> Result<String> {
        let mut authority = self.clone();
        // Ambient host usage is telemetry, not an authorization mutation.
        // Epochs, fences, retained charges and every lease remain bound.
        for d in authority.domains.values_mut() {
            d.observed = 0;
        }
        Ok(bundle::hex(&Sha256::digest(serde_json::to_vec(
            &authority,
        )?)))
    }

    pub(crate) fn migrate_inventory(
        &mut self,
        review: &str,
        epoch: String,
        inventory: BTreeMap<String, Domain>,
    ) -> Result<()> {
        self.validate()?;
        if self.review()? != review
            || self.leases.iter().any(|l| l.state != State::Released)
            || inventory.is_empty()
            || inventory.len() > 16
            || !identifier(&epoch)
            || epoch == self.manager_epoch
            || self.domains.keys().any(|id| !inventory.contains_key(id))
        {
            return Err("stale migration review, live allocation or discarded domain".into());
        }
        let mut next = self.clone();
        next.domains = inventory;
        next.manager_epoch = epoch;
        for (id, domain) in &mut next.domains {
            if let Some(old) = self.domains.get(id) {
                domain.epoch = old
                    .epoch
                    .checked_add(1)
                    .ok_or("migration epoch exhausted")?;
                domain.retained = old.retained;
                domain.quarantined = old.quarantined;
                domain.pressure = old.pressure;
                domain.observed = old.observed;
            }
        }
        next.fence_outputs();
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn fence_outputs(&mut self) {
        for lease in &mut self.leases {
            if lease.output_sha256.is_some() {
                lease.output_fenced = true;
            }
        }
    }
}

impl Owner {
    fn clone_key(&self) -> (u32, u32, u64, &str, u64, u64) {
        (
            self.uid,
            self.pid,
            self.start_ticks,
            &self.boot,
            self.cgroup_device,
            self.cgroup_inode,
        )
    }
}

pub(crate) struct Store {
    directory: PathBuf,
    directory_identity: (u64, u64),
    _lock: File,
    authority_lost: std::sync::atomic::AtomicBool,
    published_sha256: String,
    poisoned: bool,
    observations: BTreeMap<String, u64>,
    retired_owners: BTreeSet<[u8; 32]>,
    renewal_deadlines: BTreeMap<String, u64>,
    checkpoint: Option<checkpoint::Shared>,
}

pub(crate) fn initialize(directory: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    tpm::private_directory(directory)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("ledger.json"))?;
    file.write_all(&serde_json::to_vec(&Ledger::empty())?)?;
    file.sync_all()?;
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("ledger.lock"))?;
    lock.sync_all()?;
    crate::resource_manager::requests::initialize(directory)?;
    File::open(directory)?.sync_all()?;
    File::open(directory.parent().ok_or("missing resource parent")?)?.sync_all()?;
    Ok(())
}

impl Store {
    // Request receipts share this authority's lifetime exclusion. Workers never
    // receive this path, a descriptor or an independent writable store.
    pub(crate) fn request_directory(&self) -> Result<&Path> {
        self.read()?;
        Ok(&self.directory)
    }
    pub(crate) fn open(directory: &Path) -> Result<Self> {
        tpm::private_directory(directory)?;
        let directory_identity = exclusion::directory_identity(directory)?;
        let lock = tpm::exclusive_lock(&directory.join("ledger.lock"))?;
        let bytes = tpm::private_read(&directory.join("ledger.json"), MAX_BYTES)?;
        let mut store = Self {
            directory: directory.into(),
            directory_identity,
            _lock: lock,
            authority_lost: std::sync::atomic::AtomicBool::new(false),
            published_sha256: bundle::hex(&Sha256::digest(&bytes)),
            poisoned: false,
            observations: BTreeMap::new(),
            retired_owners: BTreeSet::new(),
            renewal_deadlines: BTreeMap::new(),
            checkpoint: None,
        };
        if directory == Path::new(DIRECTORY) && platform::require_live().is_err() {
            let anchor = crate::resource_checkpoint::ResourceAnchor::installed()?;
            let installation = anchor.installation().to_owned();
            store.checkpoint = Some(std::cell::RefCell::new(checkpoint::Authority::open(
                &Path::new(crate::resource_checkpoint::DIRECTORY).join("paired"),
                directory,
                &installation,
                Box::new(anchor),
            )?));
        }
        let ledger = store.read()?;
        store.retired_owners = store.verify_archives(&ledger)?;
        Ok(store)
    }

    pub(crate) fn read(&self) -> Result<Ledger> {
        if self.poisoned {
            return Err("resource publication uncertain; manager restart required".into());
        }
        let bytes = self.durable_bytes()?;
        let mut ledger: Ledger = serde_json::from_slice(&bytes)
            .map_err(|_| "malformed resource ledger; preserve state")?;
        if serde_json::to_vec(&ledger)? != bytes {
            return Err("noncanonical resource ledger; preserve state".into());
        }
        ledger.validate()?;
        // Fresh ambient observations are session-local telemetry. Every
        // authority transition (including pressure hysteresis) is durable.
        for (id, used) in &self.observations {
            ledger
                .domains
                .get_mut(id)
                .ok_or("telemetry inventory changed")?
                .observed = *used;
        }
        for lease in &mut ledger.leases {
            if lease.state == State::Active {
                if let Some(deadline) = self.renewal_deadlines.get(&lease.token.lease_id) {
                    lease.deadline_ms = *deadline;
                }
            }
        }
        self.verify_exclusion()?;
        Ok(ledger)
    }

    pub(crate) fn transact<T>(
        &mut self,
        operation: impl FnOnce(&mut Ledger) -> Result<T>,
    ) -> Result<T> {
        self.transaction(operation, true, |path, bytes| {
            platform::write_atomic(path, bytes, 0o600)
        })
    }

    pub(crate) fn observe(
        &mut self,
        operation: impl FnOnce(&mut Ledger) -> Result<()>,
    ) -> Result<()> {
        self.transaction(operation, false, |path, bytes| {
            platform::write_atomic(path, bytes, 0o600)
        })
    }

    pub(crate) fn publish_request(
        &self,
        bytes: &[u8],
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        self.verify_exclusion()?;
        match &self.checkpoint {
            Some(authority) => {
                authority
                    .borrow_mut()
                    .publish(&self.directory, "requests.json", bytes, publish)
            }
            None => publish(&self.directory.join("requests.json"), bytes),
        }
    }

    fn archived(&self, reference: &Archive) -> Result<Ledger> {
        self.verify_exclusion()?;
        let bytes = tpm::private_read(&self.directory.join(reference.name()), MAX_BYTES)?;
        if bundle::hex(&Sha256::digest(&bytes)) != reference.sha256 {
            return Err("resource archive digest mismatch; preserve state".into());
        }
        let ledger: Ledger = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&ledger)? != bytes {
            return Err("noncanonical resource archive".into());
        }
        ledger.validate()?;
        if ledger.generation != reference.through_generation
            || ledger.leases.is_empty()
            || ledger.leases.iter().any(|l| l.state != State::Released)
        {
            return Err("resource archive contains outstanding or mismatched generations".into());
        }
        self.verify_exclusion()?;
        Ok(ledger)
    }

    fn verify_archives(&self, ledger: &Ledger) -> Result<BTreeSet<[u8; 32]>> {
        self.verify_exclusion()?;
        let mut count = 0;
        for (index, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if index >= retention::MAX_DIRECTORY_ENTRIES {
                return Err("private resource directory inspection limit exceeded".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid resource state filename")?;
            if name.starts_with(".archive-stage-") || name.starts_with(".archive-retained-") {
                count += 1;
                if count > MAX_ARCHIVE_FILES {
                    return Err("retained resource archive inventory exhausted".into());
                }
                // An interrupted private write is evidence, not an archive or
                // authority. Retain its bounded bytes without interpreting it.
                if let Some(suffix) = name.strip_prefix(".archive-retained-") {
                    retention::verify_retained(&entry.path(), suffix)?;
                } else {
                    tpm::private_read(&entry.path(), MAX_BYTES)?;
                }
                continue;
            }
            if let Some(rest) = name.strip_prefix("archive-") {
                count += 1;
                if count > MAX_ARCHIVE_FILES {
                    return Err("retained resource archive inventory exhausted".into());
                }
                let (generation, hash) = rest.split_once('-').ok_or("invalid archive filename")?;
                let hash = hash.strip_suffix(".json").ok_or("invalid archive suffix")?;
                let reference = Archive {
                    through_generation: generation.parse()?,
                    sha256: hash.into(),
                };
                if reference.name() != name
                    || hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("noncanonical resource archive filename".into());
                }
                // Unreferenced publications can remain after an interrupted
                // rotation. Validate and retain them; never infer a ledger cut.
                if !ledger.archives.contains(&reference) {
                    self.archived(&reference)?;
                }
            }
        }
        let mut retired = BTreeSet::new();
        for (index, reference) in ledger.archives.iter().enumerate() {
            let archived = self.archived(reference)?;
            if archived.archives != ledger.archives[..index] {
                return Err("resource archive predecessor chain mismatch".into());
            }
            for lease in &archived.leases {
                retired.insert(Self::owner_digest(&lease.owner)?);
            }
        }
        self.verify_exclusion()?;
        Ok(retired)
    }

    pub(crate) fn owner_retired(&self, owner: &Owner) -> Result<bool> {
        if self.poisoned {
            return Err("resource publication uncertain; manager restart required".into());
        }
        self.verify_exclusion()?;
        // Reconstruct only from validated immutable receipts at open; extend
        // only after a durable cut. Admission never rescans historical files.
        Ok(self.retired_owners.contains(&Self::owner_digest(owner)?))
    }

    fn owner_digest(owner: &Owner) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(owner)?).into())
    }

    pub(crate) fn archive(&mut self, review: &str, epoch: String) -> Result<Archive> {
        let current = self.read()?;
        if current.review()? != review
            || current.leases.is_empty()
            || current.leases.iter().any(|l| l.state != State::Released)
            || current.archives.len() >= MAX_ARCHIVES
            || !identifier(&epoch)
            || epoch == current.manager_epoch
        {
            return Err("stale archive review, incomplete drainage or exhausted retention".into());
        }
        self.verify_archives(&current)?;
        // Archive the exact durable ledger, not a volatile telemetry overlay.
        let bytes = tpm::private_read(&self.directory.join("ledger.json"), MAX_BYTES)?;
        let reference = Archive {
            through_generation: current.generation,
            sha256: bundle::hex(&Sha256::digest(&bytes)),
        };
        let path = self.directory.join(reference.name());
        let count =
            fs::read_dir(&self.directory)?.try_fold(0usize, |count, entry| -> Result<usize> {
                let name = entry?.file_name();
                let name = name.to_str().ok_or("invalid resource filename")?;
                Ok(count
                    + usize::from(
                        name.starts_with("archive-")
                            || name.starts_with(".archive-stage-")
                            || name.starts_with(".archive-retained-"),
                    ))
            })?;
        let stage = self
            .directory
            .join(format!(".archive-stage-{}", reference.name()));
        if count >= MAX_ARCHIVE_FILES && !path.try_exists()? && !stage.try_exists()? {
            return Err("retained resource archive inventory exhausted".into());
        }
        let publish = (|| -> Result<()> {
            self.verify_exclusion()?;
            if path.try_exists()? {
                if tpm::private_read(&path, MAX_BYTES)? != bytes {
                    return Err("conflicting resource archive publication".into());
                }
                File::open(&path)?.sync_all()?;
                File::open(&self.directory)?.sync_all()?;
                self.verify_exclusion()?;
                return Ok(());
            }
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&stage)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if tpm::private_read(&stage, MAX_BYTES)? != bytes {
                        return Err(
                            "incomplete or conflicting archive preparation; preserve bytes".into(),
                        );
                    }
                    OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&stage)?
                }
                Err(error) => return Err(error.into()),
            };
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            let from = std::ffi::CString::new(stage.as_os_str().as_bytes())?;
            let to = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            if unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            File::open(&self.directory)?.sync_all()?;
            self.verify_exclusion()?;
            Ok(())
        })();
        if publish.is_err() {
            self.poisoned = true;
        }
        publish?;
        self.transact(|l| {
            if l.review()? != review {
                return Err("resource archive authority changed".into());
            }
            l.archives.push(reference.clone());
            l.leases.clear();
            l.manager_epoch = epoch;
            Ok(())
        })?;
        for lease in &current.leases {
            self.retired_owners
                .insert(Self::owner_digest(&lease.owner)?);
        }
        Ok(reference)
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Ledger) -> Result<T>,
        acknowledge: bool,
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<T> {
        let mut next = self.read()?;
        let result = operation(&mut next)?;
        next.validate()?;
        // Renewal is session-local and conservative after a writer restart.
        // The durable admission deadline is never prolonged by a heartbeat.
        // Other mutations keep their full generation/fence/accounting state.
        let durable_before: Ledger = serde_json::from_slice(&self.durable_bytes()?)?;
        let mut durable_next = next.clone();
        for lease in &mut durable_next.leases {
            if let Some(old) = durable_before
                .leases
                .iter()
                .find(|old| old.token == lease.token)
            {
                lease.deadline_ms = old.deadline_ms;
            }
        }
        let bytes = serde_json::to_vec(&durable_next)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("resource journal capacity exhausted".into());
        }
        let unchanged = durable_before.review()? == durable_next.review()?;
        if unchanged {
            // Exact retries acknowledge durable existing state, never acquire
            // another lease or infer success from an earlier rename alone.
            let synchronized = (|| -> Result<()> {
                self.verify_exclusion()?;
                if acknowledge {
                    File::open(self.directory.join("ledger.json"))?.sync_all()?;
                    File::open(&self.directory)?.sync_all()?;
                }
                self.durable_bytes()?;
                Ok(())
            })();
            if synchronized.is_err() {
                self.poisoned = true;
            }
            synchronized?;
            self.observations = next
                .domains
                .iter()
                .map(|(id, d)| (id.clone(), d.observed))
                .collect();
            self.renewal_deadlines = next
                .leases
                .iter()
                .filter(|l| l.state == State::Active)
                .map(|l| (l.token.lease_id.clone(), l.deadline_ms))
                .collect();
            return Ok(result);
        }
        let published = (|| -> Result<()> {
            self.verify_exclusion()?;
            match &self.checkpoint {
                Some(authority) => authority.borrow_mut().publish(
                    &self.directory,
                    "ledger.json",
                    &bytes,
                    publish,
                )?,
                None => publish(&self.directory.join("ledger.json"), &bytes)?,
            }
            self.verify_exclusion()?;
            if tpm::private_read(&self.directory.join("ledger.json"), MAX_BYTES)? != bytes {
                return Err("resource publication readback differs; preserve state".into());
            }
            self.verify_exclusion()?;
            Ok(())
        })();
        if published.is_err() {
            self.poisoned = true;
        }
        published?;
        self.published_sha256 = bundle::hex(&Sha256::digest(&bytes));
        self.observations = next
            .domains
            .iter()
            .map(|(id, d)| (id.clone(), d.observed))
            .collect();
        self.renewal_deadlines = next
            .leases
            .iter()
            .filter(|l| l.state == State::Active)
            .map(|l| (l.token.lease_id.clone(), l.deadline_ms))
            .collect();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heartbeat_renewal_changes_only_session_deadline_and_restart_is_conservative() {
        let directory = std::env::temp_dir().join(format!(
            "luma-resource-volatile-renewal-{}",
            random_id().unwrap()
        ));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        let bytes = fs::read(directory.join("ledger.json")).unwrap();
        let original = store.read().unwrap().leases[0].deadline_ms;
        store
            .transact(|l| l.renew(&token, &owner(1), 2, original + 1000))
            .unwrap();
        assert_eq!(fs::read(directory.join("ledger.json")).unwrap(), bytes);
        assert_eq!(store.read().unwrap().leases[0].deadline_ms, original + 1000);
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        assert_eq!(store.read().unwrap().leases[0].deadline_ms, original);
        store
            .transact(|l| l.restart("epoch-two".into(), ledger().domains))
            .unwrap();
        assert!(store
            .read()
            .unwrap()
            .assert_active(&token, &owner(1), 2)
            .is_err());
        assert_eq!(store.read().unwrap().charged("host").unwrap(), 100);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn output_fence_survives_physical_release_archive_and_store_restart() {
        let directory =
            std::env::temp_dir().join(format!("luma-output-receipt-{}", std::process::id()));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("a".repeat(32), ledger().domains))
            .unwrap();
        let mut who = owner(71);
        who.uid = 0;
        let token = store
            .transact(|l| {
                l.admit(
                    who.clone(),
                    "calculation".into(),
                    "c".repeat(64),
                    vec![reserve("host", 40)],
                    1,
                    100,
                )
            })
            .unwrap();
        store
            .transact(|l| l.complete_output(&token, &who, 2, &"d".repeat(64)))
            .unwrap();
        store.transact(|l| l.revoke(&token, "owner-lost")).unwrap();
        store
            .transact(|l| l.finish_draining(&token, &BTreeMap::from([("host".into(), 0)])))
            .unwrap();
        store
            .transact(|l| l.revoke(&token, "operator-revoked"))
            .unwrap();
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        let receipt = store.read().unwrap().leases[0].clone();
        assert_eq!(receipt.output_sha256, Some("d".repeat(64)));
        assert_eq!(
            receipt.output_domain_epochs,
            Some(BTreeMap::from([("host".into(), OutputEpoch(1))]))
        );
        assert!(receipt.output_fenced);
        assert_eq!(receipt.state, State::Released);
        let reference = store
            .archive(&store.read().unwrap().review().unwrap(), "b".repeat(32))
            .unwrap();
        assert_eq!(store.archived(&reference).unwrap().leases, vec![receipt]);
        drop(store);
        let store = Store::open(&directory).unwrap();
        assert!(store.archived(&reference).unwrap().leases[0].output_fenced);
        drop(store);
        fs::remove_dir_all(&directory).unwrap();
    }
    #[test]
    fn output_domain_epochs_are_complete_canonical_and_lossless() {
        let mut ledger = ledger();
        ledger.domains.get_mut("device").unwrap().epoch = u64::MAX;
        let token = admit(
            &mut ledger,
            81,
            vec![reserve("device", 20), reserve("host", 40)],
        )
        .unwrap();
        ledger
            .complete_output(&token, &owner(81), 2, &"d".repeat(64))
            .unwrap();
        assert_eq!(
            ledger.leases[0].output_domain_epochs,
            Some(BTreeMap::from([
                ("device".into(), OutputEpoch(u64::MAX)),
                ("host".into(), OutputEpoch(1))
            ]))
        );
        let value = serde_json::to_value(&ledger).unwrap();
        assert_eq!(
            value["leases"][0]["output_domain_epochs"]["device"],
            u64::MAX.to_string()
        );
        assert_eq!(
            serde_json::from_value::<Ledger>(value.clone()).unwrap(),
            ledger
        );
        for invalid in [
            serde_json::json!(1),
            serde_json::json!(true),
            serde_json::json!("01"),
            serde_json::json!("+1"),
            serde_json::json!("-1"),
            serde_json::json!("18446744073709551616"),
        ] {
            let mut changed = value.clone();
            changed["leases"][0]["output_domain_epochs"]["host"] = invalid;
            assert!(serde_json::from_value::<Ledger>(changed).is_err());
        }
        for mode in 0..5 {
            let mut changed = ledger.clone();
            match mode {
                0 => {
                    changed.leases[0]
                        .output_domain_epochs
                        .as_mut()
                        .unwrap()
                        .remove("host");
                }
                1 => {
                    changed.leases[0]
                        .output_domain_epochs
                        .as_mut()
                        .unwrap()
                        .insert("unknown".into(), OutputEpoch(1));
                }
                2 => {
                    changed.leases[0]
                        .output_domain_epochs
                        .as_mut()
                        .unwrap()
                        .insert("host".into(), OutputEpoch(0));
                }
                3 => {
                    changed.leases[0]
                        .output_domain_epochs
                        .as_mut()
                        .unwrap()
                        .insert("host".into(), OutputEpoch(2));
                }
                _ => {
                    changed.leases[0].output_sha256 = None;
                }
            }
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn legacy_output_replay_never_stamps_current_epochs_onto_missing_history() {
        let mut ledger = ledger();
        let token = admit(&mut ledger, 82, vec![reserve("host", 40)]).unwrap();
        ledger
            .complete_output(&token, &owner(82), 2, &"d".repeat(64))
            .unwrap();
        ledger.leases[0].output_domain_epochs = None;
        let bytes = serde_json::to_vec(&ledger).unwrap();
        assert!(!std::str::from_utf8(&bytes)
            .unwrap()
            .contains("output_domain_epochs"));
        assert_eq!(
            serde_json::to_vec(&serde_json::from_slice::<Ledger>(&bytes).unwrap()).unwrap(),
            bytes
        );
        ledger.validate().unwrap();
        let before = ledger.clone();
        assert!(ledger
            .complete_output(&token, &owner(82), 2, &"d".repeat(64))
            .is_err());
        assert_eq!(ledger, before);
        assert_eq!(ledger.charged("host").unwrap(), 40);
    }

    fn released_output() -> (Ledger, Token) {
        let mut ledger = ledger();
        let token = admit(
            &mut ledger,
            83,
            vec![reserve("device", 20), reserve("host", 40)],
        )
        .unwrap();
        ledger
            .complete_output(&token, &owner(83), 2, &"d".repeat(64))
            .unwrap();
        ledger.revoke(&token, "owner-lost").unwrap();
        ledger
            .finish_draining(
                &token,
                &BTreeMap::from([("device".into(), 0), ("host".into(), 7)]),
            )
            .unwrap();
        (ledger, token)
    }

    #[test]
    fn released_output_revocation_and_quarantine_are_sticky_without_capacity_changes() {
        let (ledger, token) = released_output();
        assert!(!ledger.leases[0].output_fenced);
        for mode in 0..2 {
            let mut fenced = ledger.clone();
            if mode == 0 {
                fenced.revoke(&token, "operator-revoked").unwrap();
            } else {
                fenced.quarantine("host", "worker-oom").unwrap();
            }
            assert!(fenced.leases[0].output_fenced);
            assert_eq!(fenced.leases[0].state, State::Released);
            assert_eq!(
                fenced.leases[0].output_domain_epochs,
                ledger.leases[0].output_domain_epochs
            );
            assert_eq!(fenced.leases[0].deadline_ms, ledger.leases[0].deadline_ms);
            assert_eq!(fenced.generation, ledger.generation);
            assert_eq!(fenced.charged("host").unwrap(), 7);
            assert_eq!(fenced.charged("device").unwrap(), 0);
            fenced.revoke(&token, "owner-lost").unwrap();
            assert!(fenced.leases[0].output_fenced);
            let review = fenced.review().unwrap();
            fenced
                .clear_quarantine(&review, ledger.domains.clone())
                .unwrap();
            assert!(fenced.leases[0].output_fenced);
            assert_eq!(fenced.charged("host").unwrap(), 7);
        }
    }

    #[test]
    fn epoch_cuts_fence_released_outputs_and_overflow_is_nonmutating() {
        let (ledger, _) = released_output();
        for mode in 0..3 {
            let mut changed = ledger.clone();
            let review = changed.review().unwrap();
            match mode {
                0 => changed
                    .clear_quarantine(&review, ledger.domains.clone())
                    .unwrap(),
                1 => changed
                    .restart("epoch-two".into(), ledger.domains.clone())
                    .unwrap(),
                _ => changed
                    .migrate_inventory(&review, "epoch-two".into(), ledger.domains.clone())
                    .unwrap(),
            }
            assert!(changed.leases[0].output_fenced);
            assert_eq!(
                changed.leases[0].output_domain_epochs,
                ledger.leases[0].output_domain_epochs
            );
            assert_eq!(changed.charged("host").unwrap(), 7);
            assert_eq!(changed.generation, ledger.generation);
            assert_eq!(changed.leases[0].state, State::Released);
        }
        let mut exhausted = ledger.clone();
        exhausted.domains.get_mut("host").unwrap().epoch = u64::MAX;
        let before = exhausted.clone();
        let review = exhausted.review().unwrap();
        assert!(exhausted
            .clear_quarantine(&review, ledger.domains.clone())
            .is_err());
        assert_eq!(exhausted, before);
        assert!(exhausted
            .migrate_inventory(&review, "epoch-two".into(), ledger.domains.clone())
            .is_err());
        assert_eq!(exhausted, before);
    }

    #[test]
    fn committed_output_is_immutable_durable_history_not_a_capacity_return() {
        let mut ledger = ledger();
        let token = admit(&mut ledger, 41, vec![reserve("host", 40)]).unwrap();
        let who = owner(41);
        let before = ledger.clone();
        let old_bytes = serde_json::to_vec(&before).unwrap();
        assert!(!String::from_utf8(old_bytes.clone())
            .unwrap()
            .contains("output_sha256"));
        assert_eq!(
            serde_json::from_slice::<Ledger>(&old_bytes).unwrap(),
            before
        );
        for digest in ["short".to_owned(), "A".repeat(64), "0".repeat(65)] {
            assert!(ledger.complete_output(&token, &who, 2, &digest).is_err());
            assert_eq!(ledger, before);
        }
        assert!(ledger
            .complete_output(&token, &owner(42), 2, &"a".repeat(64))
            .is_err());
        assert_eq!(ledger, before);
        ledger
            .complete_output(&token, &who, 2, &"a".repeat(64))
            .unwrap();
        assert_eq!(
            ledger.charged("host").unwrap(),
            before.charged("host").unwrap()
        );
        assert_eq!(ledger.leases[0].state, State::Active);
        let completed = ledger.clone();
        ledger
            .complete_output(&token, &who, 2, &"a".repeat(64))
            .unwrap();
        assert_eq!(ledger, completed);
        assert!(ledger
            .complete_output(&token, &who, 2, &"b".repeat(64))
            .is_err());
        assert_eq!(ledger, completed);
        let restored: Ledger =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        assert_eq!(restored, ledger);
        ledger.revoke(&token, "cancelled").unwrap();
        let revoked = ledger.clone();
        assert!(ledger
            .complete_output(&token, &who, 2, &"a".repeat(64))
            .is_err());
        assert_eq!(ledger, revoked);
        ledger
            .finish_draining(&token, &BTreeMap::from([("host".into(), 0)]))
            .unwrap();
        assert_eq!(ledger.leases[0].output_sha256, Some("a".repeat(64)));
        assert_eq!(ledger.charged("host").unwrap(), 0);
    }
    use std::sync::{Arc, Mutex};
    fn ledger() -> Ledger {
        let mut ledger = Ledger::empty();
        ledger
            .restart(
                "epoch-one".into(),
                BTreeMap::from([
                    ("host".into(), Domain::new(1000, 100, 950, 800).unwrap()),
                    ("device".into(), Domain::new(500, 50, 490, 400).unwrap()),
                ]),
            )
            .unwrap();
        ledger
    }
    #[test]
    fn reviewed_inventory_migration_preserves_receipts_retained_bytes_and_generation_floor() {
        let mut l = ledger();
        let token = l
            .admit(
                owner(1),
                "work".into(),
                "a".repeat(64),
                vec![reserve("host", 100)],
                1,
                100,
            )
            .unwrap();
        let mut inventory = l.domains.clone();
        inventory.insert("new-slot".into(), Domain::new(1, 0, 1, 0).unwrap());
        let before = l.clone();
        assert!(l
            .migrate_inventory(&l.review().unwrap(), "epoch-two".into(), inventory.clone())
            .is_err());
        assert_eq!(l, before);
        l.revoke(&token, "operator-revoked").unwrap();
        l.finish_draining(&token, &BTreeMap::from([("host".into(), 25)]))
            .unwrap();
        let before = l.clone();
        assert!(l
            .migrate_inventory(&"0".repeat(64), "epoch-two".into(), inventory.clone())
            .is_err());
        assert_eq!(l, before);
        let mut removed = inventory.clone();
        removed.remove("host");
        assert!(l
            .migrate_inventory(&l.review().unwrap(), "epoch-two".into(), removed)
            .is_err());
        assert_eq!(l, before);
        l.migrate_inventory(&l.review().unwrap(), "epoch-two".into(), inventory)
            .unwrap();
        assert_eq!(l.generation, before.generation);
        assert_eq!(l.leases, before.leases);
        assert_eq!(l.domains["host"].retained, 25);
        assert_eq!(l.domains["host"].epoch, before.domains["host"].epoch + 1);
        assert!(l.assert_active(&token, &owner(1), 2).is_err());
        let next = l
            .admit(
                owner(2),
                "fresh".into(),
                "a".repeat(64),
                vec![reserve("host", 100)],
                2,
                100,
            )
            .unwrap();
        assert!(next.generation > token.generation);
    }
    fn owner(pid: u32) -> Owner {
        Owner {
            uid: 989,
            pid,
            start_ticks: 1,
            boot: "boot-one".into(),
            cgroup_device: 1,
            cgroup_inode: u64::from(pid),
        }
    }
    fn reserve(domain: &str, amount: u64) -> Reservation {
        Reservation {
            domain: domain.into(),
            loading: amount,
            serving: amount,
        }
    }
    fn admit(l: &mut Ledger, pid: u32, rs: Vec<Reservation>) -> Result<Token> {
        l.admit(
            owner(pid),
            format!("request-{pid}"),
            "a".repeat(64),
            rs,
            1,
            100,
        )
    }
    #[test]
    fn all_domains_and_loading_peak_admit_atomically() {
        let mut l = ledger();
        let before = l.clone();
        assert!(admit(
            &mut l,
            1,
            vec![reserve("device", 451), reserve("host", 100)]
        )
        .is_err());
        assert_eq!(l, before);
        assert!(admit(&mut l, 1, vec![reserve("host", 901)]).is_err());
        assert_eq!(l, before);
        admit(
            &mut l,
            1,
            vec![Reservation {
                domain: "host".into(),
                loading: 800,
                serving: 100,
            }],
        )
        .unwrap();
        assert_eq!(l.charged("host").unwrap(), 800);
        assert!(admit(&mut l, 2, vec![reserve("host", 101)]).is_err());
    }

    #[test]
    fn verified_same_domain_cache_is_counted_once_and_cannot_credit_another_domain() {
        let mut l = ledger();
        l.observe("host", 500, 500).unwrap();
        let before = l.clone();
        assert!(l
            .admit_reusing_retained(
                owner(1),
                "one".into(),
                "a".repeat(64),
                vec![reserve("host", 800)],
                1,
                100,
                &BTreeMap::from([("host".into(), 501)])
            )
            .is_err());
        assert_eq!(l, before);
        assert!(l
            .admit_reusing_retained(
                owner(1),
                "one".into(),
                "a".repeat(64),
                vec![reserve("host", 800)],
                1,
                100,
                &BTreeMap::from([("device".into(), 1)])
            )
            .is_err());
        assert_eq!(l, before);
        let t = l
            .admit_reusing_retained(
                owner(1),
                "one".into(),
                "a".repeat(64),
                vec![reserve("host", 800)],
                1,
                100,
                &BTreeMap::from([("host".into(), 500)]),
            )
            .unwrap();
        assert_eq!(l.charged("host").unwrap(), 800);
        assert_eq!(
            l.admit_reusing_retained(
                owner(1),
                "one".into(),
                "a".repeat(64),
                vec![reserve("host", 800)],
                2,
                100,
                &BTreeMap::from([("host".into(), 500)])
            )
            .unwrap(),
            t
        );
        assert_eq!(l.charged("host").unwrap(), 800);
    }

    #[test]
    fn decimal_contract_preserves_all_bits_and_refuses_numeric_or_noncanonical_tokens() {
        let token = Token {
            lease_id: "a".repeat(32),
            generation: u64::MAX,
            manager_epoch: "b".repeat(32),
        };
        let bytes = serde_json::to_vec(&token).unwrap();
        assert_eq!(serde_json::from_slice::<Token>(&bytes).unwrap(), token);
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("\"generation\":\"18446744073709551615\""));
        for bad in [
            serde_json::json!(1),
            serde_json::json!("01"),
            serde_json::json!("-1"),
            serde_json::json!("18446744073709551616"),
        ] {
            let mut value = serde_json::to_value(&token).unwrap();
            value["generation"] = bad;
            assert!(serde_json::from_value::<Token>(value).is_err());
        }
    }

    #[test]
    fn failed_observation_and_epoch_overflow_never_mutate_authority() {
        let mut l = ledger();
        l.domains.insert(
            "host".into(),
            Domain::new(u64::MAX, 1, u64::MAX, u64::MAX - 1).unwrap(),
        );
        let before = l.clone();
        assert!(l.observe("host", u64::MAX, 0).is_err());
        assert_eq!(l, before);
        l.domains.get_mut("host").unwrap().epoch = u64::MAX;
        let before = l.clone();
        assert!(l.quarantine("host", "fault").is_err());
        assert_eq!(l, before);
    }
    #[test]
    fn hundred_concurrent_clients_never_double_reserve() {
        let l = Arc::new(Mutex::new(ledger()));
        let gate = Arc::new(std::sync::Barrier::new(100));
        let threads: Vec<_> = (1..=100)
            .map(|pid| {
                let l = Arc::clone(&l);
                let gate = Arc::clone(&gate);
                std::thread::spawn(move || {
                    gate.wait();
                    admit(&mut l.lock().unwrap(), pid, vec![reserve("host", 100)]).is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            9
        );
        assert_eq!(l.lock().unwrap().charged("host").unwrap(), 900);
    }
    #[test]
    fn revoked_expired_and_restarted_leases_hold_capacity_until_observed_drainage() {
        let mut l = ledger();
        let token = admit(&mut l, 1, vec![reserve("host", 900)]).unwrap();
        assert!(l.assert_active(&token, &owner(2), 2).is_err());
        let mut forged = token.clone();
        forged.generation += 1;
        assert!(l.assert_active(&forged, &owner(1), 2).is_err());
        l.expire(100);
        assert!(l.assert_active(&token, &owner(1), 100).is_err());
        assert_eq!(l.charged("host").unwrap(), 900);
        assert!(admit(&mut l, 2, vec![reserve("host", 1)]).is_err());
        assert!(l.finish_draining(&token, &BTreeMap::new()).is_err());
        l.finish_draining(&token, &BTreeMap::from([("host".into(), 20)]))
            .unwrap();
        assert_eq!(l.charged("host").unwrap(), 20);
        let next = admit(&mut l, 2, vec![reserve("host", 800)]).unwrap();
        let inventory = l.domains.clone();
        l.restart("epoch-two".into(), inventory).unwrap();
        assert!(l.assert_active(&next, &owner(2), 2).is_err());
        assert_eq!(l.charged("host").unwrap(), 820);
    }
    #[test]
    fn exact_replay_never_reacquires_and_conflicts_do_not_mutate() {
        let mut l = ledger();
        let t = admit(&mut l, 1, vec![reserve("host", 100)]).unwrap();
        assert_eq!(admit(&mut l, 1, vec![reserve("host", 100)]).unwrap(), t);
        assert_eq!(l.generation, 1);
        assert!(admit(&mut l, 1, vec![reserve("host", 101)]).is_err());
        l.revoke(&t, "cancelled").unwrap();
        assert!(admit(&mut l, 1, vec![reserve("host", 100)]).is_err());
        assert_eq!(l.charged("host").unwrap(), 100);
    }
    #[test]
    fn quarantine_revokes_entire_multidomain_lease_and_review_is_fenced() {
        let mut l = ledger();
        let t = admit(
            &mut l,
            1,
            vec![reserve("device", 100), reserve("host", 100)],
        )
        .unwrap();
        l.quarantine("device", "device-lost").unwrap();
        assert_eq!(l.charged("host").unwrap(), 100);
        assert!(l.assert_active(&t, &owner(1), 2).is_err());
        let review = l.review().unwrap();
        assert!(l.clear_quarantine(&review, l.domains.clone()).is_err());
        l.finish_draining(
            &t,
            &BTreeMap::from([("device".into(), 0), ("host".into(), 0)]),
        )
        .unwrap();
        assert!(l.clear_quarantine(&review, l.domains.clone()).is_err());
        let inventory = BTreeMap::from([
            ("device".into(), Domain::new(500, 50, 490, 400).unwrap()),
            ("host".into(), Domain::new(1000, 100, 950, 800).unwrap()),
        ]);
        l.clear_quarantine(&l.review().unwrap(), inventory).unwrap();
        assert!(!l.domains["device"].quarantined);
    }
    #[test]
    fn generation_overflow_and_invalid_plans_are_nonmutating() {
        let mut l = ledger();
        l.generation = u64::MAX;
        let before = l.clone();
        assert!(admit(&mut l, 1, vec![reserve("host", 1)]).is_err());
        assert_eq!(l, before);
        for rs in [
            vec![],
            vec![reserve("host", 0)],
            vec![reserve("unknown", 1)],
            vec![reserve("host", 1), reserve("host", 1)],
        ] {
            assert!(admit(&mut l, 1, rs).is_err());
            assert_eq!(l, before);
        }
    }
    #[test]
    fn pressure_has_hysteresis_and_does_not_revoke_accepted_foreground_work() {
        let mut l = ledger();
        let t = admit(&mut l, 1, vec![reserve("host", 100)]).unwrap();
        l.observe("host", 850, 0).unwrap();
        assert!(l.domains["host"].pressure);
        assert!(admit(&mut l, 2, vec![reserve("host", 1)]).is_err());
        l.assert_active(&t, &owner(1), 2).unwrap();
        l.observe("host", 750, 0).unwrap();
        assert!(l.domains["host"].pressure);
        l.observe("host", 700, 0).unwrap();
        assert!(!l.domains["host"].pressure);
    }
    #[test]
    fn private_store_serializes_restart_and_preserves_invalid_bytes() {
        let directory =
            std::env::temp_dir().join(format!("luma-resource-store-{}", random_id().unwrap()));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        assert!(Store::open(&directory).is_err());
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-two".into(), ledger().domains))
            .unwrap();
        assert!(store
            .read()
            .unwrap()
            .assert_active(&token, &owner(1), 2)
            .is_err());
        drop(store);
        fs::write(directory.join("ledger.json"), b"{").unwrap();
        assert!(Store::open(&directory).is_err());
        assert_eq!(fs::read(directory.join("ledger.json")).unwrap(), b"{");
        fs::remove_file(directory.join("ledger.json")).unwrap();
        fs::remove_file(directory.join("ledger.lock")).unwrap();
        fs::remove_file(directory.join("requests.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn lost_publication_ack_fences_session_and_restart_never_reuses_the_old_token() {
        let directory =
            std::env::temp_dir().join(format!("luma-resource-lost-ack-{}", random_id().unwrap()));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let result = store.transaction(
            |l| admit(l, 1, vec![reserve("host", 100)]),
            true,
            |path, bytes| {
                platform::write_atomic(path, bytes, 0o600)?;
                Err("injected loss after actual durable publication".into())
            },
        );
        assert!(result.is_err());
        assert!(store.read().is_err());
        assert!(store
            .transact(|l| admit(l, 2, vec![reserve("host", 100)]))
            .is_err());
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        let token = store.read().unwrap().leases[0].token.clone();
        store
            .transact(|l| l.restart("epoch-two".into(), ledger().domains))
            .unwrap();
        let state = store.read().unwrap();
        assert_eq!(state.charged("host").unwrap(), 100);
        assert!(state.assert_active(&token, &owner(1), 2).is_err());
        drop(store);
        fs::remove_file(directory.join("ledger.json")).unwrap();
        fs::remove_file(directory.join("ledger.lock")).unwrap();
        fs::remove_file(directory.join("requests.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn review_binds_authority_but_not_ambient_usage_and_rejects_changed_retained_charges() {
        let mut l = ledger();
        l.quarantine("host", "pressure").unwrap();
        let review = l.review().unwrap();
        l.observe("host", 1, 0).unwrap();
        assert_eq!(l.review().unwrap(), review);
        l.observe("host", 1, 1).unwrap();
        assert_ne!(l.review().unwrap(), review);
    }

    #[test]
    fn telemetry_ticks_do_not_republish_but_pressure_and_expiry_are_durable() {
        let directory =
            std::env::temp_dir().join(format!("luma-resource-telemetry-{}", random_id().unwrap()));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let initial = fs::read(directory.join("ledger.json")).unwrap();
        for used in 1..100 {
            store.observe(|l| l.observe("host", used, 0)).unwrap();
            assert_eq!(fs::read(directory.join("ledger.json")).unwrap(), initial);
            assert_eq!(store.read().unwrap().domains["host"].observed, used);
        }
        store.observe(|l| l.observe("host", 850, 0)).unwrap();
        assert_ne!(fs::read(directory.join("ledger.json")).unwrap(), initial);
        assert!(store.read().unwrap().domains["host"].pressure);
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        assert!(store.read().unwrap().domains["host"].pressure);
        store.observe(|l| l.observe("host", 0, 0)).unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        store
            .observe(|l| {
                l.expire(100);
                Ok(())
            })
            .unwrap();
        drop(store);
        let store = Store::open(&directory).unwrap();
        assert_eq!(store.read().unwrap().charged("host").unwrap(), 100);
        assert!(store
            .read()
            .unwrap()
            .assert_active(&token, &owner(1), 1)
            .is_err());
        drop(store);
        fs::remove_file(directory.join("ledger.json")).unwrap();
        fs::remove_file(directory.join("ledger.lock")).unwrap();
        fs::remove_file(directory.join("requests.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn reviewed_archive_preserves_charges_generation_chain_and_owner_tombstones() {
        let directory =
            std::env::temp_dir().join(format!("luma-resource-archive-{}", random_id().unwrap()));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        let before = fs::read(directory.join("ledger.json")).unwrap();
        assert!(store
            .archive(&store.read().unwrap().review().unwrap(), "epoch-two".into())
            .is_err());
        assert_eq!(fs::read(directory.join("ledger.json")).unwrap(), before);
        store.transact(|l| l.revoke(&token, "cancelled")).unwrap();
        store
            .transact(|l| l.finish_draining(&token, &BTreeMap::from([("host".into(), 20)])))
            .unwrap();
        let review = store.read().unwrap().review().unwrap();
        assert!(store.archive(&"0".repeat(64), "epoch-two".into()).is_err());
        let archive = store.archive(&review, "epoch-two".into()).unwrap();
        assert!(store.archive(&review, "epoch-three".into()).is_err());
        let state = store.read().unwrap();
        assert!(state.leases.is_empty());
        assert_eq!(state.generation, 1);
        assert_eq!(state.charged("host").unwrap(), 20);
        assert_eq!(state.archives, vec![archive.clone()]);
        assert!(state.assert_active(&token, &owner(1), 2).is_err());
        assert!(store.owner_retired(&owner(1)).unwrap());
        assert!(!store.owner_retired(&owner(2)).unwrap());
        let second = store
            .transact(|l| admit(l, 2, vec![reserve("host", 100)]))
            .unwrap();
        assert_eq!(second.generation, 2);
        assert_ne!(second.manager_epoch, token.manager_epoch);
        store.transact(|l| l.revoke(&second, "cancelled")).unwrap();
        store
            .transact(|l| l.finish_draining(&second, &BTreeMap::from([("host".into(), 30)])))
            .unwrap();
        let second_archive = store
            .archive(
                &store.read().unwrap().review().unwrap(),
                "epoch-three".into(),
            )
            .unwrap();
        assert_eq!(
            store.archived(&second_archive).unwrap().archives,
            vec![archive.clone()]
        );
        drop(store);
        let store = Store::open(&directory).unwrap();
        assert_eq!(store.read().unwrap().charged("host").unwrap(), 30);
        assert!(store.owner_retired(&owner(1)).unwrap());
        assert!(store.owner_retired(&owner(2)).unwrap());
        drop(store);
        // Referenced receipts are not advisory logs: damage must fence restart.
        let archived_bytes = fs::read(directory.join(archive.name())).unwrap();
        fs::write(directory.join(archive.name()), b"{").unwrap();
        assert!(Store::open(&directory).is_err());
        assert_eq!(fs::read(directory.join(archive.name())).unwrap(), b"{");
        fs::write(directory.join(archive.name()), archived_bytes).unwrap();
        assert!(Store::open(&directory).is_ok());
        for name in [
            "ledger.json".into(),
            "ledger.lock".into(),
            "requests.json".into(),
            archive.name(),
            second_archive.name(),
        ] {
            fs::remove_file(directory.join(name)).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn orphan_archive_publication_is_retained_and_does_not_retire_the_live_ledger() {
        let directory = std::env::temp_dir().join(format!(
            "luma-resource-archive-orphan-{}",
            random_id().unwrap()
        ));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        store.transact(|l| l.revoke(&token, "cancelled")).unwrap();
        store
            .transact(|l| l.finish_draining(&token, &BTreeMap::from([("host".into(), 0)])))
            .unwrap();
        let bytes = fs::read(directory.join("ledger.json")).unwrap();
        let reference = Archive {
            through_generation: 1,
            sha256: bundle::hex(&Sha256::digest(&bytes)),
        };
        let mut orphan = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(reference.name()))
            .unwrap();
        orphan.write_all(&bytes).unwrap();
        orphan.sync_all().unwrap();
        File::open(&directory).unwrap().sync_all().unwrap();
        drop(orphan);
        drop(store);
        let mut store = Store::open(&directory).unwrap();
        assert_eq!(store.read().unwrap().leases.len(), 1);
        assert!(store.read().unwrap().archives.is_empty());
        assert_eq!(fs::read(directory.join(reference.name())).unwrap(), bytes);
        // An exact reviewed retry publishes only the ledger cut; the archived
        // bytes cannot be overwritten or mistaken for a capacity release.
        assert_eq!(
            store
                .archive(&store.read().unwrap().review().unwrap(), "epoch-two".into())
                .unwrap(),
            reference
        );
        assert_eq!(fs::read(directory.join(reference.name())).unwrap(), bytes);
        drop(store);
        for name in [
            "ledger.json".into(),
            "ledger.lock".into(),
            "requests.json".into(),
            reference.name(),
        ] {
            fs::remove_file(directory.join(name)).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn incomplete_archive_stage_never_becomes_a_published_receipt_or_cuts_authority() {
        let directory = std::env::temp_dir().join(format!(
            "luma-resource-archive-partial-{}",
            random_id().unwrap()
        ));
        initialize(&directory).unwrap();
        let mut store = Store::open(&directory).unwrap();
        store
            .transact(|l| l.restart("epoch-one".into(), ledger().domains))
            .unwrap();
        let token = store
            .transact(|l| admit(l, 1, vec![reserve("host", 100)]))
            .unwrap();
        store.transact(|l| l.revoke(&token, "cancelled")).unwrap();
        store
            .transact(|l| l.finish_draining(&token, &BTreeMap::from([("host".into(), 20)])))
            .unwrap();
        let bytes = fs::read(directory.join("ledger.json")).unwrap();
        let reference = Archive {
            through_generation: 1,
            sha256: bundle::hex(&Sha256::digest(&bytes)),
        };
        let stage = directory.join(format!(".archive-stage-{}", reference.name()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .unwrap();
        file.write_all(b"{").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let review = store.read().unwrap().review().unwrap();
        assert!(store.archive(&review, "epoch-two".into()).is_err());
        assert!(store.read().is_err());
        assert_eq!(fs::read(directory.join("ledger.json")).unwrap(), bytes);
        assert!(!directory.join(reference.name()).exists());
        assert_eq!(fs::read(&stage).unwrap(), b"{");
        drop(store);
        let store = Store::open(&directory).unwrap();
        assert_eq!(store.read().unwrap().generation, 1);
        assert_eq!(store.read().unwrap().charged("host").unwrap(), 20);
        assert!(store.read().unwrap().archives.is_empty());
        drop(store);
        for path in [
            directory.join("ledger.json"),
            directory.join("ledger.lock"),
            directory.join("requests.json"),
            stage,
        ] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }
}
