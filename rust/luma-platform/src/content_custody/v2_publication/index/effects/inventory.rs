//! Complete ordered object-inventory closure in the PRIVATE C namespace.
//! This is bounded immutable DATA; hashing/persisting it never selects a root.
use super::*;
const DOMAIN: &str = "luma-c-index-write-inventory-v1";
pub(super) const MAX_OBJECTS: usize = 32768;
const OBJECTS_PER_PAGE: usize = 128;
const MAX_PAGES: usize = 256;
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct InventoryRoot {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    inventory_sha256: String,
    objects: u32,
    object_bytes: u64,
    pages: u16,
    closure_bytes: u64,
    first: Option<RecordRef>,
}
impl InventoryRoot {
    pub(super) fn validate(&self, binding: &OwnerBinding) -> Result<()> {
        binding.validate()?;
        self.binding.validate()?;
        digest(&self.inventory_sha256)?;
        let pages = (self.objects as usize + OBJECTS_PER_PAGE - 1) / OBJECTS_PER_PAGE;
        if self.schema_version != 1
            || self.domain != DOMAIN
            || &self.binding != binding
            || self.objects as usize > MAX_OBJECTS
            || self.object_bytes > MAX_OBJECT_BYTES
            || usize::from(self.pages) != pages
            || pages > MAX_PAGES
            || self.closure_bytes > MAX_BYTES
            || (self.objects == 0) != (self.first.is_none())
            || (self.objects == 0) != (self.closure_bytes == 0)
            || (self.objects == 0) != (self.object_bytes == 0)
            || self.object_bytes < u64::from(self.objects)
        {
            return Err("C write-inventory root changes owner/complete finite shape".into());
        }
        if let Some(first) = &self.first {
            page_ref(first)?;
        } else if self.inventory_sha256 != hash(b"[]") {
            return Err("empty C inventory is not canonical empty data".into());
        }
        Ok(())
    }
    pub(super) fn sha256(&self) -> Result<String> {
        self.validate(&self.binding)?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub(super) fn object_count(&self) -> u32 {
        self.objects
    }
    pub(super) fn object_bytes(&self) -> u64 {
        self.object_bytes
    }
    pub(super) fn closure_bytes(&self) -> u64 {
        self.closure_bytes
    }
    pub(super) fn page_count(&self) -> u16 {
        self.pages
    }
    pub(super) fn inventory_sha256(&self) -> &str {
        &self.inventory_sha256
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    domain: String,
    binding: OwnerBinding,
    inventory_sha256: String,
    ordinal: u16,
    pages: u16,
    objects: Vec<ObjectWriteSpec>,
    next: Option<RecordRef>,
}
fn page_ref(value: &RecordRef) -> Result<()> {
    value.validate()?;
    if value.bytes > PAGE_BYTES as u64 {
        return Err("C inventory page exceeds fixed16KiB frame".into());
    }
    Ok(())
}
fn objects_data(
    objects: &[ObjectWriteSpec],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(String, u64)> {
    if objects.len() > MAX_OBJECTS {
        return Err("C derivative inventory exceeds32768 objects".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for object in objects {
        check()?;
        object.validate()?;
        if !seen.insert(object.sha256.as_str()) {
            return Err("C inventory repeats an object identifier".into());
        }
        total = total
            .checked_add(u64::from(object.bytes))
            .filter(|n| *n <= MAX_OBJECT_BYTES)
            .ok_or("C derivative inventory exceeds finite source bytes")?;
    }
    check()?;
    let bytes = serde_json::to_vec(objects)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("C inventory canonical object list exceeds4MiB".into());
    }
    let sha = hash(&bytes);
    check()?;
    Ok((sha, total))
}

/// All bytes are computed before any C write. This permits an actual direct
/// publisher to reserve the exact complete closure and terminal tails first.
pub(super) struct InventoryPlan {
    root: InventoryRoot,
    pages: Vec<(RecordRef, Vec<u8>)>,
}
impl InventoryPlan {
    pub(super) fn data(
        binding: &OwnerBinding,
        objects: &[ObjectWriteSpec],
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        binding.validate()?;
        let (inventory_sha256, object_bytes) = objects_data(objects, check)?;
        let count = (objects.len() + OBJECTS_PER_PAGE - 1) / OBJECTS_PER_PAGE;
        let mut pages = Vec::with_capacity(count);
        let mut next = None;
        let mut closure_bytes = 0u64;
        for ordinal in (0..count).rev() {
            check()?;
            let first = ordinal * OBJECTS_PER_PAGE;
            let page = Page {
                schema_version: 1,
                domain: DOMAIN.into(),
                binding: binding.clone(),
                inventory_sha256: inventory_sha256.clone(),
                ordinal: ordinal.try_into()?,
                pages: count.try_into()?,
                objects: objects[first..(first + OBJECTS_PER_PAGE).min(objects.len())].to_vec(),
                next,
            };
            let bytes = serde_json::to_vec(&page)?;
            if bytes.is_empty() || bytes.len() > PAGE_BYTES {
                return Err("C inventory canonical page exceeds16KiB".into());
            }
            closure_bytes = closure_bytes
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= MAX_BYTES)
                .ok_or("C inventory full encoded closure exceeds4MiB")?;
            let reference = RecordRef {
                sha256: hash(&bytes),
                bytes: bytes.len() as u64,
            };
            page_ref(&reference)?;
            next = Some(reference.clone());
            pages.push((reference, bytes));
        }
        pages.reverse();
        let root = InventoryRoot {
            schema_version: 1,
            domain: DOMAIN.into(),
            binding: binding.clone(),
            inventory_sha256,
            objects: objects.len().try_into()?,
            object_bytes,
            pages: count.try_into()?,
            closure_bytes,
            first: next,
        };
        root.validate(binding)?;
        check()?;
        Ok(Self { root, pages })
    }
    pub(super) fn root(&self) -> &InventoryRoot {
        &self.root
    }
    #[allow(dead_code)]
    pub(super) fn pages(&self) -> &[(RecordRef, Vec<u8>)] {
        &self.pages
    }
    /// Consume the caller's ALREADY admitted C-only write reservation. This
    /// never resets capacity, calls NV, accepts an external path, or grants Go.
    pub(super) fn persist_unselected(
        &self,
        store: &PageStore,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.root.validate(&self.root.binding)?;
        for (reference, bytes) in self.pages.iter().rev() {
            check()?;
            if store.write_record(bytes, check)? != reference.sha256 {
                return Err("C inventory staged record SHA differs".into());
            }
        }
        let reopened = read(
            store,
            &self.root,
            &self.root.binding,
            self.root.closure_bytes + u64::from(self.root.pages),
            check,
        )?;
        let (sha, object_bytes) = objects_data(&reopened, check)?;
        if sha != self.root.inventory_sha256 || object_bytes != self.root.object_bytes {
            return Err("C inventory full readback differs".into());
        }
        check()
    }
}

pub(super) fn walk(
    root: &InventoryRoot,
    binding: &OwnerBinding,
    mut credit: u64,
    check: &mut impl FnMut() -> Result<()>,
    mut read: impl FnMut(&RecordRef, &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>>,
) -> Result<Vec<ObjectWriteSpec>> {
    check()?;
    root.validate(binding)?;
    let mut objects = Vec::with_capacity(root.objects as usize);
    let mut next = root.first.clone();
    let mut seen = std::collections::BTreeSet::new();
    let mut closure_bytes = 0u64;
    for ordinal in 0..root.pages {
        check()?;
        let reference = next
            .take()
            .ok_or("C inventory ends before selected complete coverage")?;
        page_ref(&reference)?;
        if !seen.insert(reference.sha256.clone()) {
            return Err("C inventory closure cycles or reuses a page".into());
        }
        credit = credit
            .checked_sub(reference.bytes + 1)
            .ok_or("C inventory read reservation exhausted before private IO")?;
        let bytes = read(&reference, check)?;
        check()?;
        if bytes.len() as u64 != reference.bytes || hash(&bytes) != reference.sha256 {
            return Err("C inventory page hash/length differs from retained reference".into());
        }
        let page: Page = canonical(&bytes, PAGE_BYTES)?;
        if page.schema_version != 1
            || page.domain != DOMAIN
            || page.binding != *binding
            || page.inventory_sha256 != root.inventory_sha256
            || page.ordinal != ordinal
            || page.pages != root.pages
            || page.objects.is_empty()
            || page.objects.len() > OBJECTS_PER_PAGE
            || (ordinal + 1 < root.pages && page.objects.len() != OBJECTS_PER_PAGE)
            || (ordinal + 1 == root.pages) != page.next.is_none()
        {
            return Err(
                "C inventory page changes exact ordinal/packed shape/owner/terminal coverage"
                    .into(),
            );
        }
        closure_bytes = closure_bytes
            .checked_add(reference.bytes)
            .filter(|n| *n <= root.closure_bytes)
            .ok_or("C inventory encoded-byte coverage exceeds selected root")?;
        if objects.len() + page.objects.len() > root.objects as usize {
            return Err("C inventory object coverage exceeds selected root".into());
        }
        objects.extend(page.objects);
        next = page.next;
    }
    if next.is_some()
        || objects.len() != root.objects as usize
        || closure_bytes != root.closure_bytes
    {
        return Err("C inventory closure omits or appends unselected data".into());
    }
    let (sha, total) = objects_data(&objects, check)?;
    if sha != root.inventory_sha256 || total != root.object_bytes {
        return Err("C inventory whole ordered object digest/count differs".into());
    }
    check()?;
    Ok(objects)
}

pub(super) fn read(
    store: &PageStore,
    root: &InventoryRoot,
    binding: &OwnerBinding,
    credit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<ObjectWriteSpec>> {
    walk(root, binding, credit, check, |reference, current| {
        // The closed hash class is derived internally, never an archive path.
        // Read enforces16KiB BEFORE allocating even for a damaged oversized file.
        let name = format!(
            "records/{}/{}/{}",
            &reference.sha256[..2],
            &reference.sha256[2..4],
            reference.sha256
        );
        store.read(&name, PAGE_BYTES, &mut || current())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    struct FilesFixture {
        root: std::path::PathBuf,
        store: PageStore,
    }
    impl FilesFixture {
        fn new() -> Self {
            assert!(
                std::path::Path::new("/.dockerenv").is_file(),
                "disposable offline container required"
            );
            assert!(
                !std::path::Path::new("/dev/tpm0").exists()
                    && !std::path::Path::new("/dev/tpmrm0").exists()
            );
            let base = std::path::PathBuf::from(
                std::env::var("LUMA_STORAGE_TEST_ROOT").expect("explicit disposable ext4 root"),
            );
            assert_eq!(std::fs::canonicalize(&base).unwrap(), base);
            let root = base.join(format!(
                "luma-tpm-index-inventory-{}",
                crate::resources::random_id().unwrap()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let binding = map::CustodyBinding {
                installation: owner().installation,
                sealed_genesis_sha256: "3".repeat(64),
            };
            let store = PageStore::create(&root, binding, &mut || Ok(())).unwrap();
            Self { root, store }
        }
        fn path(&self, sha: &str) -> std::path::PathBuf {
            self.root
                .join("paged-v3")
                .join("records")
                .join(&sha[..2])
                .join(&sha[2..4])
                .join(sha)
        }
    }
    impl Drop for FilesFixture {
        fn drop(&mut self) {
            // Only the exact exclusively created random child is test-owned.
            assert!(self
                .root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("luma-tpm-index-inventory-"));
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
    fn owner() -> OwnerBinding {
        OwnerBinding {
            installation: "1".repeat(64),
            owner: "2".repeat(64),
            owner_generation: 7,
        }
    }
    fn objects(count: usize) -> Vec<ObjectWriteSpec> {
        (0..count)
            .map(|n| ObjectWriteSpec {
                sha256: hash(&n.to_be_bytes()),
                bytes: 16,
            })
            .collect()
    }
    fn reopen(plan: &InventoryPlan) -> Result<Vec<ObjectWriteSpec>> {
        walk(
            &plan.root,
            &owner(),
            MAX_BYTES + MAX_PAGES as u64,
            &mut || Ok(()),
            |reference, current| {
                current()?;
                Ok(plan
                    .pages
                    .iter()
                    .find(|(r, _)| r == reference)
                    .ok_or("fixture page missing")?
                    .1
                    .clone())
            },
        )
    }
    #[test]
    fn full_bounded_ordered_inventory_including_empty_audit_is_complete_data() {
        for count in [0, 1, 128, 129, MAX_OBJECTS] {
            let values = objects(count);
            let plan = InventoryPlan::data(&owner(), &values, &mut || Ok(())).unwrap();
            assert_eq!(reopen(&plan).unwrap(), values);
            assert!(plan.root.closure_bytes <= MAX_BYTES);
            assert!(plan.pages.iter().all(|(_, b)| b.len() <= PAGE_BYTES));
            assert_eq!(plan.root.object_count(), count as u32);
        }
    }
    #[test]
    fn duplicate_oversized_or_revoked_inventory_refuses_before_construction() {
        let mut values = objects(2);
        values[1] = values[0].clone();
        assert!(InventoryPlan::data(&owner(), &values, &mut || Ok(())).is_err());
        assert!(InventoryPlan::data(&owner(), &objects(MAX_OBJECTS + 1), &mut || Ok(())).is_err());
        let mut values = objects(1);
        values[0].bytes = 16385;
        assert!(InventoryPlan::data(&owner(), &values, &mut || Ok(())).is_err());
        assert!(
            InventoryPlan::data(&owner(), &objects(1), &mut || Err("fixture revoked".into()))
                .is_err()
        );
    }
    #[test]
    fn bad_page_hash_missing_end_wrong_owner_and_exhausted_credit_never_complete() {
        let plan = InventoryPlan::data(&owner(), &objects(129), &mut || Ok(())).unwrap();
        assert!(walk(&plan.root, &owner(), 0, &mut || Ok(()), |_, _| panic!(
            "budget before IO"
        ))
        .is_err());
        let mut other = owner();
        other.owner_generation += 1;
        assert!(walk(
            &plan.root,
            &other,
            MAX_BYTES,
            &mut || Ok(()),
            |_, _| panic!("owner before IO")
        )
        .is_err());
        assert!(
            walk(&plan.root, &owner(), MAX_BYTES, &mut || Ok(()), |_, _| Ok(
                vec![1]
            ))
            .is_err()
        );
        let mut changed = plan.root.clone();
        changed.pages = 1;
        assert!(walk(
            &changed,
            &owner(),
            MAX_BYTES,
            &mut || Ok(()),
            |_, _| panic!("shape before IO")
        )
        .is_err());
        let mut calls = 0;
        assert!(walk(
            &plan.root,
            &owner(),
            MAX_BYTES,
            &mut || {
                calls += 1;
                if calls > 3 {
                    Err("fixture revoked".into())
                } else {
                    Ok(())
                }
            },
            |reference, _| Ok(plan
                .pages
                .iter()
                .find(|(r, _)| r == reference)
                .unwrap()
                .1
                .clone())
        )
        .is_err());
    }
    #[test]
    fn canonically_rehashed_bad_packing_or_trailing_chain_refuses() {
        let values = objects(129);
        for field in 0..4 {
            let mut plan = InventoryPlan::data(&owner(), &values, &mut || Ok(())).unwrap();
            let mut page: Page = canonical(&plan.pages[0].1, PAGE_BYTES).unwrap();
            match field {
                0 => page.ordinal += 1,
                1 => {
                    page.objects.pop();
                }
                2 => page.next = None,
                3 => page.inventory_sha256 = "3".repeat(64),
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&page).unwrap();
            let reference = RecordRef {
                sha256: hash(&bytes),
                bytes: bytes.len() as u64,
            };
            plan.root.closure_bytes =
                plan.root.closure_bytes - plan.pages[0].0.bytes + reference.bytes;
            plan.root.first = Some(reference.clone());
            plan.pages[0] = (reference, bytes);
            assert!(reopen(&plan).is_err(), "field {field}");
        }
    }
    #[test]
    fn actual_private_c_files_sync_readback_preserve_full_ordered_closure_not_selection() {
        let fixture = FilesFixture::new();
        let objects = objects(257);
        let plan = InventoryPlan::data(&owner(), &objects, &mut || Ok(())).unwrap();
        fixture
            .store
            .admit_writes(
                MAX_BYTES,
                MAX_PAGES as u64,
                2 * MAX_PAGES as u64,
                &mut || Ok(()),
            )
            .unwrap();
        plan.persist_unselected(&fixture.store, &mut || Ok(()))
            .unwrap();
        assert_eq!(
            read(
                &fixture.store,
                plan.root(),
                &owner(),
                MAX_BYTES + MAX_PAGES as u64,
                &mut || Ok(())
            )
            .unwrap(),
            objects
        );
        let actual = fixture.store.inventory(&mut || Ok(())).unwrap();
        assert_eq!(actual.files, u64::from(plan.root().pages) + 1);
        assert_eq!(actual.interrupted_files, 0);
        assert!(!fixture.root.join("paged-v3/selected.json").exists());
        assert!(!fixture.root.join("paged-v3/pending.json").exists());
    }
    #[test]
    fn actual_tampered_or_oversized_page_refuses_without_partial_complete_result() {
        use std::io::Write;
        let fixture = FilesFixture::new();
        let plan = InventoryPlan::data(&owner(), &objects(129), &mut || Ok(())).unwrap();
        fixture
            .store
            .admit_writes(
                MAX_BYTES,
                MAX_PAGES as u64,
                2 * MAX_PAGES as u64,
                &mut || Ok(()),
            )
            .unwrap();
        plan.persist_unselected(&fixture.store, &mut || Ok(()))
            .unwrap();
        let reference = plan.root.first.as_ref().unwrap();
        let path = fixture.path(&reference.sha256);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(&vec![b'x'; PAGE_BYTES + 1]).unwrap();
        file.sync_all().unwrap();
        assert!(read(
            &fixture.store,
            plan.root(),
            &owner(),
            MAX_BYTES,
            &mut || Ok(())
        )
        .is_err());
    }
    #[test]
    fn actual_revoked_partial_creation_remains_inert_and_cannot_reset_write_admission() {
        let fixture = FilesFixture::new();
        let plan = InventoryPlan::data(&owner(), &objects(129), &mut || Ok(())).unwrap();
        fixture
            .store
            .admit_writes(
                MAX_BYTES,
                MAX_PAGES as u64,
                2 * MAX_PAGES as u64,
                &mut || Ok(()),
            )
            .unwrap();
        let first_written = &plan.pages.last().unwrap().0.sha256;
        let at = fixture.path(first_written);
        assert!(plan
            .persist_unselected(&fixture.store, &mut || {
                if at.exists() {
                    Err("fixture original operation revoked after actual exclusive create".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(at.exists());
        assert!(!fixture.root.join("paged-v3/selected.json").exists());
        assert!(fixture
            .store
            .admit_writes(
                MAX_BYTES,
                MAX_PAGES as u64,
                2 * MAX_PAGES as u64,
                &mut || Ok(())
            )
            .is_err());
    }
}
