use super::*;
const ROWS: usize = 32;
#[cfg(test)]
#[path = "directory/tests.rs"]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PartCommitment {
    pub number: u32,
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub objects: u32,
    pub previous_plaintext_sha256: Option<String>,
}
impl PartCommitment {
    pub fn validate(&self) -> Result<()> {
        digest(&self.plaintext_sha256)?;
        digest(&self.ciphertext_sha256)?;
        if self.number >= MAX_SNAPSHOT_PARTS
            || self.plaintext_bytes < 20
            || self.plaintext_bytes > MAX_CANONICAL_PART_BYTES as u64
            || self.ciphertext_bytes == 0
            || self.ciphertext_bytes > self.plaintext_bytes + 65536
            || self.objects > MAX_PART_OBJECTS as u32
            || (self.objects == 0 && self.number != 0)
            || (self.number == 0) != (self.previous_plaintext_sha256.is_none())
        {
            return Err("invalid measured bounded snapshot part commitment".into());
        }
        if let Some(previous) = &self.previous_plaintext_sha256 {
            digest(previous)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PartDirectoryRef {
    pub sha256: String,
    pub first: u32,
    pub count: u32,
    pub height: u8,
    pub objects: u64,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
}
impl PartDirectoryRef {
    pub fn validate(&self) -> Result<()> {
        digest(&self.sha256)?;
        if self.count == 0
            || self.count > MAX_SNAPSHOT_PARTS
            || self.first.checked_add(self.count).is_none()
            || self.first + self.count > MAX_SNAPSHOT_PARTS
            || self.height > 8
            || self.objects > MAX_SNAPSHOT_OBJECTS
            || self.plaintext_bytes < u64::from(self.count) * 20
            || self.plaintext_bytes > u64::from(self.count) * MAX_CANONICAL_PART_BYTES as u64
            || self.ciphertext_bytes < u64::from(self.count)
            || self.ciphertext_bytes > self.plaintext_bytes + u64::from(self.count) * 65536
        {
            return Err("invalid bounded snapshot part-directory span".into());
        }
        Ok(())
    }
}
/// Fixed private export staging I/O. Implementations must forbid aliases and
/// arbitrary extraction paths and retain their real resource/delivery boundary.
pub trait SnapshotPages {
    fn put_page(
        &mut self,
        sha256: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn read_page(&mut self, sha256: &str, check: &mut dyn FnMut() -> Result<()>)
        -> Result<Vec<u8>>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema_version: u32,
    profile: String,
    intent_sha256: String,
    body: Body,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Leaf { parts: Vec<PartCommitment> },
    Branch { children: Vec<PartDirectoryRef> },
}
impl Body {
    fn reference(&self, sha: String) -> Result<PartDirectoryRef> {
        let mut value = PartDirectoryRef {
            sha256: sha,
            first: 0,
            count: 0,
            height: 0,
            objects: 0,
            plaintext_bytes: 0,
            ciphertext_bytes: 0,
        };
        match self {
            Self::Leaf { parts } => {
                if parts.is_empty() || parts.len() > ROWS {
                    return Err("snapshot directory leaf count invalid".into());
                }
                value.first = parts[0].number;
                let mut previous = None;
                for part in parts {
                    part.validate()?;
                    if part.number != value.first + value.count
                        || previous
                            .as_ref()
                            .is_some_and(|old| part.previous_plaintext_sha256.as_ref() != Some(old))
                    {
                        return Err(
                            "snapshot directory leaf reorders parts or plaintext chain".into()
                        );
                    }
                    value.count += 1;
                    value.objects = value
                        .objects
                        .checked_add(u64::from(part.objects))
                        .ok_or("snapshot objects overflow")?;
                    value.plaintext_bytes = value
                        .plaintext_bytes
                        .checked_add(part.plaintext_bytes)
                        .ok_or("snapshot plaintext overflow")?;
                    value.ciphertext_bytes = value
                        .ciphertext_bytes
                        .checked_add(part.ciphertext_bytes)
                        .ok_or("snapshot ciphertext overflow")?;
                    previous = Some(part.plaintext_sha256.clone());
                }
            }
            Self::Branch { children } => {
                if children.is_empty() || children.len() > ROWS {
                    return Err("snapshot directory fanout invalid".into());
                }
                value.first = children[0].first;
                value.height = children[0]
                    .height
                    .checked_add(1)
                    .ok_or("snapshot tree depth overflow")?;
                for child in children {
                    child.validate()?;
                    if child.first != value.first + value.count || child.height + 1 != value.height
                    {
                        return Err("snapshot directory branch loses ordered coverage".into());
                    }
                    value.count = value
                        .count
                        .checked_add(child.count)
                        .ok_or("snapshot part count overflow")?;
                    value.objects = value
                        .objects
                        .checked_add(child.objects)
                        .ok_or("snapshot objects overflow")?;
                    value.plaintext_bytes = value
                        .plaintext_bytes
                        .checked_add(child.plaintext_bytes)
                        .ok_or("snapshot plaintext overflow")?;
                    value.ciphertext_bytes = value
                        .ciphertext_bytes
                        .checked_add(child.ciphertext_bytes)
                        .ok_or("snapshot ciphertext overflow")?;
                }
            }
        }
        value.validate()?;
        Ok(value)
    }
}
fn put(
    intent: &SnapshotIntent,
    body: Body,
    pages: &mut impl SnapshotPages,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<PartDirectoryRef> {
    check()?;
    let page = Page {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256()?,
        body,
    };
    let bytes = bounded(&page, MAX_PAGE_BYTES)?;
    let sha = luma_content::sha256(&bytes);
    let reference = page.body.reference(sha.clone())?;
    pages.put_page(&sha, &bytes, check)?;
    check()?;
    if pages.read_page(&sha, check)? != bytes {
        return Err("snapshot directory retained readback differs".into());
    }
    check()?;
    Ok(reference)
}
fn get(
    intent: &SnapshotIntent,
    reference: &PartDirectoryRef,
    pages: &mut impl SnapshotPages,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Body> {
    Ok(get_page(intent, reference, pages, check)?.0)
}
fn get_page(
    intent: &SnapshotIntent,
    reference: &PartDirectoryRef,
    pages: &mut impl SnapshotPages,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Body, Vec<u8>)> {
    reference.validate()?;
    check()?;
    let bytes = pages.read_page(&reference.sha256, check)?;
    if bytes.is_empty()
        || bytes.len() > MAX_PAGE_BYTES
        || luma_content::sha256(&bytes) != reference.sha256
    {
        return Err("snapshot directory page hash/length differs".into());
    }
    let page: Page = canonical(&bytes, MAX_PAGE_BYTES)?;
    if page.schema_version != 1
        || page.profile != SNAPSHOT_PROFILE
        || page.intent_sha256 != intent.sha256()?
        || page.body.reference(reference.sha256.clone())? != *reference
    {
        return Err("snapshot directory owner/intent/span differs".into());
    }
    check()?;
    Ok((page.body, bytes))
}
pub(super) struct Builder {
    parts: Vec<PartCommitment>,
    leaves: Vec<PartDirectoryRef>,
    count: u32,
}
impl Builder {
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            leaves: Vec::new(),
            count: 0,
        }
    }
    pub fn push(
        &mut self,
        intent: &SnapshotIntent,
        part: PartCommitment,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        part.validate()?;
        if part.number != self.count || self.count >= MAX_SNAPSHOT_PARTS {
            return Err("snapshot builder part sequence/cap differs".into());
        }
        self.parts.push(part);
        self.count += 1;
        if self.parts.len() == ROWS {
            self.flush(intent, pages, check)?;
        }
        Ok(())
    }
    fn flush(
        &mut self,
        intent: &SnapshotIntent,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if !self.parts.is_empty() {
            self.leaves.push(put(
                intent,
                Body::Leaf {
                    parts: std::mem::take(&mut self.parts),
                },
                pages,
                check,
            )?);
        }
        if self.leaves.len() > (MAX_SNAPSHOT_PARTS as usize + ROWS - 1) / ROWS {
            return Err("snapshot bounded directory root buffer exhausted".into());
        }
        Ok(())
    }
    pub fn finish(
        mut self,
        intent: &SnapshotIntent,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PartDirectoryRef> {
        self.flush(intent, pages, check)?;
        if self.leaves.is_empty() {
            return Err("whole snapshot has no encrypted parts".into());
        }
        while self.leaves.len() > 1 {
            let mut next = Vec::new();
            for children in self.leaves.chunks(ROWS) {
                next.push(put(
                    intent,
                    Body::Branch {
                        children: children.to_vec(),
                    },
                    pages,
                    check,
                )?);
            }
            self.leaves = next;
        }
        self.leaves
            .pop()
            .ok_or_else(|| "snapshot directory root absent".into())
    }
}
impl WholeSnapshotManifest {
    /// Verifies every declared commitment, not ciphertext authenticity or live
    /// restore authority. Native callers verify the whole origin signature first.
    pub fn verify_directory(
        &self,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.visit_directory(pages, check, &mut |_, check| check())
    }
    /// Visits the actual canonical pages and their committed parts in packed
    /// depth-first preorder. All spans, hashes, intent, part packing and final
    /// coverage are verified using the same codec as selected part reads.
    /// Events are inert DATA, not origin authentication or permission to retain
    /// bytes. No complete result is returned after any failed visitor/check.
    pub fn visit_directory(
        &self,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
        visitor: &mut impl FnMut(
            SnapshotDirectoryEntry<'_>,
            &mut dyn FnMut() -> Result<()>,
        ) -> Result<()>,
    ) -> Result<()> {
        self.validate()?;
        let mut capacity = ROWS as u64;
        let mut height = 0;
        while u64::from(self.part_count) > capacity {
            capacity *= ROWS as u64;
            height += 1;
        }
        if self.parts.height != height {
            return Err("snapshot directory root is not minimally packed".into());
        }
        let mut next = 0_u32;
        let mut previous = None;
        let mut objects = 0_u64;
        let mut pages_seen = 0_u32;
        let mut page_bytes = 0_u64;
        walk(
            &self.intent,
            &self.parts,
            self.part_count,
            pages,
            check,
            &mut |entry, check| {
                check()?;
                match entry {
                    SnapshotDirectoryEntry::Page { bytes, .. } => {
                        pages_seen = pages_seen.checked_add(1).ok_or("directory page overflow")?;
                        page_bytes = page_bytes
                            .checked_add(bytes.len() as u64)
                            .ok_or("directory bytes overflow")?;
                        if pages_seen > MAX_SNAPSHOT_DIRECTORY_PAGES
                            || page_bytes > MAX_SNAPSHOT_DIRECTORY_BYTES
                        {
                            return Err(
                                "canonical directory exceeds bounded page reservation".into()
                            );
                        }
                    }
                    SnapshotDirectoryEntry::Part(part) => {
                        if part.number != next || part.previous_plaintext_sha256 != previous {
                            return Err("whole snapshot reordered/substituted a part chain".into());
                        }
                        if part.objects != self.expected_part_objects(part.number)? {
                            return Err(
                                "whole snapshot loses canonical fixed-size object packing".into()
                            );
                        }
                        next += 1;
                        objects = objects
                            .checked_add(u64::from(part.objects))
                            .ok_or("whole snapshot object overflow")?;
                        previous = Some(part.plaintext_sha256.clone());
                    }
                }
                visitor(entry, check)?;
                check()
            },
        )?;
        if next != self.part_count
            || objects != self.review.object_count
            || previous.as_ref() != Some(&self.last_plaintext_sha256)
        {
            return Err("whole snapshot final part/object/chain coverage incomplete".into());
        }
        check()
    }
    pub fn part_at(
        &self,
        number: u32,
        pages: &mut impl SnapshotPages,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<PartCommitment> {
        self.validate()?;
        if number >= self.part_count {
            return Err("snapshot part selection outside complete manifest".into());
        }
        let part = at(&self.intent, &self.parts, number, pages, check)?;
        if part.objects != self.expected_part_objects(number)? {
            return Err("selected snapshot part loses canonical object coverage".into());
        }
        check()?;
        Ok(part)
    }
    fn expected_part_objects(&self, number: u32) -> Result<u32> {
        if number >= self.part_count {
            return Err("snapshot part outside canonical coverage".into());
        }
        let before = u64::from(number) * MAX_PART_OBJECTS as u64;
        Ok(self
            .review
            .object_count
            .checked_sub(before)
            .ok_or("snapshot part begins after whole object coverage")?
            .min(MAX_PART_OBJECTS as u64) as u32)
    }
}
/// Borrowed canonical directory DATA. The walker retains at most one bounded
/// page per level; callers must separately account any copies they retain.
#[derive(Clone, Copy)]
pub enum SnapshotDirectoryEntry<'a> {
    Page {
        reference: &'a PartDirectoryRef,
        bytes: &'a [u8],
    },
    Part(&'a PartCommitment),
}
fn walk(
    intent: &SnapshotIntent,
    reference: &PartDirectoryRef,
    total_parts: u32,
    pages: &mut impl SnapshotPages,
    check: &mut impl FnMut() -> Result<()>,
    visitor: &mut impl FnMut(SnapshotDirectoryEntry<'_>, &mut dyn FnMut() -> Result<()>) -> Result<()>,
) -> Result<()> {
    reference.validate()?;
    let span = (ROWS as u64).pow(u32::from(reference.height) + 1);
    if u64::from(reference.first) % span != 0
        || reference.first >= total_parts
        || u64::from(reference.count) != span.min(u64::from(total_parts - reference.first))
    {
        return Err("snapshot directory does not use canonical full nonfinal spans".into());
    }
    let (body, bytes) = get_page(intent, reference, pages, check)?;
    check()?;
    visitor(
        SnapshotDirectoryEntry::Page {
            reference,
            bytes: &bytes,
        },
        check,
    )?;
    check()?;
    match body {
        Body::Leaf { parts } => {
            for part in parts {
                check()?;
                visitor(SnapshotDirectoryEntry::Part(&part), check)?;
                check()?;
            }
        }
        Body::Branch { children } => {
            for child in children {
                walk(intent, &child, total_parts, pages, check, visitor)?;
            }
        }
    }
    check()
}
fn at(
    intent: &SnapshotIntent,
    reference: &PartDirectoryRef,
    number: u32,
    pages: &mut impl SnapshotPages,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<PartCommitment> {
    match get(intent, reference, pages, check)? {
        Body::Leaf { parts } => parts
            .into_iter()
            .find(|part| part.number == number)
            .ok_or_else(|| "snapshot selected part absent".into()),
        Body::Branch { children } => {
            let child = children
                .into_iter()
                .find(|child| child.first <= number && number < child.first + child.count)
                .ok_or("snapshot selected part path absent")?;
            at(intent, &child, number, pages, check)
        }
    }
}
