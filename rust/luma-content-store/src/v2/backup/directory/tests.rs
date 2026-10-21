//! Directory DATA codec tests only, not CMS or selected custody qualification.
use super::*;
use std::collections::BTreeMap;
#[derive(Default)]
struct Pages(BTreeMap<String, Vec<u8>>);
impl SnapshotPages for Pages {
    fn put_page(
        &mut self,
        sha: &str,
        bytes: &[u8],
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.0.insert(sha.into(), bytes.to_vec());
        check()
    }
    fn read_page(&mut self, sha: &str, check: &mut dyn FnMut() -> Result<()>) -> Result<Vec<u8>> {
        check()?;
        self.0
            .get(sha)
            .cloned()
            .ok_or_else(|| "fixture directory page absent".into())
    }
}
fn fixture(count: u32) -> (WholeSnapshotManifest, Pages) {
    let head = OwnerHeadV2::empty_data(
        &OwnerBinding {
            installation: "a".repeat(64),
            owner: "b".repeat(64),
            owner_generation: 1,
        },
        PhysicalInventory::default(),
    )
    .unwrap();
    let intent = SnapshotIntent {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        snapshot_id: "c".repeat(64),
        head_sha256: head.sha256().unwrap(),
        head,
        recipient_generation: 1,
        recipients_sha256: "d".repeat(64),
        origin_spki_sha256: "e".repeat(64),
    };
    let objects = u64::from(count - 1) * 32 + 1;
    let mut review = SnapshotReview {
        schema_version: 1,
        profile: SNAPSHOT_PROFILE.into(),
        intent_sha256: intent.sha256().unwrap(),
        inventory: PhysicalInventory {
            regular_files: objects + 1,
            directories: 2,
            logical_bytes: objects,
            ..Default::default()
        },
        object_count: objects,
        object_bytes: objects,
        stream_sha256: "f".repeat(64),
        review_sha256: String::new(),
    };
    review.finish(&intent).unwrap();
    let mut pages = Pages::default();
    let mut builder = Builder::new();
    let mut previous = None;
    let mut plain = 0;
    let mut cipher = 0;
    for number in 0..count {
        let sha = luma_content::sha256(&number.to_be_bytes());
        let n = if number + 1 == count { 1 } else { 32 };
        let part = PartCommitment {
            number,
            plaintext_sha256: sha.clone(),
            plaintext_bytes: u64::from(n) + 20,
            ciphertext_sha256: luma_content::sha256(&[sha.as_bytes(), b"cipher"].concat()),
            ciphertext_bytes: u64::from(n) + 21,
            objects: n,
            previous_plaintext_sha256: previous,
        };
        plain += part.plaintext_bytes;
        cipher += part.ciphertext_bytes;
        builder
            .push(&intent, part, &mut pages, &mut || Ok(()))
            .unwrap();
        previous = Some(sha);
    }
    let root = builder.finish(&intent, &mut pages, &mut || Ok(())).unwrap();
    (
        WholeSnapshotManifest {
            schema_version: 1,
            profile: SNAPSHOT_PROFILE.into(),
            intent,
            review,
            parts: root,
            part_count: count,
            plaintext_bytes: plain,
            ciphertext_bytes: cipher,
            last_plaintext_sha256: previous.unwrap(),
        },
        pages,
    )
}
#[test]
fn streaming_preorder_preserves_rightmost_unary_internal_nodes_and_exact_coverage() {
    for (count, expected_pages) in [(1, 1), (33, 3), (1025, 36)] {
        let (manifest, mut pages) = fixture(count);
        let mut page_count = 0;
        let mut next = 0;
        manifest
            .visit_directory(&mut pages, &mut || Ok(()), &mut |entry, check| {
                check()?;
                match entry {
                    SnapshotDirectoryEntry::Page { reference, bytes } => {
                        assert_eq!(luma_content::sha256(bytes), reference.sha256);
                        page_count += 1;
                    }
                    SnapshotDirectoryEntry::Part(part) => {
                        assert_eq!(part.number, next);
                        next += 1;
                    }
                }
                Ok(())
            })
            .unwrap();
        assert_eq!((page_count, next), (expected_pages, count));
        manifest
            .verify_directory(&mut pages, &mut || Ok(()))
            .unwrap();
    }
}
#[test]
fn nonminimal_root_sparse_nonfinal_spans_corruption_and_revocation_cannot_complete() {
    let (mut manifest, mut pages) = fixture(33);
    let original = manifest.clone();
    manifest.parts = put(
        &manifest.intent,
        Body::Branch {
            children: vec![manifest.parts.clone()],
        },
        &mut pages,
        &mut || Ok(()),
    )
    .unwrap();
    assert!(manifest
        .verify_directory(&mut pages, &mut || Ok(()))
        .is_err());
    manifest = original;
    let root_bytes = pages.0.get(&manifest.parts.sha256).unwrap().clone();
    let mut root: Page = canonical(&root_bytes, MAX_PAGE_BYTES).unwrap();
    if let Body::Branch { children } = &mut root.body {
        let child = &children[0];
        let mut page: Page =
            canonical(pages.0.get(&child.sha256).unwrap(), MAX_PAGE_BYTES).unwrap();
        if let Body::Leaf { parts } = &mut page.body {
            parts.pop();
        }
        // A self-consistent sparse subtree is still not the packed format.
        let sparse = put(&manifest.intent, page.body, &mut pages, &mut || Ok(())).unwrap();
        let result = walk(
            &manifest.intent,
            &sparse,
            manifest.part_count,
            &mut pages,
            &mut || Ok(()),
            &mut |_, _| Ok(()),
        );
        assert!(result.is_err());
    } else {
        panic!("fixture must branch");
    }
    pages.0.get_mut(&manifest.parts.sha256).unwrap()[0] ^= 1;
    assert!(manifest
        .verify_directory(&mut pages, &mut || Ok(()))
        .is_err());
    let (manifest, mut pages) = fixture(33);
    let mut visited = 0;
    assert!(manifest
        .visit_directory(&mut pages, &mut || Ok(()), &mut |_, _| {
            visited += 1;
            Err("fixture original operation revoked".into())
        })
        .is_err());
    assert_eq!(visited, 1);
}
#[test]
fn framing_capacity_accounts_every_maximum_page_part_and_terminal_byte_without_uplift() {
    assert_eq!(MAX_SNAPSHOT_DIRECTORY_PAGES, 4229);
    let expected = MAX_SNAPSHOT_DIRECTORY_BYTES
        + MAX_SNAPSHOT_HEADER_BYTES as u64
        + 20
        + u64::from(MAX_SNAPSHOT_DIRECTORY_PAGES) * 5
        + u64::from(MAX_SNAPSHOT_PARTS) * 9
        + 49;
    assert_eq!(MAX_SNAPSHOT_PACKAGE_OVERHEAD, expected);
    assert_eq!(
        MAX_SNAPSHOT_EXPORT_BYTES,
        MAX_SNAPSHOT_CIPHERTEXT_BYTES + expected
    );
    assert!(MAX_SNAPSHOT_EXPORT_BYTES < 80 * 1024 * 1024 * 1024);
}
