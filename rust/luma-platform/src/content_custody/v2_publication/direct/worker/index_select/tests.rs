//! Pure attribution of a measured store walk to the C-selected accounting and
//! the C-reserved job write set. Synthetic counters only; the actual store,
//! C cut and original worker are exercised by the direct initial tests.
use super::*;

/// One C-selected object and three reserved members: the first shares the
/// held leaf, the second only the held first prefix, the third neither, so
/// at most three directories can be new.
fn held() -> String {
    format!("ab12{}", "0".repeat(60))
}
fn names() -> [String; 3] {
    [
        format!("ab12{}", "1".repeat(60)),
        format!("ab34{}", "2".repeat(60)),
        format!("cd56{}", "3".repeat(60)),
    ]
}
fn objects() -> Vec<ObjectWriteSpec> {
    names()
        .into_iter()
        .zip([10, 20, 30])
        .map(|(sha256, bytes)| ObjectWriteSpec { sha256, bytes })
        .collect()
}
fn allocation(name: &str, bytes: u64, complete: bool) -> Allocation {
    Allocation {
        relative_path: format!("objects/{}/{}/{name}", &name[..2], &name[2..4]),
        device: 1,
        inode: 1,
        bytes,
        allocated_bytes: 4096,
        complete,
    }
}
fn selected() -> PhysicalInventory {
    PhysicalInventory {
        regular_files: 1,
        directories: 4,
        logical_bytes: 7,
        allocated_bytes: 4096,
        incomplete_objects: 0,
    }
}
/// `selected` plus `files` members of `logical` bytes, each one 4096-byte
/// allocation, and `directories` new directories of 4096 bytes each.
fn ahead(files: u64, logical: u64, directories: u64) -> PhysicalInventory {
    let mut value = selected();
    value.regular_files += files;
    value.logical_bytes += logical;
    value.directories += directories;
    value.allocated_bytes += 4096 * (files + directories);
    value
}
fn walk<'p>(objects: &'p [ObjectWriteSpec], files: &[Allocation]) -> Walk<'p> {
    let mut walk = Walk::new(objects);
    walk.visit(allocation(&held(), 7, true)).unwrap();
    for file in files {
        walk.visit(file.clone()).unwrap();
    }
    walk
}

#[test]
fn a_walk_is_admitted_only_as_c_or_c_plus_complete_reserved_members() {
    let objects = objects();
    let [first, second, third] = names();
    let all = [
        allocation(&first, 10, true),
        allocation(&second, 20, true),
        allocation(&third, 30, true),
    ];
    // Exactly C; exactly C plus the whole blob and its three new directories;
    // C plus one member that needed no directory, or with directories an
    // interrupted attempt made for the members it never wrote.
    walk(&objects, &[])
        .attribute(&selected(), &selected())
        .unwrap();
    walk(&objects, &all)
        .attribute(&selected(), &ahead(3, 60, 3))
        .unwrap();
    let one = walk(&objects, &all[..1]);
    one.attribute(&selected(), &ahead(1, 10, 0)).unwrap();
    one.attribute(&selected(), &ahead(1, 10, 3)).unwrap();
    // More directories than the reserved prefixes no other file holds.
    assert!(walk(&objects, &all)
        .attribute(&selected(), &ahead(3, 60, 4))
        .is_err());
    // A store behind C, or a member's allocation that the walk lost.
    let mut behind = selected();
    behind.regular_files -= 1;
    assert!(walk(&objects, &[]).attribute(&selected(), &behind).is_err());
    let mut lost = ahead(1, 10, 0);
    lost.allocated_bytes -= 1;
    assert!(one.attribute(&selected(), &lost).is_err());
    // A foreign object beside a member, foreign bytes, or a foreign partial.
    let foreign = format!("ef78{}", "4".repeat(60));
    let mixed = walk(&objects, &[all[0].clone(), allocation(&foreign, 10, true)]);
    assert!(mixed.attribute(&selected(), &ahead(2, 20, 2)).is_err());
    assert!(one.attribute(&selected(), &ahead(1, 11, 0)).is_err());
    let mut partial = ahead(1, 10, 0);
    partial.incomplete_objects += 1;
    assert!(one.attribute(&selected(), &partial).is_err());
    // An incomplete member, or one whose length is not the reserved length,
    // is refused even where the counters would otherwise match.
    for file in [allocation(&first, 9, false), allocation(&first, 9, true)] {
        let mut measured = ahead(1, 9, 0);
        if !file.complete {
            measured.incomplete_objects += 1;
        }
        let retained = walk(&objects, &[file]);
        assert!(retained.attribute(&selected(), &measured).is_err());
        assert!(retained.attribute(&selected(), &selected()).is_err());
    }
    // A member C already accounts for is never subtracted from a store that
    // is ahead, so the walk is refused instead of guessed.
    let mut counted = selected();
    counted.regular_files += 1;
    counted.logical_bytes += 10;
    counted.allocated_bytes += 4096;
    one.attribute(&counted, &counted).unwrap();
    let mut over = counted.clone();
    over.regular_files += 1;
    over.logical_bytes += 20;
    over.allocated_bytes += 4096;
    assert!(walk(&objects, &all[..2])
        .attribute(&counted, &over)
        .is_err());
}
