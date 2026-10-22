//! Structural checks on returned DATA, not authentication of a selected root.
use super::*;
use luma_content_store::v2::ObservedFileData;

fn file(value: &ObservedFileData, directory: bool) -> Result<()> {
    if value.device == 0
        || value.inode == 0
        || value.mount_id == 0
        || value.uid != 0
        || value.gid != 0
        || value.allocated_bytes % 512 != 0
        || !(0..1_000_000_000).contains(&value.changed_nanoseconds)
        || !(0..1_000_000_000).contains(&value.modified_nanoseconds)
        || value.mode
            != if directory {
                libc::S_IFDIR | 0o700
            } else {
                libc::S_IFREG | 0o400
            }
        || if directory {
            value.links < 2
        } else {
            value.links != 1
        }
    {
        return Err("observer metadata outside fixed private file profile".into());
    }
    Ok(())
}
fn same_volume(value: &ObservedFileData, namespace: &NamespaceObservationData) -> Result<()> {
    if (value.device, value.mount_id) != (namespace.root.device, namespace.root.mount_id) {
        return Err("observer metadata volume differs from held namespace".into());
    }
    Ok(())
}
pub(super) fn namespace(value: &NamespaceObservationData, binding: &OwnerBinding) -> Result<()> {
    binding.validate()?;
    #[derive(Serialize)]
    struct Identity<'a> {
        schema_version: u32,
        domain: &'a str,
        binding: &'a OwnerBinding,
    }
    let identity = serde_json::to_vec(&Identity {
        schema_version: 1,
        domain: luma_content_store::v2::DOMAIN,
        binding,
    })?;
    if value.schema_version != 1
        || &value.binding != binding
        || value.identity_sha256 != luma_content::sha256(&identity)
        || value.identity.bytes != identity.len() as u64
    {
        return Err("observer identity data differs from exact owner namespace".into());
    }
    file(&value.root, true)?;
    file(&value.objects, true)?;
    file(&value.identity, false)?;
    same_volume(&value.objects, value)?;
    same_volume(&value.identity, value)
}
pub(super) fn raw(
    value: &RawObjectObservationData,
    selector: &str,
    bytes: &[u8],
    namespace: &NamespaceObservationData,
) -> Result<()> {
    let namespace_sha = luma_content::sha256(&serde_json::to_vec(namespace)?);
    match value {
        RawObjectObservationData::Absent {
            object_sha256,
            namespace_sha256,
            missing_component,
            nearest_ancestor,
        } if object_sha256 == selector
            && namespace_sha256 == &namespace_sha
            && *missing_component <= 2
            && bytes.is_empty() =>
        {
            file(nearest_ancestor, true)?;
            let expected = &namespace.objects;
            if *missing_component == 0
                && (
                    nearest_ancestor.device,
                    nearest_ancestor.inode,
                    nearest_ancestor.mount_id,
                    nearest_ancestor.uid,
                    nearest_ancestor.gid,
                    nearest_ancestor.mode,
                ) != (
                    expected.device,
                    expected.inode,
                    expected.mount_id,
                    expected.uid,
                    expected.gid,
                    expected.mode,
                )
            {
                return Err(
                    "observer missing prefix loses original objects-directory identity".into(),
                );
            }
            same_volume(nearest_ancestor, namespace)
        }
        RawObjectObservationData::Present {
            object_sha256,
            namespace_sha256,
            actual_sha256,
            complete,
            file: metadata,
        } if object_sha256 == selector
            && namespace_sha256 == &namespace_sha
            && metadata.bytes == bytes.len() as u64
            && bytes.len() <= luma_content_store::v2::MAX_PAGE_BYTES
            && luma_content::sha256(bytes) == *actual_sha256
            && *complete == (!bytes.is_empty() && actual_sha256 == selector) =>
        {
            file(metadata, false)?;
            same_volume(metadata, namespace)
        }
        _ => Err("observer returned substituted raw bytes/metadata binding".into()),
    }
}
