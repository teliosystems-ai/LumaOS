//! Exact original native command/source DATA checks. The broker separately
//! retains its kernel peer, original session, current grants and resource lease.
use super::*;
use crate::finite_grants::Audit;

struct Original<'a> {
    login: &'a str,
    read_grant: &'a str,
    effect_grant: Option<&'a str>,
    path: &'a Path,
}
fn arguments<'a>(args: &'a [&str], profile: &str) -> Result<Original<'a>> {
    let selected = request::parse_profile(profile)?;
    let effect = selected.mode.mutates();
    let count = if effect { 8 } else { 6 };
    if args.len() != count
        || args[0] != "/usr/libexec/luma-os/luma-platform"
        || args[1] != if effect { "index-run" } else { "index-review" }
        || args.last() != Some(&"")
        || args[2].is_empty()
        || args[2].len() > 32
        || !args[2].as_bytes()[0].is_ascii_lowercase()
        || !args[2]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        || !crate::admin_roles::identifier(args[3])
        || args[3] == "none"
        || (effect
            && (!crate::admin_roles::identifier(args[4])
                || args[4] == "none"
                || args[3] == args[4]
                || args[5] != selected.review))
    {
        return Err(
            "index proof requires its exact independent original Read/effect command".into(),
        );
    }
    let path = Path::new(args[if effect { 6 } else { 4 }]);
    if !namespace(path) {
        return Err("index original command lacks its protected immutable snapshot".into());
    }
    Ok(Original {
        login: args[2],
        read_grant: args[3],
        effect_grant: effect.then_some(args[4]),
        path,
    })
}

fn join(
    original: &Original<'_>,
    input: &request::Input,
    profile: &str,
    storage: &str,
    audit: Option<&Audit>,
) -> Result<()> {
    let selected = request::parse_profile(profile)?;
    let expected = if selected.mode.mutates() {
        input.effect_profile(selected.review)?
    } else {
        input.profile()?
    };
    if input.login != original.login || expected != profile {
        return Err("index original source/operation/review differs from its profile".into());
    }
    if let Some(audit) = audit {
        audit.validate()?;
        let grant = original.effect_grant.unwrap_or(original.read_grant);
        if audit.operation_id.is_none()
            || audit.subject != input.binding.owner
            || audit.subject_generation != input.binding.owner_generation
            || audit.grant_id != grant
            || audit.usage
                != scope::original_usage(profile, storage, &input.binding, &input.sha256()?, false)?
        {
            return Err(
                "index audit differs from the original owner/operation/grant/storage scope".into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn check_client_arguments(
    args: &[&str],
    profile: &str,
    audit: Option<&Audit>,
) -> Result<()> {
    let original = arguments(args, profile)?;
    let input = read_snapshot(original.path, profile, original.login)?;
    let storage = crate::resource_manager::storage_device(Path::new("/var"))?;
    join(&original, &input, profile, &storage, audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(effect: bool) -> request::Input {
        request::Input {
            schema_version: 1,
            login: "admin".into(),
            binding: OwnerBinding {
                installation: "1".repeat(64),
                owner: "2".repeat(64),
                owner_generation: 7,
            },
            request_id: "a".repeat(32),
            operation: if effect {
                request::Operation::Advance {
                    job_id: "b".repeat(32),
                    expected_job_sha256: "3".repeat(64),
                }
            } else {
                request::Operation::Status {}
            },
        }
    }
    fn argv(effect: bool) -> Vec<String> {
        let mut values = vec![
            "/usr/libexec/luma-os/luma-platform".into(),
            if effect {
                "index-run".into()
            } else {
                "index-review".into()
            },
            "admin".into(),
            "read-grant".into(),
        ];
        if effect {
            values.extend(["effect-grant".into(), "4".repeat(64)]);
        }
        values.extend([
            format!(
                "/run/luma-granted-client/requests/{}/index.json",
                "5".repeat(32)
            ),
            "".into(),
        ]);
        values
    }
    fn selected(input: &request::Input, effect: bool) -> String {
        if effect {
            input.effect_profile(&"4".repeat(64)).unwrap()
        } else {
            input.profile().unwrap()
        }
    }
    fn audit(input: &request::Input, profile: &str, effect: bool) -> Audit {
        Audit {
            subject: input.binding.owner.clone(),
            subject_generation: input.binding.owner_generation,
            grant_id: if effect {
                "effect-grant".into()
            } else {
                "read-grant".into()
            },
            grant_version: 1,
            checkpoint_head: "6".repeat(64),
            operation_id: Some("7".repeat(32)),
            usage: scope::original_usage(
                profile,
                "253:1",
                &input.binding,
                &input.sha256().unwrap(),
                false,
            )
            .unwrap(),
        }
    }
    #[test]
    fn exact_commands_join_source_review_and_original_attribution_as_data() {
        for effect in [false, true] {
            let input = input(effect);
            let profile = selected(&input, effect);
            let strings = argv(effect);
            let args = strings.iter().map(String::as_str).collect::<Vec<_>>();
            let original = arguments(&args, &profile).unwrap();
            let record = audit(&input, &profile, effect);
            join(&original, &input, &profile, "253:1", Some(&record)).unwrap();
            join(&original, &input, &profile, "253:1", None).unwrap();
            assert!(join(&original, &input, &profile, "253:2", Some(&record)).is_err());
            for field in 0..7 {
                let mut changed = record.clone();
                match field {
                    0 => changed.subject = "8".repeat(64),
                    1 => changed.subject_generation += 1,
                    2 => changed.grant_id = "other-grant".into(),
                    3 => changed.operation_id = None,
                    4 => changed.usage.selector.digest = "8".repeat(64),
                    5 => changed.usage.input_bytes += 1,
                    6 => changed.usage.units += 1,
                    _ => unreachable!(),
                }
                assert!(
                    join(&original, &input, &profile, "253:1", Some(&changed)).is_err(),
                    "field {field}"
                );
            }
        }
    }
    #[test]
    fn malformed_original_argv_never_reaches_snapshot_read() {
        for effect in [false, true] {
            let profile = selected(&input(effect), effect);
            let values = argv(effect);
            for field in 0..values.len() {
                let mut changed = values.clone();
                changed[field] = match field {
                    0 => "/tmp/luma-platform".into(),
                    1 => {
                        if effect {
                            "index-review".into()
                        } else {
                            "index-run".into()
                        }
                    }
                    2 => "Admin".into(),
                    3 => "not/a/grant".into(),
                    4 if effect => values[3].clone(),
                    5 if effect => "9".repeat(64),
                    _ => "/tmp/index.json".into(),
                };
                let args = changed.iter().map(String::as_str).collect::<Vec<_>>();
                assert!(arguments(&args, &profile).is_err(), "field {field}");
            }
            for delta in [-1isize, 1] {
                let mut changed = values.clone();
                if delta < 0 {
                    changed.pop();
                } else {
                    changed.push(String::new());
                }
                let args = changed.iter().map(String::as_str).collect::<Vec<_>>();
                assert!(arguments(&args, &profile).is_err());
            }
            for position in if effect { vec![3, 4] } else { vec![3] } {
                let mut changed = values.clone();
                changed[position] = "none".into();
                let args = changed.iter().map(String::as_str).collect::<Vec<_>>();
                assert!(arguments(&args, &profile).is_err());
            }
        }
    }
    #[test]
    fn review_of_mutation_is_read_only_and_changed_source_or_mode_refuses() {
        let input = input(true);
        let profile = input.profile().unwrap();
        let values = argv(false);
        let args = values.iter().map(String::as_str).collect::<Vec<_>>();
        let original = arguments(&args, &profile).unwrap();
        let record = audit(&input, &profile, false);
        assert_eq!(record.usage.action, crate::finite_grants::Action::Read);
        join(&original, &input, &profile, "253:1", Some(&record)).unwrap();
        let mut changed = input.clone();
        changed.request_id = "f".repeat(32);
        assert!(join(&original, &changed, &profile, "253:1", Some(&record)).is_err());
        changed = input.clone();
        changed.operation = request::Operation::Status {};
        assert!(join(&original, &changed, &profile, "253:1", Some(&record)).is_err());
        let effect_profile = selected(&input, true);
        assert!(arguments(&args, &effect_profile).is_err());
    }

    /// This root-owned fixed-path fixture is executed only in the disposable
    /// offline test container. It supplies no installed catalog/PAM authority.
    struct SnapshotFixture {
        directory: std::path::PathBuf,
        path: std::path::PathBuf,
    }
    impl SnapshotFixture {
        fn new(input: &request::Input) -> Self {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                "/run/luma-granted-client",
                "/run/luma-granted-client/requests",
            ] {
                match std::fs::create_dir(path) {
                    Ok(()) => {
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                            .unwrap()
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(error) => panic!("private disposable fixture parent: {error}"),
                }
            }
            let directory = Path::new("/run/luma-granted-client/requests")
                .join(crate::resources::random_id().unwrap());
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = directory.join("index.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&path)
                .unwrap();
            use std::io::Write;
            file.write_all(&input.canonical_bytes().unwrap()).unwrap();
            file.sync_all().unwrap();
            Self { directory, path }
        }
    }
    impl Drop for SnapshotFixture {
        fn drop(&mut self) {
            // Only the exact fresh random fixture child is owned by this test.
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }
    #[test]
    fn actual_protected_snapshot_pins_source_and_refuses_aliases_modes_or_changed_bytes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let input = input(true);
        let profile = selected(&input, true);
        let fixture = SnapshotFixture::new(&input);
        let mut strings = argv(true);
        strings[6] = fixture.path.to_str().unwrap().into();
        let args = strings.iter().map(String::as_str).collect::<Vec<_>>();
        let original = arguments(&args, &profile).unwrap();
        let retained = read_snapshot(original.path, &profile, original.login).unwrap();
        join(
            &original,
            &retained,
            &profile,
            "253:1",
            Some(&audit(&input, &profile, true)),
        )
        .unwrap();
        assert!(read_snapshot(original.path, &profile, "other-user").is_err());
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_snapshot(original.path, &profile, original.login).is_err());
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut changed = input.clone();
        changed.request_id = "f".repeat(32);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&fixture.path)
            .unwrap();
        use std::io::Write;
        file.write_all(&changed.canonical_bytes().unwrap()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_snapshot(original.path, &profile, original.login).is_err());
        let saved = fixture.directory.join("retained-original.json");
        std::fs::rename(&fixture.path, &saved).unwrap();
        symlink(&saved, &fixture.path).unwrap();
        assert!(read_snapshot(original.path, &profile, original.login).is_err());
    }
}
