//! Selection of attribution from an already admitted original grant pair.
//! No scope/hash parsed here authenticates a session or makes a grant current.
use super::*;
use crate::authentication::SessionPurpose;

pub(crate) fn pair(
    uses: &[(String, grants::Use)],
    requested: &grants::Use,
    purpose: SessionPurpose,
) -> Result<usize> {
    if purpose != SessionPurpose::Standard
        || uses.len() != 2
        || uses[0].0 == uses[1].0
        || uses
            .iter()
            .any(|(id, _)| !crate::admin_roles::identifier(id))
    {
        return Err("index mutation requires two distinct original Standard-session grants".into());
    }
    requested.validate()?;
    for (_, usage) in uses {
        usage.validate()?;
    }
    let read = uses
        .iter()
        .position(|(_, usage)| {
            usage.action == grants::Action::Read
                && usage.selector.kind == grants::Kind::File
                && usage.selector.id == "native-content-index-source-v2"
                && usage.input_bytes == SOURCE_READ
                && usage.output_bytes == MAX_OUTPUT
                && usage.units == 1
        })
        .ok_or("index mutation lacks its exact independent source Read")?;
    let effect = 1 - read;
    let usage = &uses[effect].1;
    let valid_effect = match usage.selector.id.as_str() {
        "native-content-index-build-v2" => {
            usage.action == grants::Action::Write && usage.output_bytes == PHASE_WRITE
        }
        "native-content-index-retain-v2" => {
            usage.action == grants::Action::Retain && usage.output_bytes == MAX_OUTPUT
        }
        _ => false,
    };
    if !valid_effect
        || usage.selector.kind != grants::Kind::Artifact
        || usage.input_bytes != PHASE_READ
        || usage.units != 1
        || usage.selector.generation != uses[read].1.selector.generation
        || usage.selector.digest != uses[read].1.selector.digest
        || usage != requested
    {
        return Err(
            "index effect differs from its exact paired Read/review/resource generation".into(),
        );
    }
    Ok(effect)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn uses(retain: bool) -> Vec<(String, grants::Use)> {
        let digest = "a".repeat(64);
        let profile = format!(
            "{PREFIX}{}-7-{}-{}",
            if retain { "retain" } else { "step" },
            "b".repeat(64),
            "c".repeat(64)
        );
        vec![
            (
                "read-grant".into(),
                usage_at(&profile, digest.clone(), true).unwrap(),
            ),
            (
                "effect-grant".into(),
                usage_at(&profile, digest, false).unwrap(),
            ),
        ]
    }
    #[test]
    fn exact_original_pair_selects_effect_in_either_order() {
        for retain in [false, true] {
            let mut values = uses(retain);
            let requested = values[1].1.clone();
            assert_eq!(
                pair(&values, &requested, SessionPurpose::Standard).unwrap(),
                1
            );
            values.reverse();
            assert_eq!(
                pair(&values, &requested, SessionPurpose::Standard).unwrap(),
                0
            );
            for purpose in [
                SessionPurpose::Export,
                SessionPurpose::ModelImport,
                SessionPurpose::ModelActivation,
                SessionPurpose::ModelQa,
            ] {
                assert!(pair(&values, &requested, purpose).is_err());
            }
        }
    }
    #[test]
    fn singleton_duplicate_or_changed_scope_never_borrows_pair_authority() {
        for retain in [false, true] {
            let values = uses(retain);
            let requested = &values[1].1;
            assert!(pair(&values[..1], requested, SessionPurpose::Standard).is_err());
            assert!(pair(&values, &values[0].1, SessionPurpose::Standard).is_err());
            for field in 0..17 {
                let mut changed = values.clone();
                match field {
                    0 => changed[1].0 = changed[0].0.clone(),
                    1 => changed[0].0 = "none/invalid".into(),
                    2 => changed[0].1.input_bytes -= 1,
                    3 => changed[0].1.output_bytes += 1,
                    4 => changed[0].1.units += 1,
                    5 => changed[0].1.selector.id.push('x'),
                    6 => changed[0].1.selector.digest = "d".repeat(64),
                    7 => changed[0].1.selector.generation += 1,
                    8 => changed[0].1.action = grants::Action::Write,
                    9 => changed[0].1.selector.kind = grants::Kind::Artifact,
                    10 => changed[1].1.input_bytes += 1,
                    11 => changed[1].1.output_bytes -= 1,
                    12 => changed[1].1.units += 1,
                    13 => changed[1].1.selector.id.push('x'),
                    14 => changed[1].1.action = grants::Action::Read,
                    15 => changed[1].1.selector.kind = grants::Kind::File,
                    16 => changed.push(changed[0].clone()),
                    _ => unreachable!(),
                }
                assert!(
                    pair(&changed, requested, SessionPurpose::Standard).is_err(),
                    "field {field}"
                );
            }
        }
    }
}
