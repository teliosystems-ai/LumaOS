//! Actual bounded memfd mechanics and pure receipt DATA; not installed PAM/C.
use super::*;
fn response() -> Response {
    Response {
        schema_version: 2,
        request_sha256: "a".repeat(64),
        binding: "b".repeat(64),
        lease: resources::Token {
            lease_id: "c".repeat(32),
            generation: 1,
            manager_epoch: "d".repeat(32),
        },
        selection_sha256: "e".repeat(64),
        result: serde_json::json!({"schema_version":2,"kind":"status","effect_executed":false,"authority_returned":false,"production_qualified":false}),
    }
}
fn receipt(response: &Response) -> serde_json::Value {
    let epochs: std::collections::BTreeMap<_, _> = resource_manager::invoice_output_domains()
        .into_iter()
        .map(|domain| (domain, resources::OutputEpoch(1)))
        .collect();
    serde_json::json!({"binding":response.binding,"output_sha256":luma_content::sha256(&serde_json::to_vec(&response.result).unwrap()),"output_domain_epochs":epochs,"lease":response.lease,"state":"released","physical_release_granted":false})
}
#[test]
fn actual_resource_output_data_requires_exact_source_binding_epochs_and_lease() {
    let response = response();
    let original = receipt(&response);
    verify_receipt_data(
        &response,
        &response.binding,
        &response.request_sha256,
        original.clone(),
    )
    .unwrap();
    for field in 0..9 {
        let mut changed = original.clone();
        match field {
            0 => changed["binding"] = "f".repeat(64).into(),
            1 => changed["output_sha256"] = "f".repeat(64).into(),
            2 => changed["lease"]["lease_id"] = "f".repeat(32).into(),
            3 => changed["lease"]["generation"] = "2".into(),
            4 => changed["physical_release_granted"] = true.into(),
            5 => {
                let domain = resource_manager::invoice_output_domains()[0];
                changed["output_domain_epochs"]
                    .as_object_mut()
                    .unwrap()
                    .remove(domain);
            }
            6 => {
                let domain = resource_manager::invoice_output_domains()[0];
                changed["output_domain_epochs"][domain] = "0".into();
            }
            7 => changed["output_domain_epochs"]["foreign"] = "1".into(),
            _ => changed["unreviewed"] = true.into(),
        }
        assert!(
            verify_receipt_data(
                &response,
                &response.binding,
                &response.request_sha256,
                changed
            )
            .is_err(),
            "field{field}"
        );
    }
    assert!(verify_receipt_data(
        &response,
        &"f".repeat(64),
        &response.request_sha256,
        original.clone()
    )
    .is_err());
    assert!(verify_receipt_data(&response, &response.binding, &"f".repeat(64), original).is_err());
}
#[test]
fn readonly_controller_modes_do_not_borrow_effect_profiles() {
    for mode in ["status", "query", "review"] {
        read_mode(&format!(
            "index-v2-{mode}-1-{}-{}",
            "a".repeat(64),
            "a".repeat(64)
        ))
        .unwrap();
    }
    for mode in ["start", "step", "advance", "publish", "retain"] {
        assert!(read_mode(&format!(
            "index-v2-{mode}-1-{}-{}",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .is_err());
    }
}
#[test]
fn actual_private_input_is_sealed_and_output_never_masquerades_as_sealed_input() {
    let bytes = b"explicit bounded fixture input";
    let mut input = anonymous("luma-index-request", bytes, true).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GET_SEALS) },
        SEALS
    );
    let mut reopened = Vec::new();
    input.read_to_end(&mut reopened).unwrap();
    assert_eq!(reopened, bytes);
    assert!(input.write_all(b"alter").is_err());
    assert!(input.set_len(0).is_err());
    let output = anonymous("luma-index-output", &[], false).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GET_SEALS) },
        SEALS
    );
}
#[test]
fn pure_scope_proposal_is_only_exact_closed_public_tuple_data() {
    let input = request::Input {
        schema_version: 1,
        login: "alice".into(),
        binding: OwnerBinding {
            installation: "1".repeat(64),
            owner: "2".repeat(64),
            owner_generation: 3,
        },
        request_id: "3".repeat(32),
        operation: request::Operation::Status {},
    };
    let value = scope_proposal_data(&input, &input.binding.installation, "253:1").unwrap();
    assert_eq!(
        value["canonical_request"].as_str().unwrap().as_bytes(),
        input.canonical_bytes().unwrap()
    );
    assert_eq!(value["request_sha256"], input.sha256().unwrap());
    for field in [
        "authority_returned",
        "private_content_read",
        "session_lease_held",
        "effect_executed",
        "actor_authenticated",
    ] {
        assert_eq!(value[field], false);
    }
    assert_eq!(value["usage"]["action"], "file.read");
    assert_eq!(value["installation_verified"], false);
    assert_eq!(
        value["usage"]["selector"]["id"],
        "native-content-index-inspect-v2"
    );
    assert!(scope_proposal_data(&input, &"f".repeat(64), "253:1").is_err());
    assert!(scope_proposal_data(&input, &input.binding.installation, "0253:1").is_err());
    let mut forged = input.clone();
    forged.binding.owner_generation += 1;
    let changed = scope_proposal_data(&forged, &forged.binding.installation, "253:1").unwrap();
    assert_ne!(value["profile"], changed["profile"]);
    assert_ne!(
        value["usage"]["selector"]["digest"],
        changed["usage"]["selector"]["digest"]
    );
}
