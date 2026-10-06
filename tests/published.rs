//! Full signed policy and separate revocations execute identically on devices.
mod common;
use cgrd::*;
use common::*;
use serde_json::{Value, json};

macro_rules! shared_test {
    ($name:ident, $body:block) => {
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        fn $name() $body
    };
}

fn requirement(gate: &str) -> Value {
    json!({"gate":gate,"level":"community","provider":"community"})
}
fn settings(policy: Value) -> Value {
    json!({
        "community":"garden", "revision":1, "policy_epoch":2,
        "content": {
            "action/admission":policy,
            "gate/community/voucher":true,
            "provider/community/voucher/community":true,
            "gate/community/other":true,
            "provider/community/other/community":true
        }
    })
}
fn action() -> Value {
    json!({"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]})
}
fn revocations() -> Value {
    json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"members":[],"devices":[]}})
}
fn check_fixture(f: &mut Fixture, settings: &Value, revocations: &Value) -> Admission {
    let mut signed = f.issue();
    signed.settings = sign(&mut f.issuer, csgn::Kind::SettingsSnapshot, settings);
    let revoked = sign(
        &mut f.issuer,
        csgn::Kind::RevocationListSnapshot,
        revocations,
    );
    let policy = PublishedPolicy {
        policy: signed.policy(),
        revocations: &revoked,
        minimum_revocations_revision: 1,
        action: "admission",
    };
    check_published(&signed.bundle, &policy, &signed.schema)
}

shared_test!(complete_all_any_threshold_policy_preserves_binding, {
    for group in ["all_of", "any_of", "k_of_n"] {
        let mut f = Fixture::new();
        let mut policy = action();
        policy[group] = match group {
            "all_of" => json!([requirement("voucher")]),
            "any_of" => json!([requirement("other"), requirement("voucher")]),
            _ => json!({"k":1,"of":[requirement("other"),requirement("voucher")]}),
        };
        let signed_settings = settings(policy);
        assert!(check_fixture(&mut f, &signed_settings, &revocations()).is_admitted());
        f.credential.gates.clear();
        refused(
            check_fixture(&mut f, &signed_settings, &revocations()),
            Refusal::Gate,
        );
    }
    let mut f = Fixture::new();
    let mut policy = action();
    policy["k_of_n"] = json!({"k":2,"of":[requirement("voucher"),requirement("other")]});
    refused(
        check_fixture(&mut f, &settings(policy.clone()), &revocations()),
        Refusal::Gate,
    );
    f.credential.gates.push(Gate {
        gate: "other".into(),
        provider: "community".into(),
        valid_until: EXPIRY,
    });
    assert!(check_fixture(&mut f, &settings(policy), &revocations()).is_admitted());
});

shared_test!(rich_policy_never_infers_absent_evidence, {
    let mut f = Fixture::new();
    let mut policy = action();
    policy["all_of"] = json!([requirement("voucher")]);
    for case in 0..9 {
        let mut settings = settings(policy.clone());
        match case {
            0 => settings["content"]["gate/community/voucher"] = json!(false),
            1 => settings["content"]["provider/community/voucher/community"] = json!(false),
            2 => settings["content"]["action/admission"]["maximum_proof_age"] = json!(300),
            3 => settings["content"]["action/admission"]["all_of"][0]["level"] = json!("global"),
            4 => settings["content"]["action/admission"]["membership"] = json!(["pending"]),
            5 => settings["content"]
                .as_object_mut()
                .unwrap()
                .remove("action/admission")
                .map(|_| ())
                .unwrap(),
            6 => settings["content"]["action/admission"]["k_of_n"] = json!({"k":0,"of":[]}),
            7 => settings["content"]["action/admission"]["unexpected"] = json!(true),
            _ => settings["content"]["action/admission"]["all_of"][0]["provider"] = json!("wrong"),
        }
        refused(
            check_fixture(&mut f, &settings, &revocations()),
            Refusal::Gate,
        );
    }
});

shared_test!(separate_revocations_and_epoch_are_mandatory, {
    let mut f = Fixture::new();
    for case in 0..6 {
        let mut revoked = revocations();
        let expected = match case {
            0 => {
                revoked["content"]["members"] = json!(["alice"]);
                Refusal::Revoked
            }
            1 => {
                revoked["content"]["devices"] = json!([f.body.device]);
                Refusal::Revoked
            }
            2 => {
                revoked["policy_epoch"] = json!(3);
                Refusal::Snapshot
            }
            3 => {
                revoked["community"] = json!("other");
                Refusal::Snapshot
            }
            4 => {
                revoked["revision"] = json!(0);
                Refusal::Snapshot
            }
            _ => {
                revoked["content"]["members"] = json!([""]);
                Refusal::Metadata
            }
        };
        refused(
            check_fixture(&mut f, &settings(action()), &revoked),
            expected,
        );
    }
    let signed = f.issue();
    let policy = PublishedPolicy {
        policy: signed.policy(),
        revocations: &[],
        minimum_revocations_revision: 1,
        action: "admission",
    };
    refused(
        check_published(&signed.bundle, &policy, &signed.schema),
        Refusal::Snapshot,
    );
});

shared_test!(
    rich_policy_still_requires_device_profile_and_pin_evidence,
    {
        for case in 0..4 {
            let mut f = Fixture::new();
            let expected = match case {
                0 => {
                    f.credential.devices = vec![[0; 32]];
                    Refusal::UnauthorizedDevice
                }
                1 => {
                    f.body.device = [0; 32];
                    Refusal::UnauthorizedDevice
                }
                2 => {
                    f.body.openings.clear();
                    Refusal::Pin
                }
                _ => {
                    f.credential.pins[0].fingerprint[0] ^= 1;
                    Refusal::Pin
                }
            };
            refused(
                check_fixture(&mut f, &settings(action()), &revocations()),
                expected,
            );
        }
        let mut f = Fixture::new();
        f.public_mut().public.insert("age".into(), json!(12));
        assert!(
            matches!(check_fixture(&mut f, &settings(action()), &revocations()), Admission::Refused { reasons } if matches!(&reasons[0], Refusal::Profile(_)))
        );
    }
);

shared_test!(
    published_floors_age_and_limits_are_enforced_independently,
    {
        for case in 0..10 {
            let mut f = Fixture::new();
            let mut settings = settings(action());
            let mut revocations = revocations();
            let expected = match case {
                0..=3 => Refusal::Snapshot,
                4 => {
                    f.schema.content.community = "other".into();
                    Refusal::Snapshot
                }
                5 => Refusal::StaleSnapshot,
                6 => {
                    revocations["content"]["members"] = json!(
                        (0..MAX_ITEMS + 1)
                            .map(|i| format!("m{i}"))
                            .collect::<Vec<_>>()
                    );
                    Refusal::Metadata
                }
                7 => {
                    revocations["content"]["devices"] = json!(
                        (0..MAX_ITEMS + 1)
                            .map(|i| {
                                let mut key = [0; 32];
                                key[..2].copy_from_slice(&(i as u16).to_be_bytes());
                                key
                            })
                            .collect::<Vec<_>>()
                    );
                    Refusal::Metadata
                }
                8 => {
                    f.schema.content.public =
                        vec![f.schema.content.public[0].clone(); MAX_ITEMS + 1];
                    Refusal::Metadata
                }
                _ => {
                    settings["policy_epoch"] = json!(3);
                    Refusal::Snapshot
                }
            };
            let mut signed = f.issue();
            signed.settings = sign(&mut f.issuer, csgn::Kind::SettingsSnapshot, &settings);
            let revoked = sign(
                &mut f.issuer,
                csgn::Kind::RevocationListSnapshot,
                &revocations,
            );
            let mut policy = PublishedPolicy {
                policy: signed.policy(),
                revocations: &revoked,
                minimum_revocations_revision: 1,
                action: "admission",
            };
            match case {
                0 => policy.policy.minimum_settings_revision = 2,
                1 => policy.policy.minimum_schema_revision = 2,
                2 => policy.minimum_revocations_revision = 2,
                3 => policy.policy.minimum_epoch = 3,
                5 => policy.policy.maximum_snapshot_age = 1,
                _ => (),
            }
            refused(
                check_published(&signed.bundle, &policy, &signed.schema),
                expected,
            );
        }
        for expiry in [NOW, u64::MAX] {
            let mut f = Fixture::new();
            f.credential.gates[0].valid_until = expiry;
            let mut policy = action();
            policy["all_of"] = json!([requirement("voucher")]);
            refused(
                check_fixture(&mut f, &settings(policy), &revocations()),
                Refusal::Gate,
            );
        }
    }
);

shared_test!(
    passkey_revocation_projection_preserves_person_profile_checks,
    {
        let mut f = Fixture::new();
        let mut revoked = revocations();
        revoked["content"]["passkeys"] = json!([vec![9; 64]]);
        // Guard still checks the person/profile. Passkey possession and lineage are
        // separate G3 obligations; this signed projection is not a shortcut for them.
        assert!(check_fixture(&mut f, &settings(action()), &revoked).is_admitted());
        for invalid in [Vec::new(), vec![9; 1025]] {
            revoked["content"]["passkeys"] = json!([invalid]);
            assert!(
                matches!(check_fixture(&mut f, &settings(action()), &revoked),
            Admission::Refused { reasons } if reasons == vec![Refusal::Metadata])
            );
        }
    }
);

shared_test!(
    recipient_capability_requires_complete_gate_and_explicit_signed_key,
    {
        for case in 0..6 {
            let mut f = Fixture::new();
            f.body.hpke_key = match case {
                1 => None,
                2 => Some([0; 32]),
                _ => Some([9; 32]),
            };
            let mut signed = f.issue();
            signed.settings = sign(
                &mut f.issuer,
                csgn::Kind::SettingsSnapshot,
                &settings(action()),
            );
            let mut revoked = revocations();
            if case == 5 {
                revoked["content"]["devices"] = json!([f.body.device]);
            }
            let revoked = sign(&mut f.issuer, csgn::Kind::RevocationListSnapshot, &revoked);
            if case == 4 {
                let mut changed: Value = serde_json::from_slice(&signed.bundle.payload).unwrap();
                changed["hpke_key"] = json!(vec![8; 32]);
                signed.bundle.payload = serde_json::to_vec(&changed).unwrap();
            }
            let policy = PublishedPolicy {
                policy: signed.policy(),
                revocations: &revoked,
                minimum_revocations_revision: 1,
                action: "admission",
            };
            let result = verify_recipient_with_contact(
                &signed.bundle,
                if case == 3 { "mallory" } else { "alice" },
                &policy,
                &signed.schema,
                &|_| cshm::ContactCheck::Unavailable,
            );
            if case == 0 {
                let recipient = result.unwrap();
                assert_eq!(recipient.community(), "garden");
                assert_eq!(recipient.member(), "alice");
                assert_eq!(recipient.device(), &f.body.device);
                assert_eq!(recipient.hpke_key(), &[9; 32]);
                assert_eq!(recipient.checked_at(), policy.policy.now);
                assert!(std::ptr::eq(recipient.bundle(), &signed.bundle));
            } else {
                assert!(result.is_err());
            }
        }
    }
);
