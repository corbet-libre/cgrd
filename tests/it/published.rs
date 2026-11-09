//! Action-bound issuer admission and current publications execute on devices.
use crate::common::*;
use cgrd::*;
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
    let signed = f.issue();
    check_signed_fixture(f, signed, settings, revocations)
}

fn check_signed_fixture(
    f: &mut Fixture,
    mut signed: Signed,
    settings: &Value,
    revocations: &Value,
) -> Admission {
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
    };
    check_published(&signed.bundle, &policy, &signed.schema)
}

shared_test!(
    required_version_and_issuer_action_have_no_legacy_defaults,
    {
        for case in 0..10 {
            let mut f = Fixture::new();
            let mut credential = serde_json::to_value(&f.credential).unwrap();
            let expected = match case {
                0 => {
                    credential.as_object_mut().unwrap().remove("purpose");
                    Refusal::Credential
                }
                1 => {
                    credential
                        .as_object_mut()
                        .unwrap()
                        .remove("issuance_action");
                    Refusal::Credential
                }
                2 => {
                    credential["purpose"] = json!("cplc.community-credential.v1");
                    Refusal::Credential
                }
                3 => {
                    credential["issuance_action"] = json!("other");
                    Refusal::Credential
                }
                4 => {
                    credential["issuance_action"] = json!("");
                    Refusal::Metadata
                }
                5 => {
                    credential["issuance_action"] = json!("admission/other");
                    Refusal::Metadata
                }
                6 => {
                    credential["issuance_action"] = json!("a".repeat(201));
                    Refusal::Metadata
                }
                7 => {
                    credential["issuance_action"] = Value::Null;
                    Refusal::Credential
                }
                8 => {
                    credential["global_gates"] = json!([]);
                    Refusal::Credential
                }
                _ => {
                    credential["admitted"] = json!(true);
                    Refusal::Credential
                }
            };
            // Genuine issuer and device signatures cannot rescue absent action
            // provenance, malformed metadata or an invented admission flag.
            refused(f.issue_payload(&credential).check(), expected.clone());
            let signed = f.issue_payload(&credential);
            refused(
                check_signed_fixture(&mut f, signed, &settings(action()), &revocations()),
                expected,
            );
        }
    }
);

shared_test!(
    trusted_action_expectation_cannot_come_from_the_presentation,
    {
        let mut f = Fixture::new();
        let mut signed = f.issue();
        let mut current = settings(action());
        current["content"]["action/other"] = action();
        signed.settings = sign(&mut f.issuer, csgn::Kind::SettingsSnapshot, &current);
        let revoked = sign(
            &mut f.issuer,
            csgn::Kind::RevocationListSnapshot,
            &revocations(),
        );
        let mut published = PublishedPolicy {
            policy: signed.policy(),
            revocations: &revoked,
            minimum_revocations_revision: 1,
        };
        published.policy.expected_issuance_action = "other";
        refused(
            check_published(&signed.bundle, &published, &signed.schema),
            Refusal::Credential,
        );
        // Both action definitions are genuine and current. Only the independently
        // expected action may authorize the signed credential's actual result.
        published.policy.expected_issuance_action = "admission";
        assert!(check_published(&signed.bundle, &published, &signed.schema).is_admitted());
        for expected in ["", "admission/other", "admission\n", "with space"] {
            published.policy.expected_issuance_action = expected;
            refused(
                check_published(&signed.bundle, &published, &signed.schema),
                Refusal::Metadata,
            );
        }
        let legacy = f.issue();
        let mut policy = legacy.policy();
        policy.expected_issuance_action = "other";
        refused(
            check(&legacy.bundle, &policy, &legacy.schema),
            Refusal::Credential,
        );
        policy.expected_issuance_action = "";
        refused(
            check(&legacy.bundle, &policy, &legacy.schema),
            Refusal::Metadata,
        );
    }
);

shared_test!(
    signed_passkey_revocations_preserve_person_and_device_checks,
    {
        let mut f = Fixture::new();
        let mut revoked = revocations();
        revoked["content"]["passkeys"] = json!([vec![73u8; 32]]);
        assert!(check_fixture(&mut f, &settings(action()), &revoked).is_admitted());
        revoked["content"]["members"] = json!(["alice"]);
        assert!(matches!(
            check_fixture(&mut f, &settings(action()), &revoked),
            Admission::Refused { reasons } if reasons == vec![Refusal::Revoked]
        ));
        revoked["content"]["members"] = json!([]);
        revoked["content"]["devices"] = json!([f.body.device]);
        assert!(matches!(
            check_fixture(&mut f, &settings(action()), &revoked),
            Admission::Refused { reasons } if reasons == vec![Refusal::Revoked]
        ));
    }
);

shared_test!(
    signed_passkey_revocations_refuse_invalid_ids_and_unknown_fields,
    {
        let mut f = Fixture::new();
        for id in [Vec::new(), vec![73u8; 1025]] {
            let mut revoked = revocations();
            revoked["content"]["passkeys"] = json!([id]);
            assert!(matches!(
                check_fixture(&mut f, &settings(action()), &revoked),
                Admission::Refused { reasons } if reasons == vec![Refusal::Metadata]
            ));
        }
        let mut revoked = revocations();
        revoked["content"]["operator_override"] = json!(true);
        assert!(matches!(
            check_fixture(&mut f, &settings(action()), &revoked),
            Admission::Refused { reasons } if reasons == vec![Refusal::Snapshot]
        ));
    }
);

shared_test!(issuer_admission_does_not_export_or_invent_global_facts, {
    for group in ["all_of", "any_of", "k_of_n"] {
        let mut f = Fixture::new();
        let mut policy = action();
        let global = json!({"gate":"person","level":"global","provider":"global"});
        policy[group] = match group {
            "all_of" => json!([global, requirement("voucher")]),
            "any_of" => json!([global, requirement("voucher")]),
            _ => json!({"k":2,"of":[global,requirement("voucher")]}),
        };
        let signed_settings = settings(policy);
        // The trusted fixture issuer signs its positive action result. This
        // leaf test does not claim that it exercised cplc's issuance evaluator.
        // The consumer checks that assertion; global evidence remains private.
        assert!(check_fixture(&mut f, &signed_settings, &revocations()).is_admitted());
        f.credential.gates.clear();
        assert!(check_fixture(&mut f, &signed_settings, &revocations()).is_admitted());
        // Legacy required community facts remain an additional constraint.
        refused(f.issue().check(), Refusal::Gate);
    }
});

shared_test!(
    issuer_action_requires_original_well_formed_current_policy,
    {
        let mut f = Fixture::new();
        let mut policy = action();
        policy["all_of"] = json!([requirement("voucher")]);
        for case in 0..4 {
            let mut settings = settings(policy.clone());
            match case {
                0 => settings["content"]
                    .as_object_mut()
                    .unwrap()
                    .remove("action/admission")
                    .map(|_| ())
                    .unwrap(),
                1 => settings["content"]["action/admission"]["k_of_n"] = json!({"k":0,"of":[]}),
                2 => settings["content"]["action/admission"]["unexpected"] = json!(true),
                _ => settings["content"]["action/admission"]["all_of"][0]["provider"] = json!(""),
            }
            refused(
                check_fixture(&mut f, &settings, &revocations()),
                Refusal::Gate,
            );
        }
    }
);

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

shared_test!(
    recipient_capability_cannot_bypass_action_provenance_or_epoch,
    {
        for case in 0..5 {
            let mut f = Fixture::new();
            f.body.hpke_key = Some([9; 32]);
            let mut credential = serde_json::to_value(&f.credential).unwrap();
            let expected = match case {
                0 => {
                    credential.as_object_mut().unwrap().remove("purpose");
                    Refusal::Credential
                }
                1 => {
                    credential
                        .as_object_mut()
                        .unwrap()
                        .remove("issuance_action");
                    Refusal::Credential
                }
                2 => {
                    credential["issuance_action"] = json!("other");
                    Refusal::Credential
                }
                3 => {
                    credential["policy_epoch"] = json!(1);
                    Refusal::Version
                }
                _ => Refusal::Credential,
            };
            let mut signed = f.issue_payload(&credential);
            let mut current = settings(action());
            current["content"]["action/other"] = action();
            signed.settings = sign(&mut f.issuer, csgn::Kind::SettingsSnapshot, &current);
            let revoked = sign(
                &mut f.issuer,
                csgn::Kind::RevocationListSnapshot,
                &revocations(),
            );
            let mut policy = PublishedPolicy {
                policy: signed.policy(),
                revocations: &revoked,
                minimum_revocations_revision: 1,
            };
            if case == 4 {
                policy.policy.expected_issuance_action = "other";
            }
            assert_eq!(
                verify_recipient_with_contact(
                    &signed.bundle,
                    "alice",
                    &policy,
                    &signed.schema,
                    &|_| cshm::ContactCheck::Unavailable,
                )
                .err(),
                Some(expected),
            );
        }
    }
);

shared_test!(a_verified_sponsor_exposes_only_charter_credential_facts, {
    let mut f = Fixture::new();
    let mut signed = f.issue();
    signed.settings = sign(
        &mut f.issuer,
        csgn::Kind::SettingsSnapshot,
        &settings(action()),
    );
    let revoked = sign(
        &mut f.issuer,
        csgn::Kind::RevocationListSnapshot,
        &revocations(),
    );
    let published = PublishedPolicy {
        policy: signed.policy(),
        revocations: &revoked,
        minimum_revocations_revision: 1,
    };
    let none = |_: &str| cshm::ContactCheck::Unavailable;
    let sponsor =
        verify_sponsor_with_contact(&signed.bundle, "alice", &published, &signed.schema, &none)
            .unwrap();
    assert_eq!(sponsor.member, "alice");
    assert_eq!(sponsor.devices, f.credential.devices);
    assert_eq!(sponsor.handle, f.credential.handle);
    assert!(
        verify_sponsor_with_contact(&signed.bundle, "bob", &published, &signed.schema, &none)
            .is_err()
    );
});

fn endorsement_wire(key: &ed25519_dalek::SigningKey, member: &str, handle: &str) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let signature = key.sign(&cvch::link::endorsement_bytes("garden", member, handle));
    cvch::link::Endorsement::new(handle, key.verifying_key().to_bytes(), signature.to_bytes())
        .unwrap()
        .to_bytes()
        .unwrap()
}

fn check_sponsored(
    wire: Option<Vec<u8>>,
    verified: bool,
    sponsors: &dyn Fn(&str) -> Option<Vec<[u8; 32]>>,
) -> Admission {
    let mut f = Fixture::new();
    f.body.vouched_by = wire;
    f.body.vouched_verified = verified;
    let mut signed = f.issue();
    signed.settings = sign(
        &mut f.issuer,
        csgn::Kind::SettingsSnapshot,
        &settings(action()),
    );
    let revoked = sign(
        &mut f.issuer,
        csgn::Kind::RevocationListSnapshot,
        &revocations(),
    );
    let published = PublishedPolicy {
        policy: signed.policy(),
        revocations: &revoked,
        minimum_revocations_revision: 1,
    };
    let none = |_: &str| cshm::ContactCheck::Unavailable;
    check_published_with_sponsors(&signed.bundle, &published, &signed.schema, &none, sponsors)
}

shared_test!(
    an_endorsement_is_refused_at_publication_unless_the_sponsor_vouches_now,
    {
        let sponsor = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let device = sponsor.verifying_key().to_bytes();
        let present = |h: &str| (h == "sponsorname").then(|| vec![device]);
        let wire = endorsement_wire(&sponsor, "alice", "sponsorname");
        assert!(check_sponsored(Some(wire.clone()), true, &present).is_admitted());
        assert!(check_sponsored(None, false, &present).is_admitted());
        // Forgery: self-signed endorsement naming an absent handle.
        let forged = endorsement_wire(&stranger, "alice", "gonehandle");
        refused(
            check_sponsored(Some(forged), true, &present),
            Refusal::Endorsement,
        );
        // Genuine handle but signed by a device the sponsor does not authorize.
        let borrowed = endorsement_wire(&stranger, "alice", "sponsorname");
        refused(
            check_sponsored(Some(borrowed), true, &present),
            Refusal::Endorsement,
        );
        // Signed for another member, unrecorded verification, or a claim without a field.
        let other = endorsement_wire(&sponsor, "bob", "sponsorname");
        refused(
            check_sponsored(Some(other), true, &present),
            Refusal::Endorsement,
        );
        refused(
            check_sponsored(Some(wire), false, &present),
            Refusal::Endorsement,
        );
        refused(check_sponsored(None, true, &present), Refusal::Endorsement);
        refused(
            check_sponsored(Some(vec![1, 2]), true, &present),
            Refusal::Endorsement,
        );
    }
);

shared_test!(
    a_lineage_snapshot_verifies_as_of_receipt_and_only_for_this_community,
    {
        let mut f = Fixture::new();
        let signed = f.issue();
        let revoked = sign(
            &mut f.issuer,
            csgn::Kind::RevocationListSnapshot,
            &revocations(),
        );
        let published = PublishedPolicy {
            policy: signed.policy(),
            revocations: &revoked,
            minimum_revocations_revision: 1,
        };
        let snapshot = |credential: Vec<u8>, at: u64| {
            cvch::link::Snapshot {
                credential,
                received_at: at,
            }
            .to_bytes()
            .unwrap()
        };
        let credential = f.body.credential.clone();
        let now = published.policy.now;
        let facts =
            verify_lineage_snapshot(&snapshot(credential.clone(), now), "garden", &published)
                .unwrap();
        assert_eq!(facts.sponsor.member, f.body.member);
        assert!(!facts.sponsor.devices.is_empty());
        assert!(
            !facts.departed,
            "a member who is not revoked is not marked departed"
        );
        // On the signed revocation list the same snapshot reads as a departed sponsor.
        let gone = sign(
            &mut f.issuer,
            csgn::Kind::RevocationListSnapshot,
            &json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"members":[f.body.member.clone()],"devices":[]}}),
        );
        let after = PublishedPolicy {
            policy: signed.policy(),
            revocations: &gone,
            minimum_revocations_revision: 1,
        };
        let departed =
            verify_lineage_snapshot(&snapshot(credential.clone(), now), "garden", &after).unwrap();
        assert!(departed.departed);
        // Another community, tampered bytes and garbage are refused.
        assert!(
            verify_lineage_snapshot(&snapshot(credential.clone(), now), "other", &published)
                .is_err()
        );
        let mut tampered = credential.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_lineage_snapshot(&snapshot(tampered, now), "garden", &published).is_err());
        assert!(verify_lineage_snapshot(&[1, 2, 3], "garden", &published).is_err());
    }
);
