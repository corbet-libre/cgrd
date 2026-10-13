#![allow(dead_code)]

use cgrd::*;
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use serde_json::json;

pub const ISSUED: u64 = 1000;
pub const NOW: u64 = 1100;
pub const EXPIRY: u64 = 2000;

// Public deterministic test keys, never production credentials.
pub fn issuer(community: &str) -> Signer {
    issuer_with_lifetime(community, 10000)
}

pub fn issuer_with_lifetime(community: &str, max_validity: u64) -> Signer {
    Signer::new(
        community,
        SecretKey::from_seed(&mut [11; 32]),
        ISSUED,
        max_validity,
    )
    .unwrap()
}

pub fn fingerprint(
    community: &str,
    member: &str,
    field: &str,
    value: &serde_json::Value,
    salt: &cpns::Salt,
) -> [u8; 32] {
    *cpns::fingerprint_v2(
        &cpns::FingerprintContext {
            community,
            member,
            field,
        },
        &pin_value_bytes(value),
        salt,
    )
    .as_bytes()
}

// Equivalent CBOR values with non-minimal tag, array or protected-byte length.
// All preserve the protected bytes, payload and Ed25519 signature.
pub fn alternate_cose_encodings(bytes: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(&bytes[..3], &[0xd2, 0x84, 0x58]);
    vec![
        [&[0xd8, 0x12][..], &bytes[1..]].concat(),
        [&[0xd2, 0x98, 0x04][..], &bytes[2..]].concat(),
        [&[0xd2, 0x84, 0x59, 0x00][..], &bytes[3..]].concat(),
    ]
}

pub fn sign<T: Serialize>(signer: &mut Signer, kind: Kind, payload: &T) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(payload).unwrap(), ISSUED, EXPIRY)
        .unwrap()
}

pub fn schema(community: &str) -> cshm::Schema {
    serde_json::from_value(json!({
        "community": community, "version": 1,
        "public": [
            {"id":"age", "label":"Age", "kind":{"type":"integer","min":18,"max":120},
             "required":true,"filterable":true,"change_preset":"stable","no_contact_details":false},
            {"id":"hobby", "label":"Hobby", "kind":{"type":"choice","options":[{"id":"hiking","label":"Hiking"},{"id":"reading","label":"Reading"}]},
             "required":false,"filterable":true,"change_preset":"free","no_contact_details":false},
            {"id":"bio", "label":"About me", "kind":{"type":"short_text","min_length":0,"max_length":100},
             "required":false,"filterable":false,"change_preset":"free","no_contact_details":false},
            {"id":"yes", "label":"Yes", "kind":{"type":"yes_no"},
             "required":false,"filterable":true,"change_preset":"free","no_contact_details":false},
            {"id":"number", "label":"Number", "kind":{"type":"decimal","min":null,"max":null},
             "required":false,"filterable":true,"change_preset":"free","no_contact_details":false},
            {"id":"place", "label":"Place", "kind":{"type":"location"},
             "required":false,"filterable":true,"change_preset":"free","no_contact_details":false},
            {"id":"text", "label":"Text", "kind":{"type":"short_text","min_length":0,"max_length":100},
             "required":false,"filterable":true,"change_preset":"free","no_contact_details":false}
        ],
        "private":[
            {"id":"secret", "label":"Private answer", "kind":{"type":"yes_no"},
             "required":true,"filterable":false,"change_preset":"occasional","no_contact_details":false}
        ]
    })).unwrap()
}

pub fn profile(community: &str) -> cshm::PublicProfile {
    cshm::PublicProfile {
        community: community.into(),
        schema_version: 1,
        public: [("age".into(), json!(34)), ("hobby".into(), json!("hiking"))].into(),
    }
}

pub fn settings(community: &str, revision: u64) -> Snapshot<Settings> {
    Snapshot {
        community: community.into(),
        revision,
        policy_epoch: 2,
        content: Settings {
            required_gates: vec![GateRequirement {
                gate: "voucher".into(),
                providers: vec!["community".into()],
            }],
            revoked_members: vec![],
            revoked_devices: vec![],
            reserved_handles: vec![],
        },
    }
}

pub struct Fixture {
    pub issuer: Signer,
    pub device: SigningKey,
    pub credential: Credential,
    pub body: BundleContent,
    pub settings: Snapshot<Settings>,
    pub schema: Snapshot<cshm::Schema>,
}

impl Fixture {
    pub fn new() -> Self {
        let device = SigningKey::from_bytes(&[22; 32]);
        let salt = cpns::Salt::from_bytes(vec![33; 16]).unwrap();
        let credential = Credential {
            purpose: CredentialPurpose::CommunityCredentialV2,
            issuance_action: "admission".into(),
            community: "garden".into(),
            member: "alice".into(),
            handle: "mountain".into(),
            schema_version: 1,
            policy_epoch: 2,
            gates: vec![Gate {
                gate: "voucher".into(),
                provider: "community".into(),
                valid_until: EXPIRY,
            }],
            pins: vec![Pin {
                field: "age".into(),
                fingerprint: fingerprint("garden", "alice", "age", &json!(34), &salt),
            }],
            devices: vec![device.verifying_key().to_bytes()],
        };
        let body = BundleContent {
            hpke_key: None,
            community: "garden".into(),
            member: "alice".into(),
            device: device.verifying_key().to_bytes(),
            credential: vec![],
            profile: Profile::Public(profile("garden")),
            openings: vec![Opening {
                field: "age".into(),
                salt: salt.as_bytes().to_vec(),
            }],
            vouched_by: None,
            vouched_verified: false,
        };
        Self {
            issuer: issuer("garden"),
            device,
            credential,
            body,
            settings: settings("garden", 1),
            schema: Snapshot {
                community: "garden".into(),
                revision: 1,
                policy_epoch: 2,
                content: schema("garden"),
            },
        }
    }

    pub fn issue(&mut self) -> Signed {
        self.issue_payload(&self.credential.clone())
    }

    pub fn issue_payload(&mut self, credential: &impl serde::Serialize) -> Signed {
        self.body.credential = sign(&mut self.issuer, Kind::Credential, credential);
        let payload = serde_json::to_vec(&self.body).unwrap();
        let bundle = Bundle {
            signature: self
                .device
                .sign(&binding_bytes(&payload))
                .to_bytes()
                .to_vec(),
            payload,
        };
        let settings = sign(&mut self.issuer, Kind::SettingsSnapshot, &self.settings);
        let schema = sign(&mut self.issuer, Kind::SchemaSnapshot, &self.schema);
        Signed {
            bundle,
            settings,
            schema,
            keys: self.issuer.key_ring().clone(),
        }
    }

    pub fn public_mut(&mut self) -> &mut cshm::PublicProfile {
        let Profile::Public(p) = &mut self.body.profile else {
            panic!("public fixture")
        };
        p
    }
}

pub struct Signed {
    pub bundle: Bundle,
    pub settings: Vec<u8>,
    pub schema: Vec<u8>,
    pub keys: csgn::KeyRing,
}

impl Signed {
    pub fn policy(&self) -> Policy<'_> {
        Policy {
            community: "garden",
            expected_issuance_action: "admission",
            keys: &self.keys,
            now: NOW,
            minimum_epoch: 2,
            minimum_settings_revision: 1,
            minimum_schema_revision: 1,
            maximum_snapshot_age: 300,
            settings: &self.settings,
        }
    }
    pub fn check(&self) -> Admission {
        check(&self.bundle, &self.policy(), &self.schema)
    }
}

pub fn refused(result: Admission, reason: Refusal) {
    assert_eq!(
        result,
        Admission::Refused {
            reasons: vec![reason]
        }
    );
}
