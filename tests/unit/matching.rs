use super::*;
use serde_json::json;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn compiled_predicates_refuse_incompatible_attribute_types() {
    let schema: Schema = serde_json::from_value(json!({
        "community": "garden", "version": 1, "private": [],
        "public": [{"id": "yes", "label": "Yes", "kind": {"type": "yes_no"},
            "required": true, "filterable": true, "change_preset": "free",
            "no_contact_details": false}]
    }))
    .unwrap();
    let profile = PublicProfile {
        community: "garden".into(),
        schema_version: 1,
        public: [("yes".into(), json!(true))].into(),
    };
    let target = Participant::new("member", &profile, &schema, &[]).unwrap();
    // Exercise the private comparison's defensive type refusals directly.
    // Public rule construction already rejects these incompatible predicates.
    for predicate in [
        Predicate::Range("yes".into(), BigDecimal::from(0), BigDecimal::from(1)),
        Predicate::OneOf("yes".into(), vec!["choice".into()]),
    ] {
        assert_eq!(
            evaluate_rule(&predicate, &target).1,
            Some(MatchReason::Different)
        );
    }
}
