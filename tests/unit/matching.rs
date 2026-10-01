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
        Predicate::Distance("yes".into(), 0.into(), 0.into(), 0.into(), 1.into()),
    ] {
        assert_eq!(
            evaluate_rule(&predicate, &target).1,
            Some(MatchReason::Different)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn distance_refuses_incompatible_source_and_nonfinite_upstream_result() {
    let schema: Schema = serde_json::from_value(json!({
        "community":"garden", "version":1, "private":[],
        "public":[{"id":"place","label":"Place","kind":{"type":"location"},
            "required":true,"filterable":true,"change_preset":"free","no_contact_details":false}]
    })).unwrap();
    let rule = Rule::DistanceRange { field:"place".into(), min_meters:"0".into(), max_meters:"1".into() };
    assert!(matches!(compile_rule(&rule, &schema, &[("place".into(), Attribute::Boolean(true))].into()), Err(RuleError::Profile)));
    let profile = PublicProfile { community:"garden".into(), schema_version:1,
        public:[("place".into(),json!({"latitude":0,"longitude":0}))].into() };
    let target = Participant::new("member", &profile, &schema, &[]).unwrap();
    // Public construction rejects latitude 1000. Defend the private comparison
    // against a nonfinite result from the real upstream geodesic implementation.
    let invalid = Predicate::Distance("place".into(), 1000.into(), 0.into(), 0.into(), 1.into());
    assert_eq!(evaluate_rule(&invalid, &target).1, Some(MatchReason::Different));
}
