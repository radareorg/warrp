use uuid::Uuid;

fn main() {
    let bb_namespace: Uuid = uuid::Uuid::parse_str("0192a178-7a5f-7936-8653-3cbaa7d6afe7").unwrap();
    let func_namespace: Uuid = uuid::Uuid::parse_str("0192a179-61ac-7cef-88ed-012296e9492f").unwrap();

    assert_eq!(
        bb_namespace.to_string(),
        "0192a178-7a5f-7936-8653-3cbaa7d6afe7"
    );
    assert_eq!(
        func_namespace.to_string(),
        "0192a179-61ac-7cef-88ed-012296e9492f"
    );

    println!("All namespace constant checks passed!");
}
