fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Protobuf output is committed under src/generated. Regeneration is an
    // explicit developer task so Docker and release builds never depend on a
    // sibling repository or a locally installed protoc plugin.
    println!("cargo:rerun-if-changed=src/generated/interchat.trust_and_safety.v2.rs");
    println!("cargo:rerun-if-changed=src/generated/prism.rs");
    println!("cargo:rerun-if-changed=src/generated/authz.v2.rs");
    Ok(())
}
