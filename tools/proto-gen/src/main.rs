use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let polarizer = generator
        .parent()
        .and_then(|path| path.parent())
        .expect("generator lives under polarizer/tools/proto-gen")
        .to_path_buf();
    let workspace = polarizer
        .parent()
        .expect("polarizer has a workspace parent");
    let trust_safety = workspace.join("interchat-protobuf");
    let iris_proto = workspace.join("iris/proto");
    let output = polarizer.join("src/generated");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir(&output)
        .compile_protos(
            &[trust_safety.join("trust_and_safety/v2/api.proto")],
            &[trust_safety.clone(), PathBuf::from("/usr/include")],
        )?;
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .out_dir(&output)
        .compile_protos(
            &[iris_proto.join("authz/v2/staff.proto")],
            &[iris_proto, PathBuf::from("/usr/include")],
        )?;
    Ok(())
}
