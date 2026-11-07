use std::fs;
use std::path::PathBuf;
use warm_compiler::{
    build_compiler_audit_payload, BundledToolchain, CompilationRequest, CompilerEngine,
    ExecutionRequest, ExecutionRunner,
};

#[test]
fn test_bundled_toolchain_locate_and_verify() {
    let toolchain = BundledToolchain::locate(None);
    assert!(
        toolchain.is_ok(),
        "Bundled toolchain must be discovered and verified: {:?}",
        toolchain.err()
    );

    let tc = toolchain.unwrap();
    assert!(
        tc.bits_stdcxx_supported,
        "Toolchain must support <bits/stdc++.h>"
    );
    assert_eq!(tc.cxx_standard, "c++23", "Standard must be C++23");
    assert!(
        !tc.sha256_hash.is_empty(),
        "Toolchain binary hash must not be empty"
    );
}

#[test]
fn test_cxx23_compilation_and_execution_with_bits_stdcxx() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let cpp_source = r#"
#include <bits/stdc++.h>
int main() {
    std::vector<std::string> words = {"Warm", "AntiCheat", "C++23"};
    for (size_t i = 0; i < words.size(); ++i) {
        std::cout << words[i] << (i + 1 == words.size() ? "" : " ");
    }
    std::cout << std::endl;
    return 0;
}
"#;

    let req = CompilationRequest {
        source_path: PathBuf::from("contest_solution.cpp"),
        source_code: Some(cpp_source.to_string()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec!["-pipe".to_string()],
    };

    let comp_res = engine.compile(req).expect("Compilation must succeed");
    assert!(comp_res.success, "Diagnostics: {}", comp_res.diagnostics);
    assert!(comp_res.output_binary_path.is_some());
    assert!(comp_res.output_binary_hash.is_some());
    assert!(!comp_res.source_sha256.is_empty());

    let bin_path = comp_res.output_binary_path.clone().unwrap();
    let bin_dir = engine.toolchain().root_dir.join("bin");

    let exec_req = ExecutionRequest {
        binary_path: bin_path,
        toolchain_bin_dir: Some(bin_dir),
        stdin_input: None,
        timeout_ms: 5000,
        args: Vec::new(),
    };

    let exec_res = ExecutionRunner::execute(exec_req).expect("Execution must succeed");
    assert!(exec_res.started);
    assert_eq!(exec_res.exit_code, Some(0));
    assert_eq!(exec_res.stdout.trim(), "Warm AntiCheat C++23");
    assert!(!exec_res.timed_out);

    // Verify audit payload generation
    let payload = build_compiler_audit_payload(&comp_res, Some(&exec_res));
    assert_eq!(payload.source_sha256, comp_res.source_sha256);
    assert_eq!(payload.program_exit_code, Some(0));
    assert!(payload.execution_started);
}

#[test]
fn test_cxx_syntax_error_diagnostics() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let invalid_cpp = r#"
#include <iostream>
int main() {
    this_is_a_syntax_error_undefined_identifier;
    return 0;
}
"#;

    let req = CompilationRequest {
        source_path: PathBuf::from("broken.cpp"),
        source_code: Some(invalid_cpp.to_string()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Compile invocation succeeds");
    assert!(
        !comp_res.success,
        "Compilation should fail for syntax errors"
    );
    assert!(comp_res.output_binary_path.is_none());
    assert!(
        comp_res
            .diagnostics
            .contains("this_is_a_syntax_error_undefined_identifier"),
        "Diagnostics must describe the syntax error: {}",
        comp_res.diagnostics
    );
}

#[test]
fn test_cxx_missing_source_file() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let req = CompilationRequest {
        source_path: PathBuf::from("non_existent_file_998877.cpp"),
        source_code: None,
        output_dir: None,
        optimization_level: None,
        standard: None,
        extra_args: vec![],
    };

    let err = engine.compile(req);
    assert!(err.is_err(), "Must report error for missing source file");
}

#[test]
fn test_cxx_spaces_and_unicode_paths() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let temp_dir = tempfile::Builder::new()
        .prefix("warm contest spaces & ünicode_")
        .tempdir()
        .unwrap();

    let src_file = temp_dir.path().join("my solution.cpp");
    fs::write(
        &src_file,
        "#include <iostream>\nint main() { std::cout << \"SpacesOK\" << std::endl; return 0; }",
    )
    .unwrap();

    let req = CompilationRequest {
        source_path: src_file.clone(),
        source_code: None,
        output_dir: Some(temp_dir.path().to_path_buf()),
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Compilation with spaced path");
    assert!(comp_res.success, "Diagnostics: {}", comp_res.diagnostics);

    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: comp_res.output_binary_path.unwrap(),
        toolchain_bin_dir: Some(engine.toolchain().root_dir.join("bin")),
        stdin_input: None,
        timeout_ms: 5000,
        args: vec![],
    })
    .expect("Execution");

    assert_eq!(exec_res.stdout.trim(), "SpacesOK");
}

#[test]
fn test_cxx_interactive_stdin() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let cpp_code = r#"
#include <iostream>
int main() {
    int a, b;
    if (std::cin >> a >> b) {
        std::cout << "SUM=" << (a + b) << std::endl;
    }
    return 0;
}
"#;

    let comp_res = engine
        .compile(CompilationRequest {
            source_path: PathBuf::from("add.cpp"),
            source_code: Some(cpp_code.to_string()),
            ..Default::default()
        })
        .expect("Compile add.cpp");

    assert!(comp_res.success);

    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: comp_res.output_binary_path.unwrap(),
        toolchain_bin_dir: Some(engine.toolchain().root_dir.join("bin")),
        stdin_input: Some("42 58\n".to_string()),
        timeout_ms: 5000,
        args: vec![],
    })
    .expect("Execute add.cpp");

    assert_eq!(exec_res.stdout.trim(), "SUM=100");
}

#[test]
fn test_cxx_infinite_loop_timeout_watchdog() {
    let tc = BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = CompilerEngine::new(tc);

    let infinite_code = r#"
#include <iostream>
int main() {
    while (true) {
        // Runaway infinite loop
    }
    return 0;
}
"#;

    let comp_res = engine
        .compile(CompilationRequest {
            source_path: PathBuf::from("infinite.cpp"),
            source_code: Some(infinite_code.to_string()),
            ..Default::default()
        })
        .expect("Compile infinite.cpp");

    assert!(comp_res.success);

    // Set strict 1000ms timeout
    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: comp_res.output_binary_path.unwrap(),
        toolchain_bin_dir: Some(engine.toolchain().root_dir.join("bin")),
        stdin_input: None,
        timeout_ms: 1000,
        args: vec![],
    })
    .expect("Execute infinite.cpp");

    assert!(
        exec_res.timed_out,
        "Watchdog should terminate the runaway process"
    );
    assert!(exec_res.resource_violation.is_some());
    assert!(exec_res
        .resource_violation
        .unwrap()
        .contains("TimeoutExceeded"));
}
