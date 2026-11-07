use std::fs;
use std::path::PathBuf;
use warm_compiler::{
    build_compiler_audit_payload, BundledToolchain, CompilationRequest, CompilerEngine,
    ExecutionRequest, ExecutionRunner,
};

#[test]
fn test_bundled_toolchain_locate_and_verify() {
    match BundledToolchain::locate(None) {
        Ok(tc) => {
            assert!(tc.bits_stdcxx_supported);
            assert_eq!(tc.cxx_standard, "c++23");
            assert!(!tc.sha256_hash.is_empty());
        }
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("toolchain")
                    || msg.contains("not found")
                    || msg.contains("Target platform")
                    || msg.contains("executable")
            );
        }
    }
}

#[test]
fn test_cxx23_compilation_and_execution_with_bits_stdcxx() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
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

    let exec_res = ExecutionRunner::execute(exec_req).expect("Execution runner must succeed");
    assert_eq!(exec_res.exit_code, Some(0));
    assert!(!exec_res.timed_out);
    assert!(exec_res.stdout.contains("Warm AntiCheat C++23"));

    let payload = build_compiler_audit_payload(&comp_res, Some(&exec_res));
    assert_eq!(payload.program_exit_code, Some(0));
    assert!(payload.execution_started);
    assert_eq!(payload.source_sha256, comp_res.source_sha256);
}

#[test]
fn test_cxx_syntax_error_diagnostics() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
    let engine = CompilerEngine::new(tc);

    let bad_source = r#"
#include <iostream>
int main() {
    this_is_an_unresolved_syntax_error();;;
    return 0
}
"#;

    let req = CompilationRequest {
        source_path: PathBuf::from("syntax_error.cpp"),
        source_code: Some(bad_source.to_string()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Engine should handle error");
    assert!(!comp_res.success);
    assert!(comp_res.output_binary_path.is_none());
    assert!(!comp_res.diagnostics.is_empty());
    assert!(
        comp_res.diagnostics.contains("error:")
            || comp_res
                .diagnostics
                .contains("this_is_an_unresolved_syntax_error")
    );

    let payload = build_compiler_audit_payload(&comp_res, None);
    assert!(!payload.execution_started);
    assert!(payload.compiler_exit_code != Some(0));
}

#[test]
fn test_cxx_missing_source_file() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
    let engine = CompilerEngine::new(tc);

    let req = CompilationRequest {
        source_path: PathBuf::from("non_existent_file_998877.cpp"),
        source_code: None,
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let res = engine.compile(req);
    assert!(res.is_err());
}

#[test]
fn test_cxx_spaces_and_unicode_paths() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
    let engine = CompilerEngine::new(tc);

    let temp_sub = std::env::temp_dir()
        .join(format!("warm space test_{}", uuid::Uuid::new_v4()))
        .join("contest dir with spaces");
    let _ = fs::create_dir_all(&temp_sub);

    let source_path = temp_sub.join("test code.cpp");
    let code = r#"
#include <iostream>
int main() {
    std::cout << "UNICODE_PATH_OK" << std::endl;
    return 0;
}
"#;
    let _ = fs::write(&source_path, code);

    let req = CompilationRequest {
        source_path: source_path.clone(),
        source_code: None,
        output_dir: Some(temp_sub.clone()),
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Compile with spaces");
    assert!(comp_res.success, "Diagnostics: {}", comp_res.diagnostics);

    let bin_path = comp_res.output_binary_path.unwrap();
    let bin_dir = engine.toolchain().root_dir.join("bin");

    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: bin_path,
        toolchain_bin_dir: Some(bin_dir),
        stdin_input: None,
        timeout_ms: 5000,
        args: Vec::new(),
    })
    .expect("Execute unicode path");

    assert!(exec_res.stdout.contains("UNICODE_PATH_OK"));

    let _ = fs::remove_dir_all(temp_sub);
}

#[test]
fn test_cxx_interactive_stdin() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
    let engine = CompilerEngine::new(tc);

    let code = r#"
#include <iostream>
#include <string>
int main() {
    std::string s;
    long long a, b;
    if (std::cin >> s >> a >> b) {
        std::cout << "GREETING:" << s << ":" << (a + b) << std::endl;
    }
    return 0;
}
"#;

    let req = CompilationRequest {
        source_path: PathBuf::from("stdin_test.cpp"),
        source_code: Some(code.to_string()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Compile stdin test");
    assert!(comp_res.success);

    let bin_path = comp_res.output_binary_path.unwrap();
    let bin_dir = engine.toolchain().root_dir.join("bin");

    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: bin_path,
        toolchain_bin_dir: Some(bin_dir),
        stdin_input: Some("Hello 100 250\n".to_string()),
        timeout_ms: 5000,
        args: Vec::new(),
    })
    .expect("Execute with stdin");

    assert_eq!(exec_res.exit_code, Some(0));
    assert!(exec_res.stdout.contains("GREETING:Hello:350"));
}

#[test]
fn test_cxx_infinite_loop_timeout_watchdog() {
    let tc = match BundledToolchain::locate(None) {
        Ok(tc) => tc,
        Err(_) => return,
    };
    let engine = CompilerEngine::new(tc);

    let code = r#"
#include <iostream>
int main() {
    std::cout << "STARTING_INFINITE_LOOP" << std::endl;
    volatile int x = 0;
    while (true) {
        x++;
    }
    return 0;
}
"#;

    let req = CompilationRequest {
        source_path: PathBuf::from("infinite_loop.cpp"),
        source_code: Some(code.to_string()),
        output_dir: None,
        optimization_level: Some("-O0".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec![],
    };

    let comp_res = engine.compile(req).expect("Compile infinite loop");
    assert!(comp_res.success);

    let bin_path = comp_res.output_binary_path.unwrap();
    let bin_dir = engine.toolchain().root_dir.join("bin");

    let exec_res = ExecutionRunner::execute(ExecutionRequest {
        binary_path: bin_path,
        toolchain_bin_dir: Some(bin_dir),
        stdin_input: None,
        timeout_ms: 1000,
        args: Vec::new(),
    })
    .expect("Watchdog execution");

    assert!(exec_res.timed_out);
    assert!(exec_res.error_message.is_some() && exec_res.error_message.unwrap().contains("1000ms"));
}
