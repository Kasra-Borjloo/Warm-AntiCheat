use crate::engine::CompilationResult;
use crate::runner::ExecutionResult;
use warm_events::CompilerEventPayload;

pub fn build_compiler_audit_payload(
    comp: &CompilationResult,
    exec: Option<&ExecutionResult>,
) -> CompilerEventPayload {
    CompilerEventPayload {
        source_path: comp.source_path.to_string_lossy().to_string(),
        source_sha256: comp.source_sha256.clone(),
        source_snapshot: comp.source_snapshot.clone(),
        compiler_version: comp.compiler_version.clone(),
        toolchain_hash: comp.toolchain_hash.clone(),
        compilation_args: comp.compilation_args.clone(),
        compilation_start: comp.start_time,
        compilation_end: comp.end_time,
        compiler_exit_code: comp.exit_code,
        compiler_diagnostics: comp.diagnostics.clone(),
        output_executable_hash: comp.output_binary_hash.clone(),
        execution_started: exec.map(|e| e.started).unwrap_or(false),
        execution_start: exec.map(|e| e.start_time),
        execution_end: exec.map(|e| e.end_time),
        program_exit_code: exec.and_then(|e| e.exit_code),
        resource_violations: exec.and_then(|e| e.resource_violation.clone()),
        execution_error: exec.and_then(|e| e.error_message.clone()),
        executable_args: exec
            .map(|e| e.command_line_args.clone())
            .unwrap_or_default(),
    }
}
