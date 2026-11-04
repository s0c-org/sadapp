//! Shared net-snmp table transport policy and bounded child execution.
use std::fmt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout_at, Instant};

pub const DEFAULT_TABLE_MAX_ROWS: usize = 128;
pub const MAX_TABLE_MAX_ROWS: usize = 10_000;
pub const MAX_TABLE_RESPONSE_BYTES: usize = 1_048_576;
pub const TABLE_WALK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableWalkAttempt {
    Bulk(u8),
    Walk,
}

impl TableWalkAttempt {
    pub fn program(self) -> &'static str {
        match self {
            Self::Bulk(_) => "snmpbulkwalk",
            Self::Walk => "snmpwalk",
        }
    }

    pub fn args(self, args: &[String]) -> Vec<String> {
        let mut planned = Vec::new();
        if let Self::Bulk(repetitions) = self {
            planned.push(format!("-Cr{repetitions}"));
        }
        planned.extend_from_slice(args);
        planned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableWalkFailure {
    TooBig,
    ByteLimit,
    RowLimit,
    Timeout,
    Unavailable,
    Authentication,
    Failed,
    Io,
}

impl fmt::Display for TableWalkFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooBig => "SNMP table response too big",
            Self::ByteLimit => "SNMP table response exceeded byte limit",
            Self::RowLimit => "SNMP table response exceeded row limit",
            Self::Timeout => "SNMP table total deadline exceeded",
            Self::Unavailable => "SNMP table command unavailable",
            Self::Authentication => "SNMP table authentication or security validation failed",
            Self::Failed => "SNMP table request failed",
            Self::Io => "SNMP table command I/O failed",
        })
    }
}

impl std::error::Error for TableWalkFailure {}

impl TableWalkFailure {
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::TooBig | Self::ByteLimit | Self::RowLimit => "SNMP_RESPONSE_LIMIT",
            Self::Timeout => "SNMP_TIMEOUT",
            Self::Unavailable | Self::Io => "SNMP_EXEC_FAILED",
            Self::Authentication => "SNMP_AUTH_FAILED",
            Self::Failed => "SNMP_GET_FAILED",
        }
    }
}

/// Inspect tool diagnostics only for classification; never return device output as an error.
pub fn classify_table_failure(output: &[u8]) -> TableWalkFailure {
    let text = String::from_utf8_lossy(output).to_ascii_lowercase();
    if [
        "authentication",
        "authorization",
        "unknown user",
        "wrongdigest",
        "decryption",
        "security",
    ]
    .iter()
    .any(|marker| text.contains(marker))
    {
        TableWalkFailure::Authentication
    } else if [
        "toobig",
        "too big",
        "message too long",
        "response too large",
        "packet too large",
    ]
    .iter()
    .any(|marker| text.contains(marker))
    {
        TableWalkFailure::TooBig
    } else if ["timeout", "timed out", "no response"]
        .iter()
        .any(|marker| text.contains(marker))
    {
        TableWalkFailure::Timeout
    } else {
        TableWalkFailure::Failed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TableWalkPolicy {
    pub max_rows: usize,
    pub max_bytes: usize,
    pub timeout: Duration,
    initial: TableWalkAttempt,
}

impl TableWalkPolicy {
    pub fn new(version: &str, max_rows: usize) -> Self {
        Self {
            max_rows: max_rows.clamp(1, MAX_TABLE_MAX_ROWS),
            max_bytes: MAX_TABLE_RESPONSE_BYTES,
            timeout: TABLE_WALK_TIMEOUT,
            initial: match version.trim().trim_start_matches('v') {
                "2" | "2c" | "3" => TableWalkAttempt::Bulk(10),
                _ => TableWalkAttempt::Walk,
            },
        }
    }

    pub fn initial(self) -> TableWalkAttempt {
        self.initial
    }

    pub fn retry_after(
        self,
        attempt: TableWalkAttempt,
        failure: TableWalkFailure,
    ) -> Option<TableWalkAttempt> {
        match (attempt, failure) {
            (
                TableWalkAttempt::Bulk(10),
                TableWalkFailure::TooBig | TableWalkFailure::ByteLimit,
            ) => Some(TableWalkAttempt::Bulk(5)),
            (
                TableWalkAttempt::Bulk(_),
                TableWalkFailure::TooBig
                | TableWalkFailure::ByteLimit
                | TableWalkFailure::Unavailable
                | TableWalkFailure::Failed,
            ) => Some(TableWalkAttempt::Walk),
            _ => None,
        }
    }
}

/// Counts both output streams toward the byte cap and nonblank stdout rows as they arrive.
pub struct TableOutputBudget {
    max_rows: usize,
    max_bytes: usize,
    bytes: usize,
    rows: usize,
    in_row: bool,
}

impl TableOutputBudget {
    pub fn new(policy: TableWalkPolicy) -> Self {
        Self {
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            bytes: 0,
            rows: 0,
            in_row: false,
        }
    }
}

pub struct TableCommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub limit: Option<TableWalkFailure>,
}

/// Bound the complete child lifetime, including concurrent stdout/stderr draining.
pub async fn execute_table_command(
    command: Command,
    policy: TableWalkPolicy,
    deadline: Instant,
) -> Result<TableCommandOutput, TableWalkFailure> {
    let output = execute_table_command_partial(command, policy, deadline).await?;
    match output.limit {
        Some(error) => Err(error),
        None => Ok(output),
    }
}

/// Retain complete successful rows when a stream exceeds a deadline or size cap.
/// The caller must report `limit`; a partial response must never be cached as complete.
pub async fn execute_table_command_partial(
    mut command: Command,
    policy: TableWalkPolicy,
    deadline: Instant,
) -> Result<TableCommandOutput, TableWalkFailure> {
    if Instant::now() >= deadline {
        return Err(TableWalkFailure::Timeout);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                TableWalkFailure::Unavailable
            } else {
                TableWalkFailure::Io
            }
        })?;
    let mut stdout = child.stdout.take().ok_or(TableWalkFailure::Io)?;
    let mut stderr = child.stderr.take().ok_or(TableWalkFailure::Io)?;
    let mut budget = TableOutputBudget::new(policy);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let collect = async {
        let mut out_buffer = [0; 4096];
        let mut err_buffer = [0; 4096];
        let mut out_done = false;
        let mut err_done = false;
        while !out_done || !err_done {
            tokio::select! {
                read = stdout.read(&mut out_buffer), if !out_done => {
                    let count = read.map_err(|_| TableWalkFailure::Io)?;
                    out_done = count == 0;
                    for byte in &out_buffer[..count] {
                        budget.push(std::slice::from_ref(byte), true)?;
                        output.push(*byte);
                    }
                }
                read = stderr.read(&mut err_buffer), if !err_done => {
                    let count = read.map_err(|_| TableWalkFailure::Io)?;
                    err_done = count == 0;
                    for byte in &err_buffer[..count] {
                        budget.push(std::slice::from_ref(byte), false)?;
                        diagnostics.push(*byte);
                    }
                }
            }
        }
        let status = child.wait().await.map_err(|_| TableWalkFailure::Io)?;
        Ok(status.success())
    };
    let result = timeout_at(deadline, collect)
        .await
        .unwrap_or(Err(TableWalkFailure::Timeout));
    if result.is_err() {
        // Explicit reaping handles local errors; kill_on_drop covers caller cancellation.
        let _ = child.kill().await;
    }
    match result {
        Ok(success) => Ok(TableCommandOutput {
            success,
            stdout: output,
            stderr: diagnostics,
            limit: None,
        }),
        Err(
            error @ (TableWalkFailure::RowLimit
            | TableWalkFailure::ByteLimit
            | TableWalkFailure::Timeout),
        ) => {
            let complete = output
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            output.truncate(complete);
            Ok(TableCommandOutput {
                success: false,
                stdout: output,
                stderr: diagnostics,
                limit: Some(error),
            })
        }
        Err(error) => Err(error),
    }
}

impl TableOutputBudget {
    pub fn push(&mut self, data: &[u8], stdout: bool) -> Result<(), TableWalkFailure> {
        self.bytes = self.bytes.saturating_add(data.len());
        if self.bytes > self.max_bytes {
            return Err(TableWalkFailure::ByteLimit);
        }
        if stdout {
            for byte in data {
                if *byte == b'\n' {
                    self.in_row = false;
                } else if !byte.is_ascii_whitespace() && !self.in_row {
                    self.in_row = true;
                    self.rows += 1;
                    if self.rows > self.max_rows {
                        return Err(TableWalkFailure::RowLimit);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn partial_execution_preserves_complete_rows_on_row_byte_and_time_limits() {
        for (script, rows, bytes, expected) in [
            (
                "printf 'first\\nsecond\\n'; exec sleep 30",
                1,
                1024,
                TableWalkFailure::RowLimit,
            ),
            (
                "printf 'first\\nsecond\\n'; exec sleep 30",
                128,
                9,
                TableWalkFailure::ByteLimit,
            ),
            (
                "printf 'first\\npartial'; exec sleep 30",
                128,
                1024,
                TableWalkFailure::Timeout,
            ),
        ] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let mut policy = TableWalkPolicy::new("1", rows);
            policy.max_bytes = bytes;
            let deadline = Instant::now() + Duration::from_millis(100);
            let output = execute_table_command_partial(command, policy, deadline)
                .await
                .unwrap();
            assert_eq!(output.stdout, b"first\n");
            assert_eq!(output.limit, Some(expected));
            assert!(!output.success);
            assert!(Instant::now() < deadline + Duration::from_secs(1));
        }
    }

    #[test]
    fn plans_versions_and_size_downgrades() {
        assert_eq!(
            TableWalkPolicy::new("1", 128).initial(),
            TableWalkAttempt::Walk
        );
        for version in ["2c", "v2c", "3"] {
            let policy = TableWalkPolicy::new(version, 128);
            assert_eq!(policy.initial(), TableWalkAttempt::Bulk(10));
            let smaller = policy
                .retry_after(policy.initial(), TableWalkFailure::TooBig)
                .unwrap();
            assert_eq!(smaller, TableWalkAttempt::Bulk(5));
            assert_eq!(
                policy.retry_after(smaller, TableWalkFailure::ByteLimit),
                Some(TableWalkAttempt::Walk)
            );
            assert_eq!(
                policy.retry_after(TableWalkAttempt::Walk, TableWalkFailure::TooBig),
                None
            );
            for failure in [
                TableWalkFailure::RowLimit,
                TableWalkFailure::Timeout,
                TableWalkFailure::Authentication,
            ] {
                assert_eq!(policy.retry_after(policy.initial(), failure), None);
            }
            assert_eq!(
                policy.retry_after(policy.initial(), TableWalkFailure::Unavailable),
                Some(TableWalkAttempt::Walk)
            );
        }
        assert_eq!(
            TableWalkAttempt::Bulk(10).args(&["-v3".into()]),
            ["-Cr10", "-v3"]
        );
        assert_eq!(TableWalkAttempt::Walk.program(), "snmpwalk");
        assert_eq!(TableWalkAttempt::Bulk(5).program(), "snmpbulkwalk");
    }

    #[test]
    fn enforces_streaming_rows_unterminated_lines_and_combined_bytes() {
        let mut policy = TableWalkPolicy::new("2c", 2);
        policy.max_bytes = 12;
        let mut budget = TableOutputBudget::new(policy);
        budget.push(b"1\n \n", true).unwrap();
        budget.push(b"2", true).unwrap();
        assert_eq!(budget.push(b"\n3", true), Err(TableWalkFailure::RowLimit));
        let mut budget = TableOutputBudget::new(policy);
        budget.push(b"123456", false).unwrap();
        budget.push(b"123456", true).unwrap();
        assert_eq!(budget.push(b"x", false), Err(TableWalkFailure::ByteLimit));
    }

    #[test]
    fn classifies_without_echoing_credentials() {
        assert_eq!(
            classify_table_failure(b"tooBig secret"),
            TableWalkFailure::TooBig
        );
        assert_eq!(
            classify_table_failure(b"Authentication failure secret"),
            TableWalkFailure::Authentication
        );
        assert_eq!(
            classify_table_failure(b"unknown secret"),
            TableWalkFailure::Failed
        );
        assert_eq!(
            classify_table_failure(b"Timeout: No Response from secret"),
            TableWalkFailure::Timeout
        );
        assert_eq!(TableWalkFailure::Timeout.diagnostic_code(), "SNMP_TIMEOUT");
        assert_eq!(
            TableWalkFailure::RowLimit.diagnostic_code(),
            "SNMP_RESPONSE_LIMIT"
        );
        assert!(!classify_table_failure(b"tooBig secret")
            .to_string()
            .contains("secret"));
    }
}
