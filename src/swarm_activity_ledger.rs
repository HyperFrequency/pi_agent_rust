//! Redacted multi-agent activity ledger for swarm runs.
//!
//! The ledger is intentionally small and append-oriented: callers provide
//! operational events, the ledger assigns monotonic sequence numbers, redacts
//! sensitive fields by default, and exports stable JSONL for incident review.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Schema emitted by every swarm activity ledger entry.
pub const SWARM_ACTIVITY_LEDGER_SCHEMA: &str = "pi.swarm.activity_ledger.v1";

const REDACTED: &str = "[REDACTED]";
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "authorization",
    "bearer",
    "body",
    "cookie",
    "key",
    "password",
    "prompt",
    "secret",
    "token",
    "transcript",
];

/// Category of activity captured by the swarm ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmActivityKind {
    /// Beads status or ownership changed.
    BeadStatus,
    /// Agent Mail message/thread activity.
    AgentMail,
    /// Agent Mail file reservation activity.
    FileReservation,
    /// RCH verification job state.
    RchJob,
    /// Local or remote verification command result.
    Verification,
    /// Git commit or push event.
    GitCommit,
    /// Explicit recovery or operator intervention.
    Recovery,
    /// General redacted note.
    Note,
}

/// Correlation identifiers attached to a swarm activity event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmActivityIds {
    /// Stable event correlation ID for joining entries across systems.
    pub correlation_id: String,
    /// Beads issue ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    /// Agent Mail thread ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_thread_id: Option<String>,
    /// Agent Mail message ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_message_id: Option<u64>,
    /// Agent name that produced or owns the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// File reservation ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_reservation_id: Option<u64>,
    /// RCH job/build ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rch_job_id: Option<String>,
    /// Verification command/run ID, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_id: Option<String>,
    /// Git commit SHA, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
}

impl SwarmActivityIds {
    /// Create ID metadata with the required correlation ID.
    #[must_use]
    pub fn new(correlation_id: impl Into<String>) -> Self {
        Self {
            correlation_id: correlation_id.into(),
            ..Self::default()
        }
    }

    /// Attach a bead ID.
    #[must_use]
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    /// Attach an Agent Mail thread ID.
    #[must_use]
    pub fn with_mail_thread_id(mut self, mail_thread_id: impl Into<String>) -> Self {
        self.mail_thread_id = Some(mail_thread_id.into());
        self
    }

    /// Attach an agent name.
    #[must_use]
    pub fn with_agent_name(mut self, agent_name: impl Into<String>) -> Self {
        self.agent_name = Some(agent_name.into());
        self
    }

    /// Attach an RCH job ID.
    #[must_use]
    pub fn with_rch_job_id(mut self, rch_job_id: impl Into<String>) -> Self {
        self.rch_job_id = Some(rch_job_id.into());
        self
    }

    /// Attach a git commit SHA.
    #[must_use]
    pub fn with_git_sha(mut self, git_sha: impl Into<String>) -> Self {
        self.git_sha = Some(git_sha.into());
        self
    }
}

/// Summary of field-level redaction applied before serialization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmActivityRedaction {
    /// Number of fields redacted in this entry.
    pub redacted_count: usize,
    /// Field names that were redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}

impl SwarmActivityRedaction {
    fn record(&mut self, field: impl Into<String>) {
        self.redacted_count = self.redacted_count.saturating_add(1);
        self.redacted_fields.push(field.into());
    }
}

/// One redacted JSONL entry in the swarm activity ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmActivityLedgerEntry {
    /// Stable schema identifier.
    pub schema: String,
    /// Monotonic sequence number assigned by the producing ledger.
    pub sequence: u64,
    /// Event timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Activity category.
    pub kind: SwarmActivityKind,
    /// Redacted human summary.
    pub summary: String,
    /// Correlation IDs for joining with Beads, Agent Mail, RCH, and Git.
    #[serde(default)]
    pub ids: SwarmActivityIds,
    /// Additional redacted structured fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    details: BTreeMap<String, String>,
    /// Redaction metadata.
    #[serde(default)]
    pub redaction: SwarmActivityRedaction,
}

impl SwarmActivityLedgerEntry {
    /// Return structured redacted detail fields.
    #[must_use]
    pub const fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    /// True when the entry uses the current schema.
    #[must_use]
    pub fn has_current_schema(&self) -> bool {
        self.schema == SWARM_ACTIVITY_LEDGER_SCHEMA
    }
}

/// Append-only in-memory activity ledger.
#[derive(Debug, Clone, Default)]
pub struct SwarmActivityLedger {
    entries: Vec<SwarmActivityLedgerEntry>,
    next_sequence: u64,
}

impl SwarmActivityLedger {
    /// Create an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Append one activity event and return its assigned sequence.
    pub fn append(
        &mut self,
        timestamp_ms: u64,
        kind: SwarmActivityKind,
        ids: SwarmActivityIds,
        summary: impl Into<String>,
        details: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        let (summary, details, redaction) = redact_entry(summary.into(), details);
        self.entries.push(SwarmActivityLedgerEntry {
            schema: SWARM_ACTIVITY_LEDGER_SCHEMA.to_string(),
            sequence,
            timestamp_ms,
            kind,
            summary,
            ids,
            details,
            redaction,
        });
        sequence
    }

    /// All entries in append order.
    #[must_use]
    pub fn entries(&self) -> &[SwarmActivityLedgerEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize entries as JSONL.
    ///
    /// # Errors
    ///
    /// Returns a serde error if an entry cannot be serialized.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        entries_to_jsonl(&self.entries)
    }
}

/// Timeline event used by replay/incident review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmActivityTimelineEvent {
    /// Original ledger sequence.
    pub sequence: u64,
    /// Event timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Activity category.
    pub kind: SwarmActivityKind,
    /// Stable event correlation ID.
    pub correlation_id: String,
    /// Redacted summary.
    pub summary: String,
}

impl From<&SwarmActivityLedgerEntry> for SwarmActivityTimelineEvent {
    fn from(entry: &SwarmActivityLedgerEntry) -> Self {
        Self {
            sequence: entry.sequence,
            timestamp_ms: entry.timestamp_ms,
            kind: entry.kind,
            correlation_id: entry.ids.correlation_id.clone(),
            summary: entry.summary.clone(),
        }
    }
}

/// Errors when parsing or validating activity ledger JSONL.
#[derive(Debug, thiserror::Error)]
pub enum SwarmActivityLedgerError {
    /// One JSONL row was not valid JSON.
    #[error("failed to parse swarm activity ledger line {line}: {source}")]
    Parse {
        /// 1-based line number.
        line: usize,
        /// serde parse error.
        source: serde_json::Error,
    },
    /// One JSONL row used an unsupported schema.
    #[error("unsupported swarm activity ledger schema on line {line}: {schema}")]
    UnsupportedSchema {
        /// 1-based line number.
        line: usize,
        /// Unsupported schema value.
        schema: String,
    },
    /// One JSONL row omitted a required correlation ID.
    #[error("missing correlation_id on swarm activity ledger line {line}")]
    MissingCorrelationId {
        /// 1-based line number.
        line: usize,
    },
}

/// Serialize entries as JSONL.
///
/// # Errors
///
/// Returns a serde error if an entry cannot be serialized.
pub fn entries_to_jsonl(entries: &[SwarmActivityLedgerEntry]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(entry)?);
    }
    Ok(out)
}

/// Parse and validate activity ledger JSONL entries.
///
/// # Errors
///
/// Returns a validation error if any row is invalid, uses an unsupported schema,
/// or omits the required correlation ID.
pub fn entries_from_jsonl(
    input: &str,
) -> Result<Vec<SwarmActivityLedgerEntry>, SwarmActivityLedgerError> {
    let mut entries = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = index + 1;
        let entry: SwarmActivityLedgerEntry =
            serde_json::from_str(line).map_err(|source| SwarmActivityLedgerError::Parse {
                line: line_number,
                source,
            })?;
        if !entry.has_current_schema() {
            return Err(SwarmActivityLedgerError::UnsupportedSchema {
                line: line_number,
                schema: entry.schema,
            });
        }
        if entry.ids.correlation_id.trim().is_empty() {
            return Err(SwarmActivityLedgerError::MissingCorrelationId { line: line_number });
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Build a deterministic timeline from JSONL, regardless of input row order.
///
/// # Errors
///
/// Returns a validation error if any JSONL row is invalid.
pub fn timeline_from_jsonl(
    input: &str,
) -> Result<Vec<SwarmActivityTimelineEvent>, SwarmActivityLedgerError> {
    let mut entries = entries_from_jsonl(input)?;
    entries.sort_by(|left, right| {
        left.timestamp_ms
            .cmp(&right.timestamp_ms)
            .then_with(|| left.sequence.cmp(&right.sequence))
            .then_with(|| left.ids.correlation_id.cmp(&right.ids.correlation_id))
    });
    Ok(entries
        .iter()
        .map(SwarmActivityTimelineEvent::from)
        .collect())
}

fn redact_entry(
    summary: String,
    details: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
) -> (String, BTreeMap<String, String>, SwarmActivityRedaction) {
    let mut redaction = SwarmActivityRedaction::default();
    let summary = redact_value("summary", summary, &mut redaction);
    let mut redacted_details = BTreeMap::new();
    for (key, value) in details {
        let key = key.into();
        let value = redact_value(&key, value.into(), &mut redaction);
        redacted_details.insert(key, value);
    }
    (summary, redacted_details, redaction)
}

fn redact_value(field: &str, value: String, redaction: &mut SwarmActivityRedaction) -> String {
    if is_sensitive_field(field) || looks_sensitive(&value) {
        redaction.record(field);
        REDACTED.to_string()
    } else {
        value
    }
}

fn is_sensitive_field(field: &str) -> bool {
    let normalized = field.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn looks_sensitive(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("bearer ")
        || normalized.contains("sk-")
        || normalized.contains("api_key")
        || normalized.contains("password=")
        || normalized.contains("token=")
}

#[cfg(test)]
mod tests {
    use super::{
        SWARM_ACTIVITY_LEDGER_SCHEMA, SwarmActivityIds, SwarmActivityKind, SwarmActivityLedger,
        SwarmActivityLedgerError, entries_from_jsonl, timeline_from_jsonl,
    };

    #[test]
    fn exports_versioned_jsonl_with_correlation_ids() {
        let mut ledger = SwarmActivityLedger::new();
        let sequence = ledger.append(
            1_000,
            SwarmActivityKind::BeadStatus,
            SwarmActivityIds::new("corr-1")
                .with_bead_id("bd-123")
                .with_agent_name("CopperOx"),
            "claimed bd-123",
            [("status", "in_progress")],
        );

        assert_eq!(sequence, 0);
        let jsonl = ledger.to_jsonl().expect("ledger should serialize");
        let entries = entries_from_jsonl(&jsonl).expect("ledger should parse");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].schema, SWARM_ACTIVITY_LEDGER_SCHEMA);
        assert_eq!(entries[0].ids.correlation_id, "corr-1");
        assert_eq!(
            entries[0].details().get("status").map(String::as_str),
            Some("in_progress")
        );
    }

    #[test]
    fn timeline_reorders_out_of_order_jsonl_deterministically() {
        let mut ledger = SwarmActivityLedger::new();
        ledger.append(
            2_000,
            SwarmActivityKind::Verification,
            SwarmActivityIds::new("corr-late").with_rch_job_id("298"),
            "verification finished",
            [("command", "cargo check --all-targets")],
        );
        ledger.append(
            1_000,
            SwarmActivityKind::AgentMail,
            SwarmActivityIds::new("corr-early").with_mail_thread_id("bd-123"),
            "start message sent",
            [("subject", "[bd-123] start")],
        );
        let lines = ledger
            .to_jsonl()
            .expect("ledger should serialize")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let reversed = format!("{}\n{}", lines[1], lines[0]);

        let timeline = timeline_from_jsonl(&reversed).expect("timeline should parse");

        assert_eq!(timeline[0].correlation_id, "corr-early");
        assert_eq!(timeline[1].correlation_id, "corr-late");
    }

    #[test]
    fn missing_optional_fields_still_parse() {
        let raw = format!(
            "{{\"schema\":\"{SWARM_ACTIVITY_LEDGER_SCHEMA}\",\"sequence\":7,\"timestamp_ms\":42,\"kind\":\"note\",\"summary\":\"ok\",\"ids\":{{\"correlation_id\":\"corr-min\"}}}}"
        );

        let entries = entries_from_jsonl(&raw).expect("minimal entry should parse");

        assert_eq!(entries[0].ids.correlation_id, "corr-min");
        assert!(entries[0].ids.bead_id.is_none());
        assert!(entries[0].details().is_empty());
    }

    #[test]
    fn redacts_prompt_bodies_and_secret_values_by_default() {
        let mut ledger = SwarmActivityLedger::new();
        ledger.append(
            1_000,
            SwarmActivityKind::Recovery,
            SwarmActivityIds::new("corr-redact").with_agent_name("CopperOx"),
            "operator used bearer token",
            [
                ("prompt_body", "please inspect this private prompt"),
                ("api_key", "sk-test-secret"),
                ("safe_status", "recovered"),
            ],
        );

        let entry = &ledger.entries()[0];

        assert_eq!(entry.summary, "[REDACTED]");
        assert_eq!(
            entry.details().get("prompt_body").map(String::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            entry.details().get("api_key").map(String::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            entry.details().get("safe_status").map(String::as_str),
            Some("recovered")
        );
        assert_eq!(entry.redaction.redacted_count, 3);
        assert!(
            entry
                .redaction
                .redacted_fields
                .contains(&"summary".to_string())
        );
        assert!(
            entry
                .redaction
                .redacted_fields
                .contains(&"prompt_body".to_string())
        );
        assert!(
            entry
                .redaction
                .redacted_fields
                .contains(&"api_key".to_string())
        );
    }

    #[test]
    fn rejects_missing_correlation_id() {
        let raw = format!(
            "{{\"schema\":\"{SWARM_ACTIVITY_LEDGER_SCHEMA}\",\"sequence\":0,\"timestamp_ms\":1,\"kind\":\"note\",\"summary\":\"ok\",\"ids\":{{\"correlation_id\":\"\"}}}}"
        );

        let error = entries_from_jsonl(&raw).expect_err("empty correlation ID should fail");

        assert!(matches!(
            error,
            SwarmActivityLedgerError::MissingCorrelationId { line: 1 }
        ));
    }
}
