//! Deterministic, read-only swarm progress SLO evaluator.
//!
//! The evaluator consumes already-normalized progress sources and emits
//! `pi.swarm.progress_slo.v1`. It never reads files, mutates Beads, sends
//! Agent Mail, starts RCH work, or changes git state.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Schema emitted by progress SLO reports.
pub const SWARM_PROGRESS_SLO_SCHEMA: &str = "pi.swarm.progress_slo.v1";

/// Contract version implemented by this evaluator.
pub const SWARM_PROGRESS_SLO_CONTRACT_VERSION: &str = "1.0.0";

const REASON_BEAD_CLOSEOUT: &str = "PROGRESS-SLO-BEAD-CLOSEOUT";
const REASON_GIT_COMMIT_DELTA: &str = "PROGRESS-SLO-GIT-COMMIT-DELTA";
const REASON_NO_READY_WORK: &str = "PROGRESS-SLO-NO-READY-WORK";
const REASON_STALE_IN_PROGRESS: &str = "PROGRESS-SLO-STALE-IN-PROGRESS";
const REASON_AGENT_MAIL_DEGRADED: &str = "PROGRESS-SLO-AGENT-MAIL-DEGRADED";
const REASON_RCH_SATURATED: &str = "PROGRESS-SLO-RCH-SATURATED";
const REASON_VALIDATION_BROKER_SATURATED: &str = "PROGRESS-SLO-VALIDATION-BROKER-SATURATED";
const REASON_MALFORMED_SOURCE: &str = "PROGRESS-SLO-MALFORMED-SOURCE";
const REASON_MISSING_AUTHORITY: &str = "PROGRESS-SLO-MISSING-AUTHORITY";
const REASON_CONVERGED_NO_OPEN_WORK: &str = "PROGRESS-SLO-CONVERGED-NO-OPEN-WORK";

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "beads_active_delta",
    "beads_closed_delta",
    "git_commit_delta",
    "rch_posture",
    "validation_broker_posture",
    "agent_mail_health",
    "operator_runpack_summary",
    "swarm_autopilot_summary",
    "context_intelligence_summary",
    "operator_time_window",
];

const PROGRESSING_AUTHORITY_SOURCE_IDS: &[&str] = &[
    "operator_time_window",
    "beads_active_delta",
    "beads_closed_delta",
    "git_commit_delta",
];

/// Top-level status for a progress SLO report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressSloStatus {
    Progressing,
    QuietBlocked,
    CoordinationDegraded,
    BuildSaturated,
    Stalled,
    ConvergedNoOpenWork,
    MalformedSourceDegraded,
    InsufficientEvidenceDegraded,
}

/// Availability state for one normalized progress source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAvailability {
    Available,
    Unavailable,
    Partial,
    Malformed,
    Stale,
    NotConfigured,
}

impl SourceAvailability {
    const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    const fn is_malformed(self) -> bool {
        matches!(self, Self::Malformed)
    }

    const fn is_degraded(self) -> bool {
        !self.is_available()
    }
}

/// Freshness state for one normalized progress source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Current,
    Stale,
    Missing,
    Malformed,
    FreshnessUnknown,
}

impl FreshnessState {
    const fn is_current(self) -> bool {
        matches!(self, Self::Current)
    }

    const fn is_malformed(self) -> bool {
        matches!(self, Self::Malformed)
    }

    const fn is_degraded(self) -> bool {
        !self.is_current()
    }
}

/// Redaction state for one normalized progress source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    None,
    Redacted,
    SensitiveOmitted,
    UnsafeToEmit,
}

/// Health posture projected from Agent Mail evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMailHealth {
    Green,
    Yellow,
    Red,
    Corrupt,
    Unavailable,
    Unknown,
}

impl AgentMailHealth {
    const fn is_degraded(self) -> bool {
        !matches!(self, Self::Green)
    }
}

/// Posture projected from RCH queue and worker evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchPosture {
    Green,
    Queueing,
    Saturated,
    FailOpenLocalRisk,
    Unavailable,
    Unknown,
}

impl RchPosture {
    const fn is_saturated(self) -> bool {
        matches!(
            self,
            Self::Saturated | Self::FailOpenLocalRisk | Self::Unavailable
        )
    }
}

/// Posture projected from validation broker evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationBrokerPosture {
    Green,
    Queueing,
    Saturated,
    StaleSlots,
    Unavailable,
    Unknown,
}

impl ValidationBrokerPosture {
    const fn is_saturated(self) -> bool {
        matches!(self, Self::Saturated | Self::StaleSlots | Self::Unavailable)
    }
}

/// Dimension status used by the saturation summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionStatus {
    Green,
    Yellow,
    Red,
    Unknown,
}

/// Advisory operator posture for the next action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedOperatorPosture {
    ContinueCurrentSwarm,
    NarrowValidationScope,
    BackoffHeavyCargo,
    RepairCoordinationTooling,
    GenerateNewBeads,
    HandoffForHumanTriage,
}

/// Observation window used for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloTimeWindow {
    pub start_utc: String,
    pub end_utc: String,
    pub duration_seconds: u64,
    pub comparison_baseline: String,
}

impl ProgressSloTimeWindow {
    #[must_use]
    pub fn new(
        start_utc: impl Into<String>,
        end_utc: impl Into<String>,
        duration_seconds: u64,
        comparison_baseline: impl Into<String>,
    ) -> Self {
        Self {
            start_utc: start_utc.into(),
            end_utc: end_utc.into(),
            duration_seconds,
            comparison_baseline: comparison_baseline.into(),
        }
    }

    fn is_valid(&self) -> bool {
        self.duration_seconds > 0
            && !self.start_utc.trim().is_empty()
            && !self.end_utc.trim().is_empty()
            && !self.comparison_baseline.trim().is_empty()
    }
}

/// One normalized source row consumed by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloSourceStatus {
    pub source_id: String,
    pub source_class: String,
    pub source_kind: String,
    pub path: Option<String>,
    pub availability: SourceAvailability,
    pub freshness_state: FreshnessState,
    pub observed_at_utc: Option<String>,
    pub source_hash: Option<String>,
    pub authoritative_for: Vec<String>,
    pub redaction_state: RedactionState,
    pub degraded_reasons: Vec<String>,
    pub suppressed_claims: Vec<String>,
}

impl ProgressSloSourceStatus {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        source_id: impl Into<String>,
        source_class: impl Into<String>,
        source_kind: impl Into<String>,
        availability: SourceAvailability,
        freshness_state: FreshnessState,
        redaction_state: RedactionState,
        authoritative_for: Vec<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            source_class: source_class.into(),
            source_kind: source_kind.into(),
            path: None,
            availability,
            freshness_state,
            observed_at_utc: None,
            source_hash: None,
            authoritative_for,
            redaction_state,
            degraded_reasons: Vec::new(),
            suppressed_claims: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_observed_at(mut self, observed_at_utc: impl Into<String>) -> Self {
        self.observed_at_utc = Some(observed_at_utc.into());
        self
    }

    #[must_use]
    pub fn with_source_hash(mut self, source_hash: impl Into<String>) -> Self {
        self.source_hash = Some(source_hash.into());
        self
    }

    #[must_use]
    pub fn with_degraded_reason(mut self, reason: impl Into<String>) -> Self {
        self.degraded_reasons.push(reason.into());
        self
    }

    #[must_use]
    pub fn with_suppressed_claim(mut self, claim: impl Into<String>) -> Self {
        self.suppressed_claims.push(claim.into());
        self
    }

    const fn is_malformed(&self) -> bool {
        self.availability.is_malformed() || self.freshness_state.is_malformed()
    }

    const fn is_degraded(&self) -> bool {
        self.availability.is_degraded() || self.freshness_state.is_degraded()
    }

    const fn is_currently_available(&self) -> bool {
        self.availability.is_available() && self.freshness_state.is_current()
    }
}

/// Aggregate progress counters over the requested time window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloMetrics {
    pub closed_beads: u64,
    pub open_beads: u64,
    pub in_progress_beads: u64,
    pub ready_beads: u64,
    pub dependency_blocked_beads: u64,
    pub commits: u64,
    pub pushed_commits: u64,
    pub closed_with_commit_reference_count: u64,
    pub validation_passes: u64,
    pub validation_failures: u64,
    pub agent_mail_health: AgentMailHealth,
    pub rch_posture: RchPosture,
    pub rch_queue_depth: u64,
    pub rch_queue_saturation_threshold: u64,
    pub validation_broker_posture: ValidationBrokerPosture,
    pub stale_in_progress_candidates: u64,
    pub malformed_source_records: u64,
    pub contradictory_source_records: u64,
}

impl Default for ProgressSloMetrics {
    fn default() -> Self {
        Self {
            closed_beads: 0,
            open_beads: 0,
            in_progress_beads: 0,
            ready_beads: 0,
            dependency_blocked_beads: 0,
            commits: 0,
            pushed_commits: 0,
            closed_with_commit_reference_count: 0,
            validation_passes: 0,
            validation_failures: 0,
            agent_mail_health: AgentMailHealth::Unknown,
            rch_posture: RchPosture::Unknown,
            rch_queue_depth: 0,
            rch_queue_saturation_threshold: 1,
            validation_broker_posture: ValidationBrokerPosture::Unknown,
            stale_in_progress_candidates: 0,
            malformed_source_records: 0,
            contradictory_source_records: 0,
        }
    }
}

/// Saturation dimensions in the emitted report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloSaturationSummary {
    pub coordination_saturation: DimensionStatus,
    pub build_saturation: DimensionStatus,
    pub validation_saturation: DimensionStatus,
    pub queue_convergence: DimensionStatus,
    pub recommended_operator_posture: RecommendedOperatorPosture,
}

/// Redaction accounting in the emitted report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloRedactionSummary {
    pub redacted_count: u64,
    pub omitted_count: u64,
    pub unsafe_to_emit_count: u64,
    pub suppressed_claims: Vec<String>,
}

/// Pure evaluator input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSloEvaluationInput {
    pub generated_at: String,
    pub time_window: ProgressSloTimeWindow,
    pub source_statuses: Vec<ProgressSloSourceStatus>,
    pub progress_metrics: ProgressSloMetrics,
}

impl ProgressSloEvaluationInput {
    #[must_use]
    pub fn new(
        generated_at: impl Into<String>,
        time_window: ProgressSloTimeWindow,
        source_statuses: Vec<ProgressSloSourceStatus>,
        progress_metrics: ProgressSloMetrics,
    ) -> Self {
        Self {
            generated_at: generated_at.into(),
            time_window,
            source_statuses,
            progress_metrics,
        }
    }
}

/// Emitted progress SLO report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressSloReport {
    pub schema: String,
    pub generated_at: String,
    pub contract_version: String,
    pub time_window: ProgressSloTimeWindow,
    pub status: ProgressSloStatus,
    pub confidence: f64,
    pub reason_ids: Vec<String>,
    pub source_statuses: Vec<ProgressSloSourceStatus>,
    pub progress_metrics: ProgressSloMetrics,
    pub saturation_summary: ProgressSloSaturationSummary,
    pub redaction_summary: ProgressSloRedactionSummary,
    pub suppressed_claims: Vec<String>,
    pub next_actions: Vec<String>,
}

struct ProgressSloClassification {
    status: ProgressSloStatus,
    reason_ids: BTreeSet<&'static str>,
    suppressed_claims: Vec<String>,
    missing_required_source_count: usize,
    malformed_source_count: u64,
    has_unsafe_redaction: bool,
}

/// Evaluate a normalized progress snapshot without touching live systems.
#[must_use]
pub fn evaluate_progress_slo(input: ProgressSloEvaluationInput) -> ProgressSloReport {
    let mut suppressed_claims = collect_suppressed_claims(&input.source_statuses);
    let redaction_summary = build_redaction_summary(&input.source_statuses, &suppressed_claims);
    let classification = classify_progress_slo(&input, &redaction_summary);

    suppressed_claims.extend(classification.suppressed_claims.iter().cloned());
    suppressed_claims.sort();
    suppressed_claims.dedup();

    let saturation_summary =
        build_saturation_summary(&input.progress_metrics, classification.status);
    let confidence = confidence_for(
        &input,
        classification.status,
        classification.missing_required_source_count,
        classification.malformed_source_count,
        classification.has_unsafe_redaction,
    );
    let next_actions = next_actions_for(classification.status, &saturation_summary);

    ProgressSloReport {
        schema: SWARM_PROGRESS_SLO_SCHEMA.to_string(),
        generated_at: input.generated_at,
        contract_version: SWARM_PROGRESS_SLO_CONTRACT_VERSION.to_string(),
        time_window: input.time_window,
        status: classification.status,
        confidence,
        reason_ids: classification
            .reason_ids
            .into_iter()
            .map(str::to_string)
            .collect(),
        source_statuses: input.source_statuses,
        progress_metrics: input.progress_metrics,
        saturation_summary,
        redaction_summary: ProgressSloRedactionSummary {
            suppressed_claims: suppressed_claims.clone(),
            ..redaction_summary
        },
        suppressed_claims,
        next_actions,
    }
}

fn classify_progress_slo(
    input: &ProgressSloEvaluationInput,
    redaction_summary: &ProgressSloRedactionSummary,
) -> ProgressSloClassification {
    let mut reason_ids = BTreeSet::new();
    let mut suppressed_claims = Vec::new();
    let source_ids = source_id_set(&input.source_statuses);
    let missing_required_sources = missing_sources(REQUIRED_SOURCE_IDS, &source_ids);
    let missing_progress_authority = missing_sources(PROGRESSING_AUTHORITY_SOURCE_IDS, &source_ids);
    let malformed_source_count = input.progress_metrics.malformed_source_records
        + u64_from_usize_saturating(
            input
                .source_statuses
                .iter()
                .filter(|source| source.is_malformed())
                .count(),
        );
    let has_unsafe_redaction = redaction_summary.unsafe_to_emit_count > 0;
    let has_malformed_required_source = input
        .source_statuses
        .iter()
        .any(|source| is_required_source(&source.source_id) && source.is_malformed());
    let has_degraded_progress_authority = input.source_statuses.iter().any(|source| {
        is_progress_authority_source(&source.source_id) && !source.is_currently_available()
    });
    let rch_saturated = input.progress_metrics.rch_posture.is_saturated()
        || input.progress_metrics.rch_queue_depth
            >= input.progress_metrics.rch_queue_saturation_threshold.max(1);
    let validation_saturated = input
        .progress_metrics
        .validation_broker_posture
        .is_saturated();
    let agent_mail_degraded = input.progress_metrics.agent_mail_health.is_degraded()
        || source_is_degraded(&input.source_statuses, "agent_mail_health");

    let status = if !input.time_window.is_valid()
        || input.source_statuses.is_empty()
        || !missing_required_sources.is_empty()
        || !missing_progress_authority.is_empty()
    {
        reason_ids.insert(REASON_MISSING_AUTHORITY);
        suppressed_claims.push("progressing".to_string());
        ProgressSloStatus::InsufficientEvidenceDegraded
    } else if has_malformed_required_source
        || malformed_source_count > 0
        || input.progress_metrics.contradictory_source_records > 0
    {
        reason_ids.insert(REASON_MALFORMED_SOURCE);
        suppressed_claims.push("progressing".to_string());
        ProgressSloStatus::MalformedSourceDegraded
    } else if has_degraded_progress_authority || has_unsafe_redaction {
        reason_ids.insert(REASON_MISSING_AUTHORITY);
        suppressed_claims.push("progressing".to_string());
        ProgressSloStatus::InsufficientEvidenceDegraded
    } else if agent_mail_degraded {
        reason_ids.insert(REASON_AGENT_MAIL_DEGRADED);
        suppressed_claims.push("coordination_green".to_string());
        ProgressSloStatus::CoordinationDegraded
    } else if rch_saturated || validation_saturated {
        if rch_saturated {
            reason_ids.insert(REASON_RCH_SATURATED);
        }
        if validation_saturated {
            reason_ids.insert(REASON_VALIDATION_BROKER_SATURATED);
        }
        suppressed_claims.push("build_capacity_green".to_string());
        ProgressSloStatus::BuildSaturated
    } else if input.progress_metrics.open_beads == 0
        && input.progress_metrics.in_progress_beads == 0
        && input.progress_metrics.ready_beads == 0
    {
        reason_ids.insert(REASON_CONVERGED_NO_OPEN_WORK);
        ProgressSloStatus::ConvergedNoOpenWork
    } else if input.progress_metrics.stale_in_progress_candidates > 0 {
        reason_ids.insert(REASON_STALE_IN_PROGRESS);
        suppressed_claims.push("progressing".to_string());
        ProgressSloStatus::Stalled
    } else if has_useful_progress(&input.progress_metrics) {
        if input.progress_metrics.closed_beads > 0 {
            reason_ids.insert(REASON_BEAD_CLOSEOUT);
        }
        if input.progress_metrics.commits > 0 || input.progress_metrics.pushed_commits > 0 {
            reason_ids.insert(REASON_GIT_COMMIT_DELTA);
        }
        ProgressSloStatus::Progressing
    } else if input.progress_metrics.ready_beads == 0 {
        reason_ids.insert(REASON_NO_READY_WORK);
        ProgressSloStatus::QuietBlocked
    } else {
        reason_ids.insert(REASON_STALE_IN_PROGRESS);
        suppressed_claims.push("progressing".to_string());
        ProgressSloStatus::Stalled
    };

    suppressed_claims.sort();
    suppressed_claims.dedup();

    ProgressSloClassification {
        status,
        reason_ids,
        suppressed_claims,
        missing_required_source_count: missing_required_sources.len(),
        malformed_source_count,
        has_unsafe_redaction,
    }
}

fn source_id_set(source_statuses: &[ProgressSloSourceStatus]) -> BTreeSet<&str> {
    source_statuses
        .iter()
        .map(|source| source.source_id.as_str())
        .collect()
}

fn missing_sources(required: &[&str], available: &BTreeSet<&str>) -> Vec<String> {
    required
        .iter()
        .filter(|source_id| !available.contains(**source_id))
        .map(|source_id| (*source_id).to_string())
        .collect()
}

fn is_required_source(source_id: &str) -> bool {
    REQUIRED_SOURCE_IDS.contains(&source_id)
}

fn is_progress_authority_source(source_id: &str) -> bool {
    PROGRESSING_AUTHORITY_SOURCE_IDS.contains(&source_id)
}

fn source_is_degraded(source_statuses: &[ProgressSloSourceStatus], source_id: &str) -> bool {
    source_statuses
        .iter()
        .find(|source| source.source_id == source_id)
        .is_some_and(ProgressSloSourceStatus::is_degraded)
}

const fn has_useful_progress(metrics: &ProgressSloMetrics) -> bool {
    metrics.closed_with_commit_reference_count > 0
        || (metrics.closed_beads > 0 && (metrics.commits > 0 || metrics.validation_passes > 0))
        || (metrics.commits > 0 && metrics.pushed_commits > 0)
}

fn collect_suppressed_claims(source_statuses: &[ProgressSloSourceStatus]) -> Vec<String> {
    let mut claims: Vec<String> = source_statuses
        .iter()
        .flat_map(|source| source.suppressed_claims.iter().cloned())
        .collect();
    claims.sort();
    claims.dedup();
    claims
}

fn build_redaction_summary(
    source_statuses: &[ProgressSloSourceStatus],
    suppressed_claims: &[String],
) -> ProgressSloRedactionSummary {
    let mut summary = ProgressSloRedactionSummary {
        redacted_count: 0,
        omitted_count: 0,
        unsafe_to_emit_count: 0,
        suppressed_claims: suppressed_claims.to_vec(),
    };

    for source in source_statuses {
        match source.redaction_state {
            RedactionState::None => {}
            RedactionState::Redacted => summary.redacted_count += 1,
            RedactionState::SensitiveOmitted => summary.omitted_count += 1,
            RedactionState::UnsafeToEmit => summary.unsafe_to_emit_count += 1,
        }
    }

    summary.suppressed_claims.sort();
    summary.suppressed_claims.dedup();
    summary
}

fn build_saturation_summary(
    metrics: &ProgressSloMetrics,
    status: ProgressSloStatus,
) -> ProgressSloSaturationSummary {
    let coordination_saturation = match metrics.agent_mail_health {
        AgentMailHealth::Green => DimensionStatus::Green,
        AgentMailHealth::Yellow => DimensionStatus::Yellow,
        AgentMailHealth::Unknown => DimensionStatus::Unknown,
        AgentMailHealth::Red | AgentMailHealth::Corrupt | AgentMailHealth::Unavailable => {
            DimensionStatus::Red
        }
    };

    let build_saturation = match metrics.rch_posture {
        RchPosture::Green => DimensionStatus::Green,
        RchPosture::Queueing => DimensionStatus::Yellow,
        RchPosture::Unknown => DimensionStatus::Unknown,
        RchPosture::Saturated | RchPosture::FailOpenLocalRisk | RchPosture::Unavailable => {
            DimensionStatus::Red
        }
    };

    let validation_saturation = match metrics.validation_broker_posture {
        ValidationBrokerPosture::Green => DimensionStatus::Green,
        ValidationBrokerPosture::Queueing => DimensionStatus::Yellow,
        ValidationBrokerPosture::Unknown => DimensionStatus::Unknown,
        ValidationBrokerPosture::Saturated
        | ValidationBrokerPosture::StaleSlots
        | ValidationBrokerPosture::Unavailable => DimensionStatus::Red,
    };

    let queue_convergence =
        if metrics.open_beads == 0 && metrics.in_progress_beads == 0 && metrics.ready_beads == 0 {
            DimensionStatus::Green
        } else if metrics.ready_beads == 0 || metrics.stale_in_progress_candidates > 0 {
            DimensionStatus::Yellow
        } else {
            DimensionStatus::Green
        };

    let recommended_operator_posture = match status {
        ProgressSloStatus::Progressing => RecommendedOperatorPosture::ContinueCurrentSwarm,
        ProgressSloStatus::QuietBlocked | ProgressSloStatus::ConvergedNoOpenWork => {
            RecommendedOperatorPosture::GenerateNewBeads
        }
        ProgressSloStatus::CoordinationDegraded => {
            RecommendedOperatorPosture::RepairCoordinationTooling
        }
        ProgressSloStatus::BuildSaturated => {
            if validation_saturation == DimensionStatus::Red {
                RecommendedOperatorPosture::NarrowValidationScope
            } else {
                RecommendedOperatorPosture::BackoffHeavyCargo
            }
        }
        ProgressSloStatus::Stalled
        | ProgressSloStatus::MalformedSourceDegraded
        | ProgressSloStatus::InsufficientEvidenceDegraded => {
            RecommendedOperatorPosture::HandoffForHumanTriage
        }
    };

    ProgressSloSaturationSummary {
        coordination_saturation,
        build_saturation,
        validation_saturation,
        queue_convergence,
        recommended_operator_posture,
    }
}

fn confidence_for(
    input: &ProgressSloEvaluationInput,
    status: ProgressSloStatus,
    missing_required_sources: usize,
    malformed_source_count: u64,
    has_unsafe_redaction: bool,
) -> f64 {
    if input.source_statuses.is_empty() {
        return 0.0;
    }

    let available_current = input
        .source_statuses
        .iter()
        .filter(|source| source.is_currently_available())
        .count();
    let coverage = f64_from_usize_saturating(available_current)
        / f64_from_usize_saturating(input.source_statuses.len());
    let base = match status {
        ProgressSloStatus::Progressing | ProgressSloStatus::ConvergedNoOpenWork => 0.92,
        ProgressSloStatus::QuietBlocked | ProgressSloStatus::BuildSaturated => 0.82,
        ProgressSloStatus::CoordinationDegraded | ProgressSloStatus::Stalled => 0.76,
        ProgressSloStatus::MalformedSourceDegraded
        | ProgressSloStatus::InsufficientEvidenceDegraded => 0.54,
    };
    let mut confidence = base * coverage;
    confidence = f64_from_usize_saturating(missing_required_sources).mul_add(-0.08, confidence);
    confidence = f64_from_u64_saturating(malformed_source_count).mul_add(-0.04, confidence);
    if has_unsafe_redaction {
        confidence -= 0.2;
    }
    confidence.clamp(0.0, 0.99)
}

fn u64_from_usize_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn f64_from_usize_saturating(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn f64_from_u64_saturating(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn next_actions_for(
    status: ProgressSloStatus,
    saturation_summary: &ProgressSloSaturationSummary,
) -> Vec<String> {
    let mut actions = Vec::new();
    match status {
        ProgressSloStatus::Progressing => {
            actions.push("continue_current_swarm".to_string());
        }
        ProgressSloStatus::QuietBlocked => {
            actions.push("inspect_dependency_blockers".to_string());
            actions.push("generate_new_beads_if_backlog_is_empty".to_string());
        }
        ProgressSloStatus::CoordinationDegraded => {
            actions.push("repair_coordination_tooling".to_string());
            actions.push("use_beads_soft_locks_until_agent_mail_recovers".to_string());
        }
        ProgressSloStatus::BuildSaturated => {
            if saturation_summary.validation_saturation == DimensionStatus::Red {
                actions.push("narrow_validation_scope".to_string());
            }
            actions.push("backoff_heavy_cargo".to_string());
        }
        ProgressSloStatus::Stalled => {
            actions.push("reclaim_or_reopen_stale_in_progress_beads".to_string());
            actions.push("reduce_scope_to_finishable_slice".to_string());
        }
        ProgressSloStatus::ConvergedNoOpenWork => {
            actions.push("generate_new_beads".to_string());
            actions.push("run_closeout_gate".to_string());
        }
        ProgressSloStatus::MalformedSourceDegraded => {
            actions.push("repair_progress_slo_source_artifact".to_string());
        }
        ProgressSloStatus::InsufficientEvidenceDegraded => {
            actions.push("provide_required_progress_sources".to_string());
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::{
        AgentMailHealth, DimensionStatus, FreshnessState, ProgressSloEvaluationInput,
        ProgressSloMetrics, ProgressSloSourceStatus, ProgressSloStatus, ProgressSloTimeWindow,
        REASON_AGENT_MAIL_DEGRADED, REASON_BEAD_CLOSEOUT, REASON_CONVERGED_NO_OPEN_WORK,
        REASON_MALFORMED_SOURCE, REASON_MISSING_AUTHORITY, REASON_NO_READY_WORK,
        REASON_RCH_SATURATED, REASON_STALE_IN_PROGRESS, REASON_VALIDATION_BROKER_SATURATED,
        RchPosture, RecommendedOperatorPosture, RedactionState, SWARM_PROGRESS_SLO_SCHEMA,
        SourceAvailability, ValidationBrokerPosture, evaluate_progress_slo,
    };

    fn window() -> ProgressSloTimeWindow {
        ProgressSloTimeWindow::new(
            "2026-05-15T02:00:00Z",
            "2026-05-15T03:00:00Z",
            3600,
            "operator_requested_window",
        )
    }

    fn source(id: &str) -> ProgressSloSourceStatus {
        ProgressSloSourceStatus::new(
            id,
            source_class_for(id),
            source_kind_for(id),
            SourceAvailability::Available,
            FreshnessState::Current,
            RedactionState::None,
            vec![format!("{id}_authority")],
        )
        .with_path(format!("evidence/{id}.json"))
        .with_observed_at("2026-05-15T03:00:00Z")
        .with_source_hash(format!("sha256-{id}"))
    }

    fn source_class_for(id: &str) -> &'static str {
        match id {
            "beads_active_delta" | "beads_closed_delta" => "beads_active_closed_delta",
            "git_commit_delta" => "git_commit_delta",
            "rch_posture" | "validation_broker_posture" => "rch_and_validation_broker_posture",
            "agent_mail_health" => "agent_mail_health",
            "operator_runpack_summary"
            | "swarm_autopilot_summary"
            | "context_intelligence_summary" => "runpack_autopilot_context_summaries",
            "operator_time_window" => "operator_provided_time_window",
            _ => "unknown",
        }
    }

    fn source_kind_for(id: &str) -> &'static str {
        match id {
            "beads_active_delta" | "beads_closed_delta" => "beads",
            "git_commit_delta" => "git",
            "rch_posture" => "rch",
            "validation_broker_posture" => "validation_broker",
            "agent_mail_health" => "agent_mail",
            "operator_runpack_summary" => "runpack",
            "swarm_autopilot_summary" => "autopilot",
            "context_intelligence_summary" => "context_intelligence",
            "operator_time_window" => "operator",
            _ => "unknown",
        }
    }

    fn all_sources() -> Vec<ProgressSloSourceStatus> {
        [
            "beads_active_delta",
            "beads_closed_delta",
            "git_commit_delta",
            "rch_posture",
            "validation_broker_posture",
            "agent_mail_health",
            "operator_runpack_summary",
            "swarm_autopilot_summary",
            "context_intelligence_summary",
            "operator_time_window",
        ]
        .into_iter()
        .map(source)
        .collect()
    }

    fn healthy_metrics() -> ProgressSloMetrics {
        ProgressSloMetrics {
            closed_beads: 2,
            open_beads: 8,
            in_progress_beads: 1,
            ready_beads: 3,
            dependency_blocked_beads: 4,
            commits: 2,
            pushed_commits: 2,
            closed_with_commit_reference_count: 2,
            validation_passes: 3,
            validation_failures: 0,
            agent_mail_health: AgentMailHealth::Green,
            rch_posture: RchPosture::Green,
            rch_queue_depth: 0,
            rch_queue_saturation_threshold: 10,
            validation_broker_posture: ValidationBrokerPosture::Green,
            stale_in_progress_candidates: 0,
            malformed_source_records: 0,
            contradictory_source_records: 0,
        }
    }

    fn evaluate(metrics: ProgressSloMetrics) -> super::ProgressSloReport {
        evaluate_progress_slo(ProgressSloEvaluationInput::new(
            "2026-05-15T03:00:00Z",
            window(),
            all_sources(),
            metrics,
        ))
    }

    #[test]
    fn healthy_closeout_and_commit_delta_reports_progressing() {
        let report = evaluate(healthy_metrics());

        assert_eq!(report.schema, SWARM_PROGRESS_SLO_SCHEMA);
        assert_eq!(report.status, ProgressSloStatus::Progressing);
        assert!(report.confidence > 0.9);
        assert!(
            report
                .reason_ids
                .iter()
                .any(|reason| reason == REASON_BEAD_CLOSEOUT)
        );
        assert!(report.progress_metrics.closed_with_commit_reference_count > 0);
        assert_eq!(
            report.saturation_summary.recommended_operator_posture,
            RecommendedOperatorPosture::ContinueCurrentSwarm
        );
        assert!(report.suppressed_claims.is_empty());
    }

    #[test]
    fn no_open_or_in_progress_work_reports_converged() {
        let report = evaluate(ProgressSloMetrics {
            closed_beads: 0,
            open_beads: 0,
            in_progress_beads: 0,
            ready_beads: 0,
            commits: 0,
            pushed_commits: 0,
            closed_with_commit_reference_count: 0,
            ..healthy_metrics()
        });

        assert_eq!(report.status, ProgressSloStatus::ConvergedNoOpenWork);
        assert!(
            report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_CONVERGED_NO_OPEN_WORK })
        );
        assert_eq!(
            report.saturation_summary.queue_convergence,
            DimensionStatus::Green
        );
        assert!(
            report
                .next_actions
                .iter()
                .any(|action| action == "generate_new_beads")
        );
    }

    #[test]
    fn no_ready_work_with_open_backlog_reports_quiet_blocked() {
        let report = evaluate(ProgressSloMetrics {
            closed_beads: 0,
            open_beads: 5,
            in_progress_beads: 0,
            ready_beads: 0,
            commits: 0,
            pushed_commits: 0,
            closed_with_commit_reference_count: 0,
            ..healthy_metrics()
        });

        assert_eq!(report.status, ProgressSloStatus::QuietBlocked);
        assert!(
            report
                .reason_ids
                .iter()
                .any(|reason| reason == REASON_NO_READY_WORK)
        );
        assert!(
            report
                .next_actions
                .iter()
                .any(|action| { action == "inspect_dependency_blockers" })
        );
    }

    #[test]
    fn stale_in_progress_without_progress_reports_stalled() {
        let report = evaluate(ProgressSloMetrics {
            closed_beads: 0,
            open_beads: 6,
            in_progress_beads: 3,
            ready_beads: 2,
            commits: 0,
            pushed_commits: 0,
            closed_with_commit_reference_count: 0,
            stale_in_progress_candidates: 2,
            ..healthy_metrics()
        });

        assert_eq!(report.status, ProgressSloStatus::Stalled);
        assert!(
            report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_STALE_IN_PROGRESS })
        );
        assert!(
            report
                .suppressed_claims
                .iter()
                .any(|claim| claim == "progressing")
        );
    }

    #[test]
    fn corrupt_agent_mail_reports_coordination_degraded() {
        let report = evaluate(ProgressSloMetrics {
            agent_mail_health: AgentMailHealth::Corrupt,
            ..healthy_metrics()
        });

        assert_eq!(report.status, ProgressSloStatus::CoordinationDegraded);
        assert!(
            report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_AGENT_MAIL_DEGRADED })
        );
        assert_eq!(
            report.saturation_summary.coordination_saturation,
            DimensionStatus::Red
        );
        assert_eq!(
            report.saturation_summary.recommended_operator_posture,
            RecommendedOperatorPosture::RepairCoordinationTooling
        );
    }

    #[test]
    fn rch_queue_or_validation_saturation_reports_build_saturated() {
        let rch_report = evaluate(ProgressSloMetrics {
            rch_posture: RchPosture::Queueing,
            rch_queue_depth: 12,
            rch_queue_saturation_threshold: 10,
            ..healthy_metrics()
        });

        assert_eq!(rch_report.status, ProgressSloStatus::BuildSaturated);
        assert!(
            rch_report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_RCH_SATURATED })
        );
        assert_eq!(
            rch_report.saturation_summary.recommended_operator_posture,
            RecommendedOperatorPosture::BackoffHeavyCargo
        );

        let validation_report = evaluate(ProgressSloMetrics {
            validation_broker_posture: ValidationBrokerPosture::Saturated,
            ..healthy_metrics()
        });

        assert_eq!(validation_report.status, ProgressSloStatus::BuildSaturated);
        assert!(
            validation_report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_VALIDATION_BROKER_SATURATED })
        );
        assert_eq!(
            validation_report
                .saturation_summary
                .recommended_operator_posture,
            RecommendedOperatorPosture::NarrowValidationScope
        );
    }

    #[test]
    fn malformed_or_contradictory_sources_fail_closed() {
        let mut sources = all_sources();
        if let Some(source) = sources
            .iter_mut()
            .find(|source| source.source_id == "beads_active_delta")
        {
            source.availability = SourceAvailability::Malformed;
            source
                .degraded_reasons
                .push("invalid_beads_jsonl".to_string());
        }

        let malformed_report = evaluate_progress_slo(ProgressSloEvaluationInput::new(
            "2026-05-15T03:00:00Z",
            window(),
            sources,
            healthy_metrics(),
        ));

        assert_eq!(
            malformed_report.status,
            ProgressSloStatus::MalformedSourceDegraded
        );
        assert!(
            malformed_report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_MALFORMED_SOURCE })
        );
        assert!(
            malformed_report
                .suppressed_claims
                .iter()
                .any(|claim| { claim == "progressing" })
        );

        let contradictory_report = evaluate(ProgressSloMetrics {
            contradictory_source_records: 1,
            ..healthy_metrics()
        });

        assert_eq!(
            contradictory_report.status,
            ProgressSloStatus::MalformedSourceDegraded
        );
    }

    #[test]
    fn missing_stale_or_unsafe_authority_degrades_without_progressing() {
        let mut missing_sources = all_sources();
        missing_sources.retain(|source| source.source_id != "git_commit_delta");
        let missing_report = evaluate_progress_slo(ProgressSloEvaluationInput::new(
            "2026-05-15T03:00:00Z",
            window(),
            missing_sources,
            healthy_metrics(),
        ));

        assert_eq!(
            missing_report.status,
            ProgressSloStatus::InsufficientEvidenceDegraded
        );
        assert!(
            missing_report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_MISSING_AUTHORITY })
        );
        assert!(
            missing_report
                .suppressed_claims
                .iter()
                .any(|claim| { claim == "progressing" })
        );

        let mut stale_sources = all_sources();
        if let Some(source) = stale_sources
            .iter_mut()
            .find(|source| source.source_id == "git_commit_delta")
        {
            source.freshness_state = FreshnessState::Stale;
            source
                .degraded_reasons
                .push("git_delta_outside_window".to_string());
        }
        let stale_report = evaluate_progress_slo(ProgressSloEvaluationInput::new(
            "2026-05-15T03:00:00Z",
            window(),
            stale_sources,
            healthy_metrics(),
        ));

        assert_eq!(
            stale_report.status,
            ProgressSloStatus::InsufficientEvidenceDegraded
        );
        assert!(
            stale_report
                .reason_ids
                .iter()
                .any(|reason| { reason == REASON_MISSING_AUTHORITY })
        );
        assert!(
            stale_report
                .suppressed_claims
                .iter()
                .any(|claim| { claim == "progressing" })
        );

        let mut unsafe_sources = all_sources();
        if let Some(source) = unsafe_sources
            .iter_mut()
            .find(|source| source.source_id == "git_commit_delta")
        {
            source.redaction_state = RedactionState::UnsafeToEmit;
        }
        let unsafe_report = evaluate_progress_slo(ProgressSloEvaluationInput::new(
            "2026-05-15T03:00:00Z",
            window(),
            unsafe_sources,
            healthy_metrics(),
        ));

        assert_eq!(
            unsafe_report.status,
            ProgressSloStatus::InsufficientEvidenceDegraded
        );
        assert_eq!(unsafe_report.redaction_summary.unsafe_to_emit_count, 1);
        assert!(unsafe_report.confidence < missing_report.confidence);
    }
}
