//! Anomalous on-chain activity detection (issue #124).
//!
//! Static thresholds cannot see the attacks that matter most on a bridge or a
//! payment channel, because the attack is usually a *deviation from that
//! contract's own normal*, not a number above some fixed line. A contract doing
//! 40 invocations a minute that suddenly does 40 000 is being drained; a
//! contract that always does 40 000 is just busy. Handing both to Prometheus
//! leaves the honest one alarm-fatigued and the draining one unnoticed.
//!
//! This module adds the other half of the alerting: a baseline learned from the
//! metric's own recent history, and a robust score for how far the newest sample
//! sits from it. The same rules run in two places:
//!
//! * as Prometheus alert rules in `monitoring/alert-rules.yml`, for the live
//!   stack, and
//! * as `stellar-toolkit monitoring anomalies --input <samples.json>`, for CI
//!   and for replaying a sample window from the command line.
//!
//! Keeping one catalogue of rules in Rust means the check a pull request runs
//! and the rule that pages an operator agree on names, thresholds and severity.
//!
//! # Why the median and the MAD
//!
//! A mean and a standard deviation are the usual choice and they are the wrong
//! one here: both are dragged around by the very outliers being hunted, so one
//! large transfer inflates the deviation and hides the next nine. The median and
//! the median absolute deviation (MAD) have a breakdown point near 50%: up to
//! half the window can be garbage before the baseline moves.
//!
//! The score is the robust z:
//!
//! ```text
//! z = (observed - median) / (1.4826 * MAD)
//! ```
//!
//! # The flat-baseline trap
//!
//! On a perfectly flat baseline the MAD is zero, and every deviation would score
//! as infinitely anomalous — a series of `0, 0, 0, …, 0` would alert on a single
//! failure. The dispersion is therefore floored at
//! `max(min_dispersion, dispersion_ratio × |median|)`, so a metric that is
//! usually zero needs a *proportionally* large jump before it fires, and a
//! metric measured in stroops is scored against its own magnitude. Both the
//! floor and the ratio are configurable, and both are tested.

use crate::monitoring_dashboard::AlertSeverity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// Samples required before a baseline is trusted. Below this the detector says
/// so instead of guessing: a two-sample baseline is noise with a decimal point.
pub const DEFAULT_MIN_SAMPLES: usize = 12;

/// How many of the most recent samples form the baseline.
pub const DEFAULT_BASELINE_WINDOW: usize = 96;

/// Lowest dispersion used when the MAD is zero.
pub const DEFAULT_MIN_DISPERSION: f64 = 1.0;

/// Fraction of the baseline median added to the dispersion floor, so a metric
/// measured in stroops is scored against its own scale.
pub const DEFAULT_DISPERSION_RATIO: f64 = 0.01;

/// Scale factor that makes the MAD comparable to a standard deviation for
/// normally distributed data.
pub const MAD_SCALE: f64 = 1.4826;

/// Which deviation from the baseline is interesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Only a spike matters: value movement, failures, replays.
    Above,
    /// Only a drop matters: senders, remaining TTL, health.
    Below,
    /// Either direction.
    Both,
}

impl Direction {
    /// True when `z` is anomalous for this direction.
    #[must_use]
    pub fn triggers(&self, z: f64, threshold: f64) -> bool {
        match self {
            Direction::Above => z >= threshold,
            Direction::Below => z <= -threshold,
            Direction::Both => z.abs() >= threshold,
        }
    }

    /// How the direction reads in a sentence.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Direction::Above => "above",
            Direction::Below => "below",
            Direction::Both => "either side of",
        }
    }
}

/// One metric to watch, and how far from its baseline counts as anomalous.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyRule {
    /// Normalised metric name (see [`normalize_metric`]).
    pub metric: String,
    pub direction: Direction,
    /// Robust z that has to be reached before the rule fires.
    pub threshold: f64,
    /// Severity attached to a firing rule.
    pub severity: AlertSeverity,
    /// What a firing rule means, in operator terms.
    pub description: String,
}

impl AnomalyRule {
    pub fn new(
        metric: impl Into<String>,
        direction: Direction,
        threshold: f64,
        severity: AlertSeverity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            metric: metric.into(),
            direction,
            threshold,
            severity,
            description: description.into(),
        }
    }
}

/// The rules the toolkit ships with, mirroring `monitoring/alert-rules.yml`.
///
/// The names are normalized, so the Prometheus series
/// `stellar_contract_invocations_total` matches the rule
/// `contract_invocations`.
#[must_use]
pub fn catalog() -> Vec<AnomalyRule> {
    vec![
        AnomalyRule::new(
            "contract_invocations",
            Direction::Above,
            4.0,
            AlertSeverity::Warning,
            "invocation burst far above this contract's own baseline — possible spam or a bot",
        ),
        AnomalyRule::new(
            "contract_failed_invocations",
            Direction::Above,
            4.0,
            AlertSeverity::Warning,
            "failed invocations spiking above baseline — a caller is retrying a call that no longer succeeds",
        ),
        AnomalyRule::new(
            "contract_auth_failures",
            Direction::Above,
            3.5,
            AlertSeverity::Critical,
            "authentication failures spiking — someone is guessing authorisations",
        ),
        AnomalyRule::new(
            "contract_outflow_stroops",
            Direction::Above,
            4.0,
            AlertSeverity::Critical,
            "value leaving the contract far above baseline — drain in progress",
        ),
        AnomalyRule::new(
            "bridge_pause_events",
            Direction::Above,
            3.0,
            AlertSeverity::Critical,
            "pause events above baseline — the bridge is being taken down repeatedly",
        ),
        AnomalyRule::new(
            "nonce_replays",
            Direction::Above,
            3.0,
            AlertSeverity::Critical,
            "consumed-nonce replays above baseline — a signed transfer is being re-presented",
        ),
        AnomalyRule::new(
            "distinct_senders",
            Direction::Below,
            3.5,
            AlertSeverity::Warning,
            "unique senders collapsing — activity has concentrated into very few accounts",
        ),
        AnomalyRule::new(
            "contract_entry_ttl_min",
            Direction::Below,
            3.5,
            AlertSeverity::Warning,
            "shortest remaining entry TTL dropping — storage is heading for archival",
        ),
    ]
}

/// Strip the exporter's decoration so one rule matches every spelling of a
/// metric: `stellar_contract_invocations_total` becomes `contract_invocations`.
#[must_use]
pub fn normalize_metric(name: &str) -> String {
    let name = name.strip_prefix("stellar_").unwrap_or(name);
    name.strip_suffix("_total").unwrap_or(name).to_string()
}

/// Tunables for the detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub min_samples: usize,
    pub baseline_window: usize,
    pub min_dispersion: f64,
    pub dispersion_ratio: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            min_samples: DEFAULT_MIN_SAMPLES,
            baseline_window: DEFAULT_BASELINE_WINDOW,
            min_dispersion: DEFAULT_MIN_DISPERSION,
            dispersion_ratio: DEFAULT_DISPERSION_RATIO,
        }
    }
}

/// A metric's own recent history: chronological, oldest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Series {
    pub metric: String,
    pub values: Vec<f64>,
}

impl Series {
    pub fn new(metric: impl Into<String>, values: Vec<f64>) -> Self {
        Self {
            metric: metric.into(),
            values,
        }
    }

    /// Build a rate series out of a monotonic counter, so a counter exported by
    /// Prometheus can be fed to a rule that reasons about per-interval changes.
    ///
    /// A counter never decreases; a decrease means the exporter restarted, and
    /// that interval is recorded as a drop to zero rather than a negative rate
    /// that would drag the baseline down.
    pub fn from_counter(metric: impl Into<String>, counters: &[f64]) -> Self {
        let mut values = Vec::with_capacity(counters.len().saturating_sub(1));
        for pair in counters.windows(2) {
            let (previous, current) = (pair[0], pair[1]);
            values.push(if current >= previous {
                current - previous
            } else {
                current
            });
        }
        Self::new(metric, values)
    }

    /// The sample the alerting path scores: the newest observation.
    #[must_use]
    pub fn latest(&self) -> Option<f64> {
        self.values.last().copied()
    }
}

/// Median plus MAD over a window, with the sample count it was built from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub median: f64,
    /// Raw median absolute deviation (not scaled).
    pub mad: f64,
    pub samples: usize,
}

impl Baseline {
    /// Learn a baseline from `window`, ignoring non-finite samples.
    #[must_use]
    pub fn learn(window: &[f64]) -> Self {
        let mut finite: Vec<f64> = window.iter().copied().filter(|v| v.is_finite()).collect();
        if finite.is_empty() {
            return Self {
                median: 0.0,
                mad: 0.0,
                samples: 0,
            };
        }
        let median = median_of(&mut finite);
        let deviations: Vec<f64> = finite.iter().map(|v| (v - median).abs()).collect();
        let mut deviations = deviations;
        let mad = median_of(&mut deviations);
        Self {
            median,
            mad,
            samples: finite.len(),
        }
    }

    /// Dispersion used in the score, floored so a flat baseline is not
    /// infinitely sensitive.
    #[must_use]
    pub fn dispersion(&self, config: &DetectorConfig) -> f64 {
        let scaled = MAD_SCALE * self.mad;
        let floor = config
            .min_dispersion
            .max(self.median.abs() * config.dispersion_ratio);
        scaled.max(floor).max(f64::MIN_POSITIVE)
    }

    /// Robust z-score of `value` against this baseline.
    #[must_use]
    pub fn robust_z(&self, value: f64, config: &DetectorConfig) -> f64 {
        (value - self.median) / self.dispersion(config)
    }
}

/// Median of a non-empty slice; `1.0` for an empty one (never used in scoring).
fn median_of(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        f64::midpoint(values[mid - 1], values[mid])
    }
}

/// What the detector concluded about one metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricVerdict {
    pub metric: String,
    pub observed: f64,
    pub baseline: Baseline,
    /// Robust z of the newest sample. `None` when there was no baseline to
    /// score against, or the sample was not a finite number.
    pub z: Option<f64>,
    /// Set only when a rule fired.
    pub severity: Option<AlertSeverity>,
    /// Rule that fired, if any.
    pub rule: Option<String>,
    /// Human-readable explanation, always set.
    pub message: String,
}

impl MetricVerdict {
    #[must_use]
    pub fn fired(&self) -> bool {
        self.severity.is_some()
    }

    #[must_use]
    pub fn is_quiet(&self) -> bool {
        !self.fired()
    }
}

/// The outcome of scoring a whole sample window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub generated_at: String,
    pub config: DetectorConfig,
    pub verdicts: Vec<MetricVerdict>,
    /// Metrics with no matching rule. Reported rather than silently scored
    /// against a default, because a missing rule is a configuration bug.
    pub unchecked_metrics: Vec<String>,
}

impl AnomalyReport {
    #[must_use]
    pub fn fired(&self) -> Vec<&MetricVerdict> {
        self.verdicts.iter().filter(|v| v.fired()).collect()
    }

    #[must_use]
    pub fn quiet(&self) -> Vec<&MetricVerdict> {
        self.verdicts.iter().filter(|v| v.is_quiet()).collect()
    }

    #[must_use]
    pub fn count_of(&self, severity: AlertSeverity) -> usize {
        self.verdicts
            .iter()
            .filter(|v| v.severity.as_ref() == Some(&severity))
            .count()
    }

    /// True when nothing fired at all.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.fired().is_empty()
    }

    /// Highest severity that fired, if anything did.
    pub fn worst_severity(&self) -> Option<AlertSeverity> {
        let mut worst: Option<AlertSeverity> = None;
        for verdict in self.fired() {
            let severity = verdict.severity.clone().unwrap_or(AlertSeverity::Info);
            if severity_rank(&severity) > worst.as_ref().map_or(0, severity_rank) {
                worst = Some(severity);
            }
        }
        worst
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "anomaly sweep ({} metric(s), baseline {} sample(s), min {} sample(s))",
            self.verdicts.len() + self.unchecked_metrics.len(),
            self.config.baseline_window,
            self.config.min_samples
        );

        for verdict in &self.verdicts {
            let tag = match &verdict.severity {
                Some(AlertSeverity::Critical) => "CRIT",
                Some(AlertSeverity::Warning) => "WARN",
                Some(AlertSeverity::Info) => "INFO",
                None => "ok  ",
            };
            let _ = writeln!(out, "  {tag}  {}", verdict.message);
        }

        for metric in &self.unchecked_metrics {
            let _ = writeln!(
                out,
                "  skip  {metric}: no rule — add one to the catalogue if this metric matters"
            );
        }

        let _ = writeln!(
            out,
            "{} critical, {} warning, {} sampled metric(s) within baseline",
            self.count_of(AlertSeverity::Critical),
            self.count_of(AlertSeverity::Warning),
            self.quiet().len()
        );
        out
    }
}

/// Severity ordering used for `worst_severity` and `--fail-on`.
#[must_use]
pub fn severity_rank(severity: &AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Info => 1,
        AlertSeverity::Warning => 2,
        AlertSeverity::Critical => 3,
    }
}

/// Scores sample series against the rule catalogue.
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    rules: Vec<AnomalyRule>,
    config: DetectorConfig,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    /// A detector with the shipped catalogue and default tunables.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: catalog(),
            config: DetectorConfig::default(),
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: DetectorConfig) -> Self {
        self.config = config;
        self
    }

    /// Replace the catalogue, e.g. with a deployment's own metrics.
    #[must_use]
    pub fn with_rules(mut self, rules: Vec<AnomalyRule>) -> Self {
        self.rules = rules;
        self
    }

    /// Add or override one rule.
    #[must_use]
    pub fn with_rule(mut self, rule: AnomalyRule) -> Self {
        self.rules.retain(|r| r.metric != rule.metric);
        self.rules.push(rule);
        self
    }

    /// Scale every threshold, so a noisy deployment can be de-sensitised without
    /// rewriting the catalogue. A scale of `1.0` changes nothing.
    #[must_use]
    pub fn with_threshold_scale(mut self, scale: f64) -> Self {
        if scale > 0.0 && scale.is_finite() {
            for rule in &mut self.rules {
                rule.threshold *= scale;
            }
        }
        self
    }

    #[must_use]
    pub fn rules(&self) -> &[AnomalyRule] {
        &self.rules
    }

    #[must_use]
    pub fn config(&self) -> &DetectorConfig {
        &self.config
    }

    #[must_use]
    pub fn rule_for(&self, metric: &str) -> Option<&AnomalyRule> {
        let normalized = normalize_metric(metric);
        self.rules.iter().find(|rule| rule.metric == normalized)
    }

    /// Score the newest sample of one series against its own history.
    #[must_use]
    pub fn evaluate(&self, series: &Series) -> MetricVerdict {
        let metric = normalize_metric(&series.metric);
        let rule = self.rule_for(&series.metric);

        let Some(observed) = series.latest() else {
            return MetricVerdict {
                metric,
                observed: f64::NAN,
                baseline: Baseline::learn(&[]),
                z: None,
                severity: None,
                rule: None,
                message: "series is empty, nothing to score".to_string(),
            };
        };

        if !observed.is_finite() {
            return MetricVerdict {
                metric,
                observed,
                baseline: Baseline::learn(&[]),
                z: None,
                severity: None,
                rule: None,
                message: "newest sample is not a finite number".to_string(),
            };
        }

        // Baseline is everything before the sample being scored, capped to the
        // window: scoring a value against itself would hide the spike.
        let history = &series.values[..series.values.len() - 1];
        let start = history.len().saturating_sub(self.config.baseline_window);
        let baseline = Baseline::learn(&history[start..]);
        let trusted = baseline.samples >= self.config.min_samples;
        let z = trusted.then(|| baseline.robust_z(observed, &self.config));

        // A metric with no rule can never fire, whatever its score, so it is
        // reported first rather than disguised as a cold baseline.
        let Some(rule) = rule else {
            let score = match z {
                Some(z) => format!("z {z:.2}"),
                None => format!(
                    "{} sample(s), {} needed for a score",
                    baseline.samples, self.config.min_samples
                ),
            };
            return MetricVerdict {
                metric: metric.clone(),
                observed,
                baseline,
                z,
                severity: None,
                rule: None,
                message: format!(
                    "{metric} = {observed} ({score}); no rule covers this metric, so it is only reported"
                ),
            };
        };

        if !trusted {
            return MetricVerdict {
                metric,
                observed,
                z: None,
                severity: None,
                rule: None,
                message: format!(
                    "{observed} scored against {} sample(s): {} needed before a baseline means anything",
                    baseline.samples, self.config.min_samples
                ),
                baseline,
            };
        }
        let z = z.unwrap_or(0.0);

        let fires = rule.direction.triggers(z, rule.threshold);
        let message = if fires {
            format!(
                "{} = {observed} is {z:.2} robust deviations {} the baseline (median {}, MAD {}, {} sample(s)) — {}",
                metric,
                rule.direction.describe(),
                baseline.median,
                baseline.mad,
                baseline.samples,
                rule.description
            )
        } else {
            format!(
                "{metric} = {observed} (z {z:.2}, threshold {:.1} {} baseline)",
                rule.threshold,
                rule.direction.describe()
            )
        };

        MetricVerdict {
            metric: metric.clone(),
            observed,
            baseline,
            z: Some(z),
            severity: fires.then(|| rule.severity.clone()),
            rule: Some(rule.metric.clone()),
            message,
        }
    }

    /// Score the newest sample of every series, in the order given.
    #[must_use]
    pub fn sweep(&self, series: &[Series]) -> AnomalyReport {
        let mut verdicts = Vec::with_capacity(series.len());
        let mut unchecked = Vec::new();
        for one in series {
            if self.rule_for(&one.metric).is_none() {
                unchecked.push(normalize_metric(&one.metric));
            }
            verdicts.push(self.evaluate(one));
        }
        unchecked.sort();
        unchecked.dedup();

        AnomalyReport {
            generated_at: now_epoch_seconds(),
            config: self.config.clone(),
            verdicts,
            unchecked_metrics: unchecked,
        }
    }
}

fn now_epoch_seconds() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

/// Parse a sample window: a JSON object mapping metric names to chronological
/// sample arrays.
///
/// ```json
/// {
///   "stellar_contract_invocations_total": [10, 12, 11, 13],
///   "stellar_contract_outflow_stroops": [500, 480, 520, 9000]
/// }
/// ```
///
/// A metric whose name ends in `_total` is a Prometheus counter, so its samples
/// are differenced into per-interval rates here rather than by hand. Every other
/// metric is scored as given — including a gauge that happens to rise, which
/// must not be silently turned into rates.
pub fn parse_series(json: &str) -> Result<Vec<Series>> {
    let raw: BTreeMap<String, Vec<f64>> = serde_json::from_str(json)
        .context("sample window is not a JSON object of number arrays")?;

    Ok(raw
        .into_iter()
        .map(|(metric, values)| {
            if is_counter_metric(&metric) {
                Series::from_counter(metric, &values)
            } else {
                Series::new(metric, values)
            }
        })
        .collect())
}

/// Prometheus counter naming: a monotonic `_total` series whose differences are
/// the interesting quantity.
fn is_counter_metric(metric: &str) -> bool {
    metric.ends_with("_total")
}

/// Read and parse a sample window from disk.
pub fn load_series(path: &Path) -> Result<Vec<Series>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading sample window {}", path.display()))?;
    parse_series(&text)
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // the fixtures assert exact values they construct
mod tests {
    use super::*;

    fn steady(value: f64) -> Vec<f64> {
        vec![value; 24]
    }

    fn with_latest(history: &[f64], latest: f64) -> Series {
        let mut values = history.to_vec();
        values.push(latest);
        Series::new("stellar_contract_outflow_stroops", values)
    }

    #[test]
    fn a_flat_series_with_a_flat_continuation_is_quiet() {
        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&with_latest(&steady(500.0), 500.0));
        assert!(verdict.is_quiet(), "{}", verdict.message);
        assert_eq!(verdict.z, Some(0.0));
        assert_eq!(verdict.baseline.median, 500.0);
    }

    #[test]
    fn a_spike_against_a_flat_baseline_fires() {
        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&with_latest(&steady(500.0), 5_000.0));
        assert!(verdict.fired(), "{}", verdict.message);
        assert_eq!(verdict.severity, Some(AlertSeverity::Critical));
        assert_eq!(verdict.rule.as_deref(), Some("contract_outflow_stroops"));
        // The MAD of a flat window is zero, so the score is driven by the
        // dispersion floor and is therefore finite rather than infinite.
        assert!(verdict.z.unwrap().is_finite());
        assert!(verdict.z.unwrap() > 4.0);
    }

    #[test]
    fn the_dispersion_floor_is_what_stops_a_flat_baseline_from_alerting_on_noise() {
        let detector = AnomalyDetector::new();
        // A zero baseline that twitches by one unit: real, but not an incident.
        let verdict = detector.evaluate(&with_latest(&vec![0.0; 30], 1.0));
        assert!(verdict.is_quiet(), "{}", verdict.message);

        // Ten times that is.
        let verdict = detector.evaluate(&with_latest(&vec![0.0; 30], 10.0));
        assert!(verdict.fired(), "{}", verdict.message);
    }

    #[test]
    fn a_steady_series_does_not_alert_on_small_jitter() {
        let detector = AnomalyDetector::new();
        let history: Vec<f64> = (0..30).map(|i| 1_000.0 + (i % 3) as f64).collect();
        let verdict = detector.evaluate(&with_latest(&history, 1_002.0));
        assert!(verdict.is_quiet(), "{}", verdict.message);
    }

    #[test]
    fn the_baseline_ignores_the_sample_being_scored() {
        let detector = AnomalyDetector::new();
        let mut series = Series::new("stellar_contract_invocations_total", steady(10.0));
        series.values.push(9_000.0);
        let verdict = detector.evaluate(&series);
        assert!(verdict.fired());
        // If the outlier were included in the baseline, the MAD would balloon
        // and swallow it.
        assert_eq!(verdict.baseline.median, 10.0);
        assert_eq!(verdict.baseline.mad, 0.0);
    }

    #[test]
    fn a_baseline_with_too_few_samples_is_not_trusted() {
        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&with_latest(&[10.0, 11.0, 10.0], 9_999.0));
        assert!(verdict.is_quiet(), "{}", verdict.message);
        assert!(verdict.z.is_none());
        assert!(verdict
            .message
            .contains("needed before a baseline means anything"));
    }

    #[test]
    fn a_median_baseline_can_absorb_an_outlier_inside_the_window() {
        let detector = AnomalyDetector::new();
        // Four huge transfers inside the window must not raise the bar for the
        // fifth: this is the property a mean/σ baseline does not have.
        let mut history = steady(100.0);
        history[0] = 100_000.0;
        history[1] = 100_000.0;
        history[2] = 100_000.0;
        history[3] = 100_000.0;
        let verdict = detector.evaluate(&with_latest(&history, 50_000.0));
        assert_eq!(verdict.baseline.median, 100.0);
        assert!(verdict.fired(), "{}", verdict.message);
    }

    #[test]
    fn a_drop_fires_only_for_rules_that_watch_for_one() {
        let detector = AnomalyDetector::new();
        // Outflow is an "above" rule: a collapse is not a drain.
        let collapse = detector.evaluate(&with_latest(&steady(500.0), 0.0));
        assert!(collapse.is_quiet(), "{}", collapse.message);

        // Distinct senders is a "below" rule: concentration is the signal.
        let mut series = Series::new("stellar_distinct_senders", steady(2_000.0));
        series.values.push(3.0);
        let verdict = detector.evaluate(&series);
        assert!(verdict.fired(), "{}", verdict.message);
        assert_eq!(verdict.severity, Some(AlertSeverity::Warning));
    }

    #[test]
    fn an_above_rule_ignores_a_rise_within_threshold() {
        let detector = AnomalyDetector::new().with_config(DetectorConfig {
            min_samples: 4,
            ..DetectorConfig::default()
        });
        let rule = AnomalyRule::new(
            "gauge",
            Direction::Above,
            50.0,
            AlertSeverity::Warning,
            "test",
        );
        let detector = detector.with_rules(vec![rule]);
        let series = Series::new("stellar_gauge", vec![100.0, 100.0, 100.0, 100.0, 101.0]);
        let verdict = detector.evaluate(&series);
        assert!(!verdict.fired(), "{}", verdict.message);
        assert!(verdict.z.unwrap() > 0.0);
        // …and the same rise past the threshold does fire.
        let verdict = detector.evaluate(&Series::new(
            "stellar_gauge",
            vec![100.0, 100.0, 100.0, 100.0, 900.0],
        ));
        assert!(verdict.fired(), "{}", verdict.message);
    }

    #[test]
    fn direction_triggers_cover_both_sides() {
        assert!(Direction::Above.triggers(5.0, 4.0));
        assert!(!Direction::Above.triggers(-5.0, 4.0));
        assert!(Direction::Below.triggers(-5.0, 4.0));
        assert!(!Direction::Below.triggers(5.0, 4.0));
        assert!(Direction::Both.triggers(5.0, 4.0));
        assert!(Direction::Both.triggers(-5.0, 4.0));
        assert!(!Direction::Both.triggers(1.0, 4.0));
    }

    #[test]
    fn metric_names_are_normalized_so_one_rule_matches_every_spelling() {
        assert_eq!(
            normalize_metric("stellar_contract_invocations_total"),
            "contract_invocations"
        );
        assert_eq!(
            normalize_metric("contract_invocations"),
            "contract_invocations"
        );

        let detector = AnomalyDetector::new();
        let series = Series::new("stellar_contract_invocations_total", {
            let mut v = steady(10.0);
            v.push(5_000.0);
            v
        });
        let verdict = detector.evaluate(&series);
        assert!(verdict.fired(), "{}", verdict.message);
        assert_eq!(verdict.rule.as_deref(), Some("contract_invocations"));
    }

    #[test]
    fn an_unknown_metric_is_reported_not_scored() {
        let detector = AnomalyDetector::new();
        let report = detector.sweep(&[Series::new("stellar_something_new", vec![1.0, 900.0])]);
        assert_eq!(report.unchecked_metrics, ["something_new"]);
        assert!(report.verdicts[0].is_quiet());
        assert!(report.verdicts[0]
            .message
            .contains("no rule covers this metric"));
        assert!(report.render().contains("no rule"));
    }

    #[test]
    fn a_counter_series_is_differenced_before_scoring() {
        // A counter that climbs steadily, then jumps: the jump is the anomaly,
        // not the absolute value.
        let mut counters: Vec<f64> = (0..30).map(|i| (i * 10) as f64).collect();
        counters.push(counters.last().unwrap() + 5_000.0);
        let series = Series::from_counter("stellar_contract_invocations_total", &counters);
        assert_eq!(series.values.len(), counters.len() - 1);
        assert_eq!(series.latest().unwrap(), 5_000.0);

        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&series);
        assert!(verdict.fired(), "{}", verdict.message);
    }

    #[test]
    fn a_counter_that_resets_is_treated_as_a_drop_to_zero() {
        let series = Series::from_counter("stellar_contract_invocations_total", &[10.0, 20.0, 5.0]);
        assert_eq!(series.values, vec![10.0, 5.0]);
    }

    #[test]
    fn the_sample_window_parser_reads_counters_and_gauges_alike() {
        let json = r#"{
            "stellar_contract_invocations_total": [10, 20, 30],
            "stellar_contract_outflow_stroops": [500, 600, 700]
        }"#;
        let mut series = parse_series(json).unwrap();
        series.sort_by(|a, b| a.metric.cmp(&b.metric));
        assert_eq!(series.len(), 2);

        // The `_total` counter is differenced into rates.
        assert_eq!(series[0].metric, "stellar_contract_invocations_total");
        assert_eq!(series[0].values, vec![10.0, 10.0]);
        // The gauge keeps its samples even though they rise: a rising gauge is
        // not a counter, and differencing it would invent an anomaly.
        assert_eq!(
            series[1].values,
            vec![500.0, 600.0, 700.0],
            "only `_total` metrics are differenced"
        );
    }

    #[test]
    fn the_sample_window_parser_rejects_anything_else() {
        assert!(parse_series("[]").is_err());
        assert!(parse_series(r#"{"metric": "not an array"}"#).is_err());
    }

    #[test]
    fn a_non_finite_sample_is_reported_rather_than_scored() {
        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&with_latest(&steady(1.0), f64::NAN));
        assert!(verdict.is_quiet());
        assert!(verdict.message.contains("not a finite number"));
    }

    #[test]
    fn an_empty_series_is_reported_rather_than_panicking() {
        let detector = AnomalyDetector::new();
        let verdict = detector.evaluate(&Series::new("stellar_contract_outflow_stroops", vec![]));
        assert!(verdict.is_quiet());
        assert!(verdict.message.contains("series is empty"));
    }

    #[test]
    fn a_sweep_reports_every_metric_and_its_worst_severity() {
        let detector = AnomalyDetector::new();
        let report = detector.sweep(&[
            with_latest(&steady(500.0), 500.0),
            with_latest(&steady(500.0), 9_000.0),
            Series::new("stellar_distinct_senders", {
                let mut v = steady(2_000.0);
                v.push(1.0);
                v
            }),
        ]);

        assert_eq!(report.verdicts.len(), 3);
        assert_eq!(report.count_of(AlertSeverity::Critical), 1);
        assert_eq!(report.count_of(AlertSeverity::Warning), 1);
        assert_eq!(report.quiet().len(), 1);
        assert!(!report.is_quiet());
        assert_eq!(report.worst_severity(), Some(AlertSeverity::Critical));
        assert!(!report.generated_at.is_empty());

        let rendered = report.render();
        assert!(rendered.contains("CRIT"));
        assert!(rendered.contains("WARN"));
        assert!(rendered.contains("1 critical, 1 warning, 1 sampled metric(s) within baseline"));
    }

    #[test]
    fn a_quiet_sweep_renders_and_serializes() {
        let detector = AnomalyDetector::new();
        let report = detector.sweep(&[with_latest(&steady(500.0), 501.0)]);
        assert!(report.is_quiet());
        assert_eq!(report.worst_severity(), None);
        assert!(report.render().contains("0 critical, 0 warning"));
        let json = report.to_json();
        assert!(json.contains("contract_outflow_stroops"));
        assert!(json.contains("\"verdicts\""));
        assert!(json.contains("\"generated_at\""));
    }

    #[test]
    fn thresholds_can_be_scaled_without_touching_the_catalogue() {
        let sensitive = AnomalyDetector::new();
        // A flat 500 baseline scores the 5_000 spike at a z in the hundreds, so
        // a scale has to be large to silence it — which is the property: the
        // scale is a raw multiplier, not a percentage.
        let desensitised = AnomalyDetector::new().with_threshold_scale(2_000.0);
        let series = with_latest(&steady(500.0), 5_000.0);
        assert!(sensitive.evaluate(&series).fired());
        assert!(
            desensitised.evaluate(&series).is_quiet(),
            "a x2000 threshold must stop a z of ~900 from firing"
        );
        // A non-positive scale is ignored rather than zeroing every threshold.
        let unchanged = AnomalyDetector::new().with_threshold_scale(0.0);
        assert_eq!(unchanged.rules()[0].threshold, catalog()[0].threshold);
    }

    #[test]
    fn a_rule_can_be_overridden_for_a_deployment_specific_metric() {
        let detector = AnomalyDetector::new().with_rule(AnomalyRule::new(
            "my_custom_metric",
            Direction::Above,
            2.0,
            AlertSeverity::Info,
            "custom",
        ));
        let mut values = steady(1.0);
        values.push(90.0);
        let verdict = detector.evaluate(&Series::new("stellar_my_custom_metric_total", values));
        assert_eq!(verdict.severity, Some(AlertSeverity::Info));
        assert_eq!(detector.rules().len(), catalog().len() + 1);
    }

    #[test]
    fn the_catalogue_matches_the_prometheus_rules() {
        // Names here must line up with `monitoring/alert-rules.yml`; the check is
        // that every rule is normalized and uniquely named.
        let mut names: Vec<String> = catalog().iter().map(|r| r.metric.clone()).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate rule name in the catalogue");
        for rule in catalog() {
            assert_eq!(rule.metric, normalize_metric(&rule.metric));
            assert!(rule.threshold > 0.0);
            assert!(!rule.description.is_empty());
        }
    }

    #[test]
    fn load_series_reads_a_file_and_reports_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("window.json");
        std::fs::write(
            &path,
            r#"{"stellar_contract_invocations_total": [1, 2, 4]}"#,
        )
        .unwrap();
        let series = load_series(&path).unwrap();
        assert_eq!(series.len(), 1);

        let error = load_series(&dir.path().join("absent.json")).unwrap_err();
        assert!(error.to_string().contains("reading sample window"));
    }
}
