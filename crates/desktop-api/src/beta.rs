use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use ts_rs::TS;

pub const BETA_METRICS_FORMAT_VERSION: &str = "0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct BetaMetricsSnapshot {
    pub first_capture_elapsed_ms: Option<u64>,
    pub supported_capture_count: u64,
    pub parsed_capture_count: u64,
    pub completed_session_count: u64,
    pub unclean_session_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct BetaMetricsPreview {
    pub suggested_filename: String,
    pub content: String,
    pub byte_count: u64,
    pub content_sha256: String,
    pub generated_at_unix_ms: u64,
    pub format_version: String,
    pub metrics: BetaMetricsSnapshot,
    pub parse_rate_basis_points: Option<u32>,
    pub crash_free_rate_basis_points: Option<u32>,
}

pub fn build_beta_metrics_preview(
    metrics: BetaMetricsSnapshot,
    generated_at_unix_ms: u64,
) -> Result<BetaMetricsPreview, serde_json::Error> {
    let parse_rate_basis_points = rate_basis_points(
        metrics.parsed_capture_count,
        metrics.supported_capture_count,
    );
    let clean_sessions = metrics
        .completed_session_count
        .saturating_sub(metrics.unclean_session_count);
    let crash_free_rate_basis_points =
        rate_basis_points(clean_sessions, metrics.completed_session_count);
    let document = json!({
        "formatVersion": BETA_METRICS_FORMAT_VERSION,
        "generatedAtUnixMs": generated_at_unix_ms,
        "product": {
            "name": "CodeIsCheap",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
        },
        "privacy": {
            "requestContentIncluded": false,
            "requestIdentifiersIncluded": false,
            "rawCaptureIncluded": false,
            "logsIncluded": false,
            "requestTimestampsIncluded": false,
            "automaticUpload": false,
        },
        "metrics": {
            "firstCaptureElapsedMs": metrics.first_capture_elapsed_ms,
            "supportedCaptureCount": metrics.supported_capture_count,
            "parsedCaptureCount": metrics.parsed_capture_count,
            "parseRateBasisPoints": parse_rate_basis_points,
            "completedSessionCount": metrics.completed_session_count,
            "uncleanSessionCount": metrics.unclean_session_count,
            "crashFreeRateBasisPoints": crash_free_rate_basis_points,
        },
    });
    let mut content = serde_json::to_string_pretty(&document)?;
    content.push('\n');
    let byte_count = u64::try_from(content.len()).unwrap_or(u64::MAX);
    let content_sha256 = format!("{:x}", Sha256::digest(content.as_bytes()));
    Ok(BetaMetricsPreview {
        suggested_filename: format!("codeischeap-beta-metrics-{generated_at_unix_ms}.json"),
        content,
        byte_count,
        content_sha256,
        generated_at_unix_ms,
        format_version: BETA_METRICS_FORMAT_VERSION.to_owned(),
        metrics,
        parse_rate_basis_points,
        crash_free_rate_basis_points,
    })
}

fn rate_basis_points(numerator: u64, denominator: u64) -> Option<u32> {
    if denominator == 0 {
        return None;
    }
    let basis_points = u128::from(numerator)
        .saturating_mul(10_000)
        .checked_div(u128::from(denominator))?
        .min(10_000);
    u32::try_from(basis_points).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn beta_preview_contains_only_aggregate_metrics() {
        let preview = build_beta_metrics_preview(
            BetaMetricsSnapshot {
                first_capture_elapsed_ms: Some(90_000),
                supported_capture_count: 200,
                parsed_capture_count: 196,
                completed_session_count: 400,
                unclean_session_count: 1,
            },
            1_700_000_000_000,
        )
        .expect("preview must encode");
        let document: Value = serde_json::from_str(&preview.content).expect("preview JSON");

        assert_eq!(preview.parse_rate_basis_points, Some(9_800));
        assert_eq!(preview.crash_free_rate_basis_points, Some(9_975));
        assert_eq!(document["privacy"]["requestContentIncluded"], false);
        assert_eq!(document["privacy"]["requestIdentifiersIncluded"], false);
        assert_eq!(document["privacy"]["automaticUpload"], false);
        assert!(document.get("requests").is_none());
        assert!(document.get("diagnostics").is_none());
        assert_eq!(preview.content_sha256.len(), 64);
    }

    #[test]
    fn rates_remain_unknown_without_denominators() {
        let preview = build_beta_metrics_preview(
            BetaMetricsSnapshot {
                first_capture_elapsed_ms: None,
                supported_capture_count: 0,
                parsed_capture_count: 0,
                completed_session_count: 0,
                unclean_session_count: 0,
            },
            1,
        )
        .expect("preview must encode");
        assert_eq!(preview.parse_rate_basis_points, None);
        assert_eq!(preview.crash_free_rate_basis_points, None);
    }
}
