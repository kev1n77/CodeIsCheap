use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CaptureMode, CaptureState, CertificateAuthorityState, CertificatePrivateMaterial,
    CertificateTrust,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct CaptureCompatibility {
    pub code: CaptureCompatibilityCode,
    pub status: CaptureCompatibilityStatus,
    pub confidence: CompatibilityConfidence,
    pub title: String,
    pub summary: String,
    pub recommended_mode: CaptureMode,
    pub action: CompatibilityAction,
    pub steps: Vec<CompatibilityStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCompatibilityCode {
    GatewayReady,
    GatewayUnavailable,
    ProxyBundleUnavailable,
    ProxyUnavailable,
    CertificateMissing,
    CertificateInvalid,
    CertificateTrustRequired,
    CapturePaused,
    ProxyCaptureUnobserved,
    ProxyCaptureObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCompatibilityStatus {
    Ready,
    Attention,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityConfidence {
    High,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityAction {
    None,
    ResumeCapture,
    TrustCertificate,
    UseGateway,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityStep {
    pub id: String,
    pub status: CompatibilityStepStatus,
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStepStatus {
    Pass,
    Attention,
    Blocked,
    Pending,
}

#[must_use]
pub fn diagnose_capture_compatibility(
    capture: &CaptureState,
    proxy_session_event_count: u64,
) -> CaptureCompatibility {
    let steps = compatibility_steps(capture, proxy_session_event_count);
    let summary = diagnostic_summary(capture, proxy_session_event_count);
    CaptureCompatibility {
        code: summary.code,
        status: summary.status,
        confidence: summary.confidence,
        title: summary.title.to_owned(),
        summary: summary.detail.to_owned(),
        recommended_mode: match summary.action {
            CompatibilityAction::UseGateway => CaptureMode::Gateway,
            _ => capture.mode,
        },
        action: summary.action,
        steps,
    }
}

struct DiagnosticSummary {
    code: CaptureCompatibilityCode,
    status: CaptureCompatibilityStatus,
    confidence: CompatibilityConfidence,
    title: &'static str,
    detail: &'static str,
    action: CompatibilityAction,
}

fn diagnostic_summary(capture: &CaptureState, proxy_session_event_count: u64) -> DiagnosticSummary {
    if capture.mode == CaptureMode::Gateway {
        return gateway_summary(capture);
    }
    if !capture.proxy_available {
        return summary(
            CaptureCompatibilityCode::ProxyBundleUnavailable,
            CaptureCompatibilityStatus::Blocked,
            CompatibilityConfidence::High,
            "Explicit proxy unavailable",
            "The verified Proxy bundle is missing or incompatible. Continue with Gateway capture.",
            CompatibilityAction::UseGateway,
        );
    }
    if capture.endpoint == "Not connected" {
        return summary(
            CaptureCompatibilityCode::ProxyUnavailable,
            CaptureCompatibilityStatus::Blocked,
            CompatibilityConfidence::High,
            "Explicit proxy unavailable",
            "The Proxy runtime did not expose a usable loopback endpoint. Return to Gateway capture.",
            CompatibilityAction::UseGateway,
        );
    }
    if capture.certificate_authority.state == CertificateAuthorityState::Invalid
        || capture.certificate_authority.private_material == CertificatePrivateMaterial::Insecure
    {
        return summary(
            CaptureCompatibilityCode::CertificateInvalid,
            CaptureCompatibilityStatus::Blocked,
            CompatibilityConfidence::High,
            "Local CA is invalid",
            "The local certificate authority cannot be used safely. Return to Gateway until it is repaired.",
            CompatibilityAction::UseGateway,
        );
    }
    if capture.certificate_authority.state == CertificateAuthorityState::Missing {
        return summary(
            CaptureCompatibilityCode::CertificateMissing,
            CaptureCompatibilityStatus::Attention,
            CompatibilityConfidence::High,
            "Local CA is not ready",
            "The Proxy runtime has not produced a usable local certificate authority. Gateway capture remains available.",
            CompatibilityAction::UseGateway,
        );
    }
    if capture.certificate_authority.trust != CertificateTrust::Trusted {
        return summary(
            CaptureCompatibilityCode::CertificateTrustRequired,
            CaptureCompatibilityStatus::Attention,
            CompatibilityConfidence::High,
            "System trust is required",
            "Trust the verified local CA before expecting HTTPS applications to use Proxy capture.",
            if capture.certificate_authority.can_manage_trust {
                CompatibilityAction::TrustCertificate
            } else {
                CompatibilityAction::UseGateway
            },
        );
    }
    if !capture.active {
        return summary(
            CaptureCompatibilityCode::CapturePaused,
            CaptureCompatibilityStatus::Attention,
            CompatibilityConfidence::High,
            "Proxy capture paused",
            "The Proxy runtime is available, but new requests are not being recorded.",
            CompatibilityAction::ResumeCapture,
        );
    }
    if proxy_session_event_count == 0 {
        return summary(
            CaptureCompatibilityCode::ProxyCaptureUnobserved,
            CaptureCompatibilityStatus::Attention,
            CompatibilityConfidence::Low,
            "No Proxy capture observed yet",
            "Send one request from the target application. If it succeeds there but remains absent here, the application may bypass the proxy or pin certificates; use Gateway capture instead.",
            CompatibilityAction::UseGateway,
        );
    }
    summary(
        CaptureCompatibilityCode::ProxyCaptureObserved,
        CaptureCompatibilityStatus::Ready,
        CompatibilityConfidence::High,
        "Proxy capture observed",
        "This Proxy session has delivered a sanitized capture event to the encrypted workspace.",
        CompatibilityAction::None,
    )
}

fn gateway_summary(capture: &CaptureState) -> DiagnosticSummary {
    if capture.endpoint == "Not connected" {
        return summary(
            CaptureCompatibilityCode::GatewayUnavailable,
            CaptureCompatibilityStatus::Blocked,
            CompatibilityConfidence::High,
            "Gateway unavailable",
            "The local Gateway endpoint is not available. Capture cannot start until the runtime is restored.",
            CompatibilityAction::None,
        );
    }
    if !capture.active {
        return summary(
            CaptureCompatibilityCode::CapturePaused,
            CaptureCompatibilityStatus::Attention,
            CompatibilityConfidence::High,
            "Gateway capture paused",
            "Traffic can still be forwarded, but new requests are not being recorded.",
            CompatibilityAction::ResumeCapture,
        );
    }
    summary(
        CaptureCompatibilityCode::GatewayReady,
        CaptureCompatibilityStatus::Ready,
        CompatibilityConfidence::High,
        "Gateway capture ready",
        "Route the target client to the local Gateway endpoint. Local certificate trust is not required.",
        CompatibilityAction::None,
    )
}

const fn summary(
    code: CaptureCompatibilityCode,
    status: CaptureCompatibilityStatus,
    confidence: CompatibilityConfidence,
    title: &'static str,
    detail: &'static str,
    action: CompatibilityAction,
) -> DiagnosticSummary {
    DiagnosticSummary {
        code,
        status,
        confidence,
        title,
        detail,
        action,
    }
}

fn compatibility_steps(
    capture: &CaptureState,
    proxy_session_event_count: u64,
) -> Vec<CompatibilityStep> {
    let runtime_ready = capture.endpoint != "Not connected";
    if capture.mode == CaptureMode::Gateway {
        return vec![
            compatibility_step(
                "gateway_runtime",
                if runtime_ready {
                    CompatibilityStepStatus::Pass
                } else {
                    CompatibilityStepStatus::Blocked
                },
                "Local Gateway",
                if runtime_ready {
                    capture.endpoint.clone()
                } else {
                    "No loopback endpoint".to_owned()
                },
            ),
            compatibility_step(
                "certificate_interception",
                CompatibilityStepStatus::Pass,
                "Certificate interception",
                "Not required in Gateway mode",
            ),
            compatibility_step(
                "recording",
                if capture.active {
                    CompatibilityStepStatus::Pass
                } else {
                    CompatibilityStepStatus::Attention
                },
                "Recording",
                if capture.active { "Active" } else { "Paused" },
            ),
        ];
    }

    vec![
        compatibility_step(
            "proxy_bundle",
            if capture.proxy_available {
                CompatibilityStepStatus::Pass
            } else {
                CompatibilityStepStatus::Blocked
            },
            "Verified Proxy bundle",
            if capture.proxy_available {
                "Available"
            } else {
                "Unavailable"
            },
        ),
        compatibility_step(
            "proxy_runtime",
            if runtime_ready {
                CompatibilityStepStatus::Pass
            } else {
                CompatibilityStepStatus::Blocked
            },
            "Proxy runtime",
            if runtime_ready {
                capture.endpoint.clone()
            } else {
                "No loopback endpoint".to_owned()
            },
        ),
        compatibility_step(
            "local_ca",
            certificate_step_status(capture),
            "Local certificate authority",
            match capture.certificate_authority.state {
                CertificateAuthorityState::Missing => "Not generated".to_owned(),
                CertificateAuthorityState::Invalid => "Invalid".to_owned(),
                CertificateAuthorityState::Ready => format!(
                    "Ready · {} private material",
                    private_material_label(capture.certificate_authority.private_material)
                ),
            },
        ),
        compatibility_step(
            "system_trust",
            if capture.certificate_authority.trust == CertificateTrust::Trusted {
                CompatibilityStepStatus::Pass
            } else {
                CompatibilityStepStatus::Attention
            },
            "System trust",
            certificate_trust_label(capture.certificate_authority.trust),
        ),
        compatibility_step(
            "session_capture",
            if proxy_session_event_count > 0 {
                CompatibilityStepStatus::Pass
            } else {
                CompatibilityStepStatus::Pending
            },
            "Current Proxy session",
            if proxy_session_event_count > 0 {
                format!("{proxy_session_event_count} sanitized capture events observed")
            } else {
                "No capture event observed yet".to_owned()
            },
        ),
    ]
}

fn certificate_step_status(capture: &CaptureState) -> CompatibilityStepStatus {
    match capture.certificate_authority.state {
        CertificateAuthorityState::Ready
            if capture.certificate_authority.private_material
                != CertificatePrivateMaterial::Insecure =>
        {
            CompatibilityStepStatus::Pass
        }
        CertificateAuthorityState::Invalid => CompatibilityStepStatus::Blocked,
        CertificateAuthorityState::Missing => CompatibilityStepStatus::Attention,
        CertificateAuthorityState::Ready => CompatibilityStepStatus::Blocked,
    }
}

fn compatibility_step(
    id: &str,
    status: CompatibilityStepStatus,
    label: &str,
    detail: impl Into<String>,
) -> CompatibilityStep {
    CompatibilityStep {
        id: id.to_owned(),
        status,
        label: label.to_owned(),
        detail: detail.into(),
    }
}

const fn private_material_label(material: CertificatePrivateMaterial) -> &'static str {
    match material {
        CertificatePrivateMaterial::Missing => "missing",
        CertificatePrivateMaterial::Restricted => "restricted",
        CertificatePrivateMaterial::Unchecked => "unchecked",
        CertificatePrivateMaterial::Insecure => "insecure",
    }
}

const fn certificate_trust_label(trust: CertificateTrust) -> &'static str {
    match trust {
        CertificateTrust::Unchecked => "unchecked",
        CertificateTrust::Trusted => "trusted",
        CertificateTrust::NotTrusted => "not trusted",
        CertificateTrust::Unsupported => "unsupported",
    }
}
