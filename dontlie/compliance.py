"""Evidence-support maps for regulatory and assurance reviews.

The maps in this module are deliberately not compliance determinations.
They show where a Don't-Lie artifact can support a control owner and where
the operator must supply other technical, administrative, legal, or physical
controls.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Literal

Coverage = Literal["supported", "supporting_evidence", "operator_required", "out_of_scope"]


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    coverage: Coverage
    dontlie_evidence: str
    operator_action: str
    source_url: str


@dataclass(frozen=True)
class Framework:
    framework_id: str
    title: str
    as_of: str
    disclaimer: str
    controls: tuple[Control, ...]


HHS_SECURITY_RULE = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/"
HHS_RISK_ANALYSIS = (
    "https://www.hhs.gov/hipaa/for-professionals/security/guidance/"
    "guidance-risk-analysis/"
)
HHS_NPRM = (
    "https://www.hhs.gov/hipaa/for-professionals/security/"
    "hipaa-security-rule-nprm/"
)
EU_AI_ACT = "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"
EU_AI_TIMELINE = (
    "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai"
)

DISCLAIMER = (
    "Evidence-support map only. It is not legal advice, certification, a "
    "conformity assessment, or a determination that any organization complies."
)

HIPAA = Framework(
    framework_id="hipaa-security",
    title="HIPAA Security Rule evidence-support map",
    as_of="2026-07-30",
    disclaimer=(
        f"{DISCLAIMER} The current HIPAA Security Rule remains in effect; the "
        "2024 cybersecurity update is a proposed rule, not a final rule."
    ),
    controls=(
        Control(
            "45 CFR 164.308(a)(1)",
            "Security management process and risk analysis",
            "operator_required",
            "Receipts can identify recorded AI data flows and verification failures.",
            "Perform and document an enterprise-wide ePHI risk analysis and risk management plan.",
            HHS_RISK_ANALYSIS,
        ),
        Control(
            "45 CFR 164.308(a)(1)(ii)(D)",
            "Information system activity review",
            "supporting_evidence",
            "Signed receipts, search, verification results, and proof packets can support review of recorded AI calls.",
            "Define review scope, cadence, responsible personnel, escalation, and evidence that reviews occurred.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.308(a)(3)-(5)",
            "Workforce security, information access, and security awareness",
            "operator_required",
            "No workforce lifecycle, training, or authoritative access-management control.",
            "Implement authorization, supervision, termination, access review, and training procedures.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.308(a)(6)",
            "Security incident procedures",
            "supporting_evidence",
            "Verified receipts can preserve the recorded AI exchange and tamper findings used in an investigation.",
            "Maintain incident identification, response, mitigation, documentation, and breach-assessment procedures.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.308(a)(7)-(8)",
            "Contingency plan and periodic evaluation",
            "operator_required",
            "Portable packets can be included in backup and recovery exercises.",
            "Implement backup, disaster recovery, emergency operations, testing, and periodic evaluation.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.310",
            "Physical safeguards",
            "out_of_scope",
            "No facility, workstation, device, or media control.",
            "Apply physical safeguards to every system that stores or accesses ePHI.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.312(a)",
            "Access control",
            "operator_required",
            "Local files can inherit host permissions, but Don't-Lie is not the authoritative identity or access-control system.",
            "Implement unique identities, authorization, emergency access, session controls, and encryption decisions.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.312(b)",
            "Audit controls",
            "supporting_evidence",
            "Automatically records configured AI calls and provides search, export, and independent verification.",
            "Prove capture coverage, protect the host, define review procedures, and include all in-scope systems—not only AI calls.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.312(c)",
            "Integrity",
            "supported",
            "Ed25519 signatures and a hash-linked chain detect alteration of recorded receipts.",
            "Protect ePHI outside the receipt vault and establish trusted key ownership and capture completeness.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.312(d)",
            "Person or entity authentication",
            "operator_required",
            "Receipts identify a signing key; they do not establish that the key belongs to a named person or authorized service.",
            "Use an authoritative identity provider and bind/pin signing keys through a documented key-custody process.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.312(e)",
            "Transmission security",
            "operator_required",
            "Receipts can record a route but do not secure network transport.",
            "Use appropriately configured transport encryption and integrity protection for every ePHI transmission.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "45 CFR 164.314 and 164.316",
            "Organizational arrangements, policies, and documentation",
            "operator_required",
            "Proof packets can be retained as evidence; Don't-Lie does not create BAAs or the operator's policies.",
            "Execute required agreements and maintain written policies, procedures, decisions, and required documentation.",
            HHS_SECURITY_RULE,
        ),
        Control(
            "HIPAA Privacy and Breach Notification Rules",
            "Privacy, permitted uses, minimum necessary, and breach notification",
            "out_of_scope",
            "Redaction is heuristic and receipts do not determine lawful use, disclosure, or breach status.",
            "Apply privacy, minimum-necessary, authorization, accounting, and breach-notification processes with counsel.",
            "https://www.hhs.gov/hipaa/for-professionals/privacy/",
        ),
        Control(
            "2024 HIPAA Security Rule NPRM",
            "Proposed cybersecurity amendments",
            "out_of_scope",
            "The proposal can inform future-readiness planning but is not represented as current law.",
            "Track rulemaking and update the control map only when HHS publishes a final rule.",
            HHS_NPRM,
        ),
    ),
)


EU = Framework(
    framework_id="eu-ai-act",
    title="EU AI Act evidence-support map",
    as_of="2026-07-30",
    disclaimer=(
        f"{DISCLAIMER} Obligations depend on system classification and role "
        "(provider, deployer, importer, distributor, or GPAI provider). "
        "Application dates are phased and have changed; confirm the current "
        "timeline and classification before relying on this map."
    ),
    controls=(
        Control(
            "Article 4",
            "AI literacy",
            "out_of_scope",
            "No training or competency-management system.",
            "Ensure relevant staff have sufficient AI literacy for their role and context.",
            EU_AI_ACT,
        ),
        Control(
            "Article 5",
            "Prohibited AI practices",
            "out_of_scope",
            "A receipt can preserve evidence but does not prevent a prohibited use.",
            "Classify and prohibit disallowed practices before deployment.",
            EU_AI_ACT,
        ),
        Control(
            "Article 9",
            "Risk management system",
            "operator_required",
            "Receipts can provide operational evidence for identified risks and tests.",
            "Establish a continuous, documented risk-management lifecycle with testing and mitigation.",
            EU_AI_ACT,
        ),
        Control(
            "Article 10",
            "Data and data governance",
            "operator_required",
            "Receipts can fingerprint or preserve configured inputs; they do not establish dataset quality or lawful processing.",
            "Govern training, validation, testing, provenance, bias, representativeness, and personal-data processing.",
            EU_AI_ACT,
        ),
        Control(
            "Article 11 and Annex IV",
            "Technical documentation",
            "supporting_evidence",
            "Proof packets document recorded runtime exchanges and verification results.",
            "Maintain the complete technical file, system description, design, validation, changes, performance, and monitoring plan.",
            EU_AI_ACT,
        ),
        Control(
            "Article 12",
            "Automatic event logging",
            "supporting_evidence",
            "Automatically records configured model calls with signed, hash-linked receipts.",
            "Demonstrate that all required events are captured over the system lifetime, with appropriate interpretation, access, and coverage.",
            EU_AI_ACT,
        ),
        Control(
            "Article 13",
            "Transparency and instructions to deployers",
            "supporting_evidence",
            "The packet exposes recorded model, request, response, and verification boundaries.",
            "Provide complete instructions, capabilities, limitations, performance, oversight, and logging information required for the system.",
            EU_AI_ACT,
        ),
        Control(
            "Article 14",
            "Human oversight",
            "supporting_evidence",
            "Signed annotations and decision records can preserve configured review events.",
            "Design effective human oversight, authority, competence, intervention, override, and stop mechanisms.",
            EU_AI_ACT,
        ),
        Control(
            "Article 15",
            "Accuracy, robustness, and cybersecurity",
            "supporting_evidence",
            "Receipt verification detects record alteration; it does not measure model accuracy or secure the whole system.",
            "Define and test accuracy, resilience, fault tolerance, security, and adversarial protections.",
            EU_AI_ACT,
        ),
        Control(
            "Articles 16-21",
            "Provider obligations, QMS, documentation retention, logs, and corrective action",
            "operator_required",
            "Packets and verification results can be retained inside the provider's evidence system.",
            "Operate the QMS, retain required records, investigate nonconformity, take corrective action, and cooperate with authorities.",
            EU_AI_ACT,
        ),
        Control(
            "Article 26",
            "Deployer obligations",
            "supporting_evidence",
            "Receipts can support monitoring and retention of logs under the deployer's control.",
            "Follow instructions, assign competent oversight, monitor operation, retain required logs, and report incidents.",
            EU_AI_ACT,
        ),
        Control(
            "Article 27",
            "Fundamental rights impact assessment",
            "supporting_evidence",
            "Runtime evidence can support parts of an assessment after the system is correctly classified.",
            "Perform the assessment where applicable and address affected persons, risks, oversight, and mitigation.",
            EU_AI_ACT,
        ),
        Control(
            "Articles 43, 47, and 49",
            "Conformity assessment, declaration, and registration",
            "out_of_scope",
            "No conformity assessment, CE declaration, notified-body function, or EU registration.",
            "Complete each applicable assessment, declaration, marking, and registration requirement.",
            EU_AI_ACT,
        ),
        Control(
            "Article 50",
            "Transparency for interactive and generated-content systems",
            "out_of_scope",
            "Receipts do not notify affected people or mark AI-generated content.",
            "Implement applicable interaction disclosures and machine-readable or visible content labels.",
            EU_AI_ACT,
        ),
        Control(
            "Articles 72-73",
            "Post-market monitoring and serious incident reporting",
            "supporting_evidence",
            "Receipts can supply recorded incident and performance evidence.",
            "Operate the monitoring plan, detect and investigate incidents, and meet applicable reporting duties and deadlines.",
            EU_AI_ACT,
        ),
        Control(
            "GDPR and other Union or national law",
            "Personal-data and sector-specific obligations",
            "out_of_scope",
            "Evidence modes can reduce disclosure, but heuristic redaction is not anonymization or a lawful-processing determination.",
            "Apply GDPR, sector law, retention limits, data-subject rights, security, and transfer requirements.",
            EU_AI_ACT,
        ),
        Control(
            "Application timeline",
            "Phased application dates",
            "operator_required",
            "The map records its as-of date but cannot determine the deadline for a customer's specific system.",
            "Confirm current dates using the Commission timeline and counsel; do not rely on legacy August 2026 high-risk dates.",
            EU_AI_TIMELINE,
        ),
    ),
)

FRAMEWORKS: dict[str, Framework] = {
    HIPAA.framework_id: HIPAA,
    EU.framework_id: EU,
}


def get_framework(framework_id: str) -> Framework:
    """Return a framework or raise a stable, user-facing error."""
    try:
        return FRAMEWORKS[framework_id]
    except KeyError as exc:
        choices = ", ".join(sorted(FRAMEWORKS))
        raise ValueError(f"unknown framework {framework_id!r}; choose: {choices}") from exc


def render_text(framework: Framework, *, only_gaps: bool = False) -> str:
    """Render a reviewer-friendly text report."""
    controls = [
        control
        for control in framework.controls
        if not only_gaps or control.coverage in {"operator_required", "out_of_scope"}
    ]
    lines = [
        framework.title,
        f"As of: {framework.as_of}",
        framework.disclaimer,
        "",
    ]
    for control in controls:
        lines.extend(
            [
                f"[{control.coverage.upper()}] {control.control_id} — {control.title}",
                f"  Don't-Lie: {control.dontlie_evidence}",
                f"  Operator:  {control.operator_action}",
                f"  Source:    {control.source_url}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_json(framework: Framework, *, only_gaps: bool = False) -> str:
    """Render deterministic JSON for GRC ingestion and regression tests."""
    payload = asdict(framework)
    if only_gaps:
        payload["controls"] = [
            control
            for control in payload["controls"]
            if control["coverage"] in {"operator_required", "out_of_scope"}
        ]
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
