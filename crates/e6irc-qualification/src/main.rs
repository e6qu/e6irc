//! Run credential-gated external qualifications and write safe evidence.

mod native;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const USAGE: &str = "usage: e6irc-qualification KIND --target TARGET --source REVISION --host HOST --output PATH --workload NAME=VALUE --budget NAME=VALUE [--executable PATH] [--probe PATH [-- PROBE_ARGS...]]\n       e6irc-qualification verify EVIDENCE --source REVISION --target TARGET --max-age-seconds SECONDS";

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == "verify")
    {
        return verify(arguments.into_iter().skip(1));
    }
    match parse_args(arguments) {
        Ok(args) => run(args),
        Err(error) => {
            eprintln!("e6irc-qualification: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TargetKind {
    Discord,
    Slack,
    Oidc,
    PublicIrc,
    Scale,
}

impl TargetKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "discord" => Ok(Self::Discord),
            "slack" => Ok(Self::Slack),
            "oidc" => Ok(Self::Oidc),
            "public-irc" => Ok(Self::PublicIrc),
            "scale" => Ok(Self::Scale),
            _ => Err("KIND must be discord, slack, oidc, public-irc, or scale".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::Slack => "slack",
            Self::Oidc => "oidc",
            Self::PublicIrc => "public-irc",
            Self::Scale => "scale",
        }
    }

    fn required_environment(self) -> &'static [&'static str] {
        match self {
            Self::Discord => &["E6IRC_DISCORD_BOT_TOKEN", "E6IRC_DISCORD_CHANNEL_ID"],
            Self::Slack => &[
                "E6IRC_SLACK_BOT_TOKEN",
                "E6IRC_SLACK_APP_TOKEN",
                "E6IRC_SLACK_CHANNEL_ID",
            ],
            Self::Oidc => &["E6IRC_OIDC_CLIENT_ID", "E6IRC_OIDC_CLIENT_SECRET"],
            Self::PublicIrc | Self::Scale => &[],
        }
    }

    fn rejects_oracle_endpoint(self) -> bool {
        match self {
            Self::Discord => std::env::var_os("E6IRC_DISCORD_API_BASE").is_some(),
            Self::Slack => std::env::var_os("E6IRC_SLACK_API_BASE").is_some(),
            Self::Oidc | Self::PublicIrc | Self::Scale => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SourceRevision(String);

impl SourceRevision {
    fn parse(value: String) -> Result<Self, String> {
        if !(value.len() == 40 || value.len() == 64)
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("--source needs a 40- or 64-character hexadecimal revision".into());
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    fn validate(&self, flag: &str) -> Result<(), String> {
        let parsed = Self::parse(self.0.clone())
            .map_err(|_| format!("{flag} needs a 40- or 64-character hexadecimal revision"))?;
        (parsed.0 == self.0)
            .then_some(())
            .ok_or_else(|| format!("{flag} must use lowercase hexadecimal"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SafeText(String);

impl SafeText {
    fn parse(value: String, flag: &str) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > 255
            || value.contains(char::is_control)
            || value.contains('@')
            || value.contains('?')
            || value.contains('#')
        {
            return Err(format!("{flag} must be a non-secret identifier"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EvidenceHost(String);

impl EvidenceHost {
    fn parse(value: String, flag: &str) -> Result<Self, String> {
        SafeText::parse(value.clone(), flag)?;
        if value.len() > 253
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || !value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !value
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(format!("{flag} must be a non-secret host label"));
        }
        Ok(Self(value))
    }

    fn validate(&self, flag: &str) -> Result<(), String> {
        Self::parse(self.0.clone(), flag).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct CampaignTarget(SafeText);

impl CampaignTarget {
    fn parse(kind: TargetKind, value: String) -> Result<Self, String> {
        let target = Self(SafeText::parse(value, "--target")?);
        target.validate(kind)?;
        Ok(target)
    }

    fn validate(&self, kind: TargetKind) -> Result<(), String> {
        SafeText::parse(self.0.0.clone(), "target")?;
        match kind {
            TargetKind::Discord if self.0.0 != "discord.com" => {
                Err("Discord target must be discord.com".into())
            }
            TargetKind::Slack if self.0.0 != "slack.com" => {
                Err("Slack target must be slack.com".into())
            }
            TargetKind::Oidc => validate_external_oidc_issuer(&self.0.0),
            TargetKind::PublicIrc if !matches!(self.0.0.as_str(), "libera" | "oftc" | "ergo") => {
                Err("public-irc target must be libera, oftc, or ergo".into())
            }
            TargetKind::Discord | TargetKind::Slack | TargetKind::PublicIrc | TargetKind::Scale => {
                Ok(())
            }
        }
    }

    fn as_str(&self) -> &str {
        &self.0.0
    }
}

fn validate_external_oidc_issuer(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| "OIDC target must be an HTTPS issuer URL")?;
    if url.scheme() != "https"
        || !url.host_str().is_some_and(native::is_external_host)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("OIDC target must be an HTTPS issuer URL with a public DNS host".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PositiveDecimal(String);

impl PositiveDecimal {
    fn parse(value: String, flag: &str) -> Result<Self, String> {
        let parsed: f64 = value
            .parse()
            .map_err(|_| format!("{flag} value must be a positive finite number"))?;
        if !parsed.is_finite() || parsed <= 0.0 {
            return Err(format!("{flag} value must be a positive finite number"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Measurements(BTreeMap<String, PositiveDecimal>);

impl Measurements {
    fn parse(values: Vec<String>, flag: &str) -> Result<Self, String> {
        if values.is_empty() {
            return Err(format!("{flag} is required at least once"));
        }
        let mut parsed = BTreeMap::new();
        for value in values {
            let (name, value) = value
                .split_once('=')
                .ok_or_else(|| format!("{flag} needs NAME=VALUE"))?;
            validate_measurement_name(name, flag)?;
            if parsed
                .insert(
                    name.to_string(),
                    PositiveDecimal::parse(value.to_string(), flag)?,
                )
                .is_some()
            {
                return Err(format!("{flag} repeats {name}"));
            }
        }
        Ok(Self(parsed))
    }

    fn validate(&self, flag: &str) -> Result<(), String> {
        if self.0.is_empty() {
            return Err(format!("{flag} is required at least once"));
        }
        for (name, value) in &self.0 {
            validate_measurement_name(name, flag)?;
            PositiveDecimal::parse(value.0.clone(), flag)?;
        }
        Ok(())
    }
}

fn validate_measurement_name(value: &str, flag: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!(
            "{flag} names use lowercase ASCII letters, digits, and underscores"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CredentialEnv(String);

impl CredentialEnv {
    fn parse(value: String) -> Result<Self, String> {
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err("--credential-env needs an environment-variable name".into());
        };
        if !first.is_ascii_uppercase()
            || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(
                "--credential-env names use uppercase ASCII letters, digits, and underscores"
                    .into(),
            );
        }
        Ok(Self(value))
    }

    fn is_present(&self) -> bool {
        std::env::var_os(&self.0).is_some_and(|value| !value.is_empty())
    }

    fn validate(&self) -> Result<(), String> {
        Self::parse(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug)]
struct Campaign {
    kind: TargetKind,
    target: CampaignTarget,
    source: SourceRevision,
    host: EvidenceHost,
    executable: Option<PathBuf>,
    output: PathBuf,
    workload: Measurements,
    budgets: Measurements,
    probe: Option<PathBuf>,
    credentials: Vec<CredentialEnv>,
    probe_args: Vec<OsString>,
}

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Campaign, String> {
    let mut arguments = arguments.into_iter().collect::<Vec<_>>().into_iter();
    let kind = arguments
        .next()
        .ok_or_else(|| "KIND is required".to_string())?
        .into_string()
        .map_err(|_| "KIND must be UTF-8".to_string())?;
    let mut target = None;
    let mut source = None;
    let mut host = None;
    let mut executable = None;
    let mut output = None;
    let mut workloads = Vec::new();
    let mut budgets = Vec::new();
    let mut probe = None;
    let mut credentials = Vec::new();
    let mut probe_args = Vec::new();
    while let Some(flag) = arguments.next() {
        if flag == "--" {
            probe_args.extend(arguments);
            break;
        }
        let flag = flag
            .into_string()
            .map_err(|_| "arguments must be UTF-8".to_string())?;
        let value = |arguments: &mut std::vec::IntoIter<OsString>, flag: &str| {
            arguments
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))?
                .into_string()
                .map_err(|_| format!("{flag} value must be UTF-8"))
        };
        match flag.as_str() {
            "--target" => {
                if target.is_some() {
                    return Err("--target must occur once".into());
                }
                target = Some(value(&mut arguments, "--target")?)
            }
            "--source" => {
                if source.is_some() {
                    return Err("--source must occur once".into());
                }
                source = Some(SourceRevision::parse(value(&mut arguments, "--source")?)?);
            }
            "--host" => {
                if host.is_some() {
                    return Err("--host must occur once".into());
                }
                host = Some(EvidenceHost::parse(
                    value(&mut arguments, "--host")?,
                    "--host",
                )?);
            }
            "--executable" => {
                if executable.is_some() {
                    return Err("--executable must occur once".into());
                }
                executable = Some(PathBuf::from(value(&mut arguments, "--executable")?))
            }
            "--output" => {
                if output.is_some() {
                    return Err("--output must occur once".into());
                }
                output = Some(PathBuf::from(value(&mut arguments, "--output")?));
            }
            "--workload" => workloads.push(value(&mut arguments, "--workload")?),
            "--budget" => budgets.push(value(&mut arguments, "--budget")?),
            "--probe" => {
                if probe.is_some() {
                    return Err("--probe must occur once".into());
                }
                probe = Some(PathBuf::from(value(&mut arguments, "--probe")?));
            }
            "--credential-env" => {
                let credential = CredentialEnv::parse(value(&mut arguments, "--credential-env")?)?;
                if credentials
                    .iter()
                    .any(|existing: &CredentialEnv| existing.0 == credential.0)
                {
                    return Err(format!("--credential-env repeats {}", credential.0));
                }
                credentials.push(credential);
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    let output = output.ok_or_else(|| "--output is required".to_string())?;
    if output.exists() {
        return Err(format!(
            "--output must not already exist: {}",
            output.display()
        ));
    }
    if let Some(path) = executable.as_ref().filter(|path| !path.is_file()) {
        return Err(format!(
            "--executable is not a regular file: {}",
            path.display()
        ));
    }
    let kind = TargetKind::parse(&kind)?;
    if matches!(kind, TargetKind::Scale) != executable.is_some() {
        return Err(if matches!(kind, TargetKind::Scale) {
            "--executable is required for scale".into()
        } else {
            "--executable is only valid for scale".into()
        });
    }
    if kind.rejects_oracle_endpoint() {
        return Err("external campaigns cannot set a local oracle endpoint".into());
    }
    if kind.uses_native_campaign() && probe.is_some() {
        return Err(format!(
            "{} uses its built-in adapter; --probe is invalid",
            kind.name()
        ));
    }
    let probe = if kind.uses_native_campaign() {
        None
    } else {
        let probe = probe.ok_or_else(|| "--probe is required for this campaign".to_string())?;
        if !probe.is_file() {
            return Err(format!(
                "--probe is not a regular file: {}",
                probe.display()
            ));
        }
        Some(probe)
    };
    for name in kind.required_environment() {
        let credential = CredentialEnv::parse((*name).to_string())?;
        if !credentials
            .iter()
            .any(|existing| existing.0 == credential.0)
        {
            credentials.push(credential);
        }
    }
    Ok(Campaign {
        kind,
        target: CampaignTarget::parse(
            kind,
            target.ok_or_else(|| "--target is required".to_string())?,
        )?,
        source: source.ok_or_else(|| "--source is required".to_string())?,
        host: host.ok_or_else(|| "--host is required".to_string())?,
        executable,
        output,
        workload: Measurements::parse(workloads, "--workload")?,
        budgets: Measurements::parse(budgets, "--budget")?,
        probe,
        credentials,
        probe_args,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PhaseOutcome {
    Passed,
    Rejected,
    Failed,
    NotApplicable,
    NotRun,
}

#[derive(Clone, Copy)]
enum QualificationPhase {
    Authentication,
    Delivery,
    Reconnect,
    Cleanup,
    Persistence,
}

impl QualificationPhase {
    const ALL: [Self; 5] = [
        Self::Authentication,
        Self::Delivery,
        Self::Reconnect,
        Self::Cleanup,
        Self::Persistence,
    ];
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeReport {
    authentication: PhaseOutcome,
    delivery: PhaseOutcome,
    reconnect: PhaseOutcome,
    cleanup: PhaseOutcome,
    persistence: PhaseOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeResult {
    challenge: String,
    #[serde(flatten)]
    report: ProbeReport,
}

impl ProbeReport {
    fn not_run(kind: TargetKind) -> Self {
        let outcome = |phase| {
            if kind.requires_phase(phase) {
                PhaseOutcome::NotRun
            } else {
                PhaseOutcome::NotApplicable
            }
        };
        Self {
            authentication: outcome(QualificationPhase::Authentication),
            delivery: outcome(QualificationPhase::Delivery),
            reconnect: outcome(QualificationPhase::Reconnect),
            cleanup: outcome(QualificationPhase::Cleanup),
            persistence: outcome(QualificationPhase::Persistence),
        }
    }

    fn uniform(outcome: PhaseOutcome) -> Self {
        Self {
            authentication: outcome,
            delivery: outcome,
            reconnect: outcome,
            cleanup: outcome,
            persistence: outcome,
        }
    }

    fn closed_outcome(&self, kind: TargetKind) -> ClosedOutcome {
        let outcomes = self.phase_outcomes();
        if outcomes
            .iter()
            .any(|(_, outcome)| *outcome == PhaseOutcome::Failed)
        {
            ClosedOutcome::Failed
        } else if outcomes.iter().all(|(phase, outcome)| {
            *outcome == PhaseOutcome::Passed
                || (*outcome == PhaseOutcome::NotApplicable && !kind.requires_phase(*phase))
        }) {
            ClosedOutcome::Passed
        } else {
            ClosedOutcome::Rejected
        }
    }

    fn has_valid_applicability(&self, kind: TargetKind) -> bool {
        self.phase_outcomes().iter().all(|(phase, outcome)| {
            (*outcome == PhaseOutcome::NotApplicable) != kind.requires_phase(*phase)
        })
    }

    fn phase_outcomes(&self) -> [(QualificationPhase, PhaseOutcome); 5] {
        [
            (QualificationPhase::Authentication, self.authentication),
            (QualificationPhase::Delivery, self.delivery),
            (QualificationPhase::Reconnect, self.reconnect),
            (QualificationPhase::Cleanup, self.cleanup),
            (QualificationPhase::Persistence, self.persistence),
        ]
    }
}

impl TargetKind {
    fn requires_phase(self, phase: QualificationPhase) -> bool {
        match self {
            Self::Discord | Self::Slack => true,
            Self::Oidc => !matches!(phase, QualificationPhase::Delivery),
            Self::PublicIrc => matches!(
                phase,
                QualificationPhase::Authentication
                    | QualificationPhase::Reconnect
                    | QualificationPhase::Cleanup
            ),
            Self::Scale => matches!(
                phase,
                QualificationPhase::Authentication
                    | QualificationPhase::Delivery
                    | QualificationPhase::Cleanup
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClosedOutcome {
    Passed,
    Rejected,
    Failed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryEvidence {
    sha256: Sha256Digest,
}

impl BinaryEvidence {
    fn validate(&self) -> Result<(), String> {
        self.sha256.validate("subject.sha256")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct Sha256Digest(String);

impl Sha256Digest {
    fn parse(value: String, field: &str) -> Result<Self, String> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!(
                "{field} needs a 64-character lowercase hexadecimal digest"
            ));
        }
        Ok(Self(value))
    }

    fn validate(&self, field: &str) -> Result<(), String> {
        Self::parse(self.0.clone(), field).map(|_| ())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceSubject {
    QualificationRunner(BinaryEvidence),
    TargetDaemon(BinaryEvidence),
}

impl EvidenceSubject {
    fn validate(&self, kind: TargetKind) -> Result<(), String> {
        match (kind, self) {
            (TargetKind::Scale, Self::TargetDaemon(binary))
            | (
                TargetKind::Discord | TargetKind::Slack | TargetKind::Oidc | TargetKind::PublicIrc,
                Self::QualificationRunner(binary),
            ) => binary.validate(),
            (TargetKind::Scale, Self::QualificationRunner(_)) => {
                Err("scale evidence must identify its target daemon".into())
            }
            (_, Self::TargetDaemon(_)) => Err(
                "provider and public-network evidence must identify its qualification runner"
                    .into(),
            ),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationEvidence {
    format_version: u8,
    kind: TargetKind,
    target: CampaignTarget,
    source: SourceRevision,
    subject: EvidenceSubject,
    host: EvidenceHost,
    started_at_unix_ms: u128,
    finished_at_unix_ms: u128,
    workload: Measurements,
    budgets: Measurements,
    credential_environment: Vec<CredentialEnv>,
    scale_artifacts: Option<ScaleArtifacts>,
    probe: ProbeReport,
    outcome: ClosedOutcome,
}

impl QualificationEvidence {
    fn validate(&self) -> Result<(), String> {
        if self.format_version != 2 {
            return Err("unsupported evidence format version".into());
        }
        self.target.validate(self.kind)?;
        self.source.validate("source")?;
        self.subject.validate(self.kind)?;
        self.host.validate("host")?;
        if self.started_at_unix_ms > self.finished_at_unix_ms {
            return Err("evidence finished before it started".into());
        }
        self.workload.validate("workload")?;
        self.budgets.validate("budget")?;
        let mut credentials = BTreeSet::new();
        for credential in &self.credential_environment {
            credential.validate()?;
            if !credentials.insert(credential.0.as_str()) {
                return Err(format!("credential_environment repeats {}", credential.0));
            }
        }
        for required in self.kind.required_environment() {
            if !credentials.contains(required) {
                return Err(format!("credential_environment omits {required}"));
            }
        }
        match (self.kind, self.scale_artifacts.as_ref()) {
            (TargetKind::Scale, Some(artifacts)) => artifacts.validate()?,
            (TargetKind::Scale, None) => return Err("scale evidence omits raw artifacts".into()),
            (_, None) => {}
            (_, Some(_)) => return Err("only scale evidence may contain raw artifacts".into()),
        }
        if !self.probe.has_valid_applicability(self.kind) {
            return Err("probe has invalid phase applicability".into());
        }
        if self.probe.closed_outcome(self.kind) != self.outcome {
            return Err("outcome does not match probe phases".into());
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScaleArtifacts {
    result_sha256: Sha256Digest,
    host_sha256: Sha256Digest,
}

impl ScaleArtifacts {
    fn capture(evidence: &Path) -> Result<Self, String> {
        let directory = evidence.parent().unwrap_or_else(|| Path::new("."));
        let digest = |name| {
            sha256_file(&directory.join(name))
                .map(Sha256Digest)
                .map_err(|error| format!("cannot read scale {name}: {error}"))
        };
        Ok(Self {
            result_sha256: digest("result.json")?,
            host_sha256: digest("host.txt")?,
        })
    }

    fn validate(&self) -> Result<(), String> {
        self.result_sha256
            .validate("scale_artifacts.result_sha256")?;
        self.host_sha256.validate("scale_artifacts.host_sha256")
    }

    fn verify_files(&self, path: &Path, evidence: &QualificationEvidence) -> Result<(), String> {
        let actual = Self::capture(path)?;
        if actual.result_sha256.0 != self.result_sha256.0 {
            return Err("scale result.json digest does not match evidence".into());
        }
        if actual.host_sha256.0 != self.host_sha256.0 {
            return Err("scale host.txt digest does not match evidence".into());
        }
        verify_scale_result(
            &path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("result.json"),
            evidence,
            self,
        )
    }
}

struct VerificationContext {
    source: SourceRevision,
    target: SafeText,
    maximum_age_ms: u128,
}

impl VerificationContext {
    fn parse(arguments: &[OsString]) -> Result<(&Path, Self), String> {
        let [
            path,
            source_flag,
            source,
            target_flag,
            target,
            age_flag,
            age,
        ] = arguments
        else {
            return Err(
                "verify needs EVIDENCE --source REVISION --target TARGET --max-age-seconds SECONDS"
                    .into(),
            );
        };
        if source_flag != "--source" || target_flag != "--target" || age_flag != "--max-age-seconds"
        {
            return Err(
                "verify needs EVIDENCE --source REVISION --target TARGET --max-age-seconds SECONDS"
                    .into(),
            );
        }
        let source = SourceRevision::parse(
            source
                .clone()
                .into_string()
                .map_err(|_| "--source must be UTF-8")?,
        )?;
        let target = SafeText::parse(
            target
                .clone()
                .into_string()
                .map_err(|_| "--target must be UTF-8")?,
            "--target",
        )?;
        let seconds = age
            .to_str()
            .ok_or("--max-age-seconds must be UTF-8")?
            .parse::<u64>()
            .map_err(|_| "--max-age-seconds needs a positive integer")?;
        let maximum_age_ms = u128::from(seconds)
            .checked_mul(1_000)
            .filter(|age| *age > 0)
            .ok_or("--max-age-seconds needs a positive integer")?;
        Ok((
            Path::new(path),
            Self {
                source,
                target,
                maximum_age_ms,
            },
        ))
    }

    fn verify(&self, evidence: &QualificationEvidence, path: &Path) -> Result<(), String> {
        if evidence.source.0 != self.source.0 {
            return Err("evidence source does not match the required revision".into());
        }
        if evidence.target.as_str() != self.target.0 {
            return Err("evidence target does not match the required target".into());
        }
        let now = now_ms();
        let age = now
            .checked_sub(evidence.finished_at_unix_ms)
            .ok_or("evidence finished in the future")?;
        if age > self.maximum_age_ms {
            return Err("evidence exceeds the permitted age".into());
        }
        if let Some(artifacts) = evidence.scale_artifacts.as_ref() {
            artifacts.verify_files(path, evidence)?;
        }
        Ok(())
    }
}

fn verify_scale_result(
    path: &Path,
    evidence: &QualificationEvidence,
    artifacts: &ScaleArtifacts,
) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("cannot read scale result.json: {error}"))?,
    )
    .map_err(|error| format!("cannot parse scale result.json: {error}"))?;
    let report = value
        .get("report")
        .and_then(serde_json::Value::as_object)
        .ok_or("scale result.json omits its report object")?;
    if report
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
    {
        return Err("scale result.json has an unsupported format version".into());
    }
    let request = report
        .get("request")
        .and_then(serde_json::Value::as_object)
        .ok_or("scale result.json omits its request object")?;
    if request.get("addr").and_then(serde_json::Value::as_str) != Some(evidence.target.as_str()) {
        return Err("scale result.json target does not match evidence".into());
    }
    if request
        .get("host_provenance_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(artifacts.host_sha256.0.as_str())
    {
        return Err("scale result.json host provenance does not match evidence".into());
    }
    for name in ["clients", "channels", "burst"] {
        let expected = evidence
            .workload
            .0
            .get(name)
            .ok_or_else(|| format!("scale evidence omits workload {name}"))?
            .0
            .parse::<u64>()
            .map_err(|_| format!("scale workload {name} must be an integer"))?;
        if request.get(name).and_then(serde_json::Value::as_u64) != Some(expected) {
            return Err(format!(
                "scale result.json workload {name} does not match evidence"
            ));
        }
    }
    let thresholds = request
        .get("thresholds")
        .and_then(serde_json::Value::as_object)
        .ok_or("scale result.json omits its thresholds object")?;
    for (evidence_name, result_name) in [
        ("minimum_connect_rate", "minimum_connect_rate"),
        ("minimum_fanout_rate", "minimum_fanout_rate"),
        ("maximum_p99_ms", "maximum_p99_ms"),
        (
            "maximum_rss_per_connection",
            "maximum_server_rss_per_connection_bytes",
        ),
    ] {
        let expected = evidence
            .budgets
            .0
            .get(evidence_name)
            .ok_or_else(|| format!("scale evidence omits budget {evidence_name}"))?
            .0
            .parse::<f64>()
            .map_err(|_| format!("scale budget {evidence_name} is invalid"))?;
        if thresholds
            .get(result_name)
            .and_then(serde_json::Value::as_f64)
            != Some(expected)
        {
            return Err(format!(
                "scale result.json budget {evidence_name} does not match evidence"
            ));
        }
    }
    let expected_outcome = match (
        value.get("status").and_then(serde_json::Value::as_str),
        report.get("outcome").and_then(serde_json::Value::as_str),
    ) {
        (Some("completed"), Some("passed")) => ClosedOutcome::Passed,
        (Some("completed"), Some("rejected")) => ClosedOutcome::Rejected,
        (Some("failed"), None) => ClosedOutcome::Failed,
        _ => return Err("scale result.json has an invalid status or outcome".into()),
    };
    if evidence.outcome != expected_outcome {
        return Err("scale result.json outcome does not match evidence".into());
    }
    Ok(())
}

fn verify(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let result = VerificationContext::parse(&arguments).and_then(|(path, context)| {
        fs::read(path)
            .map_err(|error| format!("cannot read evidence: {error}"))
            .and_then(|bytes| {
                serde_json::from_slice::<QualificationEvidence>(&bytes)
                    .map_err(|error| format!("cannot parse evidence: {error}"))
            })
            .and_then(|evidence| {
                evidence.validate()?;
                context.verify(&evidence, path)?;
                Ok((evidence.kind.name(), evidence.outcome))
            })
    });
    match result {
        Ok((kind, outcome)) => {
            println!("e6irc-qualification: verified {kind} evidence with {outcome:?} outcome");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("e6irc-qualification: invalid evidence: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Campaign) -> ExitCode {
    let subject = match evidence_subject(&args) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("e6irc-qualification: cannot identify campaign subject: {error}");
            return ExitCode::FAILURE;
        }
    };
    let started_at_unix_ms = now_ms();
    let challenge = challenge(&args, subject_sha256(&subject), started_at_unix_ms);
    let probe_directory = match probe_directory(&args.output, &challenge) {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("e6irc-qualification: cannot create isolated probe directory: {error}");
            return ExitCode::FAILURE;
        }
    };
    let probe_report_path = probe_directory.join("report.json");
    let missing_credential = args
        .credentials
        .iter()
        .any(|credential| !credential.is_present());
    let result = if missing_credential {
        CampaignResult::Report(ProbeReport::not_run(args.kind))
    } else if args.kind.uses_native_campaign() {
        CampaignResult::Report(native::run(args.kind, args.target.as_str()))
    } else if let Some(probe) = args.probe.as_deref() {
        run_probe(&args, probe, &probe_report_path, &challenge)
    } else {
        CampaignResult::FailedBeforePhase
    };
    let (report, outcome) = match result {
        CampaignResult::Report(report) => {
            let outcome = report.closed_outcome(args.kind);
            (report, outcome)
        }
        CampaignResult::FailedBeforePhase => {
            (ProbeReport::not_run(args.kind), ClosedOutcome::Failed)
        }
    };
    let scale_artifacts = if matches!(args.kind, TargetKind::Scale) {
        match ScaleArtifacts::capture(&args.output) {
            Ok(artifacts) => Some(artifacts),
            Err(error) => {
                eprintln!("e6irc-qualification: cannot retain scale raw evidence: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let evidence = QualificationEvidence {
        format_version: 2,
        kind: args.kind,
        target: args.target,
        source: args.source,
        subject,
        host: args.host,
        started_at_unix_ms,
        finished_at_unix_ms: now_ms(),
        workload: args.workload,
        budgets: args.budgets,
        credential_environment: args.credentials,
        scale_artifacts,
        probe: report,
        outcome,
    };
    let _ = fs::remove_dir_all(probe_directory);
    if let Err(error) = write_evidence(&args.output, &evidence) {
        eprintln!("e6irc-qualification: could not write evidence: {error}");
        return ExitCode::FAILURE;
    }
    match outcome {
        ClosedOutcome::Passed => ExitCode::SUCCESS,
        ClosedOutcome::Rejected => ExitCode::from(3),
        ClosedOutcome::Failed => ExitCode::FAILURE,
    }
}

fn evidence_subject(args: &Campaign) -> std::io::Result<EvidenceSubject> {
    match args.executable.as_deref() {
        Some(path) => sha256_file(path).map(|sha256| {
            EvidenceSubject::TargetDaemon(BinaryEvidence {
                sha256: Sha256Digest(sha256),
            })
        }),
        None => std::env::current_exe()
            .and_then(|path| sha256_file(&path))
            .map(|sha256| {
                EvidenceSubject::QualificationRunner(BinaryEvidence {
                    sha256: Sha256Digest(sha256),
                })
            }),
    }
}

fn subject_sha256(subject: &EvidenceSubject) -> &str {
    match subject {
        EvidenceSubject::QualificationRunner(binary) | EvidenceSubject::TargetDaemon(binary) => {
            &binary.sha256.0
        }
    }
}

impl TargetKind {
    fn uses_native_campaign(self) -> bool {
        matches!(self, Self::Discord | Self::Slack | Self::Oidc)
    }
}

enum CampaignResult {
    Report(ProbeReport),
    FailedBeforePhase,
}

fn run_probe(args: &Campaign, probe: &Path, report_path: &Path, challenge: &str) -> CampaignResult {
    let status = Command::new(probe)
        .args(&args.probe_args)
        .env("E6IRC_QUALIFICATION_KIND", args.kind.name())
        .env("E6IRC_QUALIFICATION_TARGET", args.target.as_str())
        .env("E6IRC_QUALIFICATION_PROBE_REPORT", report_path)
        .env("E6IRC_QUALIFICATION_CHALLENGE", challenge)
        .status();
    if !matches!(status, Ok(status) if status.success()) {
        return CampaignResult::FailedBeforePhase;
    }
    let Ok(bytes) = std::fs::read(report_path) else {
        return CampaignResult::FailedBeforePhase;
    };
    match serde_json::from_slice::<ProbeResult>(&bytes) {
        Ok(result)
            if result.challenge == challenge
                && result.report.has_valid_applicability(args.kind) =>
        {
            CampaignResult::Report(result.report)
        }
        _ => CampaignResult::FailedBeforePhase,
    }
}

fn challenge(args: &Campaign, executable_sha256: &str, started_at_unix_ms: u128) -> String {
    let mut digest = Sha256::new();
    digest.update(executable_sha256);
    digest.update(args.output.as_os_str().as_encoded_bytes());
    digest.update(started_at_unix_ms.to_le_bytes());
    format!("{:x}", digest.finalize())
}

fn probe_directory(output: &Path, challenge: &str) -> std::io::Result<PathBuf> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let directory = parent.join(format!(".e6irc-qualification-{challenge}"));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn write_evidence(path: &Path, evidence: &QualificationEvidence) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(evidence)
        .map_err(|error| std::io::Error::other(format!("encode evidence: {error}")))?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_passed_is_the_only_passing_evidence() {
        assert_eq!(
            ProbeReport::uniform(PhaseOutcome::Passed).closed_outcome(TargetKind::Discord),
            ClosedOutcome::Passed
        );
        assert_eq!(
            ProbeReport::uniform(PhaseOutcome::Rejected).closed_outcome(TargetKind::Discord),
            ClosedOutcome::Rejected
        );
        assert_eq!(
            ProbeReport::uniform(PhaseOutcome::Failed).closed_outcome(TargetKind::Discord),
            ClosedOutcome::Failed
        );
        assert_eq!(
            ProbeReport::not_run(TargetKind::Discord).closed_outcome(TargetKind::Discord),
            ClosedOutcome::Rejected
        );
    }

    #[test]
    fn failures_take_precedence_over_rejections() {
        let report = ProbeReport {
            authentication: PhaseOutcome::Passed,
            delivery: PhaseOutcome::Rejected,
            reconnect: PhaseOutcome::Failed,
            cleanup: PhaseOutcome::Passed,
            persistence: PhaseOutcome::Passed,
        };
        assert_eq!(
            report.closed_outcome(TargetKind::Discord),
            ClosedOutcome::Failed
        );
    }

    #[test]
    fn evidence_identifiers_exclude_secret_shaped_targets() {
        assert!(SafeText::parse("https://issuer.example".into(), "--target").is_ok());
        assert!(SafeText::parse("https://user:secret@example".into(), "--target").is_err());
        assert!(SafeText::parse("https://example?token=secret".into(), "--target").is_err());
    }

    #[test]
    fn measurements_require_unique_positive_values() {
        assert!(
            Measurements::parse(vec!["clients=1".into(), "p99_ms=0.1".into()], "--workload")
                .is_ok()
        );
        assert!(Measurements::parse(vec!["clients=0".into()], "--workload").is_err());
        assert!(
            Measurements::parse(vec!["clients=1".into(), "clients=2".into()], "--workload")
                .is_err()
        );
    }

    #[test]
    fn credential_environment_names_are_not_values() {
        assert!(CredentialEnv::parse("E6IRC_DISCORD_TOKEN".into()).is_ok());
        assert!(CredentialEnv::parse("token".into()).is_err());
    }

    #[test]
    fn provider_campaign_targets_are_canonical() {
        assert!(CampaignTarget::parse(TargetKind::Discord, "discord.com".into()).is_ok());
        assert!(CampaignTarget::parse(TargetKind::Slack, "slack.com".into()).is_ok());
        assert!(CampaignTarget::parse(TargetKind::Discord, "example.test".into()).is_err());
        assert!(CampaignTarget::parse(TargetKind::Slack, "example.test".into()).is_err());
    }

    #[test]
    fn external_oidc_issuers_cannot_use_ip_literals() {
        assert!(CampaignTarget::parse(TargetKind::Oidc, "https://issuer.example".into()).is_ok());
        assert!(CampaignTarget::parse(TargetKind::Oidc, "https://127.0.0.1".into()).is_err());
        assert!(CampaignTarget::parse(TargetKind::Oidc, "https://10.0.0.1".into()).is_err());
        assert!(CampaignTarget::parse(TargetKind::Oidc, "https://[fd00::1]".into()).is_err());
        assert!(
            CampaignTarget::parse(TargetKind::Oidc, "https://issuer.localhost".into()).is_err()
        );
    }

    #[test]
    fn scale_evidence_binds_the_raw_result_and_host() {
        let directory = std::env::temp_dir().join(format!(
            "e6irc-qualification-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&directory).expect("create test directory");
        let evidence_path = directory.join("qualification.json");
        let host_path = directory.join("host.txt");
        fs::write(&host_path, "controlled host\n").expect("write host provenance");
        let host_sha256 = sha256_file(&host_path).expect("hash host provenance");
        let result = |target: &str| {
            format!(
                r#"{{"status":"completed","report":{{"format_version":2,"request":{{"addr":"{target}","clients":2,"channels":1,"burst":3,"host_provenance_sha256":"{host_sha256}","thresholds":{{"minimum_connect_rate":1.0,"minimum_fanout_rate":2.0,"maximum_p99_ms":3.0,"maximum_server_rss_per_connection_bytes":4}}}},"outcome":"passed"}}}}"#
            )
        };
        let result_path = directory.join("result.json");
        fs::write(&result_path, result("127.0.0.1:6667")).expect("write result");
        let mut evidence = QualificationEvidence {
            format_version: 2,
            kind: TargetKind::Scale,
            target: CampaignTarget::parse(TargetKind::Scale, "127.0.0.1:6667".into())
                .expect("scale target"),
            source: SourceRevision::parse("a".repeat(40)).expect("source"),
            subject: EvidenceSubject::TargetDaemon(BinaryEvidence {
                sha256: Sha256Digest("b".repeat(64)),
            }),
            host: EvidenceHost::parse("scale-host".into(), "host").expect("host"),
            started_at_unix_ms: now_ms(),
            finished_at_unix_ms: now_ms(),
            workload: Measurements::parse(
                vec![
                    "core_workers=1".into(),
                    "clients=2".into(),
                    "channels=1".into(),
                    "burst=3".into(),
                ],
                "workload",
            )
            .expect("workload"),
            budgets: Measurements::parse(
                vec![
                    "minimum_connect_rate=1".into(),
                    "minimum_fanout_rate=2".into(),
                    "maximum_p99_ms=3".into(),
                    "maximum_rss_per_connection=4".into(),
                ],
                "budget",
            )
            .expect("budgets"),
            credential_environment: Vec::new(),
            scale_artifacts: Some(ScaleArtifacts::capture(&evidence_path).expect("capture raw")),
            probe: ProbeReport {
                authentication: PhaseOutcome::Passed,
                delivery: PhaseOutcome::Passed,
                reconnect: PhaseOutcome::NotApplicable,
                cleanup: PhaseOutcome::Passed,
                persistence: PhaseOutcome::NotApplicable,
            },
            outcome: ClosedOutcome::Passed,
        };
        evidence.validate().expect("validate evidence");
        evidence
            .scale_artifacts
            .as_ref()
            .expect("artifacts")
            .verify_files(&evidence_path, &evidence)
            .expect("verify raw evidence");

        fs::write(&result_path, result("127.0.0.1:6668")).expect("rewrite result");
        assert!(
            evidence
                .scale_artifacts
                .as_ref()
                .expect("artifacts")
                .verify_files(&evidence_path, &evidence)
                .is_err()
        );
        evidence.scale_artifacts =
            Some(ScaleArtifacts::capture(&evidence_path).expect("recapture raw"));
        assert!(
            evidence
                .scale_artifacts
                .as_ref()
                .expect("artifacts")
                .verify_files(&evidence_path, &evidence)
                .is_err()
        );
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn evidence_host_is_a_bounded_non_secret_label() {
        assert!(EvidenceHost::parse("scale-host-01".into(), "--host").is_ok());
        assert!(EvidenceHost::parse("host.example".into(), "--host").is_ok());
        assert!(EvidenceHost::parse("host name".into(), "--host").is_err());
        assert!(EvidenceHost::parse("-host".into(), "--host").is_err());
        assert!(EvidenceHost::parse("host-".into(), "--host").is_err());
    }

    #[test]
    fn required_environment_is_bound_to_target_kind() {
        assert_eq!(
            TargetKind::Discord.required_environment(),
            ["E6IRC_DISCORD_BOT_TOKEN", "E6IRC_DISCORD_CHANNEL_ID"]
        );
        assert_eq!(
            TargetKind::Slack.required_environment(),
            [
                "E6IRC_SLACK_BOT_TOKEN",
                "E6IRC_SLACK_APP_TOKEN",
                "E6IRC_SLACK_CHANNEL_ID"
            ]
        );
        assert_eq!(
            TargetKind::Oidc.required_environment(),
            ["E6IRC_OIDC_CLIENT_ID", "E6IRC_OIDC_CLIENT_SECRET"]
        );
        assert_eq!(TargetKind::PublicIrc.required_environment(), &[] as &[&str]);
    }

    #[test]
    fn each_target_makes_its_non_applicable_phases_explicit() {
        let public_irc = ProbeReport {
            authentication: PhaseOutcome::Passed,
            delivery: PhaseOutcome::NotApplicable,
            reconnect: PhaseOutcome::Passed,
            cleanup: PhaseOutcome::Passed,
            persistence: PhaseOutcome::NotApplicable,
        };
        assert_eq!(
            public_irc.closed_outcome(TargetKind::PublicIrc),
            ClosedOutcome::Passed
        );
        assert_eq!(
            public_irc.closed_outcome(TargetKind::Discord),
            ClosedOutcome::Rejected
        );
        assert!(public_irc.has_valid_applicability(TargetKind::PublicIrc));
        assert!(!public_irc.has_valid_applicability(TargetKind::Discord));
    }
}
