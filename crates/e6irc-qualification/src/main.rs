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

const USAGE: &str = "usage: e6irc-qualification KIND --target TARGET --source REVISION --host HOST --output PATH --workload NAME=VALUE --budget NAME=VALUE [--executable PATH] [--probe PATH [-- PROBE_ARGS...]]\n       e6irc-qualification verify EVIDENCE";

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
    sha256: String,
}

impl BinaryEvidence {
    fn validate(&self) -> Result<(), String> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("subject.sha256 needs a 64-character hexadecimal digest".into());
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
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
        if !self.probe.has_valid_applicability(self.kind) {
            return Err("probe has invalid phase applicability".into());
        }
        if self.probe.closed_outcome(self.kind) != self.outcome {
            return Err("outcome does not match probe phases".into());
        }
        Ok(())
    }
}

fn verify(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let [path] = arguments.as_slice() else {
        eprintln!("e6irc-qualification: verify needs one evidence path\n{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(path);
    let result = fs::read(&path)
        .map_err(|error| format!("cannot read evidence: {error}"))
        .and_then(|bytes| {
            serde_json::from_slice::<QualificationEvidence>(&bytes)
                .map_err(|error| format!("cannot parse evidence: {error}"))
        })
        .and_then(|evidence| {
            evidence.validate()?;
            Ok((evidence.kind.name(), evidence.outcome))
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
        Some(path) => {
            sha256_file(path).map(|sha256| EvidenceSubject::TargetDaemon(BinaryEvidence { sha256 }))
        }
        None => std::env::current_exe()
            .and_then(|path| sha256_file(&path))
            .map(|sha256| EvidenceSubject::QualificationRunner(BinaryEvidence { sha256 })),
    }
}

fn subject_sha256(subject: &EvidenceSubject) -> &str {
    match subject {
        EvidenceSubject::QualificationRunner(binary) | EvidenceSubject::TargetDaemon(binary) => {
            &binary.sha256
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
