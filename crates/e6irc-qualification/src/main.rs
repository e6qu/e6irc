//! Run credential-gated external qualifications and write safe evidence.

mod native;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: e6irc-qualification KIND --target TARGET --source REVISION --host HOST --executable PATH --output PATH --workload NAME=VALUE --budget NAME=VALUE [--probe PATH [-- PROBE_ARGS...]]";

fn main() -> ExitCode {
    match parse_args(std::env::args_os().skip(1)) {
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

    fn required_credentials(self) -> &'static [&'static str] {
        match self {
            Self::Discord => &["E6IRC_DISCORD_BOT_TOKEN"],
            Self::Slack => &["E6IRC_SLACK_BOT_TOKEN", "E6IRC_SLACK_APP_TOKEN"],
            Self::Oidc => &["E6IRC_OIDC_CLIENT_SECRET"],
            Self::PublicIrc | Self::Scale => &[],
        }
    }
}

#[derive(Clone, Debug, Serialize)]
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
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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
}

#[derive(Debug)]
struct Args {
    kind: TargetKind,
    target: SafeText,
    source: SourceRevision,
    host: SafeText,
    executable: PathBuf,
    output: PathBuf,
    workload: Measurements,
    budgets: Measurements,
    probe: Option<PathBuf>,
    credentials: Vec<CredentialEnv>,
    probe_args: Vec<OsString>,
}

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
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
                target = Some(SafeText::parse(
                    value(&mut arguments, "--target")?,
                    "--target",
                )?)
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
                host = Some(SafeText::parse(value(&mut arguments, "--host")?, "--host")?);
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
    let executable = executable.ok_or_else(|| "--executable is required".to_string())?;
    if !executable.is_file() {
        return Err(format!(
            "--executable is not a regular file: {}",
            executable.display()
        ));
    }
    let kind = TargetKind::parse(&kind)?;
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
    for name in kind.required_credentials() {
        let credential = CredentialEnv::parse((*name).to_string())?;
        if !credentials
            .iter()
            .any(|existing| existing.0 == credential.0)
        {
            credentials.push(credential);
        }
    }
    Ok(Args {
        kind,
        target: target.ok_or_else(|| "--target is required".to_string())?,
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
        let outcomes = self.outcomes();
        if outcomes.contains(&PhaseOutcome::Failed) {
            ClosedOutcome::Failed
        } else if outcomes.iter().enumerate().all(|(index, outcome)| {
            *outcome == PhaseOutcome::Passed
                || (*outcome == PhaseOutcome::NotApplicable && !kind.requires_phase(index))
        }) {
            ClosedOutcome::Passed
        } else {
            ClosedOutcome::Rejected
        }
    }

    fn outcomes(&self) -> [PhaseOutcome; 5] {
        [
            self.authentication,
            self.delivery,
            self.reconnect,
            self.cleanup,
            self.persistence,
        ]
    }
}

impl TargetKind {
    fn requires_phase(self, index: usize) -> bool {
        match self {
            Self::Discord | Self::Slack => true,
            Self::Oidc => matches!(index, 0 | 2 | 3 | 4),
            Self::PublicIrc => matches!(index, 0 | 2 | 3),
            Self::Scale => matches!(index, 0 | 1 | 3),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClosedOutcome {
    Passed,
    Rejected,
    Failed,
}

#[derive(Serialize)]
struct ExecutableEvidence {
    sha256: String,
}

#[derive(Serialize)]
struct QualificationEvidence {
    format_version: u8,
    kind: TargetKind,
    target: SafeText,
    source: SourceRevision,
    executable: ExecutableEvidence,
    host: SafeText,
    started_at_unix_ms: u128,
    finished_at_unix_ms: u128,
    workload: Measurements,
    budgets: Measurements,
    credential_environment: Vec<CredentialEnv>,
    probe: ProbeReport,
    outcome: ClosedOutcome,
}

fn run(args: Args) -> ExitCode {
    let executable_sha256 = match sha256_file(&args.executable) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("e6irc-qualification: cannot hash executable: {error}");
            return ExitCode::FAILURE;
        }
    };
    let started_at_unix_ms = now_ms();
    let challenge = challenge(&args, &executable_sha256, started_at_unix_ms);
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
    let report = if missing_credential {
        ProbeReport::uniform(PhaseOutcome::Rejected)
    } else if args.kind.uses_native_campaign() {
        native::run(args.kind, &args.target.0)
    } else if let Some(probe) = args.probe.as_deref() {
        run_probe(&args, probe, &probe_report_path, &challenge)
    } else {
        ProbeReport::uniform(PhaseOutcome::Failed)
    };
    let outcome = report.closed_outcome(args.kind);
    let evidence = QualificationEvidence {
        format_version: 1,
        kind: args.kind,
        target: args.target,
        source: args.source,
        executable: ExecutableEvidence {
            sha256: executable_sha256,
        },
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

impl TargetKind {
    fn uses_native_campaign(self) -> bool {
        matches!(self, Self::Discord | Self::Slack | Self::Oidc)
    }
}

fn run_probe(args: &Args, probe: &Path, report_path: &Path, challenge: &str) -> ProbeReport {
    let status = Command::new(probe)
        .args(&args.probe_args)
        .env("E6IRC_QUALIFICATION_KIND", args.kind.name())
        .env("E6IRC_QUALIFICATION_TARGET", &args.target.0)
        .env("E6IRC_QUALIFICATION_PROBE_REPORT", report_path)
        .env("E6IRC_QUALIFICATION_CHALLENGE", challenge)
        .status();
    if !matches!(status, Ok(status) if status.success()) {
        return ProbeReport::uniform(PhaseOutcome::Failed);
    }
    let Ok(bytes) = std::fs::read(report_path) else {
        return ProbeReport::uniform(PhaseOutcome::Failed);
    };
    match serde_json::from_slice::<ProbeResult>(&bytes) {
        Ok(result) if result.challenge == challenge => result.report,
        _ => ProbeReport::uniform(PhaseOutcome::Failed),
    }
}

fn challenge(args: &Args, executable_sha256: &str, started_at_unix_ms: u128) -> String {
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
    fn credential_requirements_are_bound_to_target_kind() {
        assert_eq!(
            TargetKind::Discord.required_credentials(),
            ["E6IRC_DISCORD_BOT_TOKEN"]
        );
        assert_eq!(
            TargetKind::Slack.required_credentials(),
            ["E6IRC_SLACK_BOT_TOKEN", "E6IRC_SLACK_APP_TOKEN"]
        );
        assert_eq!(TargetKind::PublicIrc.required_credentials(), &[] as &[&str]);
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
    }
}
