use anyhow::Context;
use anyhow::bail;
use clap::Parser;
use clap::ValueEnum;
use codex_tui::Cli as TuiCli;
use codex_utils_cli::CliConfigOverrides;
use serde_json::Map;
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::process::Command;

const SECURITY_SCAN_OUTPUT_SCHEMA: &str = include_str!("security_scan.schema.json");

#[derive(Debug, Parser)]
pub struct SecurityCommand {
    #[command(subcommand)]
    pub subcommand: SecuritySubcommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum SecuritySubcommand {
    /// Scan a repository for security vulnerabilities and export findings.
    Scan(SecurityScanArgs),
}

#[derive(Debug, Clone, Parser)]
pub struct SecurityScanArgs {
    /// Report format to emit.
    #[arg(long = "format", value_enum, default_value_t = SecurityOutputFormat::Md)]
    pub format: SecurityOutputFormat,

    /// Output path for the selected format.
    ///
    /// With `--format all`, this path must be a directory.
    #[arg(long = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Shortcut for SARIF output path (equivalent to `--format sarif --out <file>`).
    #[arg(long = "sarif", value_name = "FILE")]
    pub sarif: Option<PathBuf>,

    /// Minimum severity to include in emitted findings.
    #[arg(
        long = "severity-floor",
        value_enum,
        default_value_t = SecuritySeverity::Medium
    )]
    pub severity_floor: SecuritySeverity,

    /// Minimum confidence (0.0-1.0) to include in emitted findings.
    #[arg(long = "confidence-floor", default_value_t = 0.5)]
    pub confidence_floor: f64,

    /// Optional scan scope path(s), relative to repository root.
    #[arg(long = "scope", value_name = "PATH")]
    pub scope: Vec<PathBuf>,

    /// Optional exclusion glob(s).
    #[arg(long = "exclude", value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Maximum number of files to scan.
    #[arg(long = "max-files", default_value_t = 10_000)]
    pub max_files: usize,

    /// Maximum bytes per file to include in scan context.
    #[arg(long = "max-file-bytes", default_value_t = 200_000)]
    pub max_file_bytes: usize,

    /// Disable patch proposal generation.
    #[arg(
        long = "no-patches",
        default_value_t = false,
        conflicts_with = "patches"
    )]
    pub no_patches: bool,

    /// Explicitly enable patch proposal generation.
    #[arg(
        long = "patches",
        default_value_t = false,
        conflicts_with = "no_patches"
    )]
    pub patches: bool,

    /// Apply generated patches (reserved for future implementation).
    #[arg(long = "apply", default_value_t = false)]
    pub apply: bool,

    /// Preferred parallel worker count hint for the model workflow.
    #[arg(long = "parallel", value_name = "N")]
    pub parallel: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SecurityOutputFormat {
    #[default]
    Md,
    Json,
    Sarif,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SecuritySeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }
}

pub async fn run_security_scan(
    args: SecurityScanArgs,
    root_config_overrides: CliConfigOverrides,
    interactive: &TuiCli,
) -> anyhow::Result<()> {
    if !(0.0..=1.0).contains(&args.confidence_floor) {
        bail!("--confidence-floor must be between 0.0 and 1.0");
    }
    if args.apply {
        bail!(
            "--apply is not implemented yet; use proposed diffs from `codex security scan` for manual review."
        );
    }

    let mut schema_file = NamedTempFile::new().context("failed to create temporary schema file")?;
    schema_file
        .write_all(SECURITY_SCAN_OUTPUT_SCHEMA.as_bytes())
        .context("failed to write temporary schema file")?;

    let report_file = NamedTempFile::new().context("failed to create temporary report file")?;
    let prompt = build_scan_prompt(&args);

    let mut command =
        Command::new(std::env::current_exe().context("failed to resolve current executable")?);
    command
        .arg("exec")
        .arg("--skip-git-repo-check")
        .arg("--ephemeral")
        .arg("--color")
        .arg("never")
        .arg("--sandbox")
        .arg("read-only")
        .arg("--output-schema")
        .arg(schema_file.path())
        .arg("--output-last-message")
        .arg(report_file.path());

    if let Some(model) = interactive.model.as_ref() {
        command.arg("--model").arg(model);
    }
    if interactive.oss {
        command.arg("--oss");
    }
    if let Some(provider) = interactive.oss_provider.as_ref() {
        command.arg("--local-provider").arg(provider);
    }
    if let Some(profile) = interactive.config_profile.as_ref() {
        command.arg("--profile").arg(profile);
    }
    if let Some(cwd) = interactive.cwd.as_ref() {
        command.arg("--cd").arg(cwd);
    }
    for add_dir in &interactive.add_dir {
        command.arg("--add-dir").arg(add_dir);
    }

    for override_value in &root_config_overrides.raw_overrides {
        command.arg("-c").arg(override_value);
    }

    // Keep scans local-only by default.
    command.arg("-c").arg("web_search=\"disabled\"");
    command.arg("-c").arg("tools.web_search=false");

    command.arg(prompt);

    let output = command
        .output()
        .await
        .context("failed to execute `codex exec` for security scan")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("security scan command failed:\n{stderr}");
    }

    let raw_report = fs::read_to_string(report_file.path())
        .context("security scan did not produce a final output payload")?;
    let mut parsed_report = parse_scan_report(&raw_report)?;
    filter_findings(
        &mut parsed_report,
        args.severity_floor.rank(),
        args.confidence_floor,
    );

    let markdown = render_markdown_report(&parsed_report);
    let json_report =
        serde_json::to_string_pretty(&parsed_report).context("failed to serialize JSON report")?;
    let sarif_report = serde_json::to_string_pretty(&to_sarif(&parsed_report))
        .context("failed to serialize SARIF report")?;

    let (output_format, output_path) = if let Some(sarif_path) = args.sarif {
        (SecurityOutputFormat::Sarif, Some(sarif_path))
    } else {
        (args.format, args.out)
    };

    emit_reports(
        output_format,
        output_path.as_deref(),
        &markdown,
        &json_report,
        &sarif_report,
    )
}

fn build_scan_prompt(args: &SecurityScanArgs) -> String {
    let mut lines = vec![
        "Run `$security-scan` in scan-only mode and return JSON only.".to_string(),
        "Do not use markdown fences or explanatory prose.".to_string(),
        "The response must be a single JSON object matching the provided output schema."
            .to_string(),
        "Never apply code changes.".to_string(),
        format!(
            "Only include findings with severity >= {} and confidence >= {:.2}.",
            args.severity_floor.as_str(),
            args.confidence_floor
        ),
        format!("Maximum files to consider: {}.", args.max_files),
        format!("Maximum bytes per file: {}.", args.max_file_bytes),
    ];

    if args.scope.is_empty() {
        lines.push("Scope: entire repository root.".to_string());
    } else {
        let scope_paths = args
            .scope
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("Scope paths: {scope_paths}."));
    }

    if !args.exclude.is_empty() {
        lines.push(format!("Exclude globs: {}.", args.exclude.join(", ")));
    }

    if let Some(parallel) = args.parallel {
        lines.push(format!(
            "Parallel scanning hint: use approximately {parallel} workers/subpasses."
        ));
    }

    let include_patches = args.patches || !args.no_patches;
    if include_patches {
        lines.push(
            "For confirmed findings, include minimal `proposed_patch.diff` hunks where practical."
                .to_string(),
        );
    } else {
        lines.push("Set `proposed_patch.diff` to null for all findings.".to_string());
    }

    lines.join("\n")
}

fn parse_scan_report(raw: &str) -> anyhow::Result<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("security scan returned an empty response");
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        validate_scan_report_shape(&value)?;
        return Ok(value);
    }

    if trimmed.starts_with("```") {
        let mut lines = trimmed.lines();
        let _ = lines.next();
        let mut payload_lines = Vec::new();
        for line in lines {
            if line.trim_start().starts_with("```") {
                break;
            }
            payload_lines.push(line);
        }
        let fenced_payload = payload_lines.join("\n");
        if !fenced_payload.trim().is_empty()
            && let Ok(value) = serde_json::from_str::<Value>(fenced_payload.trim())
        {
            validate_scan_report_shape(&value)?;
            return Ok(value);
        }
    }

    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}'))
        && start < end
    {
        let candidate = &trimmed[start..=end];
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            validate_scan_report_shape(&value)?;
            return Ok(value);
        }
    }

    bail!("security scan output was not valid JSON")
}

fn validate_scan_report_shape(value: &Value) -> anyhow::Result<()> {
    let report_obj = value
        .as_object()
        .context("security scan output must be a JSON object")?;
    let findings = report_obj
        .get("findings")
        .and_then(Value::as_array)
        .context("security scan output missing `findings` array")?;

    for (index, finding) in findings.iter().enumerate() {
        if !finding.is_object() {
            bail!("security finding at index {index} is not an object");
        }
    }

    Ok(())
}

fn filter_findings(report: &mut Value, minimum_severity_rank: u8, minimum_confidence: f64) {
    let Some(findings) = report.get_mut("findings").and_then(Value::as_array_mut) else {
        return;
    };

    findings.retain(|finding| {
        let severity_rank = finding
            .get("severity")
            .and_then(Value::as_str)
            .map(severity_rank)
            .unwrap_or_default();
        let confidence = finding
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or_default();
        severity_rank >= minimum_severity_rank && confidence >= minimum_confidence
    });
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn render_markdown_report(report: &Value) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Security Scan Report\n\n");

    if let Some(scope) = report.get("scope").and_then(Value::as_object) {
        if let Some(root) = scope.get("root").and_then(Value::as_str) {
            markdown.push_str(&format!("**Scope root:** `{root}`\n\n"));
        }
        if let Some(paths) = scope.get("paths").and_then(Value::as_array)
            && !paths.is_empty()
        {
            let paths = paths
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            markdown.push_str(&format!("**Paths:** {paths}\n\n"));
        }
    }

    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if findings.is_empty() {
        markdown.push_str("No findings matched the selected severity and confidence thresholds.\n");
        return markdown;
    }

    let mut counts: Map<String, Value> = Map::new();
    for level in ["critical", "high", "medium", "low", "info"] {
        counts.insert(level.to_string(), Value::from(0));
    }
    for finding in &findings {
        if let Some(severity) = finding.get("severity").and_then(Value::as_str) {
            let normalized = severity.to_ascii_lowercase();
            if let Some(existing_count) = counts.get_mut(&normalized)
                && let Some(count) = existing_count.as_i64()
            {
                *existing_count = Value::from(count + 1);
            }
        }
    }

    markdown.push_str("## Summary\n\n");
    for level in ["critical", "high", "medium", "low", "info"] {
        let count = counts
            .get(level)
            .and_then(Value::as_i64)
            .unwrap_or_default();
        markdown.push_str(&format!("- {}: {count}\n", level.to_ascii_uppercase()));
    }
    markdown.push('\n');

    markdown.push_str("## Findings\n\n");
    for finding in findings {
        let id = finding
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("CSS-UNKNOWN");
        let title = finding
            .get("title")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("Security finding");
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_ascii_uppercase();
        let status = finding
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let confidence = finding
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or_default();

        markdown.push_str(&format!("### {id}: {title}\n\n"));
        markdown.push_str(&format!(
            "- Severity: **{severity}**\n- Status: `{status}`\n- Confidence: `{confidence:.2}`\n"
        ));

        if let Some(summary) = finding.get("summary").and_then(Value::as_str)
            && !summary.is_empty()
        {
            markdown.push_str(&format!("- Summary: {summary}\n"));
        }
        if let Some(impact) = finding.get("impact").and_then(Value::as_str)
            && !impact.is_empty()
        {
            markdown.push_str(&format!("- Impact: {impact}\n"));
        }
        if let Some(recommendation) = finding.get("recommendation").and_then(Value::as_str)
            && !recommendation.is_empty()
        {
            markdown.push_str(&format!("- Recommendation: {recommendation}\n"));
        }

        if let Some(files) = finding.get("files").and_then(Value::as_array)
            && !files.is_empty()
        {
            markdown.push_str("- Evidence locations:\n");
            for file in files {
                if let Some(path) = file.get("path").and_then(Value::as_str) {
                    let start = file.get("start_line").and_then(Value::as_i64).unwrap_or(1);
                    let end = file
                        .get("end_line")
                        .and_then(Value::as_i64)
                        .unwrap_or(start);
                    markdown.push_str(&format!("  - `{path}:{start}-{end}`\n"));
                }
            }
        }

        if let Some(diff) = finding
            .get("proposed_patch")
            .and_then(Value::as_object)
            .and_then(|patch| patch.get("diff"))
            .and_then(Value::as_str)
            && !diff.trim().is_empty()
        {
            markdown.push_str("\n```diff\n");
            markdown.push_str(diff);
            if !diff.ends_with('\n') {
                markdown.push('\n');
            }
            markdown.push_str("```\n");
        }

        markdown.push('\n');
    }

    markdown
}

fn to_sarif(report: &Value) -> Value {
    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut rules_by_id: Map<String, Value> = Map::new();
    let mut results = Vec::new();

    for finding in findings {
        if finding
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status.eq_ignore_ascii_case("dismissed"))
        {
            continue;
        }

        let rule_id = finding
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("CSS-UNKNOWN");
        let title = finding
            .get("title")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("Security finding");
        let summary = finding
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or(title);
        let recommendation = finding
            .get("recommendation")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let impact = finding
            .get("impact")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let category = finding
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("security");
        let status = finding
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_ascii_lowercase();
        let level = match severity.as_str() {
            "critical" | "high" => "error",
            "medium" => "warning",
            _ => "note",
        };
        let confidence = finding
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or_default();

        if !rules_by_id.contains_key(rule_id) {
            let cwe = finding
                .get("cwe")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let help_text = if recommendation.is_empty() {
                impact.to_string()
            } else if impact.is_empty() {
                recommendation.to_string()
            } else {
                format!("{recommendation}\n\nImpact:\n{impact}")
            };
            rules_by_id.insert(
                rule_id.to_string(),
                json!({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": { "text": title },
                    "fullDescription": { "text": summary },
                    "help": { "text": help_text },
                    "properties": {
                        "tags": [category],
                        "security-severity": severity,
                        "confidence": confidence,
                        "cwe": cwe
                    }
                }),
            );
        }

        let message = if summary.is_empty() {
            title.to_string()
        } else {
            format!("{title}\n\n{summary}")
        };

        let mut result = json!({
            "ruleId": rule_id,
            "level": level,
            "message": { "text": message },
            "properties": {
                "severity": severity,
                "confidence": confidence,
                "status": status,
                "category": category
            }
        });

        if let Some(files) = finding.get("files").and_then(Value::as_array)
            && let Some(first_location) = files.first()
            && let Some(path) = first_location.get("path").and_then(Value::as_str)
        {
            let mut physical_location = Map::new();
            physical_location.insert("artifactLocation".to_string(), json!({ "uri": path }));

            let mut region = Map::new();
            if let Some(start_line) = first_location.get("start_line").and_then(Value::as_i64) {
                region.insert("startLine".to_string(), Value::from(start_line));
            }
            if let Some(end_line) = first_location.get("end_line").and_then(Value::as_i64) {
                region.insert("endLine".to_string(), Value::from(end_line));
            }
            if !region.is_empty() {
                physical_location.insert("region".to_string(), Value::Object(region));
            }

            if let Some(result_obj) = result.as_object_mut() {
                result_obj.insert(
                    "locations".to_string(),
                    Value::Array(vec![json!({
                        "physicalLocation": Value::Object(physical_location)
                    })]),
                );
            }
        }

        results.push(result);
    }

    let rules = rules_by_id.into_values().collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report
                        .get("tool")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .unwrap_or("codex-security-scan"),
                    "informationUri": "https://developers.openai.com/codex/",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn emit_reports(
    output_format: SecurityOutputFormat,
    output_path: Option<&Path>,
    markdown: &str,
    json_report: &str,
    sarif_report: &str,
) -> anyhow::Result<()> {
    match (output_format, output_path) {
        (SecurityOutputFormat::Md, None) => {
            println!("{markdown}");
        }
        (SecurityOutputFormat::Json, None) => {
            println!("{json_report}");
        }
        (SecurityOutputFormat::Sarif, None) => {
            println!("{sarif_report}");
        }
        (SecurityOutputFormat::All, None) => {
            println!("{markdown}\n---\n");
            println!("{json_report}\n---\n");
            println!("{sarif_report}");
        }
        (SecurityOutputFormat::All, Some(path)) => {
            if path.exists() && !path.is_dir() {
                bail!("--out must be a directory when using --format all");
            }
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create output directory {}", path.display()))?;
            write_text_file(&path.join("security-scan.md"), markdown)?;
            write_text_file(&path.join("security-scan.json"), json_report)?;
            write_text_file(&path.join("security-scan.sarif"), sarif_report)?;
        }
        (SecurityOutputFormat::Md, Some(path)) => {
            write_text_file(path, markdown)?;
        }
        (SecurityOutputFormat::Json, Some(path)) => {
            write_text_file(path, json_report)?;
        }
        (SecurityOutputFormat::Sarif, Some(path)) => {
            write_text_file(path, sarif_report)?;
        }
    }
    Ok(())
}

fn write_text_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parse_scan_report_accepts_fenced_json() {
        let report = parse_scan_report(
            r#"
```json
{"tool":"codex-security-scan","schema_version":"0.1","generated_at":"2026-02-24T00:00:00Z","scope":{"root":".","paths":["."]},"findings":[]}
```
"#,
        )
        .expect("should parse fenced json");

        let findings = report
            .get("findings")
            .and_then(Value::as_array)
            .expect("findings should be an array");
        assert!(findings.is_empty());
    }

    #[test]
    fn filter_findings_applies_floor_thresholds() {
        let mut report = json!({
            "findings": [
                {"id":"CSS-1","severity":"high","confidence":0.9},
                {"id":"CSS-2","severity":"medium","confidence":0.95},
                {"id":"CSS-3","severity":"critical","confidence":0.4}
            ]
        });
        filter_findings(&mut report, SecuritySeverity::High.rank(), 0.5);

        let findings = report["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["id"], "CSS-1");
    }

    #[test]
    fn to_sarif_maps_severity_levels() {
        let report = json!({
            "tool": "codex-security-scan",
            "findings": [{
                "id": "CSS-007",
                "title": "Example",
                "severity": "medium",
                "status": "confirmed",
                "confidence": 0.81,
                "summary": "Summary",
                "impact": "Impact",
                "recommendation": "Fix",
                "category": "injection.sql",
                "files": [{"path":"src/main.rs","start_line": 10, "end_line": 14}]
            }]
        });

        let sarif = to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");
        assert_eq!(
            sarif["runs"][0]["results"][0]["ruleId"],
            Value::String("CSS-007".to_string())
        );
    }

    #[test]
    fn build_scan_prompt_disables_patches_when_requested() {
        let args = SecurityScanArgs {
            format: SecurityOutputFormat::Md,
            out: None,
            sarif: None,
            severity_floor: SecuritySeverity::Medium,
            confidence_floor: 0.5,
            scope: vec![PathBuf::from("src")],
            exclude: vec!["target/**".to_string()],
            max_files: 100,
            max_file_bytes: 2000,
            no_patches: true,
            patches: false,
            apply: false,
            parallel: Some(4),
        };

        let prompt = build_scan_prompt(&args);
        assert!(prompt.contains("Set `proposed_patch.diff` to null"));
        assert!(prompt.contains("Scope paths: src."));
    }
}
