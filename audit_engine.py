# AI Security Audit Tool - Core Engine

import json

INPUT_FILE = "sample_input.json"
OUTPUT_FILE = "report_output.md"


def load_input():
    with open(INPUT_FILE, "r") as file:
        return json.load(file)


def analyze_iam(iam):
    findings = []

    if not iam.get("mfa_enabled"):
        findings.append(("HIGH", "MFA is not enabled"))

    if iam.get("password_policy") == "weak":
        findings.append(("HIGH", "Weak password policy"))

    if not iam.get("account_lockout"):
        findings.append(("MEDIUM", "No account lockout policy"))

    if iam.get("session_timeout_minutes", 0) == 0:
        findings.append(("MEDIUM", "No session timeout"))

    if not iam.get("privileged_access_review"):
        findings.append(("HIGH", "No privileged access reviews"))

    return findings


def analyze_security(sec):
    findings = []

    if not sec.get("api_rate_limiting"):
        findings.append(("HIGH", "No API rate limiting"))

    if not sec.get("centralized_logging"):
        findings.append(("HIGH", "No centralized logging"))

    if not sec.get("file_upload_validation"):
        findings.append(("HIGH", "File upload validation missing"))

    if not sec.get("waf_enabled"):
        findings.append(("MEDIUM", "Web Application Firewall not enabled"))

    return findings


def generate_report(data, findings):
    with open(OUTPUT_FILE, "w") as f:
        f.write("# AI Security Audit Report\n\n")

        # Executive Summary
        f.write("## Executive Summary\n\n")
        total_findings = len(findings)
        high_findings = sum(1 for severity, issue in findings if severity == "HIGH")
        medium_findings = sum(1 for severity, issue in findings if severity == "MEDIUM")

        if high_findings >= 4:
            overall_risk = "HIGH"
        elif high_findings >= 1 or medium_findings >= 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        f.write(f"- Total Findings: {total_findings}\n")
        f.write(f"- High Severity Findings: {high_findings}\n")
        f.write(f"- Medium Severity Findings: {medium_findings}\n")
        f.write(f"- Overall Risk Level: {overall_risk}\n\n")

        # Target Information
        f.write("## Target Information\n\n")
        f.write(f"- Target System: {data['target_system']}\n")
        f.write(f"- System Type: {data['system_type']}\n")
        f.write(f"- Description: {data['description']}\n")
        f.write(f"- Industry: {data['business_context']['industry']}\n")
        f.write(f"- Data Sensitivity: {data['business_context']['data_sensitivity']}\n")
        f.write(f"- Internet Facing: {data['business_context']['internet_facing']}\n\n")

        # Findings
        f.write("## Detailed Findings\n\n")

        for index, (severity, issue) in enumerate(findings, start=1):
            if severity == "HIGH":
                cvss_score = "8.8"
            elif severity == "MEDIUM":
                cvss_score = "6.2"
            else:
                cvss_score = "3.5"

            f.write(f"### Finding {index}: {issue}\n")
            f.write(f"- Severity: {severity}\n")
            f.write(f"- CVSS Score: {cvss_score}\n")
            f.write(f"- Recommendation: Review and remediate {issue.lower()}.\n\n")

        # Remediation Roadmap
        f.write("## Remediation Roadmap\n\n")
        f.write("### Immediate Actions (0-7 days)\n")
        for severity, issue in findings:
            if severity == "HIGH":
                f.write(f"- {issue}\n")

        f.write("\n### Short-Term Actions (1-4 weeks)\n")
        for severity, issue in findings:
            if severity == "MEDIUM":
                f.write(f"- {issue}\n")

        f.write("\n### Long-Term Improvements (1-3 months)\n")
        f.write("- Add Splunk-based evidence ingestion\n")
        f.write("- Add ML-based anomaly scoring\n")
        f.write("- Expand compliance control mapping\n")

    print("Enhanced audit report generated successfully.")

def main():
    data = load_input()

    iam_findings = analyze_iam(data["iam_controls"])
    security_findings = analyze_security(data["security_controls"])

    all_findings = iam_findings + security_findings

    generate_report(data, all_findings)


if __name__ == "__main__":
    main()