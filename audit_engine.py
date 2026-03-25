# AI Security Audit Tool - Core Engine

import json
from datetime import datetime

INPUT_FILE = "sample_input.json"
OUTPUT_FILE = "report_output.md"


def load_input():
    with open(INPUT_FILE, "r") as file:
        return json.load(file)


def analyze_iam(iam):
    findings = []

    if not iam.get("mfa_enabled"):
        findings.append({
            "severity": "HIGH",
            "title": "MFA Not Enabled",
            "issue": "Multi-factor authentication is not enabled for user accounts.",
            "cvss": "8.8",
            "recommendation": "Enable MFA for all users, especially privileged accounts.",
            "framework": "NIST PR.AA / HIPAA Access Control"
        })

    if iam.get("password_policy") == "weak":
        findings.append({
            "severity": "HIGH",
            "title": "Weak Password Policy",
            "issue": "Password complexity requirements are weak or insufficient.",
            "cvss": "8.4",
            "recommendation": "Enforce strong password length, complexity, and rotation policies.",
            "framework": "NIST PR.AA / PCI-DSS 8"
        })

    if not iam.get("account_lockout"):
        findings.append({
            "severity": "MEDIUM",
            "title": "No Account Lockout Policy",
            "issue": "Accounts are not locked after repeated failed login attempts.",
            "cvss": "6.2",
            "recommendation": "Implement account lockout thresholds after repeated failures.",
            "framework": "NIST PR.AC"
        })

    if iam.get("session_timeout_minutes", 0) == 0:
        findings.append({
            "severity": "MEDIUM",
            "title": "No Session Timeout",
            "issue": "User sessions do not appear to expire after inactivity.",
            "cvss": "6.0",
            "recommendation": "Add inactivity timeouts for authenticated sessions.",
            "framework": "NIST PR.AC"
        })

    if not iam.get("privileged_access_review"):
        findings.append({
            "severity": "HIGH",
            "title": "No Privileged Access Reviews",
            "issue": "Privileged accounts are not reviewed on a defined schedule.",
            "cvss": "8.1",
            "recommendation": "Establish recurring privileged access reviews.",
            "framework": "NIST PR.AA / ISO 27001 Access Control"
        })

    return findings


def analyze_security(sec):
    findings = []

    if not sec.get("api_rate_limiting"):
        findings.append({
            "severity": "HIGH",
            "title": "No API Rate Limiting",
            "issue": "Public-facing API endpoints do not appear to enforce rate limiting.",
            "cvss": "8.0",
            "recommendation": "Implement rate limiting and throttling on exposed APIs.",
            "framework": "NIST PR.PT"
        })

    if not sec.get("centralized_logging"):
        findings.append({
            "severity": "HIGH",
            "title": "No Centralized Logging",
            "issue": "Security events are not centrally aggregated for monitoring and investigation.",
            "cvss": "7.8",
            "recommendation": "Enable centralized logging and security event collection.",
            "framework": "NIST DE.CM / HIPAA Audit Controls"
        })

    if not sec.get("file_upload_validation"):
        findings.append({
            "severity": "HIGH",
            "title": "Missing File Upload Validation",
            "issue": "Uploaded files are not validated before acceptance.",
            "cvss": "8.6",
            "recommendation": "Restrict file types, validate content, and scan uploads.",
            "framework": "OWASP A05 / NIST SI"
        })

    if not sec.get("waf_enabled"):
        findings.append({
            "severity": "MEDIUM",
            "title": "WAF Not Enabled",
            "issue": "A web application firewall is not enabled for internet-facing traffic.",
            "cvss": "5.9",
            "recommendation": "Deploy a WAF for public-facing application protection.",
            "framework": "NIST PR.PT"
        })

    return findings


def generate_report(data, findings):
    with open(OUTPUT_FILE, "w") as f:
        f.write("# AI Security Audit Report\n\n")
        f.write(f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Executive Summary
        f.write("## Executive Summary\n\n")
        total_findings = len(findings)
        high_findings = sum(1 for fnd in findings if fnd["severity"] == "HIGH")
        medium_findings = sum(1 for fnd in findings if fnd["severity"] == "MEDIUM")

        risk_score = min((high_findings * 12) + (medium_findings * 6), 100)

        if high_findings >= 4:
            overall_risk = "HIGH"
        elif high_findings >= 1 or medium_findings >= 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        f.write(f"- Total Findings: {total_findings}\n")
        f.write(f"- High Severity Findings: {high_findings}\n")
        f.write(f"- Medium Severity Findings: {medium_findings}\n")
        f.write(f"- Risk Score: {risk_score}/100\n")
        f.write(f"- Overall Risk Level: {overall_risk}\n\n")

        # Target Information
        f.write("## Target Information\n\n")
        f.write(f"- Target System: {data['target_system']}\n")
        f.write(f"- System Type: {data['system_type']}\n")
        f.write(f"- Description: {data['description']}\n")
        f.write(f"- Industry: {data['business_context']['industry']}\n")
        f.write(f"- Data Sensitivity: {data['business_context']['data_sensitivity']}\n")
        f.write(f"- Internet Facing: {data['business_context']['internet_facing']}\n\n")

        # Detailed Findings
        f.write("## Detailed Findings\n\n")

        for index, finding in enumerate(findings, start=1):
            f.write(f"### SA-{index:03d}: {finding['title']}\n")
            f.write(f"- Severity: {finding['severity']}\n")
            f.write(f"- CVSS Score: {finding['cvss']}\n")
            f.write(f"- Issue: {finding['issue']}\n")
            f.write(f"- Recommendation: {finding['recommendation']}\n")
            f.write(f"- Framework Mapping: {finding['framework']}\n\n")

        # Remediation Roadmap
        f.write("## Remediation Roadmap\n\n")
        f.write("### Immediate Actions (0-7 days)\n")
        for finding in findings:
            if finding["severity"] == "HIGH":
                f.write(f"- {finding['title']}\n")

        f.write("\n### Short-Term Actions (1-4 weeks)\n")
        for finding in findings:
            if finding["severity"] == "MEDIUM":
                f.write(f"- {finding['title']}\n")

        f.write("\n## Limitations\n\n")
        f.write("- This report is based on provided configuration input and not on direct system access or live exploitation.\n")
        f.write("- Findings are intended to support defensive review and remediation planning.\n")

    print("Professional audit report generated successfully.")


def main():
    data = load_input()

    iam_findings = analyze_iam(data["iam_controls"])
    security_findings = analyze_security(data["security_controls"])

    all_findings = iam_findings + security_findings

    generate_report(data, all_findings)


if __name__ == "__main__":
    main()