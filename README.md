# AI Security Audit Tool

AI-assisted cybersecurity audit tool for evaluating IAM and security controls and generating structured Markdown audit reports.

## Overview

This project simulates a context-aware cybersecurity audit workflow. It analyzes identity and security control settings from structured JSON input and produces a professional-style audit report with:

- Executive Summary
- Risk scoring
- CVSS-style severity mapping
- Framework mapping
- Remediation roadmap
- Report limitations

## Why This Project Matters

Traditional audits are often time-consuming and difficult to operationalize. This project shows how Python can be used to transform security configuration data into readable, actionable findings that support:

- IAM reviews
- control gap analysis
- compliance-oriented reporting
- security engineering documentation

## Features

- IAM control analysis
  - MFA checks
  - password policy review
  - account lockout review
  - session timeout review
  - privileged access review checks

- Security control analysis
  - API rate limiting review
  - centralized logging review
  - file upload validation review
  - WAF status review

- Reporting enhancements
  - report date
  - risk score
  - finding IDs
  - framework mapping
  - remediation roadmap
  - limitations section

## Project Structure

```text
ai-security-audit-tool/
├── .gitignore
├── audit_engine.py
├── README.md
├── report_output.md
├── requirements.txt
├── sample_input.json
└── screenshots/
    └── run.png