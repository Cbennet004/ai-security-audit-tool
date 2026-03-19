\# AI Security Audit Tool



\## Overview



This project simulates an AI-assisted cybersecurity audit system that analyzes IAM and system security controls and generates a structured audit report.



It demonstrates how security context can be transformed into actionable audit findings using Python.



\---



\## Why This Project Matters



Traditional audit reports are often:

\- static

\- hard to interpret

\- slow to generate



This tool shows how automation can:

\- detect misconfigurations

\- prioritize risks

\- generate readable audit reports



\---



\## Features



\- IAM control analysis (MFA, password policy, session controls)

\- Security control validation (logging, API protection, file uploads)

\- Risk scoring logic

\- CVSS-style severity mapping

\- Automated Markdown audit report generation



\---



\## Input



The tool reads from:



\- `sample\_input.json`



The input models:



\- target system details

\- business context

\- IAM controls

\- security controls

\- compliance-related context



\---



\## Output



The tool generates:



\- `report\_output.md`



The report includes:



\- Executive Summary

\- Target Information

\- Detailed Findings

\- Remediation Roadmap



\---



\## Tech Stack



\- Python

\- JSON

\- Markdown

\- PyCharm

\- PowerShell



\---



\## How to Run



From the project directory:



```bash

python audit\_engine.py

