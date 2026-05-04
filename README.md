# ICS-344 DVSA Vulnerability Discovery and Remediation

This repository contains the GitHub-ready course project submission for the OWASP DVSA vulnerability discovery and remediation assignment. The lessons are organized separately and follow the required project structure: goal, root cause, environment, reproduction steps, evidence, mitigation, code/configuration changes, post-fix verification, structured analysis tables, and takeaway.

## Repository Structure

```text
.
├── README.md
├── docs/
│   ├── project-overview.md
│   ├── unified-report.md
│   └── ICS344_DVSA_Unified_Submission_Report_Lessons_1_to_10.docx
├── lessons/
│   ├── lesson-01-.../
│   ├── lesson-02-.../
│   └── ...
├── tools/
└── .gitignore
```

## Included Lessons

| Lesson | Vulnerability / Topic | Folder |
|---:|---|---|
| 1 | Event Injection | [`lessons/lesson-01-event-injection/`](lessons/lesson-01-event-injection/) |
| 2 | Broken Authentication | [`lessons/lesson-02-broken-authentication/`](lessons/lesson-02-broken-authentication/) |
| 3 | Sensitive Data Exposure | [`lessons/lesson-03-sensitive-data-exposure/`](lessons/lesson-03-sensitive-data-exposure/) |
| 4 | Insecure Cloud Configuration | [`lessons/lesson-04-insecure-cloud-configuration/`](lessons/lesson-04-insecure-cloud-configuration/) |
| 5 | Broken Access Control | [`lessons/lesson-05-broken-access-control/`](lessons/lesson-05-broken-access-control/) |
| 6 | Denial of Service (DoS) | [`lessons/lesson-06-denial-of-service-dos/`](lessons/lesson-06-denial-of-service-dos/) |
| 7 | Over-Privileged Function | [`lessons/lesson-07-over-privileged-function/`](lessons/lesson-07-over-privileged-function/) |
| 8 | Logic Vulnerabilities | [`lessons/lesson-08-logic-vulnerabilities/`](lessons/lesson-08-logic-vulnerabilities/) |
| 9 | Vulnerable Dependencies | [`lessons/lesson-09-vulnerable-dependencies/`](lessons/lesson-09-vulnerable-dependencies/) |
| 10 | Unhandled Exceptions | [`lessons/lesson-10-unhandled-exceptions/`](lessons/lesson-10-unhandled-exceptions/) |

## Evidence Handling

Screenshots and extracted evidence images are stored inside each lesson's `evidence/` folder. Sensitive values such as JWTs, session tokens, and private identifiers are redacted or represented with variables such as `$TOKEN`, `$JWT`, and `$API`.

## Submission Notes

- Each lesson has a standalone `README.md`.
- Each lesson has a `CHECKLIST.md` verifying the required report sections.
- The final unified Word report is included in `docs/` for reference.
- The Markdown files are the GitHub-friendly version of the same content.

## Course Context

- Course: ICS-344 Information Security
- Project: DVSA Vulnerability Discovery and Remediation
- Region used in the submitted evidence: `us-east-1` / United States (N. Virginia)
