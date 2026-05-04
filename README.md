# ICS-344 DVSA Vulnerability Discovery and Remediation

This repository contains the GitHub-ready course project submission for the OWASP DVSA vulnerability discovery and remediation assignment. The project documents the identification, exploitation, remediation, and verification of vulnerabilities across the DVSA serverless application.

Each lesson is organized separately and follows the required project structure: goal, root cause, environment and setup, reproduction steps, evidence, mitigation, code/configuration changes, post-fix verification, structured operation/security analysis tables, and takeaway.

---

## Course and Team Information

| Field                    | Value                                                             |
| ------------------------ | ----------------------------------------------------------------- |
| Course                   | ICS-344 Information Security                                      |
| Project                  | DVSA Vulnerability Discovery and Remediation                      |
| Target Application       | OWASP DVSA - Damn Vulnerable Serverless Application               |
| AWS Region Used          | `us-east-1` / United States (N. Virginia)                         |
| Final Report             | `docs/ICS344_DVSA_Unified_Submission_Report_Lessons_1_to_10.docx` |
| Video Evidence Inventory | `video_evidence_inventory_report_format.md`                       |

---

## Team Members

| Student Name     | Student ID |
| ---------------- | ---------- |
| Hussain Albaggal | s202253340 |
| Karrar Alqallaf  | s202267840 |
| Zeyad Alghamdi   | s202269960 |

---

## Repository Structure

```text
.
├── README.md
├── docs/
│   ├── project-overview.md
│   ├── unified-report.md
│   └── ICS344_DVSA_Unified_Submission_Report_Lessons_1_to_10.docx
├── lessons/
│   ├── lesson-01-event-injection/
│   ├── lesson-02-broken-authentication/
│   ├── lesson-03-sensitive-data-exposure/
│   ├── lesson-04-insecure-cloud-configuration/
│   ├── lesson-05-broken-access-control/
│   ├── lesson-06-denial-of-service-dos/
│   ├── lesson-07-over-privileged-function/
│   ├── lesson-08-logic-vulnerabilities/
│   ├── lesson-09-vulnerable-dependencies/
│   └── lesson-10-unhandled-exceptions/
├── tools/
├── video_evidence_inventory_report_format.md
└── .gitignore
```

---

## Included Lessons

| Lesson | Vulnerability / Topic        | Primary Component                            | Folder                                                                                               |
| -----: | ---------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
|      1 | Event Injection              | API Gateway / Lambda / `node-serialize`      | [`lessons/lesson-01-event-injection/`](lessons/lesson-01-event-injection/)                           |
|      2 | Broken Authentication        | Cognito JWT / Authorization handling         | [`lessons/lesson-02-broken-authentication/`](lessons/lesson-02-broken-authentication/)               |
|      3 | Sensitive Data Exposure      | S3 receipt access / API response handling    | [`lessons/lesson-03-sensitive-data-exposure/`](lessons/lesson-03-sensitive-data-exposure/)           |
|      4 | Insecure Cloud Configuration | S3 feedback bucket / Lambda event processing | [`lessons/lesson-04-insecure-cloud-configuration/`](lessons/lesson-04-insecure-cloud-configuration/) |
|      5 | Broken Access Control        | `/dvsa/order` API / DynamoDB order updates   | [`lessons/lesson-05-broken-access-control/`](lessons/lesson-05-broken-access-control/)               |
|      6 | Denial of Service (DoS)      | API Gateway / Lambda concurrency             | [`lessons/lesson-06-denial-of-service-dos/`](lessons/lesson-06-denial-of-service-dos/)               |
|      7 | Over-Privileged Function     | IAM role / SAM template                      | [`lessons/lesson-07-over-privileged-function/`](lessons/lesson-07-over-privileged-function/)         |
|      8 | Logic Vulnerabilities        | Billing and order workflow logic             | [`lessons/lesson-08-logic-vulnerabilities/`](lessons/lesson-08-logic-vulnerabilities/)               |
|      9 | Vulnerable Dependencies      | Unsafe dependency usage                      | [`lessons/lesson-09-vulnerable-dependencies/`](lessons/lesson-09-vulnerable-dependencies/)           |
|     10 | Unhandled Exceptions         | Payment processing error handling            | [`lessons/lesson-10-unhandled-exceptions/`](lessons/lesson-10-unhandled-exceptions/)                 |

---

## Evidence and Deliverables

The repository includes the following project deliverables:

| Deliverable                     | Location                                                          |
| ------------------------------- | ----------------------------------------------------------------- |
| Final unified Word report       | `docs/ICS344_DVSA_Unified_Submission_Report_Lessons_1_to_10.docx` |
| GitHub-friendly lesson writeups | `lessons/lesson-XX-*/README.md`                                   |
| Lesson checklists               | `lessons/lesson-XX-*/CHECKLIST.md`                                |
| Screenshot evidence             | `lessons/lesson-XX-*/evidence/`                                   |
| Video evidence inventory        | `video_evidence_inventory_report_format.md`                       |
| Supporting tools/scripts        | `tools/`                                                          |

Screenshots and extracted evidence images are stored inside each lesson's `evidence/` folder. Sensitive values such as JWTs, session tokens, private API values, and authorization headers are redacted or represented with variables such as `$TOKEN`, `$JWT`, and `$API`.

---

## Report Structure

Each lesson follows the required project format:

1. Goal and vulnerability summary
2. Why this works / root cause
3. Environment and setup
4. Reproduction steps
5. Evidence and proof
6. Fix strategy / probable mitigation
7. Code / configuration changes
8. Verification after fix
9. Structured operation and security analysis
10. Takeaway / lessons learned

Where required, each lesson also includes the structured summary tables:

* **Table A:** Intended rules, artifacts, normal behavior, and exploit behavior
* **Table B:** Deviation analysis, classification, fix applied, and post-fix verification

---

## Security and Privacy Notes

All testing was performed only in the DVSA educational AWS environment prepared for this course project. The repository is intended for academic submission and documentation purposes only.

The following handling rules were applied:

* JWTs, session identifiers, and sensitive request headers are redacted.
* Commands use placeholders such as `$TOKEN`, `$JWT`, and `$API`.
* Screenshots are cropped where needed to avoid exposing sensitive values.
* No real AWS access keys, passwords, or private secrets are included.
* Exploit payloads are documented only as part of the authorized DVSA lab exercise.

---

## Video Evidence

Recording links are listed in:

```text
video_evidence_inventory_report_format.md
```

The video evidence inventory follows the same organization used in the final report. Lessons 1-6 use a single video link, while Lessons 7-10 separate proof/problem explanation videos from solution/verification videos.

---

## Submission Notes

* The final Word report in `docs/` is the primary submission document.
* The lesson folders provide a GitHub-friendly version of the same work.
* Each lesson folder contains its own evidence and checklist.
* The repository structure is designed to make grading easier by separating each vulnerability into its own folder.
* SharePoint video links should be checked before submission to confirm that the required course audience can view them.

---

## References

* OWASP DVSA official repository: [https://github.com/OWASP/DVSA](https://github.com/OWASP/DVSA)
* ICS-344 course project instructions
* AWS Console evidence collected from the DVSA lab deployment
