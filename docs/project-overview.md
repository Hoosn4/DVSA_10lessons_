# Project Overview

ICS-344 DVSA Vulnerability Discovery and Remediation

Unified Solution Report for Lessons 1-10

ICS-344 DVSA Vulnerability Discovery and Remediation

| Field | Value |
| --- | --- |
| Course / Section | ICS-344 Information Security / 03 |
| Student Name(s) + ID(s) | Hussain Albaggal |
| DVSA Website URL | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| AWS Region | us-east-1 (United States, N. Virginia) |
| Date | 4 May 2026 |
| Included Lessons | Lessons #1 through #10 |
| Evidence handling | Screenshots are cropped/redacted where needed to avoid exposing JWTs, session identifiers, or sensitive values. |
| Report structure | Each lesson follows the project template: goal, root cause, environment, reproduction, proof, mitigation, code/configuration changes, verification, structured analysis tables, and takeaway. |

Report Scope and Organization

This unified document consolidates the DVSA lesson write-ups into one consistent report format. The lessons are sorted from Lesson #1 to Lesson #10 and use consistent headings, figure captions, evidence tables, code/configuration blocks, verification sections, and the required structured analysis tables.

Security and privacy note: all testing described in this report was limited to the DVSA educational AWS environment. Tokens, session identifiers, and other sensitive values are redacted or represented through local variables such as $TOKEN, $JWT, and $API.

Quick Index of Included Vulnerabilities

| Lesson | Vulnerability | Primary Component | Main Proof | Main Fix |
| --- | --- | --- | --- | --- |
| 1 | Event Injection | API Gateway / DVSA-ORDER-MANAGER / node-serialize | CloudWatch FILE READ SUCCESS marker after crafted payload | Remove unsafe deserialization, use safe JSON parsing, validate actions |
| 2 | Broken Authentication | Cognito JWT / Authorization header | Tampered JWT allowed access to another user's data | Validate JWT signature and claims using Cognito verifier |
| 3 | Sensitive Data Exposure | S3 receipts bucket / API response | ngrok captured response containing S3 download URL and receipt file | Restrict S3 access and avoid exposing direct download URLs |
| 4 | Insecure Cloud Configuration | S3 feedback bucket / Lambda event processing | Malicious S3 object key printed ICS344_L4_SUCCESS in CloudWatch | Validate filenames, remove shell execution, harden S3 bucket policy |
| 5 | Broken Access Control | /dvsa/order, DVSA-ORDER-MANAGER, DynamoDB | Direct update changed DynamoDB itemList without payment/admin approval | Add backend authorization check for the update action |
| 6 | Denial of Service (DoS) | API Gateway / Lambda concurrency | Parallel requests caused 500 errors and instability | Apply API Gateway throttling and request rate control |
| 7 | Over-Privileged Function | IAM role / SAM template.yml | IAM Policy Simulator showed unnecessary S3/DynamoDB permissions | Restrict resources and replace CRUD with least-privilege permissions |
| 8 | Logic Vulnerability | Billing/update workflow and DynamoDB state | Billing and late update both succeeded against conflicting order states | Add atomic conditional writes and state-based update blocking |
| 9 | Vulnerable Dependencies | order-manager.js / node-serialize | CloudWatch marker confirmed dependency gadget execution | Remove unsafe unserialize and parse JSON safely with action allowlisting |
| 10 | Unhandled Exceptions | payment_processing.py | Malformed expiration value caused HTTP 502 and traceback | Validate request shape and handle malformed payment fields safely |
