# SECURITY ENGINEER INTERVIEW PREP - PART 5
# Business Logic Vulnerabilities - Complete Deep Dive
## Jagdeep Singh | 100 Real Q&A

---

## SECTION A: FUNDAMENTALS (Q1-30)

### Q1: What is a business logic vulnerability?
**A:**

A **business logic vulnerability** is a flaw in the design or implementation of an application's intended workflow that allows attackers to abuse legitimate functionality to achieve unintended outcomes. Unlike technical vulnerabilities (XSS, SQLi), business logic flaws don't exploit code bugs — they exploit assumptions developers made about how users would behave.

**Key characteristics:**
- No malicious code/payloads needed
- Uses legitimate features in unintended ways
- Specific to each application's logic
- Hard to detect with automated tools
- Often requires deep understanding of the business

**Classic example:** PepsiCo finding (your bug bounty) — price manipulation from ₹13,750 → ₹1. The site's logic didn't validate that final price matched product price. No SQL injection, no XSS — just exploiting the assumption that users wouldn't tamper with price values.

**Why dangerous:**
- Financial impact direct and immediate
- Bypasses security tools (WAF doesn't catch this)
- Often high CVSS (data integrity / financial loss)
- Bug bounty rewards typically high ($1K-$50K)

### Q2: How do business logic flaws differ from technical vulnerabilities?
**A:**

|
 Aspect 
|
 Technical Vuln 
|
 Business Logic 
|
|
--------
|
---------------
|
----------------
|
|
 Cause 
|
 Code bug 
|
 Design flaw 
|
|
 Detection 
|
 Automated tools find 
|
 Manual testing required 
|
|
 Examples 
|
 XSS, SQLi, RCE 
|
 Price manipulation, race conditions 
|
|
 Payload 
|
 Malicious input 
|
 Legitimate input, unexpected sequence 
|
|
 Universal 
|
 Same across apps 
|
 Unique per app 
|
|
 Fix 
|
 Patch code 
|
 Redesign workflow 
|
|
 Skills needed 
|
 Tech knowledge 
|
 Business understanding 
|

**Technical vuln example:**
```python
# SQL Injection - code bug
query = "SELECT * FROM users WHERE id = " + user_input
```

**Business logic vuln example:**
```python
# No code bug, but logic flaw
def apply_discount(cart, coupon):
    if coupon.is_valid():
        cart.total -= coupon.amount
    return cart  # Doesn't check if total goes negative
```

User applies coupon worth more than cart total → gets paid by company!

### Q3: Why are business logic flaws hard to detect automatically?
**A:**

**Automation challenges:**

1. **No signatures:** Unlike XSS (`<script>`) or SQLi (`' OR 1=1`), no patterns to scan for.

2. **Context-dependent:** What's a flaw in one app might be a feature in another. Scanner can't know intent.

3. **Multi-step exploitation:** Flaws often require sequence of legitimate operations. Scanners test endpoints in isolation.

4. **State-dependent:** Behavior changes based on app state, user role, time, history. Hard to fuzz.

5. **Requires business knowledge:** Scanner doesn't know that "negative price means company pays you."

6. **No clear input/output mapping:** Some flaws span multiple endpoints, hours, sessions.

**Why human testing essential:**

- Understanding business context
- Imagining "what if user did this?"
- Combining features creatively
- Patient multi-step testing
- Recognizing unusual outcomes

**Tools that help (partial):**
- Burp Suite Pro (Logger++)
- Custom scripts for race conditions
- Workflow recording tools
- AI-assisted testing (emerging)

But fundamentally, finding business logic flaws is a creative human skill.

### Q4: What's the OWASP classification for business logic flaws?
**A:**

**OWASP Top 10 2021:** A04 - Insecure Design (new category, includes business logic)

**OWASP API Security Top 10 2023:**
- **API6:** Unrestricted Access to Sensitive Business Flows (new!)

**Both highlight business logic as critical category.**

**Why A04 is new:**
Previous OWASP focused on implementation flaws. 2021 added "Insecure Design" recognizing that:
- Some flaws are design problems, not code problems
- Can't fix with patches — need redesign
- Threat modeling crucial
- "Shift left" — security at design phase

**API6 specifically:**
- Sensitive business flows accessed without rate limits
- Examples: bulk operations, financial transactions, account creation
- Can be exploited without "hacking" — just legitimate API abuse

**Other relevant categories:**
- **A01: Broken Access Control** — Many BL flaws involve authorization
- **A05: Security Misconfiguration** — Workflow misconfigurations
- **A04: Insecure Design** — Primary BL category

### Q5: Real-world business logic flaw examples
**A:**

**Classic examples from breaches and bug bounties:**

**1. Starbucks app (2015):**
- Refund $1 to gift card → balance increases
- Move funds between cards → trigger refund
- Race condition: Multiple simultaneous transfers
- Free unlimited money

**2. United Airlines (2015):**
- Reward miles displayed
- Modify cart to ridiculous amounts
- Some processed before validation

**3. Shopify (multiple):**
- Negative quantity in cart
- Discount applied before quantity check
- Free items or money back

**4. PayPal (historical):**
- Race condition in payment confirmation
- Same payment used multiple times
- Double-spending

**5. Indian travel booking site (real case):**
- Apply promo code → discount applied
- Modify request → discount applied multiple times
- Tickets free or negative price

**6. Your PepsiCo finding:**
- Product price ₹13,750
- Cart total ₹13,750
- Modify cart total → ₹1
- Validation only checked items, not total
- Hall of Fame placement

**7. E-commerce coupon stacking:**
- Apply 50% off coupon
- Apply another 50% off coupon
- Apply $20 off coupon
- Result: -$5 (company pays user)

**8. Trading platform (real bug bounty):**
- Buy stocks
- Cancel immediately
- Race condition: Order both processed AND refunded
- Free stocks

**9. Loyalty point exploits:**
- Transfer points between accounts
- Convert to cash
- Race condition during transfer = duplication

**10. Airline class upgrade:**
- Buy economy
- Cancel within free window
- But upgrade processed first
- Keep business class, get refund

### Q6: What's the CVSS scoring for business logic flaws?
**A:**

**Typical CVSS ranges:**

**Low impact BL flaw (5.0-6.9):**
- View other users' non-sensitive data
- Limited financial impact
- Easily detected/reversed

**Medium impact (7.0-7.9):**
- Modify own data inappropriately
- Single-user financial impact
- Workflow bypass

**High impact (8.0-8.9):**
- Manipulate prices/discounts
- Skip payment
- Account takeover via workflow
- Mass exploitation possible

**Critical (9.0-10.0):**
- Unlimited money generation
- Mass account compromise
- Critical infrastructure manipulation
- Direct financial loss to company

**CVSS challenges for BL flaws:**

**Issue 1:** Standard CVSS designed for technical vulns. Doesn't capture business impact well.

**Issue 2:** "Impact" subjective:
- $1 free coupon = annoying
- Unlimited free coupons = company shutdown

**Issue 3:** Authorization context matters:
- Auth required: PR:L
- No auth: PR:N (higher CVSS)

**Example calculations:**

**Price manipulation (PepsiCo style):**
```
AV:N (network) AC:L (low) PR:L (need account)
UI:N S:U C:N I:H (modify orders) A:N
Score: 6.5 (Medium) or 8.1 (High) if mass exploitable
```

**Free money generation:**
```
AV:N AC:L PR:L UI:N S:C (impacts whole org)
C:N I:H A:N
Score: 8.1 or higher
```

**Account takeover via workflow:**
```
AV:N AC:L PR:N (pre-auth) UI:R (some user action)
S:C C:H I:H A:H
Score: 9.0+
```

### Q7: How do you systematically find business logic flaws?
**A:**

**My methodology:**

**Step 1: Map the application thoroughly**
- All user roles
- All workflows
- All state transitions
- All financial operations
- All limits and quotas

**Step 2: Identify trust boundaries**
- Where does user input become trusted?
- What validations happen where?
- What happens on different paths?

**Step 3: Look for assumptions**
- "User won't do X"
- "This always happens before Y"
- "Y can only be triggered by Z"

**Step 4: Test breaking assumptions**

**Common questions to ask:**
- Can I do this without the prerequisite step?
- Can I do it multiple times when expected once?
- Can I do it concurrently?
- Can I send unexpected values?
- Can I modify what shouldn't be modifiable?
- Can I skip required steps?
- Can I go backwards in workflow?

**Step 5: Combine features**
- Two features alone safe
- Combined unexpectedly?
- Edge cases at intersection

**Step 6: Test boundaries**
- Negative numbers
- Zero
- Maximum values
- Empty strings
- Special characters
- Type confusion

**Step 7: Time-based testing**
- Race conditions
- Timing windows
- Stale state usage

**Step 8: Document and validate**
- Reproduce reliably
- Quantify impact
- Suggest fix

### Q8: Common categories of business logic flaws
**A:**

**Major categories:**

**1. Workflow bypass:**
- Skip required steps
- Reach final state without intermediate
- Backward navigation

**2. Race conditions:**
- Concurrent operations
- Time-of-check vs time-of-use (TOCTOU)
- State manipulation between steps

**3. Price/discount manipulation:**
- Negative prices
- Multiple discount stacking
- Currency mismatch
- Decimal manipulation

**4. Quantity manipulation:**
- Negative quantities
- Zero quantities
- Excessive quantities
- Decimal manipulation

**5. Authentication context abuse:**
- Use auth token after logout
- Cross-session contamination
- Multiple session abuse

**6. Authorization context abuse:**
- Permission inherited inappropriately
- Role transitions
- Approval bypass

**7. Limit/quota bypass:**
- Rate limit bypass
- Trial period extension
- Resource limit bypass

**8. Currency/numeric tricks:**
- Integer overflow
- Floating point precision
- Currency conversion abuse

**9. State manipulation:**
- State machine bypass
- Stale state usage
- Forced state transitions

**10. Business rule violations:**
- KYC bypass
- Age verification bypass
- Geographic restriction bypass

### Q9: How to identify race condition vulnerabilities?
**A:**

**Race condition** = Outcome depends on timing of concurrent events. Two operations modifying same data can produce unexpected results.

**Classic example:**

```python
def transfer_money(from_account, to_account, amount):
    if from_account.balance >= amount:  # CHECK
        from_account.balance -= amount    # USE
        to_account.balance += amount
```

Sequential attack:
- Account has $100
- Transfer $100 to account A
- Transfer $100 to account B simultaneously
- Both checks pass before either deduction
- Account ends at -$100, both transfers succeed
- Created $100 from nothing

**Detection signs:**

**Likely race conditions:**
- "Last write wins" semantics
- Atomic operations not used
- Multi-step processes
- Financial transactions
- Counter increments
- Status changes
- Resource allocation

**Where to look:**
- Account funding
- Coupon redemption
- Inventory updates
- Like/vote counters
- Friend requests
- Profile updates with limits
- Subscription cancellations

**Testing technique:**

**Manual:**
- Open multiple browser tabs
- Submit same form simultaneously
- Look for inconsistent results

**Automated:**
```python
import asyncio
import aiohttp

async def make_request(session):
    return await session.post('/api/transfer', json={
        'to': 'attacker',
        'amount': 100
    })

async def race():
    async with aiohttp.ClientSession() as session:
        # Send 20 concurrent requests
        tasks = [make_request(session) for _ in range(20)]
        responses = await asyncio.gather(*tasks)
        
        # How many succeeded?
        success = sum(1 for r in responses if r.status == 200)
        print(f"Successful: {success}")
```

**Burp Suite Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)
    
    for i in range(30):
        engine.queue(target.req)
    
    engine.start()
```

Sends 30 simultaneous requests, perfect for race conditions.

### Q10: Time-of-check vs Time-of-use (TOCTOU) vulnerabilities
**A:**

**TOCTOU** = Specific type of race condition where security check and resource use happen at different times.

**Pattern:**
```
1. Check authorization
2. ... delay ...
3. Use resource
```

Between 1 and 3, state can change.

**Classic example:**
```python
def withdraw(amount):
    if account.balance >= amount:  # CHECK (time T1)
        # Delay: log, validate, etc.
        ...
        account.balance -= amount  # USE (time T2)
```

Between T1 and T2:
- Another thread reads same balance
- Both pass check
- Both deduct
- Negative balance

**TOCTOU in file systems (classic):**
```c
if (access("file.txt", W_OK) == 0) {
    // ... permission check passed
    fd = open("file.txt", O_WRONLY);  // But file changed between!
    // Symbolic link swap exploit possible
}
```

**TOCTOU in web apps:**

**Coupon redemption:**
```python
def apply_coupon(coupon_code, user):
    coupon = Coupon.get(coupon_code)
    if not coupon.used and coupon.user == user:  # CHECK
        # Time gap
        order.discount = coupon.amount
        order.save()
        coupon.used = True  # USE
        coupon.save()
```

Race: Apply same coupon multiple times concurrently before `used=True` saved.

**Gift card redemption:**
```python
def redeem_gift_card(code):
    card = GiftCard.get(code)
    if card.balance > 0:  # CHECK
        amount = card.balance
        order.credit(amount)
        # Time gap
        card.balance = 0  # USE
        card.save()
```

Race: Multiple redemptions before balance set to 0.

**Defense:**

**1. Atomic operations:**
```python
# Database-level atomicity
@transaction.atomic
def withdraw(amount):
    account = Account.objects.select_for_update().get(id=account_id)
    if account.balance >= amount:
        account.balance -= amount
        account.save()
```

**2. Optimistic locking:**
```python
account = Account.objects.get(id=account_id)
version = account.version

# Update with version check
updated = Account.objects.filter(
    id=account_id,
    version=version
).update(
    balance=F('balance') - amount,
    version=version + 1
)

if updated == 0:
    raise ConcurrentModificationError()
```

**3. Database constraints:**
```sql
ALTER TABLE accounts ADD CONSTRAINT positive_balance
    CHECK (balance >= 0);
```

**4. Idempotency keys:**
```python
def transfer(idempotency_key, amount):
    if Transfer.objects.filter(idempotency_key=idempotency_key).exists():
        return existing_transfer
    # Process
```

### Q11: How to find workflow bypass vulnerabilities?
**A:**

**Workflow bypass:** Skipping required steps in a multi-step process.

**Common workflows:**
- Registration → Email verification → Activation
- Cart → Address → Payment → Confirmation
- KYC: Personal info → Document upload → Verification → Approval
- Approval workflows: Submit → Manager review → Approval → Action

**Bypass techniques:**

**1. Direct URL access:**

```
Normal flow: /step1 → /step2 → /step3 → /step4
Bypass: Directly access /step4 (skip 1, 2, 3)
```

**2. Hidden field manipulation:**

```html

```

Change to:
```html

```

**3. URL parameter manipulation:**

```
?stage=verification → ?stage=approved
```

**4. JSON state modification:**

```json
{"workflow_state": "pending_review"}
```

Change to:
```json
{"workflow_state": "approved"}
```

**5. Replay completed step:**

Captured request from successful flow, replay later with modified data.

**6. Skip via different endpoint:**

Some flows have admin/alternate endpoints. Find via:
- JavaScript code analysis
- Old API versions
- Documentation
- Wayback Machine

**Testing methodology:**

1. **Map the workflow:**
   - Complete the flow normally
   - Document each step's request/response
   - Note state changes

2. **Test each step:**
   - Skip step 2, try step 3
   - Skip step 3, try step 4
   - Try to access "completed" state

3. **Manipulate state parameters:**
   - Look for state in URLs, hidden fields, cookies
   - Modify to advanced state

4. **Backward navigation:**
   - Try going back after completion
   - Modify completed steps

**Real example - account verification bypass:**

**Normal flow:**
```
1. POST /signup → user created (status: pending)
2. Email sent → user clicks link
3. POST /verify-email → user activated (status: active)
4. GET /dashboard → access granted
```

**Bypass:**
- Skip step 2-3
- Directly POST `/activate-account` (found via JS analysis)
- Now active without email verification
- Login proceeds

**Impact:**
- Spam accounts
- Fake account creation at scale
- KYC bypass in regulated industries

### Q12: Discount/coupon manipulation testing
**A:**

**Coupon abuse vectors:**

**1. Multiple application of same coupon:**

```
POST /cart/apply-coupon
{"code": "SAVE50"}

Repeat 10 times:
- If coupon doesn't track per-cart usage, applies 10 times
- 500% off discount!
```

**2. Coupon stacking (when not allowed):**

```
Apply COUPON1 (10% off)
Apply COUPON2 (15% off)
Apply COUPON3 (20% off)
...
Total: 100%+ off (free or company pays you)
```

**3. Negative price exploitation:**

```
Cart: $100
Coupon: $150 off
Total: -$50

If app refunds difference → company pays $50
```

**4. Cross-account coupon reuse:**

```
Coupon valid once per account
Create multiple accounts
Apply on each
```

**5. Race condition on coupon usage:**

```python
def apply_coupon(code):
    coupon = Coupon.get(code)
    if coupon.uses_remaining > 0:  # TOCTOU
        cart.discount = coupon.amount
        coupon.uses_remaining -= 1
        coupon.save()
```

Concurrent applications all pass check.

**6. Coupon enumeration:**

```
COUPON1, COUPON2, ... predictable codes
SAVE10, SAVE20, ... brand patterns
SUMMER2026, FALL2026, ... seasonal
ADMIN50OFF, EMPLOYEE100 ... internal codes
```

**7. Internal coupon codes:**

Sometimes employee codes leaked:
- WELCOME (10% off)
- VIPCUSTOMER (50% off)
- EMPLOYEE100 (free!)

**8. Currency conversion abuse:**

```
Apply $100 coupon
Convert to INR: ₹8000
But original currency was USD, internal logic confused
```

**9. Decimal precision:**

```
Apply coupon: 0.0001% discount
Stack 1000000 times
0.0001 * 1000000 = 100% discount
```

**10. Coupon for premium features:**

```
Premium-only coupon
Apply on free tier order
Unlocks premium features for free
```

**Testing approach:**

1. Look at coupon application requests
2. Try concurrent applications
3. Modify coupon parameters
4. Test negative values
5. Cross-account reuse
6. Look for admin coupon endpoints

### Q13: Price manipulation - your PepsiCo finding deep dive
**A:**

**Your real-world bug bounty example:**

**Scenario:**
- E-commerce site (PepsiCo)
- Product price: ₹13,750
- Vulnerability: Final price not validated server-side

**Attack chain:**

**Step 1: Add product to cart**
```
POST /api/cart/add
{
  "product_id": "12345",
  "quantity": 1
}
```

**Step 2: Initiate checkout - intercept request**
```
POST /api/checkout/initiate
{
  "cart_id": "cart_xyz",
  "total": 13750,
  "items": [
    {
      "product_id": "12345",
      "quantity": 1,
      "price": 13750
    }
  ]
}
```

**Step 3: Modify total in request**
```
POST /api/checkout/initiate
{
  "cart_id": "cart_xyz",
  "total": 1,          ← Modified
  "items": [
    {
      "product_id": "12345",
      "quantity": 1,
      "price": 13750
    }
  ]
}
```

**Step 4: Payment processed for ₹1**
- Server trusted client-side total
- No verification against database product price
- Order placed for ₹1

**Why this worked:**

1. **Client-side trust:** Server accepted user-provided total
2. **No validation:** Didn't recompute from items
3. **No integrity check:** No hash/signature
4. **Single source of truth missing:** Multiple sources, conflicting

**Variations of price manipulation:**

**1. Quantity * unit price calculation:**
```
Modify unit price in request
Server multiplies by quantity
Total = manipulated value × quantity
```

**2. Currency manipulation:**
```
Order in USD
Switch to weak currency in request
Pay in different currency
```

**3. Tax manipulation:**
```
Remove tax field
Or set negative tax
Total decreases
```

**4. Shipping manipulation:**
```
Add huge negative shipping cost
Subtotal goes negative
```

**5. Discount manipulation:**
```
Set discount > total
Net amount negative
```

**6. Decimal manipulation:**
```
Total: 100.00
Modify to: 0.10
Decimal placement abuse
```

**Defense:**

```python
@checkout_endpoint
def process_checkout(request):
    cart = Cart.objects.get(id=request.data['cart_id'])
    
    # ALWAYS recompute server-side
    actual_total = 0
    for item in cart.items.all():
        # Use DATABASE price, not user-supplied
        product = Product.objects.get(id=item.product_id)
        actual_total += product.price * item.quantity
    
    # Apply discounts (validated)
    if cart.coupon:
        actual_total -= cart.coupon.amount
    
    # Compare with user-supplied total (audit)
    if abs(actual_total - request.data['total']) > 0.01:
        log_suspicious_activity(request.user, "Total mismatch")
        return error("Total mismatch")
    
    # Process payment for ACTUAL total
    process_payment(amount=actual_total)
```

**Bug bounty value:**
- PepsiCo placement: Hall of Fame
- Similar findings: $1K-$50K depending on company
- Critical because: direct financial impact

### Q14: How to test for quantity manipulation?
**A:**

**Quantity manipulation flaws:**

**1. Negative quantities:**

```
POST /cart/add
{"product_id": "shoes", "quantity": -1}
```

**Possible outcomes:**
- Total decreases (refund-like behavior)
- Stock increases (free inventory)
- Order placed for "negative shoes"
- Money flow reverses

**2. Zero quantities with side effects:**

```
{"product_id": "premium", "quantity": 0}
```

Some apps:
- Free trial unlocked
- Premium status granted (the item was the upgrade)
- Coupon counted as used despite zero qty

**3. Massive quantities (overflow):**

```
{"quantity": 99999999999}
```

May cause:
- Integer overflow (becomes negative)
- Float precision loss
- DB errors revealing info
- Pricing miscalculation

**4. Decimal quantities:**

```
{"quantity": 0.5}
```

For non-divisible items:
- 0.5 shoes ordered
- Price * 0.5 = half price
- Item delivered (server rounds up?)

**5. String quantities:**

```
{"quantity": "1"}
{"quantity": "1; DROP TABLE"}
{"quantity": "abc"}
```

Type confusion bypasses validation.

**6. Multiple items, mixed quantities:**

```
{
  "items": [
    {"product": "free_item", "quantity": 100},
    {"product": "expensive", "quantity": -99}
  ]
}
```

Stacking exploits.

**Testing approach:**

1. **Find quantity inputs:**
   - Add to cart forms
   - Quantity updaters
   - Bulk operations
   - Subscription quantity

2. **Boundary testing:**
   - -1, 0, 1
   - Max int (2147483647)
   - Max int + 1 (overflow)
   - Decimals
   - Strings
   - Scientific notation (1e9)

3. **Combination testing:**
   - With discounts
   - With shipping
   - With tax

4. **Observe behaviors:**
   - Final price calculation
   - Stock changes
   - Order status
   - Confirmation emails

**Real example - airline tickets:**

```
POST /booking/passengers
{
  "adults": 1,
  "children": -1,    ← Subtracts child price from total
  "infants": 0
}
```

If child price = $200, total reduced by $200.

### Q15: Currency and decimal exploitation
**A:**

**Currency-based business logic flaws:**

**1. Currency conversion exploitation:**

```
Step 1: Set currency to USD
Step 2: Add $100 to cart
Step 3: Switch currency to INR (weaker)
Step 4: System converts: $100 = ₹8000
Step 5: But payment processed in USD as $100
Step 6: Order worth ₹8000 for $100 (or vice versa)
```

**2. Currency mismatch:**

```
Order placed in EUR: €100
Payment gateway sees USD
Pays $100 (which is ~€88)
Saves €12 per order
```

**3. Conversion rate manipulation:**

```
Application calls API for rate
Cache rate for performance
Submit order when rate cached old
But payment uses live rate
Difference exploited
```

**4. Decimal precision attacks:**

**Floating point issues:**
```python
0.1 + 0.2  # = 0.30000000000000004 in many languages

# Accumulated:
0.1 * 1000000  # Should be 100000
# Actually: 100000.00000001234
```

Pricing edge cases.

**5. Rounding direction:**

```python
def calculate_total(items):
    total = sum(item.price * item.quantity for item in items)
    return round(total)  # Rounds 0.5 to 0 (banker's rounding)

# Item: $0.49
# Bought 10
# Total: $4.90
# Rounded: $5

# But:
# Item: $0.51
# Bought 10
# Total: $5.10
# Rounded: $5
```

Choose direction strategically.

**6. Stripe/payment processor precision:**

Some processors require cents (integer):
- $10.50 = 1050 cents
- But some apps confuse units
- Send 1050 thinking dollars
- Charged $1050!

(Real bugs in major apps)

**7. Negative decimal:**

```
Cart: $100
Apply discount: $0.0001 off
Repeat 1,000,000 times: $100 discount

But individually: tiny discount, no flag raised
```

**8. Currency symbol manipulation:**

Some apps display currency symbol from user input:
```
"$100" vs "₹100" vs "JPY 100"
```

If symbol affects backend processing → exploit.

**9. Free trial currency arbitrage:**

```
Free trial in US: 30 days
Same trial in India: 30 days
Switch currency mid-trial
Trial extends?
```

**Testing approach:**

1. Identify currency handling
2. Try switching mid-transaction
3. Use unusual decimal values
4. Test rounding behaviors
5. Stack tiny amounts
6. Mismatch declared vs actual currency

### Q16: Authentication context abuse
**A:**

**Using auth in unintended contexts:**

**1. Use after logout:**

```python
# Login
POST /login → SESSION cookie

# Logout
POST /logout → "Logged out"

# Use saved session anyway
GET /dashboard
Cookie: SESSION=

# Still works? Session not properly invalidated!
```

**2. Use after password change:**

```
1. Login from Device A → SESSION_A
2. Change password from Device B
3. Use SESSION_A still works?
```

Should invalidate all sessions on password change.

**3. Cross-tenant abuse:**

```
Login to Tenant A
Get auth token
Use token on Tenant B's endpoint
Token still works?
```

**4. Authentication for one service used elsewhere:**

```
Login to /api/v1/
Get token
Use token on /admin/api/
Different service trusts token?
```

**5. Tokens after account deletion:**

```
1. Generate API key
2. Delete account
3. Use API key
4. Still works? (Should be revoked)
```

**6. Service account abuse:**

```
Service account for backend
Find way to extract its token
Use externally
Much higher permissions than user accounts
```

**7. Impersonation features:**

```
Admin can "Login as user X"
Generates session for user X
Audit trail?
Persistent after admin logout?
```

**8. Mobile vs web auth:**

```
Login via mobile app (longer tokens)
Use mobile token on web
Different security model
```

**Testing approach:**

1. Login, capture all auth materials
2. Logout, try same materials
3. Change password, try old materials
4. Delete account, try residual tokens
5. Test cross-service token usage
6. Look for "impersonate" features

### Q17: How to test for rate limit bypass?
**A:**

**Rate limit bypass techniques:**

**1. Header manipulation:**

```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Forwarded-Host: ...
X-Originating-IP: ...
```

Rate limiter checks header for IP, allows new "IP" each request.

**2. User-Agent rotation:**

If rate limit per IP+UA:
```
Request 1: User-Agent: Mozilla/5.0...
Request 2: User-Agent: Chrome/91...
Request 3: User-Agent: random_string
```

Each unique combination = separate limit bucket.

**3. Authentication switching:**

If rate limit per-user:
```
Account 1: 10 requests
Account 2: 10 requests
Account 3: 10 requests
...
```

**4. Path variations:**

```
/api/users          (rate limited)
/api/users/         (with slash - different path?)
/api//users         (double slash)
/api/users?dummy=1  (different query)
/api/Users          (case sensitivity)
```

**5. HTTP method switching:**

```
GET /api/data       (rate limited)
POST /api/data      (separate limit?)
HEAD /api/data
OPTIONS /api/data
```

**6. Subdomain rotation:**

```
api.example.com
api1.example.com
backup.example.com
```

If different subdomains have separate limits.

**7. Token reuse:**

```
Get token at T0
Use 10 times (limit reached)
Get new token at T1
Use 10 more times
```

If new tokens reset limits.

**8. Distributed attack:**

```
Multiple IPs (cloud functions, residential proxies)
Each below rate limit individually
Combined = exceed limit
```

**9. Burst window timing:**

```
Limit: 10/minute
At 0:00 - 10 requests (limit reached)
At 0:59 - wait
At 1:00 - 10 more requests (new window)
```

Burst at window edges.

**10. Rate limit storage attack:**

```
If limits stored in Redis with TTL
Many users hammering = Redis pressure
Limits fail open
```

**Testing methodology:**

1. **Identify rate limits:**
   - Hit endpoint repeatedly
   - Note when 429 returned
   - Test recovery time

2. **Try header tricks** - X-Forwarded-For, etc.

3. **Account hopping** - Multiple accounts

4. **Find different endpoints** with same effect

5. **Test edge cases** - Method, path, case

### Q18: How does parameter pollution affect business logic?
**A:**

**HTTP Parameter Pollution (HPP):**

```
GET /api/transfer?amount=100&amount=10
```

Different backends handle differently:
- Take first: amount=100
- Take last: amount=10
- Combine: amount=100,10
- Array: amount=[100,10]

**Business logic exploits:**

**1. Discount pollution:**

```
POST /apply-discount
discount=50&discount=99
```

If frontend says 50% but backend takes max → 99%.

**2. Permission pollution:**

```
POST /api/action
role=user&role=admin
```

Backend might take last value → role=admin.

**3. Recipient pollution:**

```
POST /api/send-message
to=victim@example.com&to=attacker@example.com
```

Message sent to both.

**4. Currency pollution:**

```
POST /checkout
amount=100&currency=USD&currency=INR
```

Charged in cheaper currency.

**5. Quantity pollution:**

```
POST /cart
items=item1&quantity=1&quantity=0
```

Order placed but billed for 0.

**6. Authentication pollution:**

```
GET /api/user
user_id=100&user_id=101
```

Some implementations: returns data for both, or wrong user.

**Different frameworks:**

|
 Framework 
|
 Default Behavior 
|
|
-----------
|
------------------
|
|
 PHP 
|
 Takes last value 
|
|
 Java (Tomcat) 
|
 Takes first value 
|
|
 ASP.NET 
|
 Combines (comma-separated) 
|
|
 Python (Django) 
|
 Takes last (depends on parser) 
|
|
 Node.js (Express) 
|
 Array 
|

**Real example - payment processor:**

```
POST /process-payment
amount=10000&currency=USD&amount=10
```

Pay $10 for $10,000 order.

**Testing:**

1. Identify parameters in requests
2. Duplicate each parameter
3. Use different values
4. Observe backend behavior
5. Look for inconsistencies

### Q19: How to find authorization business logic flaws?
**A:**

**Authorization context flaws:**

**1. Operation only checks permission existence, not context:**

```python
def update_order(order_id, user):
    if user.has_permission('update_order'):  # Permission check
        order = Order.get(order_id)
        order.update(...)  # But doesn't check if user owns order!
```

User has `update_order` permission for their orders, but uses it on others' orders.

**2. Permission inheritance issues:**

```
Manager → can approve team's expenses
Manager promoted → keeps Manager role + new role
Now has approvals for old team AND new team
Cross-team approval abuse
```

**3. Time-bound permissions not enforced:**

```python
# Temporary permission for project
user.grant_permission('project_x_admin', expires=tomorrow)

# Day later
if user.has_permission('project_x_admin'):  # Checks existence, not expiration
    allow()
```

**4. Approval chain bypass:**

```
Normal: Submit → Manager → Director → CFO
Bypass: Submit directly to CFO endpoint?
```

**5. Workflow state machine bypass:**

```
States: draft → submitted → reviewed → approved
Bypass: draft → approved (skipping)
```

**6. Inherited permissions:**

```
User in Group A
Group A in Group B  
Group B has admin access
User → A → B → admin
```

May not be intended.

**7. Trust chains:**

```
Service A trusts Service B
Service B trusts Service C  
Service C has user input
Indirect attacker → trusted service
```

**Real bug bounty example:**

**Slack workspace promotion (real bug):**

- Free workspace had user X as admin
- User X invited to PAID workspace as guest
- Permission inherited from somewhere
- Guest in paid workspace had admin rights
- Could see private channels, etc.

**Testing:**

1. **Map all permissions:**
   - What roles exist?
   - What can each do?
   - When can they do it?
   - On what objects?

2. **Test all combinations:**
   - Role X on object owned by role Y
   - Permission used in different contexts
   - Time-based permissions after expiry

3. **Look for state changes:**
   - Permissions during transitions
   - Race conditions in grants/revokes

### Q20: Common business logic flaws in e-commerce
**A:**

**E-commerce specific BL flaws:**

**1. Free shipping abuse:**

```
Free shipping threshold: $50
Add items totaling $50 → free shipping
Remove items after checkout starts
Final order $20 with free shipping
```

**2. Loyalty point manipulation:**

```
Earn 100 points per $1
Buy and return → keep points
Repeat → unlimited points
```

**3. Refund abuse:**

```
Return an item
Buy same item
Use refund to fund purchase
But return processed AFTER new purchase
Both refund and new item in possession
```

**4. Inventory race conditions:**

```
Only 1 item left
2 users both add to cart simultaneously
Both checkouts succeed
Inventory goes negative
Both expect delivery
```

**5. Cart manipulation:**

```
Add expensive item ($1000)
Coupon applies (50% off)
Switch item to cheap ($10)
Coupon still applied
Pay $5 for $10 item (or other anomaly)
```

**6. Gift card stacking:**

```
Gift card $100
Order total $150
Apply twice somehow → $200 credit
Order paid, get $50 back?
```

**7. Subscription manipulation:**

```
Monthly plan: $10
Yearly plan: $100 (save $20)
Switch between mid-cycle
Get yearly benefits, pay monthly?
```

**8. Auction sniping/manipulation:**

```
Last-second bidding
Race conditions
Bid stacking
```

**9. Returns/exchanges:**

```
Return policy: 30 days
Order at day 25
Exchange to different product
New 30-day clock starts on exchange
Infinite return cycle
```

**10. Product recommendation manipulation:**

```
Algorithm suggests based on cart
Inject items to manipulate
SEO for hostile products
```

### Q21: API rate limiting business logic abuse (OWASP API6)
**A:**

**OWASP API6 - Unrestricted Access to Sensitive Business Flows**

**Examples:**

**1. Bulk operations without limits:**

```
POST /api/users/bulk
[user1, user2, ..., user10000]
```

If no limit, can:
- Mass create accounts
- DDoS via signups
- Spam database

**2. Financial operations bulk:**

```
POST /api/transfers/bulk
[
  {to: account1, amount: 1},
  {to: account2, amount: 1},
  ...
  {to: account10000, amount: 1}
]
```

Massive operations in one request.

**3. Resource creation flooding:**

```
POST /api/files/upload (no limit)
Upload 1000 files quickly
Fill storage, hit quota
DoS for legitimate users
```

**4. Account creation flooding:**

```
POST /signup (rate limit per IP only)
With proxy rotation: unlimited signups
Account farms for spam, fraud
```

**5. Email/SMS notifications:**

```
POST /api/forgot-password
Request reset for user@example.com
Repeat 1000 times
Victim spammed with emails
```

**6. API token generation:**

```
POST /api/tokens
Generate 1000 tokens
Each token still works
Unlimited authentication keys
```

**7. Discount code generation:**

```
POST /api/coupons/generate
Generate codes en masse
Each works once
Effectively unlimited free products
```

**8. Review/rating manipulation:**

```
POST /api/reviews
[review1, review2, ..., review1000]
Manipulate ratings
SEO impact
```

**Defense:**

1. **Rate limit ALL endpoints** - Not just auth
2. **Limit batch sizes** - Max items per request
3. **Cost-based limits** - Expensive ops cost more
4. **Behavioral analysis** - Detect abuse patterns
5. **CAPTCHA** for sensitive operations
6. **Email/SMS deduplication** - Don't send same notification repeatedly

### Q22: How to test 2FA bypass via business logic?
**A:**

**2FA bypass via business logic flaws:**

**1. Email/phone change without re-auth:**

```
1. Login as victim somehow (initial breach)
2. Change email/phone (no re-verification required)
3. Disable 2FA via new email/phone
4. Now full account access
```

**2. Recovery flow abuse:**

```
"I lost my 2FA device"
Process: Email confirmation
Email compromised? → bypass 2FA
```

**3. Backup code generation:**

```
Generate backup codes
Save them
Disable 2FA
Re-enable 2FA
Old backup codes still work?
```

**4. Race condition during 2FA setup:**

```
Set up 2FA
Before confirmation step
Other endpoint actions might disable
Or use old auth state
```

**5. Session persistence after 2FA disable:**

```
Login with 2FA
Get session
Disable 2FA in another session
Old session still requires 2FA?
```

**6. Trusted device abuse:**

```
"Trust this device for 30 days"
Token in cookie
Steal cookie → bypass 2FA
```

**7. API endpoints without 2FA enforcement:**

```
Web login requires 2FA
API endpoint /api/login allows password only
Use API to bypass web 2FA
```

**8. Mobile app vs web:**

```
Web requires 2FA
Mobile app uses biometric only
Mobile token has more permissions
```

**Testing:**

1. Set up 2FA on test account
2. Try every account modification without 2FA
3. Test all login surfaces (web, mobile, API)
4. Recovery flows for weaknesses
5. Time gaps in 2FA enforcement

### Q23: Business logic in payment flows
**A:**

**Payment flow exploitation:**

**1. Payment confirmation bypass:**

```
1. Add items to cart
2. Initiate payment
3. Get to confirmation page
4. Don't actually pay
5. Try to access "order complete" page directly
6. Order processed?
```

**2. Payment method switching:**

```
1. Select credit card payment
2. Submit
3. Modify payment_method to "voucher" in transit
4. Free order via wrong method
```

**3. Tip manipulation:**

```
POST /order
{
  "items": [...],
  "tip": -1000   ← Negative tip
}
```

Reduces order total.

**4. Loyalty redemption inflation:**

```
100 points = $1 off
Modify ratio: 100 points = $1000 off
```

**5. Refund to different account:**

```
Refund $100 to account A
Modify request to send to attacker account
```

**6. Payment retry abuse:**

```
Payment fails
Retry counted as new payment attempt
Eventually succeeds
But order processed multiple times
```

**7. Chargeback abuse:**

```
Place order
Chargeback via card issuer
Keep product
Order system doesn't sync with chargebacks
```

**8. Saved payment method confusion:**

```
Have 2 saved cards
Modify request to use other user's card
Other user charged
```

**9. Currency conversion gap:**

```
Pay in INR amount = $100 equivalent
Currency rate updates
Charged in USD using new rate
Pay less due to rate change
```

**10. Subscription downgrades:**

```
Monthly $50 plan
Downgrade to free
Prorated refund: $30
But fully used features for the month
Effectively paid $20 for full month
```

### Q24: Business logic in subscription services
**A:**

**Subscription-specific flaws:**

**1. Trial period extension:**

```
Free 30-day trial
Cancel before charge
Re-signup with same details
Trial extends infinitely
```

**2. Trial cancellation timing:**

```
Trial ends midnight
Cancel at 11:59 PM
Service grants full month sometimes (off-by-one)
```

**3. Plan downgrade timing:**

```
Subscribe yearly: $100
Downgrade to monthly: $10/mo
Refund: $90 (11 months remaining)
But yearly grants future months
```

**4. Upgrade without immediate charge:**

```
Free plan → upgrade to premium
Charge happens at next cycle
But premium features active immediately
Cancel before charge → free premium
```

**5. Feature flag manipulation:**

```javascript
// Client-side feature flags
if (user.plan === 'premium') {
    showAdvancedFeatures();
}
```

Modify user.plan in browser → access features.

**6. Multiple device limits:**

```
Plan allows 3 devices
4th device replaces oldest
Cycle: device A → B → C → A → ...
But sessions don't actually expire
All 4 still active
```

**7. Refund and rejoin:**

```
Cancel and request refund
Re-subscribe
Use refund credit
Effective free subscription
```

**8. Free tier abuse:**

```
Limited free tier (1 project)
Create project, delete, create new
Loophole: deletes don't count
Unlimited projects
```

**9. Promotional pricing perpetuity:**

```
First month: $1
Then $20/month
But cancellation triggers retention offer
Retention: $1 again
Infinite cheap subscription
```

**10. Family plan abuse:**

```
Family plan: 6 members
Add yourself + 5 strangers
They pay you for "subscription"
Profit
```

### Q25: How do business logic flaws affect finance/banking apps?
**A:**

**Banking BL flaws (your Zorvyn fintech relevance):**

**1. Transfer manipulation:**

**Negative transfer:**
```
Transfer -$1000 to victim
Effectively pulls $1000 from victim
```

**Self-transfer abuse:**
```
Transfer A to B and B to A simultaneously
Race conditions create money
```

**Wrong currency:**
```
Send 100 (in INR thinking)
Actually USD = ₹8000
```

**2. Loan/credit manipulation:**

```
Loan application
Modify interest rate to 0%
Or modify principal upward
Free money
```

**3. Investment trades:**

```
Buy stocks at certain price
Cancel order milliseconds later
Race: order both filled AND cancelled
Stocks granted, money refunded
```

**4. Account opening:**

```
KYC requirements bypassable
Submit incomplete docs → approved
Identity not verified
Money laundering enabled
```

**5. Limit bypass:**

```
Daily transfer limit: $10,000
Schedule 10 transfers of $5,000 each
All scheduled before limit check
All execute
```

**6. Statement manipulation:**

```
GET /statements/{id}
Change ID to other user's statement
Account number, balance exposed
```

**7. Reward point exploits:**

```
Earn points on purchase
Return purchase → keep points (race condition)
Convert points to cash
```

**8. Interest calculation:**

```
Account interest calculated daily
Manipulate balance during calculation window
Inflated interest paid
```

**9. Bill payment scheduling:**

```
Schedule payment for future
Modify before execution
Pay less than agreed
```

**10. Stop payment abuse:**

```
Issue check
Use it
Then stop payment on check
Got product, didn't pay
```

**Defense critical because:**
- Financial regulations strict
- Direct money loss
- Customer trust paramount
- Audit requirements high

### Q26: Authentication bypass through business logic
**A:**

**Auth bypass via business logic:**

**1. Forgot password flow:**

```
1. Request password reset for victim@example.com
2. Reset email sent
3. Token check has flaw:
   - Token includes user_id
   - Modify user_id in token
   - Reset different user's password
```

**2. Account creation race:**

```
1. Start signup as victim@example.com
2. Email verification pending
3. Submit completion endpoint with victim's info
4. Account created, marked verified
```

**3. OAuth account linking:**

```
1. Login with Google
2. Modify OAuth response
3. Linked to victim's account
4. Now login as victim via Google
```

**4. SSO assertion replay:**

```
1. Capture SAML assertion from valid login
2. Replay assertion (no anti-replay check)
3. Authenticated again
```

**5. Pre-existing account hijack:**

```
1. Find user's email
2. Request reset for them
3. But also try registration
4. If registration overrides existing: hijack
```

**6. Email verification skip:**

```
1. Sign up with attacker@evil.com
2. Don't verify email
3. Change email to victim@example.com
4. Skip verification (system trusts internal change)
5. Account "for" victim
```

**7. Password reset token leak:**

```
1. Request reset → email contains token
2. Email forwarded/intercepted
3. Token reusable
4. Account takeover
```

**8. 2FA setup race:**

```
1. Compromise account (initial)
2. Start 2FA setup
3. Cancel
4. Try login from new device
5. App thinks 2FA pending, allows bypass
```

**9. Session token in URL:**

```
1. App passes session in URL
2. Token in browser history, server logs
3. Steal from logs/history
```

**10. Predictable account recovery:**

```
Security questions: "Mother's maiden name"
Find on social media
Bypass MFA via recovery
```

### Q27: Common BL flaws in social media platforms
**A:**

**Social media specific:**

**1. Privacy setting bypass:**

```
User sets profile to private
But profile data still in:
- Search results
- Recommendation widgets
- Friends-of-friends views
- Old API versions
```

**2. Friend request manipulation:**

```
1. Send friend request
2. Cancel before recipient sees
3. But system already granted access to private content
```

**3. Post visibility:**

```
"Only friends" post
But appears in:
- Friend-of-friend feeds
- Public group activity
- Search indexes
```

**4. Mention/tag abuse:**

```
Tag yourself in others' photos
Now in their network's notifications
Increased visibility
```

**5. Block bypass:**

```
User A blocks User B
User B uses different account
Or accesses via shared content
Or sees in search
```

**6. Account verification gaming:**

```
"Verified" badge based on metrics
Manipulate metrics (followers, etc.)
Get badge without legitimate basis
```

**7. Direct message after block:**

```
Block user
Old conversations still visible
New messages route differently
Block bypass via legacy routes
```

**8. Story view tracking:**

```
View story without "Seen by" appearing
By using different viewers/apps
```

**9. Reach/engagement manipulation:**

```
Algorithm boosts engaging posts
Manipulate engagement (bots, exchanges)
Artificial reach
```

**10. Account suspension evasion:**

```
Account banned
Create new account with same details
System detects: blocks
Workarounds: different device, IP, slight variations
```

### Q28: Multi-tenancy business logic flaws
**A:**

**Multi-tenant SaaS specific:**

**1. Cross-tenant data exposure:**

```
Tenant A user
API call: /api/tenants/{id}/data
Modify {id} to Tenant B
Access B's data
```

**2. Tenant settings bleed:**

```
Tenant A configures feature
Affects Tenant B due to shared resource
Configuration not isolated
```

**3. Billing manipulation:**

```
Tenant A modifies tenant_id in upgrade request
Tenant B upgraded, charged
```

**4. User migration abuse:**

```
Move user between tenants
Permissions inherited weirdly
Old tenant access retained
```

**5. Shared resource quotas:**

```
Tenant A's heavy usage
Affects Tenant B's performance
Or fills shared quota
```

**6. Tenant admin abuse:**

```
Tenant admin role
Can manage their tenant
Can also access shared/global resources?
```

**7. Tenant deletion:**

```
Delete tenant
But users in other tenants still see data
Or backups have data
GDPR compliance issues
```

**8. Sub-tenant hierarchies:**

```
Parent tenant
Sub-tenants under it
Permissions cascade incorrectly
Parent sees sub-tenant private data
```

**9. Tenant isolation in:**
- Database (shared DB, tenant_id column)
- Cache (shared Redis, tenant prefix)
- Search (shared Elasticsearch index)
- Backups (commingled)

Any failure = cross-tenant exposure.

**10. Tenant onboarding:**

```
Free trial includes premium features
Trial expires
But premium features remain (logic flaw)
```

### Q29: Healthcare app business logic flaws
**A:**

**Healthcare BL flaws (HIPAA risk):**

**1. Appointment manipulation:**

```
Book appointment
View other patients' appointments via parameter manipulation
Cancel others' appointments
Reschedule for unauthorized user
```

**2. Prescription manipulation:**

```
Modify prescription quantity
Refill more times than allowed
Different medication (dangerous!)
```

**3. Patient record access:**

```
Patient role accesses only their records
Family member proxy access
Inherited from old account
Cross-family access enabled inadvertently
```

**4. Doctor's notes:**

```
Patients see doctor notes
Some apps allow editing (patient-side)
Modify notes to misrepresent diagnosis
Insurance fraud
```

**5. Insurance claims:**

```
Modify procedure code
Insurance pays for different procedure
Patient receives unintended treatment cost
```

**6. Lab results:**

```
Lab results auto-routed to insurance
Patient can intercept/modify
Insurance receives modified results
```

**7. Telehealth abuse:**

```
Video consultation with doctor
Recording without consent
Or doctor's notes accessible to all
```

**8. Pharmacy delivery:**

```
Order prescription
Change delivery address mid-process
Medications to wrong person
Potential abuse (controlled substances)
```

**9. Vaccination records:**

```
Modify vaccination status
False positive for travel/work requirements
Public health implications
```

**10. Genetic testing data:**

```
DNA data more sensitive than typical health data
Access by family members
Insurance discrimination based on genetic data
Long-term privacy impact
```

### Q30: How to write a business logic flaw report?
**A:**

**Comprehensive report template:**

```markdown
# Business Logic Flaw - Price Manipulation in Checkout

## Severity: Critical
## CVSS 3.1: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

## Executive Summary

The checkout process trusts client-supplied price totals without 
server-side verification. This allows authenticated users to 
modify order totals to any value, including ₹1 for products 
worth thousands of rupees. The flaw is in business logic, not 
code — there's no SQL injection or technical vulnerability.

## Affected Component
- Endpoint: POST /api/checkout/initiate
- Parameter: total (in JSON body)
- Affected workflow: Order placement

## Detailed Description

When initiating checkout, the application accepts a 'total' value 
in the request body. This value is passed to the payment gateway 
without server-side recomputation from cart items. The server 
trusts the client-supplied total, allowing manipulation.

## Step-by-Step Reproduction

### Setup
- Logged in user account
- Burp Suite or similar proxy
- Test product worth significant amount (₹13,750)

### Steps

1. **Add product to cart:**
   POST /api/cart/add
   {"product_id": "12345", "quantity": 1}

2. **Initiate checkout (intercept):**
   POST /api/checkout/initiate
   {
     "cart_id": "cart_xyz",
     "total": 13750,
     "items": [{"product_id": "12345", "quantity": 1, "price": 13750}]
   }

3. **Modify total in Burp Repeater:**
   POST /api/checkout/initiate
   {
     "cart_id": "cart_xyz",
     "total": 1,    ← Modified from 13750
     "items": [{"product_id": "12345", "quantity": 1, "price": 13750}]
   }

4. **Server processes ₹1 payment for ₹13,750 product**

5. **Order placed successfully, product shipped**

## Proof of Concept

### Successful order at ₹1:
- Order ID: ORD-123456
- Product: Premium Product (MRP: ₹13,750)
- Paid: ₹1
- Status: Shipped

### Repeated successful exploitation:
- 5 orders placed
- Total products worth: ₹68,750
- Total paid: ₹5
- Profit (loss to company): ₹68,745

## Impact

### Financial
- Direct revenue loss
- Per exploit: ₹13,749 (per ₹13,750 product)
- Mass exploitation: Unlimited
- Company-wide: Severe (depends on inventory)

### Operational
- Order fulfillment for free items
- Shipping costs
- Customer service overhead

### Brand
- Once disclosed: Reputational damage
- Customer trust impact
- Stock price impact (if public)

### Estimated total impact: ₹50,00,000+ (depending on disclosure period)

## Affected Endpoints

After investigation, similar pattern found in:
- POST /api/checkout/initiate (this report)
- POST /api/orders/create
- POST /api/subscriptions/create (different products)

## Remediation

### Immediate (Within 24 hours)

Add server-side validation:

```python
def initiate_checkout(request):
    cart = Cart.objects.get(id=request.data['cart_id'])
    
    # ALWAYS recompute server-side
    actual_total = 0
    for item in cart.items.all():
        product = Product.objects.get(id=item.product_id)
        actual_total += product.price * item.quantity  # DB price, not request
    
    if abs(actual_total - request.data.get('total', 0)) > 0.01:
        # Log suspicious activity
        log_security_event(request.user, "Price manipulation attempt")
        return error("Total mismatch")
    
    # Process payment with ACTUAL total
    process_payment(amount=actual_total)
```

### Long-term

1. **Audit all financial endpoints** - Find similar patterns
2. **Implement integrity checks** - Sign cart contents
3. **Server-side authoritative pricing** - Single source of truth
4. **Monitor for anomalies** - Order total < product price = alert
5. **Reconciliation** - Compare orders to product database daily
6. **Security testing** - Add this scenario to test suite

## Detection of Exploitation

To check if exploited:
```sql
SELECT o.order_id, o.total, SUM(p.price * oi.quantity) as expected_total
FROM orders o
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id
GROUP BY o.order_id, o.total
HAVING o.total < SUM(p.price * oi.quantity) * 0.5
```

Any results = likely exploited orders.

## References
- CWE-840: Business Logic Errors
- OWASP Top 10: A04 - Insecure Design
- OWASP API Top 10: API6 - Unrestricted Business Flow Access

## Timeline
- 2026-06-01: Vulnerability discovered
- 2026-06-01: Report submitted
- 2026-06-02: Acknowledged
- 2026-06-03: Fix deployed
- 2026-06-04: Verified

## Acknowledgment

Discovered by Jagdeep Singh
Bug bounty submission via responsible disclosure
```

---

## SECTION B: TESTING METHODOLOGIES (Q31-65)

### Q31: How to map application business logic?
**A:**

**Application mapping for BL testing:**

**Phase 1: Understand the business**

- What does the app do?
- Who uses it?
- What's the revenue model?
- What's sensitive data?
- What are regulatory requirements?

**Phase 2: Identify user roles**

- Regular user
- Premium user
- Admin
- Support staff
- Third-party integrations
- API consumers

**Phase 3: Document workflows**

For each role, document:
- Onboarding flow
- Core functionality flow
- Payment flow
- Account management flow
- Termination flow

**Phase 4: Identify state transitions**

```
User states: 
  pending → email_verified → active → suspended → deleted

Order states:
  cart → checkout → payment → confirmed → shipped → delivered → returned

Subscription states:
  trial → active → past_due → canceled → expired
```

**Phase 5: List all assumptions**

For each workflow, ask:
- "What does the app assume?"
- "What if that's not true?"

Examples:
- "User clicks email link" → What if URL leaks?
- "Payment completes before delivery" → Race condition?
- "User won't enter negative quantity" → What if they do?

**Phase 6: Catalog functions**

For each function:
- Input
- Processing
- Output
- Side effects
- Authorization required
- Audit logging

**Phase 7: Create attack surface map**

Visual diagram showing:
- All entry points
- Trust boundaries
- State transitions
- Critical paths
- Sensitive operations

### Q32: How to test for race conditions effectively?
**A:**

**Race condition testing methodology:**

**Step 1: Identify candidate endpoints**

Look for:
- Financial operations
- Resource allocation
- Counter increments/decrements
- Status changes
- Limit checks before action

**Step 2: Understand the race window**

- What needs to happen?
- How long is the window?
- What state matters?

**Step 3: Choose testing tool**

**Burp Suite Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          engine=Engine.BURP)
    
    for i in range(30):
        engine.queue(target.req)
    
    engine.start()

def handleResponse(req, interesting):
    table.add(req)
```

**Python with asyncio:**
```python
import asyncio
import aiohttp

async def race_request(session, url, data):
    return await session.post(url, json=data)

async def race_test():
    async with aiohttp.ClientSession() as session:
        tasks = [
            race_request(session, '/api/transfer',
                       {'amount': 100, 'to': 'attacker'})
            for _ in range(50)
        ]
        responses = await asyncio.gather(*tasks)
        successes = sum(1 for r in responses if r.status == 200)
        print(f"Successful: {successes}")

asyncio.run(race_test())
```

**Step 4: Run with high concurrency**

- Start with 10 concurrent
- Increase to 50, 100
- Different times of day
- Different network conditions

**Step 5: Observe results**

- Count successful operations
- Check final state
- Verify integrity

**Step 6: Repeat to confirm**

Race conditions intermittent - repeat 100+ times.

**Common race-vulnerable patterns:**

```python
# Pattern 1: Check-then-act
if balance >= amount:
    balance -= amount

# Pattern 2: Find-then-use
record = find_record()
if record.available:
    record.assign(user)

# Pattern 3: Counter increment
count = get_counter()
set_counter(count + 1)

# Pattern 4: Status check-then-update
if order.status == 'pending':
    order.status = 'processing'
```

### Q33: Race condition in coupon redemption - detailed walkthrough
**A:**

**Real-world race condition test:**

**Setup:**
- Application: E-commerce
- Feature: Coupon usable once per account
- Endpoint: POST /api/cart/apply-coupon

**Hypothesis:**

Race condition between:
1. Check if coupon used (no)
2. Mark coupon as used

```python
# Server pseudocode
def apply_coupon(user, code):
    coupon = Coupon.get(code)
    if not Redemption.exists(user=user, coupon=coupon):  # CHECK
        # Race window
        cart.apply(coupon)
        Redemption.create(user=user, coupon=coupon)  # USE
        return success
```

**Exploit:**

20 concurrent requests, all pass check before any creates Redemption.

**Burp Turbo Intruder script:**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=1,
        engine=Engine.BURP
    )
    
    request = '''POST /api/cart/apply-coupon HTTP/1.1
Host: target.com
Cookie: SESSION=user_session
Content-Type: application/json
Content-Length: 28

{"code": "SAVE50PERCENT"}
'''
    
    for i in range(30):
        engine.queue(request)
    
    engine.start()

def handleResponse(req, interesting):
    if 'applied' in req.response:
        table.add(req)
```

**Execution:**

1. Login to test account
2. Add expensive item to cart
3. Open Burp Suite
4. Send apply-coupon to Turbo Intruder
5. Modify script if needed
6. Run

**Expected results without race condition:**
- 1 successful (200 OK)
- 29 errors (409 Conflict or similar)

**Race condition results:**
- 5-15 successful (depending on timing)
- Coupon applied multiple times
- Total: 90%+ off (instead of 50%)

**Validation:**

Check cart total in dashboard:
- Original: $100
- Single coupon: $50 (50% off)
- Race exploit: $5-10 (90%+ off)

**Report this as:**
- Severity: High (CVSS ~7.5)
- Impact: Financial loss per exploit
- Mass: Yes, with multiple test accounts

**Common variations:**

- Coupon usage counter (10 uses allowed → 30 used)
- One-time discount codes (used 10 times)
- Promotional pricing (applied multiple times)

### Q34: Currency manipulation - testing approach
**A:**

**Testing currency-based BL flaws:**

**Step 1: Identify currency handling**

Where is currency present?
- User profile (preferred currency)
- URL parameter
- Cookie
- Request header
- Body parameter

**Step 2: Map currency conversions**

- What converts when?
- Rate source?
- Cache TTL?
- Update frequency?

**Step 3: Test currency switching**

**Mid-checkout switching:**
```
1. Add product to cart in USD ($100)
2. Begin checkout
3. Switch currency to INR (₹8000)
4. Continue checkout
5. Observe what currency the payment goes through
```

**Inconsistent currencies:**
```
POST /checkout
{
  "currency": "USD",
  "items": [{"price": 100, "currency": "INR"}],
  "total": 100
}
```

Mixed currencies in single request.

**Currency in URL vs body:**
```
POST /checkout?currency=USD
{
  "currency": "INR",
  "total": 100
}
```

**Step 4: Test edge cases**

**Unsupported currencies:**
```
{"currency": "XYZ"}
```

**Negative amounts:**
```
{"amount": -100, "currency": "USD"}
```

**Very small amounts:**
```
{"amount": 0.001, "currency": "USD"}
```

**Step 5: Test conversion timing**

- Place order at one rate
- Wait for rate change
- Complete payment
- Check which rate used

**Step 6: Currency in API endpoints**

```
GET /api/products/123?currency=USD  → $100
GET /api/products/123?currency=INR  → ₹8000
GET /api/products/123?currency=JPY  → ¥15000
```

Different products in different currencies?

**Real example:**

App had bug where:
```
1. Browse in USD: products $100
2. Add to cart
3. Switch to JPY
4. Cart shows ¥100 (not converted)
5. Check out for ¥100 = $0.67
6. Get $100 product
```

### Q35: Discount code enumeration testing
**A:**

**Coupon code enumeration:**

**Step 1: Find coupon code patterns**

Observed codes:
- `WELCOME10` (10% off)
- `SAVE15` (15% off)
- `SUMMER2026` (seasonal)
- `STUDENT50` (50% off students)

Patterns:
- Word + number
- Word + year
- Category prefixes

**Step 2: Build wordlist**

```python
wordlist = []

# Combinations
words = ['SAVE', 'DISCOUNT', 'OFF', 'WELCOME', 'NEW', 'STUDENT',
         'TEACHER', 'EMPLOYEE', 'VIP', 'PROMO', 'SPECIAL', 'FREE']
modifiers = ['', '5', '10', '15', '20', '25', '50', '75', '100']
years = ['2024', '2025', '2026']
seasons = ['SUMMER', 'WINTER', 'SPRING', 'FALL', 'HOLIDAY', 'CHRISTMAS']

for word in words:
    for mod in modifiers:
        wordlist.append(f"{word}{mod}")
        wordlist.append(f"{word}{mod}OFF")
        wordlist.append(f"{word}{mod}%")
        for year in years:
            wordlist.append(f"{word}{year}")

for season in seasons:
    for year in years:
        wordlist.append(f"{season}{year}")
```

**Step 3: Brute force endpoint**

```python
import requests

def test_coupon(code):
    response = requests.post(
        'https://target.com/api/cart/apply-coupon',
        cookies={'SESSION': 'your_session'},
        json={'code': code}
    )
    
    if 'invalid' not in response.text.lower():
        if 'applied' in response.text or 'success' in response.text:
            print(f"[+] Valid coupon: {code}")
            return True
    return False

for code in wordlist:
    test_coupon(code)
```

**Step 4: Burp Intruder approach**

1. Capture apply-coupon request
2. Send to Intruder
3. Position payload on code parameter
4. Load wordlist
5. Sniper attack
6. Sort by response length (success differs)

**Step 5: Look for clues**

- Error messages reveal valid format
- Response time differences
- Different HTTP status codes
- Partial matches showing pattern

**Step 6: Leaked codes online**

Some codes posted publicly:
- Reddit r/promocodes
- Honey
- RetailMeNot
- Slickdeals

**Step 7: Internal codes**

Sometimes employee codes:
- EMPLOYEE100 (free)
- VIPSTAFF50
- BETA2026
- ADMIN

**Mitigation that should exist:**

- Rate limit coupon attempts (5/minute)
- Lockout after many failed attempts
- Random, unguessable codes
- Per-account usage tracking
- Audit logs

### Q36: Workflow bypass through state manipulation
**A:**

**State manipulation testing:**

**Step 1: Map state machine**

Document all states:
```
ORDER STATES:
draft → submitted → paid → packed → shipped → delivered → 
                                                    refund_requested → refunded

User can be in states:
unverified → verified → active → suspended → banned → deleted
```

**Step 2: Find state in requests**

State might be:
- URL parameter: `?state=paid`
- Hidden form field: `<input name="state" value="pending">`
- JSON body: `{"order_state": "draft"}`
- Cookie: `state=cart`

**Step 3: Test forward jumps**

```
Normal: draft → submitted → paid → shipped
Test:   draft → shipped (skip submission and payment)
```

**Step 4: Test backward jumps**

```
Normal: One-way forward
Test:   delivered → cart (re-add items)
        refunded → paid (undo refund)
```

**Step 5: Test loops**

```
Test: shipped → returned → shipped (multiple times)
      paid → refunded → paid (multiple)
```

**Step 6: Test invalid combinations**

```
Order shipped without payment
User active without verification
Subscription premium without billing
```

**Real example - photo upload flow:**

**Normal flow:**
```
1. POST /upload/init → upload_token
2. POST /upload/chunk → upload chunks
3. POST /upload/complete → process file
4. Photo visible
```

**Bypass:**
```
1. Skip /upload/init
2. POST /upload/complete with photo_id from other user
3. Their photo replaced/modified
```

**Real example - banking transfer:**

**Normal flow:**
```
1. POST /transfer/init → returns transfer_token
2. POST /transfer/verify → 2FA code
3. POST /transfer/execute → money moves
```

**Bypass:**
```
1. Skip /transfer/init and /verify
2. POST /transfer/execute with crafted transfer_token
3. Money moves without 2FA
```

### Q37: Testing for negative number business logic
**A:**

**Negative number exploitation:**

**Where to test negatives:**

1. **Quantities:**
   - Cart items
   - Bulk operations
   - Inventory adjustments

2. **Money amounts:**
   - Transfers
   - Refunds
   - Tips
   - Donations

3. **Discounts:**
   - Percentage
   - Fixed amounts

4. **Counts:**
   - Days (subscriptions)
   - Items per order
   - User limits

5. **Prices:**
   - Product price
   - Service fees

**Testing approach:**

```
For each numeric field, try:
- -1 (small negative)
- 0 (boundary)
- -999999999 (large negative)
- -0.001 (negative decimal)
- -0 (negative zero)
- "-0" (string negative zero)
- "+0" vs "-0"
```

**Real examples:**

**1. Negative quantity → free items:**
```
POST /cart/add
{"product_id": "shoes", "quantity": 1, "price": 100}
→ Cart total: $100

POST /cart/update
{"product_id": "shoes", "quantity": -1}
→ Cart total: -$100

POST /cart/add
{"product_id": "shoes", "quantity": 1}
→ Cart total: $0 (cancels out)

# But you got the shoes for free!
```

**2. Negative transfer → gain money:**
```
POST /transfer
{"to": "attacker", "amount": -100}

Interpreted as: pull $100 FROM attacker
Or: refund attacker $100
Either way, money to attacker
```

**3. Negative discount → price increase (for others):**
```
Some apps process discounts as:
total = total - discount

If discount = -100:
total = total - (-100) = total + 100
```

**4. Negative refund → keep product + money:**
```
POST /refund
{"order_id": "123", "amount": -100}

Refund decreases your balance?
Or company pays you?
Depends on implementation
```

**5. Negative subscription days:**
```
PUT /subscription
{"days_remaining": -30}

If trial counts negative as "future":
Or "already expired"
Status confused
```

**Defense:**

```python
def update_cart(item_id, quantity):
    if quantity < 0:
        return error("Invalid quantity")
    
    if quantity > MAX_QUANTITY:
        return error("Exceeds maximum")
    
    if not isinstance(quantity, int):
        return error("Must be integer")
```

### Q38: Integer overflow business logic
**A:**

**Integer overflow scenarios:**

**1. JavaScript precision loss:**

```javascript
// JavaScript max safe integer
Number.MAX_SAFE_INTEGER  // 9007199254740991

// Beyond this, precision lost
9007199254740992 + 1  // = 9007199254740992 (no change!)
```

If app does math in JS, precision matters.

**2. Backend integer overflow:**

```python
# Python: arbitrary precision (no overflow)
# But many DBs and languages have limits:

# MySQL INT: -2147483648 to 2147483647
# MySQL BIGINT: -9223372036854775808 to 9223372036854775807

# Test:
balance = 2147483647
balance += 1  # In some langs: -2147483648 (overflow!)
```

**3. Money overflow:**

```
Account balance: 2,147,483,647 cents ($21.47M)
Add 1 cent
Balance: -2,147,483,648 cents (-$21.47M)
```

Test by funding account to max int.

**4. Quantity overflow:**

```python
quantity = 2147483647
total = quantity * price  # Overflow
# Becomes negative
# Discount-like behavior
```

**5. Loyalty points overflow:**

```
Earn unlimited points
Exceed integer max
Wraps to negative
Convert to cash: negative payment (refund to attacker)
```

**6. Time/timestamp overflow:**

```python
import time

# 32-bit timestamp max: 2147483647
# Equals: 2038-01-19 03:14:07 UTC

# Test setting expiration to:
expires_at = 99999999999
# In 32-bit: overflow
# Treated as past = expired
# Or as 1970-something
```

**7. ID overflow:**

```
Auto-increment ID
Reaches max int
Insertion fails or behaves oddly
DoS condition
```

**Testing approach:**

```python
test_values = [
    -2147483648,
    -2147483647,
    -1,
    0,
    1,
    2147483646,
    2147483647,    # Max signed 32-bit
    2147483648,    # Overflow
    4294967295,    # Max unsigned 32-bit
    4294967296,    # Beyond
    9007199254740992,  # JS unsafe integer
    9223372036854775807,  # Max 64-bit
]
```

### Q39: Race condition in account funding/withdrawal
**A:**

**Banking-specific race conditions:**

**1. Double withdrawal:**

```python
# Vulnerable
def withdraw(account_id, amount):
    account = Account.get(account_id)  # Read 1
    
    if account.balance >= amount:
        # Time gap (network, processing)
        account.balance -= amount  # Write 1
        account.save()
        return success
```

**Race attack:**
```
Thread 1: Read balance (100)
Thread 2: Read balance (100)
Thread 1: Check 100 >= 50 ✓
Thread 2: Check 100 >= 50 ✓
Thread 1: Set balance to 50
Thread 2: Set balance to 50  ← Overwrites!
Final: 50 instead of 0

Withdrew $100 total but only deducted $50
```

**2. Double deposit:**

```python
def deposit(account_id, amount):
    account = Account.get(account_id)
    account.balance += amount
    account.save()
```

If same transaction processed twice:
- Both increment balance
- Net effect: deposit credited twice

**3. Transfer race:**

```python
def transfer(from_id, to_id, amount):
    sender = Account.get(from_id)
    if sender.balance >= amount:
        sender.balance -= amount
        sender.save()
        
        receiver = Account.get(to_id)
        receiver.balance += amount
        receiver.save()
```

Concurrent transfers:
- Both check sender has funds
- Both deduct
- But sender goes negative

**4. Coupon redemption:**

Same pattern - check then mark used.

**5. Loyalty points conversion:**

```
Points: 1000
Convert all to $10
Race: do it twice before deduction
Get $20 for 1000 points
```

**Defense:**

**1. Database transactions with locking:**

```python
@transaction.atomic
def withdraw(account_id, amount):
    # SELECT FOR UPDATE locks the row
    account = Account.objects.select_for_update().get(id=account_id)
    
    if account.balance >= amount:
        account.balance -= amount
        account.save()
```

**2. Atomic updates:**

```sql
-- Single SQL statement is atomic
UPDATE accounts 
SET balance = balance - 100
WHERE id = 123 AND balance >= 100
```

If WHERE matches 0 rows → insufficient funds.

**3. Idempotency keys:**

```python
def transfer(idempotency_key, amount):
    # Check if already processed
    existing = Transfer.objects.filter(
        idempotency_key=idempotency_key
    ).first()
    
    if existing:
        return existing.result  # Return same result
    
    # Process new
    with transaction.atomic():
        # ... process ...
        Transfer.objects.create(
            idempotency_key=idempotency_key,
            ...
        )
```

**4. Optimistic locking:**

```python
account = Account.get(id)
version = account.version

# Update only if version matches
updated = Account.objects.filter(
    id=id, version=version
).update(
    balance=F('balance') - amount,
    version=version + 1
)

if updated == 0:
    raise ConcurrentModificationError()
```

### Q40: How to find file upload business logic flaws?
**A:**

**File upload BL flaws:**

**1. Extension-only validation:**

```python
def upload(file):
    if file.name.endswith('.jpg'):  # Only checks extension
        save_file(file)
```

Upload `shell.jpg` containing PHP code.

**2. Content-Type only validation:**

```python
def upload(file):
    if file.content_type == 'image/jpeg':  # Spoofable header
        save_file(file)
```

Upload script with fake Content-Type.

**3. Double extension:**

```
filename.php.jpg
```

Some apps see .jpg and accept, but Apache serves as PHP.

**4. Null byte injection:**

```
filename.jpg%00.php
```

Some apps validate before null byte, save after.

**5. File size manipulation:**

```
Claim 1KB file, actually 1GB
DoS via storage exhaustion
```

**6. File path manipulation:**

```
filename: ../../../etc/passwd
filename: ../../var/www/html/shell.php
```

Path traversal in filename.

**7. Polyglot files:**

```
GIF89a<?php phpinfo(); ?>
```

Valid GIF AND valid PHP.

**8. Race condition in scanning:**

```
1. Upload malicious file
2. File saved temporarily
3. Antivirus scans
4. If scanning takes time, access file before scan completes
```

**9. Quota bypass:**

```
User limit: 100MB
Upload 100MB
Delete file (not really)
Upload another 100MB
File restored from "deleted" state
```

**10. Permission inheritance:**

```
Upload to public folder
File has restrictive permissions
But folder is public
File accessible
```

**Testing:**

1. Try various extensions
2. Manipulate Content-Type
3. Use null bytes
4. Path traversal in filename
5. Polyglot files
6. Size manipulation
7. Race conditions

### Q41: Business logic in API rate limiting (deep dive)
**A:**

**Rate limit business logic flaws:**

**1. Rate limit bypass via account creation:**

```
Limit: 10 password reset emails per account per day

Attack:
- Create 100 accounts
- Each gets 10 emails
- Use to spam target email
- Actually attacking same email indirectly
```

**2. Rate limit window manipulation:**

```
Limit: 100 requests per minute

Attack:
- Hit 99 at 0:00
- Hit 99 at 0:59
- Effectively 198 per minute (across window edge)
```

**3. Rate limit per resource ID:**

```
Limit: 10 requests per resource per minute
Resource IDs: 1-1000

Attack:
- Hit /api/resource/1 (10 times)
- Hit /api/resource/2 (10 times)
- ...
- Total: 10,000 requests per minute
```

**4. Rate limit per endpoint:**

```
Limit per endpoint: 100/minute

Find endpoints achieving same goal:
- /api/v1/users
- /api/v2/users
- /api/legacy/users
- /admin/users
- /internal/users

Hit each 100 times = effective 500/minute
```

**5. Tier-based rate limit abuse:**

```
Free tier: 100 requests/day
Premium: 10,000 requests/day

Attack:
- Free account does some operations
- Premium does others
- Multiple free + one premium = high throughput
```

**6. Rate limit cache poisoning:**

If rate limit stored in cache (Redis):
- Cache evicted under pressure
- Limits reset
- Repeated attacks evict legitimate counts

**7. Cost-based rate limiting bypass:**

```
Endpoint A: 10 cost units
Endpoint B: 1 cost unit
Daily budget: 100 units

Attack: Always use cheap endpoint
Achieve same effect as expensive with 10x more calls
```

### Q42: Privilege escalation through business logic
**A:**

**BL-based privilege escalation:**

**1. Role assignment race:**

```
1. User has no role
2. Request promotion to "manager" (admin approves)
3. Simultaneously request promotion to "admin" (auto-approved temporary)
4. End state: admin role (race condition)
```

**2. Group membership inheritance:**

```
User joins Group A (low privilege)
Group A includes Group B (high privilege)
Group B includes Group C (admin)
User → A → B → C → admin

Designed for cascading down, but cascades up via membership.
```

**3. Permission boundary checks:**

```python
def grant_permission(user, permission, granter):
    # Check granter has the permission
    if granter.has_permission(permission):
        user.add_permission(permission)
```

Edge case: granter has subset, grants superset.

**4. Time-bound role abuse:**

```
Temporary admin for 1 hour (project work)
During that hour:
- Grant yourself permanent admin
- Modify access logs
- Plant backdoors

After: permanent admin, audit trail clean
```

**5. Tenant admin abuse:**

```
Admin in Tenant A
API call: PUT /tenants/B/admins
Modify tenant_id
Become admin of Tenant B
```

**6. Sub-admin escalation:**

```
Sub-admin can manage their org's users
Modify user to include "super admin" role
Self-promotion within own org first
Then access global features
```

**7. Service account abuse:**

```
Application uses service account internally
If you can trigger service account to act on your behalf:
- Service has more permissions
- Actions in your name with service permissions
```

**8. Approval workflow escalation:**

```
Submit request requiring approval
Approve own request via different role
Loophole in approval logic
```

### Q43: Testing payment workflows for BL flaws
**A:**

**Payment workflow testing:**

**1. Pre-payment state manipulation:**

```
1. Add items to cart ($100)
2. Click checkout
3. Get to payment page
4. Modify amount in form/JS state to $1
5. Submit
6. Server processes $1 payment for $100 order
```

**2. Post-payment manipulation:**

```
1. Place order
2. Order created in "pending payment" state
3. Manually trigger "order confirmed" endpoint
4. Order proceeds without payment
```

**3. Refund manipulation:**

```
1. Get order
2. Request refund
3. Modify refund amount to be more than paid
4. Profit from refund
```

**4. Partial refund abuse:**

```
1. Order has multiple items ($100 each, 5 items, $500 total)
2. Request partial refund for item 1
3. Modify request to refund all items at item 1's price
4. Refund: $500 (full), but only items 2-5 are returned
```

**5. Currency mid-payment:**

```
1. Pay in INR
2. Mid-transaction, switch to USD
3. Charge in cheaper currency
```

**6. Payment method swap:**

```
1. Select credit card payment
2. Submit
3. Backend processing with valid card token
4. Modify payment_method to "in-store credit"
5. Order processed with credit, card not charged
6. Profit from misallocation
```

**7. Gift card double-redemption:**

```
1. Gift card balance: $100
2. Use $80 on order
3. Race condition: order saved, balance not updated
4. Use $100 again on different order
5. Total: $180 from $100 gift card
```

**8. Subscription billing manipulation:**

```
1. Subscribe to $50/month plan
2. Modify billing endpoint to charge $1
3. Plan active, paying $1/month
```

**9. Promotional pricing reuse:**

```
1. Promotion: $1 first month
2. Cancel after first month
3. Subscribe again with new email
4. Get $1 first month again
5. Repeat indefinitely
```

**10. Chargeback timing:**

```
1. Place order
2. Receive product
3. Dispute charge with card issuer
4. Order system doesn't track chargebacks
5. Repeat
```

### Q44: How to chain BL flaws with technical vulnerabilities?
**A:**

**Chaining examples:**

**Chain 1: IDOR + Business Logic**

```
Step 1: IDOR allows accessing other users' orders
Step 2: Business logic flaw allows modifying order state
Step 3: Combine: Modify any user's order (refund, cancel, etc.)
```

**Chain 2: SQL Injection + Business Logic**

```
Step 1: SQLi reveals admin credentials
Step 2: Login as admin
Step 3: Use admin features with BL flaws
Step 4: Mass exploitation
```

**Chain 3: Mass Assignment + Business Logic**

```
Step 1: Mass assignment allows setting role=admin
Step 2: Business logic allows self-approval as admin
Step 3: Self-promote to admin without approval
```

**Chain 4: XSS + Business Logic**

```
Step 1: XSS in profile (stored)
Step 2: When admin views profile, JS executes
Step 3: Admin's session used to trigger BL flaw
Step 4: Discount/transfer/etc. as admin
```

**Chain 5: Race condition + Privilege**

```
Step 1: Race condition during role assignment
Step 2: Get elevated role briefly
Step 3: Use BL flaw requiring elevated role
Step 4: Maintain access
```

**Chain 6: Session fixation + Workflow bypass**

```
Step 1: Fix victim's session
Step 2: Victim logs in
Step 3: You have their authenticated session
Step 4: Use BL flaw on their behalf
```

**Chain 7: CSRF + Race condition**

```
Step 1: CSRF triggers multiple simultaneous requests
Step 2: Race condition in target endpoint
Step 3: Cross-site exploitation of BL
```

**Chain 8: Open Redirect + Account takeover**

```
Step 1: Open redirect in password reset
Step 2: Send victim modified reset link
Step 3: Token sent to attacker site
Step 4: Use token: BL flaw allows password change
Step 5: Account takeover
```

**Each chain compounds severity. CVSS often Critical (9+).**

### Q45: Common BL flaws in food delivery apps
**A:**

**Food delivery specific (Swiggy, Zomato, DoorDash style):**

**1. Coupon abuse:**

```
First-order coupon: 50% off first order
Create new account → first order
But existing account? 

Tricks:
- Different email
- Different phone (but same address)
- Use family member's number
- Use guest checkout
```

**2. Refund abuse:**

```
Order food
Eat it
Report missing/cold/wrong
Get refund
Repeat
```

Some apps don't track patterns.

**3. Driver tipping manipulation:**

```
Order with $10 tip
After delivery, modify tip to $0 or negative
Get money back
```

**4. Order modification timing:**

```
Place order ($30)
Restaurant accepts
Modify cart to lower price ($10)
Pay $10 for $30 order
```

**5. Address gaming:**

```
Restaurant has free delivery within 5km
Set address far away (out of zone)
But mark as nearby in app
Get delivery anyway
```

**6. Membership pricing:**

```
Free tier: 5% commission
Premium tier: $5/month, no commission

If you toggle tiers:
- Premium for ordering
- Free after order (no monthly fee)
```

**7. Restaurant rating manipulation:**

```
Submit fake order
Don't actually order
Leave bad review
Restaurant rating drops
```

**8. Referral program abuse:**

```
Refer friend → both get $10
Create fake friend account
Both accounts get $10
You control both
$20 free credit
```

**9. Order cancellation:**

```
Place big order
Cancel after restaurant prepared
Restaurant absorbs cost
Order app might refund
You get free preparation
```

**10. Delivery time exploitation:**

```
Promised delivery: 30 min
Took 45 min
Some apps auto-refund for late delivery
Order at peak times deliberately
Get refunded but received food
```

### Q46: Loyalty/rewards program manipulation
**A:**

**Loyalty program BL flaws:**

**1. Points farming:**

```
Earn 10 points per dollar spent
Place order $100 = 1000 points
Cancel order
If points kept = free 1000 points
Repeat
```

**2. Cross-account transfers:**

```
Account A earns points (legitimately)
Transfer to Account B (allowed for family)
But B is also you
Consolidate large amounts
```

**3. Tier manipulation:**

```
Silver tier: $500 spent
Gold tier: $1000 spent
Platinum: $2000 spent

Buy $2000 of products
Reach Platinum status
Return all products
Keep Platinum benefits
```

**4. Birthday bonus abuse:**

```
Birthday: 500 bonus points
Change birthday every year
Or every month
Multiple bonus claims
```

**5. Anniversary bonuses:**

```
Account anniversary: 1000 points
Create account at year start
Get bonus
Account birthday → bonus again
Subsequent years → more bonuses
```

**6. Referral chain:**

```
A refers B (A gets points)
B refers C (B gets points)
C refers D (C gets points)
All same person with different accounts
Cumulative bonus
```

**7. Combination redemption:**

```
500 points = $5 cash
Redeem 100 × 5 points = $5 each
$500 cash from 500 points (if no minimum)
```

**8. Status match abuse:**

```
"Match your status from competitor"
Claim status (fake document)
Get tier benefits
```

**9. Promotional point multipliers:**

```
2x points this weekend
Buy then cancel after weekend ends
Keep 2x points
```

**10. Account merger abuse:**

```
Multiple accounts → merge
Combined points
Edge case: points doubled in merge
```

### Q47: BL flaws in dating/social matching apps
**A:**

**Dating app specific:**

**1. Premium feature bypass:**

```
"Like" limit: 50 per day (free)
Premium: unlimited

Test:
- Hit limit via API
- Modify request to claim premium
- Like more
```

**2. See-who-liked-you bypass:**

```
Premium feature: see profiles that liked you
Free tier: hidden

Test API endpoints:
- /api/likes/incoming
- /api/profile/123/liked-by
Returns data without premium check?
```

**3. Boost feature:**

```
Premium boost: prioritize profile in matches
Free version uses default ranking

Test: modify boost flag in profile updates
```

**4. Profile visibility:**

```
Set profile to "men only" or "women only"
But profile in opposite gender's matches?
```

**5. Distance manipulation:**

```
Set max distance: 10 miles
But matches from any distance shown?
Or modify location to "show local"
```

**6. Age range manipulation:**

```
Age filter: 25-35
But profiles outside range shown?
Or modify own age dynamically
```

**7. Block bypass:**

```
User A blocks User B
B creates new profile
Same person, different account
A sees B again
```

**8. Verification badge:**

```
Verified profiles get badge
Steal verification token
Display badge without verification
```

**9. Read receipts:**

```
Free: no read receipts
Premium: read receipts

But premium can see if non-premium read?
Asymmetric tracking
```

**10. Message limit bypass:**

```
Free: 5 messages per day
Test: rate limit per account or per recipient?
Multiple recipients = effectively unlimited?
```

### Q48: Travel booking app business logic flaws
**A:**

**Travel/airline/hotel specific:**

**1. Price freeze abuse:**

```
"Hold price for 24 hours" (free)
Hold ticket
Don't book
Hold again with different account
```

**2. Loyalty points + currency arbitrage:**

```
Points → INR conversion: 1000 points = ₹100
Points → USD: 1000 points = $2 (= ₹160)
Switch to USD conversion, get more
```

**3. Inventory race conditions:**

```
1 seat left
Two simultaneous bookings
Both succeed
Airline overbooked manually
```

**4. Refund + rebook arbitrage:**

```
Buy ticket at higher price
Wait for price drop
Cancel ticket → refund
Rebook at lower price
Keep difference
```

**5. Multi-leg booking:**

```
Single round-trip ticket cheaper than two one-ways
Buy round-trip
Skip outbound, take return
Common "throwaway ticketing"
```

**6. Hidden city ticketing:**

```
NYC → London → Paris cheaper than NYC → London
Buy first
Skip London → Paris leg
But airline penalizes... if detected
```

**7. Membership status grant:**

```
Buy ticket for someone else
They earn miles
But you also somehow?
Status purchasing schemes
```

**8. Currency hopping:**

```
Search in INR (₹50,000)
Switch to USD ($500 = ₹40,000)
Booking in USD
Pay less due to rate gap
```

**9. Free cancellation abuse:**

```
Book multiple tickets
"Hold" all
Closer to date, decide
Cancel unused
Effectively reserve seats without commitment
```

**10. Class upgrade exploitation:**

```
Book economy
Use rewards to upgrade
Cancel ticket
Refund includes upgrade value
Cycle continues
```

### Q49: Online education platform BL flaws
**A:**

**Education platform specific:**

**1. Free trial abuse:**

```
7-day free trial
After trial, charge
Cancel before charge
Sign up again with different email
Endless trials
```

**2. Course completion bypass:**

```
Course requires:
- Watch all videos
- Pass quiz
- Submit assignment

Bypass:
- API call directly marking complete
- Skip ahead in video player
- Take quiz only
```

**3. Certificate generation:**

```
Certificate issued on completion
Modify course_id in request
Get certificate for course you didn't take
```

**4. Premium content access:**

```
Premium course $99
Pay for one course
Modify course_id in API
Access other premium courses
```

**5. Refund + rejoin:**

```
"Money back if not satisfied"
Take course, get certificate
Request refund (satisfaction guarantee)
Profit: free course + certificate
```

**6. Test/exam manipulation:**

```
Online exam
Time limit: 60 minutes
Modify time in request
Or submit answers from previous attempts
```

**7. Discussion forum gaming:**

```
Points for participation
Spam posts
Earn points
Trade for course discounts
```

**8. Peer review system:**

```
Submit assignment
Peers review
Manipulate peer pool
Friends review favorably
```

**9. Live class bypass:**

```
Live classes require subscription
Recordings available later
Bypass: get recording link without watching live
```

**10. Bulk enrollment:**

```
Corporate plan: $1000 for 100 students
Use 50 students
Sell access to remaining 50
Resell what you paid for
```

### Q50: How does business logic affect compliance?
**A:**

**Compliance implications:**

**1. KYC/AML (banking, fintech):**

BL flaws bypassing KYC:
- Submit incomplete documents → approved
- Race condition during verification
- Document validation skipped

Impact:
- Money laundering enabled
- Sanctions evasion
- Regulatory fines (millions)
- License suspension

**2. GDPR (EU):**

BL allowing access to others' data:
- Even without "hacking" classic
- Counts as data breach
- 72-hour notification required
- Fines up to 4% global revenue

**3. HIPAA (US healthcare):**

BL exposing patient data:
- Patient portal flaws
- Workflow bypasses
- Cross-patient access

Penalties:
- $100-$50K per violation
- Annual cap: $1.5M
- Criminal for willful violation

**4. PCI-DSS (payments):**

BL in payment flow:
- Card data exposure
- Transaction manipulation
- Compliance failure

Impact:
- Fines $5K-$100K/month
- Loss of card processing
- Forensic audit costs

**5. SOX (financial reporting):**

BL affecting financial records:
- Manipulation of figures
- Audit trail issues
- Internal controls failure

CEOs personally liable.

**6. CCPA (California):**

BL exposing personal info:
- Right to know violated
- Right to delete violated
- Per-violation fines

**7. Industry-specific:**

- Energy: NERC CIP
- Telecom: CPNI
- Education: FERPA
- Children: COPPA

**For your career (fintech):**

BL findings in fintech directly impact:
- RBI compliance (India)
- SEBI regulations
- AML/CFT requirements
- KYC norms

High-value findings, well-paid bug bounties, career-defining work.

### Q51-65: Continuing advanced topics

### Q51: How to perform business logic threat modeling?
**A:**

**Threat modeling for BL:**

**Step 1: Decompose application**

- All features and workflows
- All user types
- All data assets
- All interfaces (web, mobile, API)

**Step 2: Identify assets and their value**

- Money (direct value)
- PII (regulatory value)
- Reputation (brand value)
- IP (competitive value)
- Operations (continuity value)

**Step 3: Threat identification (STRIDE)**

- **S**poofing - Identity flaws
- **T**ampering - Data integrity
- **R**epudiation - Audit issues
- **I**nformation Disclosure - Data leaks
- **D**enial of Service - Availability
- **E**levation of Privilege - Authorization

For BL specifically, focus on T and E.

**Step 4: Threat scenarios**

For each workflow:
- "What if user does X?"
- "What if user does Y between steps?"
- "What if multiple users simultaneously?"
- "What if state is in unexpected condition?"

**Step 5: Rate threats**

DREAD or similar:
- **D**amage
- **R**eproducibility
- **E**xploitability
- **A**ffected users
- **D**iscoverability

**Step 6: Mitigation strategies**

For each high-risk threat:
- Prevention (best)
- Detection (next best)
- Response (last resort)

**Step 7: Implement and review**

- Regular reviews
- After feature additions
- After incidents
- Annual minimum

### Q52: BL testing for SaaS B2B applications
**A:**

**B2B SaaS specific concerns:**

**1. Tenant isolation:**

```
Tenant A's data must never appear in Tenant B's queries
Test:
- Modify tenant_id in all requests
- Try cross-tenant resource access
- Check API responses for other tenants' data
```

**2. Role inheritance:**

```
Organization → Department → Team → Project
User belongs to project
Inherits permissions from team → department → org

Test inheritance edge cases:
- Removed from team, kept project access?
- Org admin sees all departments?
- Department merge: who has what?
```

**3. Approval workflows:**

```
Manager approves expenses
Multi-level approval
- $1000+: VP approval
- $10000+: CFO approval

Test:
- Modify amount in approved request
- Bypass approval levels
- Self-approve
```

**4. Compliance reporting:**

```
SOC 2 requires audit logs
Generate reports for compliance
Test:
- Modify audit logs
- Delete events
- Fake event entries
```

**5. Integration security:**

```
SaaS integrates with Salesforce, Slack, etc.
OAuth flows
Webhook deliveries

Test:
- OAuth account linking attacks
- Webhook spoofing
- Cross-integration data leaks
```

**6. Bulk operations:**

```
"Export all users"
"Bulk update permissions"
"Mass delete records"

Test:
- Authorization on bulk
- Rate limiting on bulk
- Audit logging
- Idempotency
```

**7. Custom fields/scripts:**

```
Customers customize fields
Some platforms allow scripts (Salesforce Apex)

Test:
- Script injection
- Custom field exposure
- Cross-tenant script execution
```

**8. SSO/SAML edge cases:**

```
Customer-provided IdP
SAML assertions trusted

Test:
- Assertion manipulation
- Replay attacks
- IdP compromise impact
```

**9. Billing and tier management:**

```
Different pricing tiers
Per-seat licensing
Usage-based billing

Test:
- Feature access at lower tiers
- Seat count manipulation
- Usage report manipulation
```

**10. Data residency:**

```
EU customers' data must stay in EU
Test:
- Backup destinations
- DR site locations
- Third-party services used
- Logs/metrics shipping
```

### Q53: Common BL flaws in cryptocurrency exchanges
**A:**

**Crypto exchange specific:**

**1. Withdrawal limit bypass:**

```
Daily limit: 1 BTC
Submit 1 BTC withdrawal
Pending state
Submit another 1 BTC (limit hasn't decremented)
Both pending → both succeed
```

**2. Deposit confirmation race:**

```
Deposit BTC to exchange
Network confirmations (6 needed)
Exchange credits at 1 confirmation
Trade with credit
Original transaction reversed (chain reorg)
Trade unaffected
Free crypto
```

**3. Order book manipulation:**

```
Place buy order at high price
Place sell order at low price
Same direction, different prices
Race: orders match? Wash trading?
```

**4. Price oracle manipulation:**

```
Exchange uses external price oracle
Manipulate oracle (flash loan attack)
Trigger liquidations
Profit from manipulated price
```

**5. Fee structure abuse:**

```
Maker: 0.05% fee
Taker: 0.1% fee

Place orders to qualify as maker
Bot front-runs to make you taker
Exploit fee differential
```

**6. Decimal precision:**

```
Crypto has 8+ decimals (BTC)
Some apps truncate vs round
Test edge cases:
0.000000001 BTC
1e-9 BTC
```

**7. Wallet address manipulation:**

```
Generate deposit address
Modify address in some way
Funds sent there
Lost? Or attacker's address?
```

**8. Cross-currency arbitrage:**

```
BTC/USD rate
BTC/EUR rate
EUR/USD rate
If inconsistent: free money
Exchange usually corrects fast
But may have race conditions
```

**9. KYC tier abuse:**

```
Different KYC tiers, different limits
Tier 1: 1 BTC/day
Tier 2: 10 BTC/day
Tier 3: 100 BTC/day

Multiple accounts at different tiers
Aggregate higher limit
```

**10. Margin trading:**

```
Borrow against collateral
Trade with leverage
If liquidation logic flawed:
- Late liquidation = profit
- Early liquidation = loss
Find timing windows
```

### Q54: How to test gift card/voucher systems
**A:**

**Gift card BL testing:**

**1. Balance manipulation:**

```
Balance: $50
Spend $30
Balance shown: $20
Modify balance in API: $200
Spend $200
```

**2. PIN/code brute force:**

```
Gift cards have:
- Card number (visible)
- PIN/scratch code (hidden)

If PIN is short/predictable:
- Brute force valid PINs
- Activate inactive cards
```

**3. Card swap:**

```
Two cards: Card A ($50), Card B ($100)
Use B
But system credits A instead
Pay from A, B still has $100
```

**4. Refund as gift card:**

```
Order $100
Return for gift card refund (full)
Use gift card to buy same product
Return again for gift card
Infinite cycle
```

**5. Currency conversion:**

```
USD gift card
Switch to weak currency mid-payment
Pay less in real terms
```

**6. Bulk activation:**

```
Buy 100 gift cards (with discount)
Some apps offer "buy 100 for $50"
Activate via API in bulk
Some race conditions allow $0 cost
```

**7. Expiration manipulation:**

```
Cards expire in 1 year
Modify expiration date in API
Use expired cards
```

**8. Transfer to other accounts:**

```
Personal gift card
Transfer to family member
But "family member" controlled by you
Re-aggregate
```

**9. Combination with promotions:**

```
Gift card $50
Promotion: 50% off
Apply gift card, then promotion
Or vice versa - order matters
Stack for maximum discount
```

**10. Cross-merchant exchange:**

```
Some platforms exchange gift cards
Card A worth $100 → exchange for Card B worth $90
Manipulate exchange ratio
Or detect when system mispriced
```

### Q55: Business logic in healthcare insurance
**A:**

**Health insurance BL flaws:**

**1. Pre-existing condition manipulation:**

```
Apply for insurance
List no pre-existing conditions
Later: claim made
Modify medical history claim
Insurance covers what shouldn't be
```

**2. Multiple policies:**

```
Buy from Insurer A
Buy from Insurer B
Claim from both for same incident
Both pay
Double coverage (fraud)
```

**3. Out-of-network manipulation:**

```
In-network: 80% covered
Out-of-network: 50% covered

Provider listed in network
Modify "out-of-network" flag in claim
Get 80% even when 50% applicable
```

**4. Pre-authorization bypass:**

```
Procedure requires pre-authorization
Workflow: request → review → approve → procedure
Bypass: directly submit procedure claim
Pre-authorization seems forgotten
```

**5. Deductible manipulation:**

```
Annual deductible: $1000
Manipulate paid amount toward deductible
Exceed earlier
Insurance kicks in sooner
```

**6. Coverage limit gaming:**

```
Annual coverage: $100K
Submit claims close to limit
Year-end: claim small amount
But manipulate date
Spread to multiple years
```

**7. Beneficiary manipulation:**

```
Life insurance beneficiary listed
Modify beneficiary post-death
Redirect payout
```

**8. Family plan abuse:**

```
Family plan covers spouse, children
Add additional people via API
"Family member" not verified
Cover extended family
```

**9. Renewal manipulation:**

```
Premiums adjust based on risk
Insurer reviews annually
Modify health questionnaire
Lower premium next year
```

**10. Network provider gaming:**

```
Network lists certain providers
Use any provider
Modify claim to show network provider
Get network rates
```

### Q56: Insurance claim fraud detection bypass
**A:**

**Bypassing fraud detection:**

**1. Pattern recognition evasion:**

```
Insurer detects:
- Multiple claims short time
- Unusual amounts
- Specific providers

Bypass:
- Spread claims over time
- Vary amounts (avoid round numbers)
- Use multiple providers
```

**2. Document forgery (now detected by AI):**

```
Submit forged medical bills
AI detects forgery
Modify metadata
Submit through different channels
```

**3. Crowd-sourced fraud:**

```
Many small fraud cases
Each below detection threshold
Aggregate: massive
```

**4. Internal collaboration:**

```
Insurance employee + provider
Submit fake claims
Approve internally
Profit split
```

**5. Claim aggregation:**

```
Many small claims under daily limit
Aggregate over months
Total: large fraud
```

### Q57: Crypto wallet business logic flaws
**A:**

**Cryptocurrency wallet BL:**

**1. Seed phrase entropy:**

```
12-word seed phrase
2048 words possible per position
Different ways to handle entropy
Bad implementations have predictability
```

**2. Address generation:**

```
Hierarchical Deterministic (HD) wallets
Generate addresses from seed
If path predictable: future addresses guessable
Drain funds before user sees
```

**3. Transaction fee manipulation:**

```
User sets fee
Wallet uses different fee
Difference goes to wallet provider
Hidden fee extraction
```

**4. Multi-sig threshold:**

```
2-of-3 multi-sig wallet
Modify signature counting logic
1 signature accepted
Single-key control
```

**5. Wallet locking:**

```
Wallet locks after suspicious activity
"Unlock" requires KYC
Some apps allow unlock with different proof
Bypass via account confusion
```

**6. Backup phrase exposure:**

```
Wallet backup
"Encrypted" backup
Encryption with predictable password
Or password sent to server
```

**7. Smart contract interaction:**

```
Wallet interacts with contracts
Trusts contract responses
Malicious contract returns wrong data
Wallet processes incorrectly
```

**8. Transaction confirmation:**

```
Wallet shows transaction
"Confirm to send"
Modify what's signed
User confirms different transaction
Funds to attacker
```

**9. Address book manipulation:**

```
Saved addresses for known recipients
Modify address: same name, different address
User sends to attacker
```

**10. NFT manipulation:**

```
NFT shown in wallet
Display from metadata
Metadata changes
NFT replaced visually (but actual NFT same)
```

### Q58: Business logic in real estate platforms
**A:**

**Real estate platform BL flaws:**

**1. Property listing manipulation:**

```
Search results based on:
- Price range
- Location
- Amenities

Modify listing fields:
- Set price to $1
- Mark as "premium" (boost)
- Fake amenities
```

**2. Mortgage calculator abuse:**

```
Calculator inputs:
- Income
- Debt
- Down payment

Manipulate to qualify for impossible loan
But calculator just suggests, doesn't approve
However, displayed prominence might be game-able
```

**3. Agent commission split:**

```
Buyer's agent: 3%
Seller's agent: 3%
Split between buyer/seller agents

Modify split:
- Same agent both sides
- 6% to attacker
```

**4. Closing cost manipulation:**

```
Closing costs estimated
Some required, some optional
Modify estimates downward
Misrepresent total cost
```

**5. Tour scheduling:**

```
Schedule property tour
Specific property
Modify property in request
Tour scheduled for different (more valuable) property
```

**6. Offer submission:**

```
Submit offer on property
Race condition with other buyer
Multiple offers submitted simultaneously
System may process out of order
```

**7. Background check bypass:**

```
Tenant application requires background check
Skip background check API
Application advances
```

**8. Rental payment manipulation:**

```
Pay rent through app
Modify payment amount
Owner receives less
Difference unaccounted
```

**9. Property valuation:**

```
Auto-valuation models (AVM)
Compare to similar properties
Manipulate "comparable" properties
Inflate own value
Lower others' value
```

**10. Premium listing features:**

```
Premium listings: featured, top of search
Free listings: lower priority
Test premium flag manipulation
```

### Q59: Recruiting platform BL flaws
**A:**

**Recruiting/job platforms:**

**1. Job application limits:**

```
Free tier: 10 applications per day
Premium: unlimited

Test:
- API endpoint per application
- Multiple accounts
- Bulk apply
```

**2. Resume parsing manipulation:**

```
ATS extracts data from resume
Manipulate parsed data
"Years of experience: 50"
"Skills: every keyword they search"
```

**3. Background check timing:**

```
Apply for job
Get offer pending background check
Modify info during background check window
Re-submit
```

**4. Reference verification:**

```
Provide references
Some apps email references for verification
"Verify your reference"
What if you control reference's email?
```

**5. Salary disclosure:**

```
Job posts: "Salary: $X-Y"
You apply with salary expectation $Z
Logic: filter based on range overlap
Modify "expected" silently
```

**6. Employer subscription:**

```
Companies pay for posting jobs
Premium accounts: featured posts
Test free posting masquerading as premium
```

**7. Candidate matching:**

```
Algorithm matches candidates to jobs
Manipulate profile to match more jobs
Inflate qualifications
Spam applications
```

**8. Skills verification:**

```
Some platforms verify skills (LinkedIn Skills)
Take assessment
Manipulate assessment results
False badge
```

**9. Referral bonuses:**

```
Employee refers candidate
Hire → bonus to employee
Fake referrals
Game system
```

**10. Endorsements:**

```
Skills endorsements (LinkedIn-style)
Endorse own skills via API
Or trade endorsements with fake accounts
```

### Q60: Telehealth platform BL flaws
**A:**

**Telehealth specific:**

**1. Appointment booking:**

```
Time slots: 9 AM, 9:30 AM, 10 AM
Limited availability
Book multiple slots simultaneously
Race condition: all succeed
Block legitimate patients
```

**2. Prescription request:**

```
Request prescription
Doctor reviews
Approval required for controlled substances
Bypass approval workflow?
```

**3. Insurance integration:**

```
Insurance covers $200 of visit
Modify visit cost or coverage
Patient pays less / insurance more
```

**4. Provider rating:**

```
Patients rate providers
Multiple ratings from same patient
Or fake patient accounts
Manipulate ratings
```

**5. Provider specialty:**

```
Search by specialty (psychiatrist, cardiologist)
Modify provider's specialty list
Become "psychiatrist" without credentials
```

**6. Video session manipulation:**

```
Video sessions logged
Modify session duration
Doctor billed for less time
Or more time (insurance fraud)
```

**7. Medical record access:**

```
Patient sees own records
Family member access (proxy)
Modify proxy relationships
Access others' records
```

**8. Test results:**

```
Lab results integrated
Modify result values
Insurance covers based on results
Falsify for coverage
```

**9. Chronic care plan:**

```
Chronic conditions ongoing care
Subscription model
Cancel after initial setup
Keep medication access
```

**10. Emergency contact:**

```
Emergency contacts have special access
Mark fake emergency contact
Access patient's records
```

### Q61: Investment/trading platform business logic
**A:**

**Stock trading BL flaws:**

**1. Wash trading:**

```
Buy and sell same stock
Generates volume
Appears as legitimate activity
Manipulates market signals
```

**2. Stop-loss manipulation:**

```
Place stop-loss order
Price approaches stop
Modify stop-loss higher
Or cancel and replace
Avoid execution
```

**3. Margin call abuse:**

```
Margin calls when value drops
Some apps allow positions during call
Trade more, hoping for recovery
Or pull funds before margin call
```

**4. Short selling:**

```
Borrow shares to sell
Buy back later (hopefully lower)
Manipulate borrow availability
Or stock locate fraud
```

**5. Options exercise:**

```
Options expire in/out of money
Last-minute exercise
Manipulate price near expiration
Or exercise after market close
```

**6. Dividend record date:**

```
Own stock on record date → dividend
Buy day before, sell day after
"Dividend capture"
Modify holding date in records
```

**7. Tax loss harvesting:**

```
Sell at loss for tax benefit
Buy back after 30 days (wash rule)
Modify dates in records
Claim loss without 30-day wait
```

**8. Order routing:**

```
Best execution required
Routes to exchange with best price
Manipulate routing for kickbacks
Payment for order flow abuse
```

**9. Pre-IPO allocation:**

```
Limited allocation
Friends and family preference
Modify priority list
Get larger allocation
```

**10. Dark pool abuse:**

```
Dark pools hide orders
Front-run dark pool orders
Internal info leakage
```

### Q62: Social media business logic in detail
**A:**

**Already covered key points in Q27. Adding more depth:**

**Algorithm manipulation:**

```
1. Reach scoring
   - Engagement = boost
   - Time spent = boost
   - Click-through = boost
   
2. Manipulate:
   - Bot engagement
   - Engagement pods (groups boosting each other)
   - Click farms
   - Fake "time spent" reporting
```

**Verification badge:**

```
Verified requires:
- Identity confirmation
- Notable status
- Originality

Bypass:
- Steal verification badge token
- Display badge without verification
- Catfishing legit accounts
```

**Monetization features:**

```
Creator fund
Ad revenue share
Tips/donations

Manipulate:
- Fake views/engagement
- Tip yourself with multiple accounts
- Ad fraud (bot views)
```

**Account recovery flaws:**

```
"I lost access to my account"
Recovery via friends, ID, security questions
- Social engineer friends
- Forged ID
- Public answers to security questions
```

**Privacy slip:**

```
Settings:
- Public profile
- Private profile
- Friends only

But:
- Old API versions ignore privacy
- Search engines indexed
- Shared content propagates
- Backups don't honor privacy changes
```

### Q63: Common BL flaws in CMS platforms
**A:**

**Content Management Systems BL:**

**1. User role assignment:**

```
Admin → Editor → Author → Contributor → Subscriber

Self-assign higher role:
- Modify role in profile update
- Mass assignment vuln
- Role inheritance abuse
```

**2. Post status manipulation:**

```
Draft → Pending → Scheduled → Published → Trash

Skip stages:
- Draft → Published (bypass review)
- Modify status in API
```

**3. Author attribution:**

```
Posts have author
Modify author to someone else
Or unassigned posts visible
```

**4. Comment moderation:**

```
Comments require approval
Auto-approve based on:
- Previous approved comments
- Whitelisted users

Manipulate:
- Get one approved
- Then all auto-approved
- Spam through approved account
```

**5. Plugin/theme installation:**

```
Admin can install plugins
But some plugins have own auth bypass
Sub-admin installs plugin
Plugin grants higher permissions
```

**6. Multisite installation:**

```
Multisite network
Super admin manages
Individual site admins
But cross-site access via shared resources
```

**7. Media library:**

```
Upload media
Other users see public media
Mark sensitive as private
Privacy check on listing but not direct URL
```

**8. Custom post types:**

```
Custom types: products, events, properties
Different access rules per type
Manipulate post_type field
Bypass type-specific permissions
```

**9. Taxonomy abuse:**

```
Categories, tags
Some restricted to certain users
Modify post category to restricted one
Boost visibility
```

**10. SEO meta manipulation:**

```
Meta fields editable
Modify others' posts' SEO
Sabotage competitors
```

### Q64: Bug bounty methodology for BL findings
**A:**

**Finding BL flaws in bug bounty:**

**Step 1: Choose right program**

- New programs (less tested)
- Complex business logic apps
- Financial/e-commerce
- Multi-tenant SaaS
- High-traffic apps

**Step 2: Understand the business**

Spend time:
- Reading docs
- Using the app legitimately
- Watching marketing videos
- Reading blog posts
- Understanding user flows

**Step 3: Build a mental model**

What are:
- The valuable assets?
- The trust assumptions?
- The expected flows?
- The constraints/limits?

**Step 4: Test creatively**

For each feature, ask:
- Can I do this twice?
- Can I do this in unexpected order?
- Can I do this with wrong inputs?
- Can I bypass prerequisites?
- Can I race against the system?

**Step 5: Document and verify**

- Reproduce reliably
- Quantify impact
- Suggest fix
- Write clear PoC

**Step 6: Report well**

Good BL reports include:
- Business impact (not just technical)
- Real-world attack scenarios
- Affected user count
- Financial estimates
- Multiple PoCs if possible

**Successful BL findings examples (from your portfolio):**

- PepsiCo: ₹13,750 → ₹1 (Hall of Fame)
- JBL: 15 subdomains auth bypass (High)
- snapdeploy.dev: Race condition CVSS 9.1

**Bug bounty payouts for BL:**

- Price manipulation: $1K-$10K
- Race conditions: $2K-$50K
- Workflow bypass: $1K-$20K
- Account takeover via BL: $5K-$50K
- Financial flaws: $10K-$100K+

### Q65: Real bug bounty BL findings - case studies
**A:**

**Notable disclosed BL findings:**

**1. Uber - Free rides**

Researcher found:
- Promo code system allowed stacking
- Multiple codes applied
- Total cost: negative
- Uber paid researcher for rides

Bounty: ~$1000-5000

**2. Shopify - $0 orders**

Multiple researchers found:
- Discount logic allowed total < $0
- Free products + refund of "remainder"

Bounty: $500-$10,000 per finding

**3. PayPal - Race conditions**

Several researchers:
- Concurrent operations
- Created money out of thin air
- Or unauthorized transfers

Bounty: $5,000-$50,000

**4. Tesla - Account linking**

Researcher:
- OAuth flow allowed account linking
- Steal someone's Tesla account
- Control their car remotely

Bounty: $10,000

**5. Slack - Workspace promotion**

Multiple findings:
- Free workspace permissions inherited to paid
- Cross-workspace access
- Premium features accessible free

Bounty: $5,000-$15,000

**6. GitHub - Workflow abuse**

Various:
- Actions workflow manipulation
- Secrets exposure
- Privilege escalation

Bounty: $5,000-$30,000

**7. Airbnb - Refund abuse**

Researcher:
- Booking cancellation timing
- Race conditions
- Got refunded and kept reservation

Bounty: $5,000-$10,000

**8. Coinbase - Trading exploits**

Various:
- Order matching flaws
- Race conditions in trading
- Withdrawal bypasses

Bounty: $10,000-$100,000

**Patterns from these:**

- Financial flows = high payout
- Race conditions universal
- Workflow assumptions universal
- Documentation gaps reveal flaws

---

## SECTION C: ADVANCED TOPICS (Q66-100)

### Q66: How AI is changing BL testing
**A:**

**AI assisting BL testing:**

**1. Pattern recognition:**

LLMs analyze:
- Workflow descriptions
- Code paths
- API documentation
- Find anomalies humans miss

**2. Edge case generation:**

AI generates:
- Boundary values
- Unexpected sequences
- Edge case scenarios

**3. Code review:**

LLMs read code:
- Identify BL assumptions
- Suggest test cases
- Highlight potential flaws

**4. Test automation:**

AI-generated test cases:
- Cover business scenarios
- Maintain over time
- Detect regressions

**5. Anomaly detection:**

In production:
- ML models detect unusual patterns
- Flag potential abuse
- Real-time response

**AI tools for testing:**

- **GitHub Copilot** - Suggests test cases
- **OpenAI/Anthropic** - Pattern analysis
- **Custom ML** - App-specific anomaly detection
- **AI-assisted fuzzers** - Smarter test generation

**Limitations:**

- AI doesn't fully understand business context
- Misses creative/lateral thinking
- Manual testing still critical
- Combine with human expertise

**Your career impact:**

- Learn AI tools for productivity
- But human creativity essential
- Specialize in things AI can't do well
- Use AI to scale your work

### Q67: How to build a BL testing checklist for your team
**A:**

**Team BL testing checklist:**

**1. Pre-development:**

- [ ] Threat model reviewed
- [ ] BL assumptions documented
- [ ] State machines diagrammed
- [ ] Edge cases identified
- [ ] Approval workflows mapped

**2. Code review:**

- [ ] All state transitions validated
- [ ] No client-side trust
- [ ] Server-side recomputation
- [ ] Authorization at every step
- [ ] Audit logging present
- [ ] Idempotency keys for sensitive ops
- [ ] Race condition prevention

**3. Unit tests:**

- [ ] Each state transition tested
- [ ] Edge cases (boundaries)
- [ ] Negative values
- [ ] Zero values
- [ ] Maximum values
- [ ] Type confusion

**4. Integration tests:**

- [ ] Multi-step workflows
- [ ] Concurrent operations
- [ ] State machine validation
- [ ] Cross-component interactions

**5. Manual testing:**

- [ ] Workflow bypass attempts
- [ ] Race condition scenarios
- [ ] State manipulation
- [ ] Privilege escalation
- [ ] Resource limit testing

**6. Security testing:**

- [ ] Annual pentest
- [ ] Bug bounty program
- [ ] Regular code review
- [ ] Threat model updates

**7. Production monitoring:**

- [ ] Anomaly detection
- [ ] Pattern recognition
- [ ] Alert on:
  - [ ] Multiple failed operations
  - [ ] Unusual sequences
  - [ ] Cross-tenant attempts
  - [ ] Financial anomalies

**8. Incident response:**

- [ ] Playbooks for BL incidents
- [ ] Quick response capability
- [ ] Customer communication plan
- [ ] Regulatory notification

### Q68: Defensive coding for business logic
**A:**

**Patterns for secure BL:**

**1. Server-side authoritative:**

```python
# BAD: trust client
def create_order(data):
    order.total = data['total']  # Trust client
    order.save()

# GOOD: recompute server-side
def create_order(data):
    items = data['items']
    actual_total = 0
    for item in items:
        product = Product.objects.get(id=item['id'])
        # Use DB price
        actual_total += product.price * item['quantity']
    
    if abs(data['total'] - actual_total) > 0.01:
        raise ValidationError("Total mismatch")
    
    order = Order.objects.create(total=actual_total)
```

**2. State machine validation:**

```python
ALLOWED_TRANSITIONS = {
    'draft': ['submitted'],
    'submitted': ['paid', 'cancelled'],
    'paid': ['shipped', 'refunded'],
    'shipped': ['delivered'],
    'delivered': ['returned'],
    'returned': ['refunded']
}

def transition_state(order, new_state):
    if new_state not in ALLOWED_TRANSITIONS[order.status]:
        raise InvalidTransitionError(
            f"Cannot transition from {order.status} to {new_state}"
        )
    order.status = new_state
    order.save()
```

**3. Atomic operations:**

```python
# BAD: race condition
def withdraw(amount):
    if account.balance >= amount:
        account.balance -= amount
        account.save()

# GOOD: atomic
@transaction.atomic
def withdraw(amount):
    account = Account.objects.select_for_update().get(id=account_id)
    if account.balance >= amount:
        account.balance -= amount
        account.save()
        return True
    return False
```

**4. Idempotency:**

```python
def transfer(idempotency_key, amount, to):
    # Already processed?
    existing = Transfer.objects.filter(idempotency_key=idempotency_key).first()
    if existing:
        return existing
    
    # Process new
    with transaction.atomic():
        transfer = Transfer.objects.create(
            idempotency_key=idempotency_key,
            amount=amount,
            to=to
        )
        # ... process ...
    return transfer
```

**5. Authorization on every step:**

```python
def process_step_n(workflow_id, user):
    workflow = Workflow.objects.get(id=workflow_id)
    
    # Authorize at each step
    if not user.can_access(workflow):
        raise PermissionError()
    
    # Validate state
    if workflow.current_step != n - 1:
        raise InvalidStateError("Must complete previous step")
    
    # ... process ...
```

**6. Comprehensive logging:**

```python
def sensitive_operation(user, data):
    log_event({
        'event': 'sensitive_op_attempt',
        'user': user.id,
        'data': sanitize(data),
        'ip': request.ip,
        'timestamp': datetime.now()
    })
    
    try:
        result = process(data)
        log_event({'event': 'sensitive_op_success', ...})
        return result
    except Exception as e:
        log_event({'event': 'sensitive_op_failure', 'error': str(e), ...})
        raise
```

**7. Input validation:**

```python
def update_quantity(item_id, quantity):
    # Type check
    if not isinstance(quantity, int):
        raise ValidationError("Must be integer")
    
    # Range check
    if quantity < 0:
        raise ValidationError("Must be positive")
    
    if quantity > 1000:
        raise ValidationError("Maximum 1000")
    
    # Business rule
    item = Item.objects.get(id=item_id)
    if quantity > item.stock:
        raise ValidationError("Exceeds available stock")
    
    # ... update ...
```

### Q69: Logging and detection for BL attacks
**A:**

**What to log:**

**1. State transitions:**

```python
def transition_state(order, new_state):
    log_event({
        'event': 'state_transition',
        'order_id': order.id,
        'from_state': order.status,
        'to_state': new_state,
        'user': request.user.id,
        'ip': request.ip
    })
    order.status = new_state
    order.save()
```

**2. Failed transitions:**

```python
try:
    transition_state(order, new_state)
except InvalidTransitionError as e:
    log_event({
        'event': 'invalid_transition_attempt',
        'order_id': order.id,
        'attempted_state': new_state,
        'current_state': order.status,
        'user': request.user.id
    })
```

**3. Authorization checks:**

```python
def check_permission(user, action):
    has_perm = user.has_permission(action)
    log_event({
        'event': 'permission_check',
        'user': user.id,
        'action': action,
        'result': has_perm
    })
    return has_perm
```

**4. Financial operations:**

```python
def transfer(from_account, to_account, amount):
    log_event({
        'event': 'transfer',
        'from': from_account.id,
        'to': to_account.id,
        'amount': amount,
        'user': request.user.id,
        'balance_before': from_account.balance
    })
    # ... process ...
```

**5. Race condition indicators:**

```python
def increment_counter():
    initial_value = counter.value
    counter.value += 1
    counter.save()
    
    # Detect anomaly
    if counter.value != initial_value + 1:
        log_event({
            'event': 'race_condition_suspected',
            'expected': initial_value + 1,
            'actual': counter.value
        })
```

**Detection patterns:**

**1. Velocity checks:**

```sql
-- Many transactions in short time
SELECT user_id, COUNT(*) 
FROM transactions 
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(*) > 50;
```

**2. Anomaly detection:**

```python
# User suddenly makes much larger transactions
def check_transaction_anomaly(user, amount):
    avg_amount = Transaction.objects.filter(
        user=user
    ).aggregate(Avg('amount'))['amount__avg']
    
    if amount > avg_amount * 10:
        alert_security(f"Anomalous transaction: {user.id}")
```

**3. State sequence analysis:**

```python
def detect_workflow_skips(order):
    expected_sequence = ['draft', 'submitted', 'paid', 'shipped']
    actual_sequence = [event.state for event in order.events.all()]
    
    if not is_valid_sequence(expected_sequence, actual_sequence):
        alert_security(f"Invalid workflow: {order.id}")
```

### Q70: BL flaws specific to API security
**A:**

**API-specific BL flaws (OWASP API Top 10):**

**API1: BOLA** - Covered in Part 2

**API2: Broken Authentication** - Covered in Part 4

**API3: Broken Object Property Level Authorization:**

```python
# User updates own profile
PUT /api/users/me
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin"  ← Mass assignment
}
```

**API4: Unrestricted Resource Consumption:**

```
POST /api/search
{"query": "*", "fields": "*", "limit": 100000}
```

Massive query response.

**API5: Broken Function Level Authorization:**

```
Regular user calls /api/admin/users
Should be 403
Actually accessible
```

**API6: Unrestricted Access to Sensitive Business Flows:**

Already covered in Q21.

**API7: SSRF** - Covered in Part 7

**API8: Security Misconfiguration**

**API9: Improper Inventory Management:**

- Old API versions running
- Undocumented endpoints
- Test environments accessible
- Different security per version

**API10: Unsafe Consumption of APIs:**

- Trusting third-party APIs blindly
- No validation of responses
- Trusting external user data

### Q71: How to test "wallet" or balance systems?
**A:**

**Comprehensive wallet testing:**

**1. Balance manipulation:**

```
GET /api/wallet/balance → 100
Modify in transit/response (caching?)
Or directly set via API:
PUT /api/wallet/balance
{"amount": 9999999}
```

**2. Concurrent operations:**

```
Withdraw 50 (twice simultaneously)
Both check balance (100 >= 50 ✓)
Both deduct
Final: -50 (negative)
But you got 100 total
```

**3. Currency mixing:**

```
Wallet shows $100
Operations in INR
Pay ₹100 (= $1.20)
Effectively pay $1.20 for $50 worth
```

**4. Transaction reversal:**

```
Make payment
Cancel transaction
But goods/service received already
Balance not adjusted
```

**5. Rewards crediting:**

```
Earn rewards on purchase
Refund purchase
Rewards not deducted (logic flaw)
```

**6. Transfer manipulation:**

```
Transfer $10 to account A
Modify recipient to attacker
Or modify amount to $1000
```

**7. Cashback abuse:**

```
2% cashback on purchases
Buy and refund
Keep cashback
Repeat
```

**8. Limit bypass:**

```
Daily limit: $1000
Operations close to limit
Concurrent: both succeed, total $1500
```

**9. Negative balance allowed:**

```
Balance: 0
Transaction: -$100
Becomes: -$100 (no overdraft prevention)
```

**10. Reconciliation:**

```
Internal accounting doesn't match wallet display
Modify display
Or modify internal records
Difference becomes profit
```

### Q72: Marketplace/auction BL flaws
**A:**

**Marketplace specific:**

**1. Listing manipulation:**

```
Create listing for product X
After bid received, modify product
Bidder pays for X, gets Y (lower value)
```

**2. Bid manipulation:**

```
Place bid
Cancel after others see
Manipulate price perception
```

**3. Auto-bid abuse:**

```
Set auto-bid maximum
Other bidders manipulate to your max
You pay maximum
```

**4. Withdrawal of winning bid:**

```
Win auction
Don't pay
Some systems penalize
Some don't
```

**5. Seller fee manipulation:**

```
Final value fee: 10%
Modify final value
Pay less in fees
```

**6. Shipping cost manipulation:**

```
Buyer-paid shipping
Modify shipping amount
Buyer pays inflated shipping
```

**7. Return abuse:**

```
Win auction
Pay
Receive item
"Item not as described"
Return for full refund
Keep item
```

**8. Feedback manipulation:**

```
Bad seller / buyer
Manipulate feedback ratings
Modify rating values
```

**9. Closing time manipulation:**

```
Auctions close at specific time
Manipulate time/timezone
Extended bidding window
Last-second sniping
```

**10. Reserve price abuse:**

```
Reserve: $100
Bids: $90 max
Doesn't meet reserve
But modify reserve to $80
Sale completes
```

### Q73: SaaS quotas and limits BL flaws
**A:**

**Quota/limit bypass:**

**1. Concurrent resource creation:**

```
Limit: 10 projects
Create 10 successfully
Race condition: create 5 more simultaneously
All succeed before limit check
```

**2. Soft delete and recreate:**

```
Limit: 10 projects
Have 10
Delete 1
Create 1 (counts as 11 if soft deletes count)
Repeat
```

**3. Multiple account workaround:**

```
Free tier: 100 API calls per day
Use 100
Create another account
Use 100 more
Aggregate higher
```

**4. Time-based quota:**

```
Daily quota
Hit at 11:59 PM
1 minute later: new day, full quota
Effective burst at midnight
```

**5. Resource scope confusion:**

```
Quota per workspace
Or per user?
Or per organization?
Manipulate scope
```

**6. Inactive vs active:**

```
Inactive resources don't count toward quota
"Inactivate" then "Use"
Or modify status
```

**7. Cross-tenant counting:**

```
Multi-tenant
Quota per tenant
Resources in shared pool
Tenant A uses 50, but quota counts only 30 (logic flaw)
```

**8. Free trial extension:**

```
30-day trial
Cancel before charge
Re-signup
Trial extends
```

**9. Beta access:**

```
Beta features: free during beta
Beta ends
Modify "user joined beta" flag
Keep free access
```

**10. Grandfathered pricing:**

```
Old users grandfathered to lower pricing
Modify "user since" date
Get grandfathered rate
```

### Q74: BL flaws in subscription auto-renewal
**A:**

**Subscription renewal abuse:**

**1. Cancel just before renewal:**

```
Monthly subscription
Cancel hour before renewal
Service continues until period end
"Effectively free" if patterns gamed
```

**2. Card on file manipulation:**

```
Credit card stored
Modify card to expired/invalid
Subscription fails to renew
But continues working (grace period)
```

**3. Renewal pricing:**

```
First month: $1
Renewal: $20
Modify renewal to keep $1
Or change subscription before renewal
```

**4. Refund + retry:**

```
Subscription renews
Request refund for renewal
Get refund
Subscription continues (logic flaw)
```

**5. Promotional codes on renewal:**

```
Code only for new subscriptions
Apply on renewal?
Some systems don't validate
```

**6. Plan downgrade timing:**

```
Annual plan: $100
Downgrade to monthly day before renewal
Refund prorated
But monthly billing starts
Effectively skip a year
```

**7. Family plan modification:**

```
Family plan with N members
Renewal coming
Reduce members to 1 (cheaper rate)
After renewal, add back
```

**8. Free trial extension:**

```
Trial → paid
Cancel during trial
Resubscribe immediately
Trial extended (sometimes)
```

**9. Billing currency change:**

```
Subscribed in USD
Switch to INR before renewal
Renewal in INR (cheaper)
Or vice versa
```

**10. Service location change:**

```
US: $20/month
India: $5/month
Change country before renewal
Renew at cheaper rate
```

### Q75: Government/civic platform BL flaws
**A:**

**Government services BL:**

**1. Application timing:**

```
Application deadline: today
Submit at 11:59 PM
Server time vs local time confusion
Effective extension
```

**2. Document submission:**

```
Required: passport, ID, address proof
Submit incomplete
"Pending documents" status
But process advances
Documents never re-checked
```

**3. Appointment booking:**

```
Limited appointment slots
Premium booking service for fee
Test bypassing premium
```

**4. Voter registration:**

```
Eligibility verification
Modify eligibility data
Register where not eligible
```

**5. License renewal:**

```
Renewal window
Renew early (price change?)
Or late (penalty?)
Modify dates
```

**6. Tax filing:**

```
Tax software
Multiple deductions
Some require documentation
Skip docs, claim deductions
```

**7. Public records:**

```
Public records access
Some require fee
Bypass fee with modified requests
```

**8. Permit applications:**

```
Building permit
Required inspections
Modify inspection results
Skip inspections
```

**9. Welfare/benefit eligibility:**

```
Income-based benefits
Modify reported income
Eligible for benefits not entitled to
```

**10. Court document access:**

```
Court records (some restricted)
Bypass restriction in public access portal
View sealed records
```

### Q76: How to test for sequence manipulation?
**A:**

**Sequence/order manipulation:**

**1. Order of operations:**

```
Workflow: Step A → Step B → Step C
Each modifies state

Test:
- Reverse order (C → B → A)
- Mix order (A → C → B)
- Repeat steps (A → A → B → C)
- Skip steps (A → C)
```

**2. Same operation multiple times:**

```
"Apply coupon" → success once
Test:
- Apply same coupon 100 times
- Apply multiple different coupons
- Apply and remove and apply
```

**3. Concurrent operations:**

```
Operation X must happen first
Operation Y depends on X

Test:
- Y before X
- X and Y simultaneously
- Multiple Y's after one X
```

**4. State preservation:**

```
Save draft
Modify
Save again
Modify
... and so on

Test:
- State snapshot manipulation
- Roll back to old state
- Mix new and old data
```

**5. Approval chains:**

```
Submit → Manager → Director → Done

Test:
- Submit directly to Director endpoint
- Bypass Manager
- Approve at multiple levels simultaneously
- Reject after approval
```

**6. Multi-actor workflows:**

```
Buyer initiates → Seller accepts → Payment → Shipping

Test:
- Buyer trying to skip seller acceptance
- Modify seller's response
- Manipulate payment timing
```

**7. Time-based sequences:**

```
Action A required before time T
Action B after time T

Test:
- A after T (should fail, but maybe succeeds)
- B before T
- Concurrent A and B at T
```

**8. State transitions:**

Already covered. Re-emphasizing test:
- Forward jumps
- Backward jumps
- Loops
- Invalid combinations

### Q77: Defensive design for race conditions
**A:**

**Architecture for race condition prevention:**

**1. Database-level constraints:**

```sql
-- Prevent negative balance
ALTER TABLE accounts 
ADD CONSTRAINT positive_balance CHECK (balance >= 0);

-- Unique constraints for idempotency
ALTER TABLE transactions
ADD CONSTRAINT unique_idempotency UNIQUE (idempotency_key);
```

**2. Application-level locking:**

```python
# Pessimistic locking
@transaction.atomic
def withdraw(account_id, amount):
    account = Account.objects.select_for_update().get(id=account_id)
    # Row locked until transaction ends
    if account.balance >= amount:
        account.balance -= amount
        account.save()
```

**3. Optimistic locking:**

```python
account = Account.objects.get(id=account_id)
version = account.version

# Only update if version unchanged
updated = Account.objects.filter(
    id=account_id, version=version
).update(
    balance=F('balance') - amount,
    version=F('version') + 1
)

if updated == 0:
    raise ConcurrentModificationError()
```

**4. Atomic operations:**

```python
# Single SQL statement
Account.objects.filter(
    id=account_id, balance__gte=amount
).update(balance=F('balance') - amount)

# Check rows affected
# 0 = insufficient funds
# 1 = success
```

**5. Distributed locks (Redis):**

```python
import redis_lock

def withdraw(account_id, amount):
    with redis_lock.Lock(redis_client, f"account:{account_id}"):
        account = Account.objects.get(id=account_id)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
```

**6. Queue-based serialization:**

```python
# Don't process directly, queue
def transfer(from_id, to_id, amount):
    queue.put({
        'from': from_id,
        'to': to_id,
        'amount': amount
    })
    # Worker processes serially
```

**7. Event sourcing:**

```python
# Store events, not state
events = [
    {'type': 'deposit', 'amount': 100},
    {'type': 'withdraw', 'amount': 50},
    {'type': 'deposit', 'amount': 25}
]

# Balance computed from events
balance = sum(
    e['amount'] if e['type'] == 'deposit' else -e['amount']
    for e in events
)
```

**8. CQRS pattern:**

Commands handled serially
Queries from read replicas
Separation prevents races

**9. Idempotent operations:**

```python
def perform_action(idempotency_key, action):
    # Check if already done
    if ActionLog.objects.filter(key=idempotency_key).exists():
        return existing_result
    
    # Do action
    result = execute(action)
    ActionLog.objects.create(key=idempotency_key, result=result)
    return result
```

**10. Saga pattern:**

For distributed transactions:
- Each step has compensating action
- If any fails, rollback all
- Maintains consistency

### Q78: Audit trails and forensics for BL incidents
**A:**

**Audit trail design:**

**1. What to capture:**

```python
class AuditEvent:
    timestamp = DateTimeField()
    user = ForeignKey(User)
    event_type = CharField()  # 'order_created', 'payment_processed', etc.
    object_type = CharField()  # 'order', 'payment', etc.
    object_id = CharField()
    
    before_state = JSONField()  # State before change
    after_state = JSONField()   # State after change
    
    ip_address = GenericIPAddressField()
    user_agent = TextField()
    session_id = CharField()
    
    # Metadata
    request_id = CharField()
    api_version = CharField()
    
    # Result
    success = BooleanField()
    error_message = TextField()
```

**2. Logging discipline:**

- Log ALL state changes
- Log decision points
- Log security checks
- Log financial operations
- Don't log sensitive data (passwords, tokens)

**3. Tamper-resistant storage:**

```python
# Append-only log
# Hash chain for integrity
def append_audit(event):
    last_event = AuditEvent.objects.order_by('-id').first()
    prev_hash = last_event.hash if last_event else None
    
    event.previous_hash = prev_hash
    event.hash = compute_hash(event)
    event.save()
```

**4. Forensic queries:**

For incident response:

```sql
-- All actions by user
SELECT * FROM audit_events 
WHERE user_id = ? 
ORDER BY timestamp;

-- Actions on object
SELECT * FROM audit_events 
WHERE object_type = ? AND object_id = ?
ORDER BY timestamp;

-- All transitions of an order
SELECT timestamp, before_state, after_state 
FROM audit_events 
WHERE object_id = 'order_123'
ORDER BY timestamp;
```

**5. Anomaly detection:**

```python
def detect_anomalies():
    # Multiple state transitions in short time
    suspicious = AuditEvent.objects.filter(
        event_type='state_transition',
        timestamp__gte=datetime.now() - timedelta(minutes=1)
    ).values('user_id').annotate(count=Count('id')).filter(count__gt=10)
    
    # Off-hours activity
    off_hours = AuditEvent.objects.filter(
        Q(timestamp__hour__lt=6) | Q(timestamp__hour__gt=22),
        event_type__in=SENSITIVE_EVENTS
    )
    
    # Unusual sequences
    # ... pattern matching
```

**6. Retention:**

- Compliance often 7+ years
- GDPR: appropriate retention
- HIPAA: 6 years
- SOX: 7 years
- Tax: 7 years

**7. Access controls:**

Audit logs themselves protected:
- Read-only for most users
- Admin write requires approval
- Modifications themselves audited
- Encrypted at rest
- Separate database recommended

### Q79: Building security culture around business logic
**A:**

**Building team awareness:**

**1. Threat modeling sessions:**

- Each feature gets threat model
- Cross-functional input
- Devs, QA, security, product

**2. Security champions:**

- Person on each team
- Trained in security
- Reviews PRs
- Liaison with security team

**3. Code review checklist:**

- Authorization at every step?
- State machine validated?
- Server-side authoritative?
- Race condition prevention?
- Audit logging?

**4. Training:**

Topics:
- OWASP Top 10
- BL flaws specifically
- Recent breaches
- Code examples
- Hands-on exercises

**5. Bug bounty internal:**

- Reward employees finding bugs
- Pre-release testing
- Internal CTFs

**6. Post-incident reviews:**

- Every incident analyzed
- Lessons documented
- Process improvements
- Wider team awareness

**7. Security gates:**

- Required reviews for sensitive features
- Threat model required
- Security testing required
- Logging verified

**8. Metrics and KPIs:**

Track:
- Time to fix critical issues
- Bug bounty payouts
- Security incidents
- Compliance status

**9. Documentation:**

- BL assumptions documented
- State machines documented
- Authorization rules documented
- Audit requirements clear

**10. Continuous improvement:**

- Annual security review
- Threat model updates
- Penetration testing
- External audits

### Q80: Working with developers to fix BL flaws
**A:**

**Effective collaboration:**

**1. Clear reporting:**

When reporting BL flaw to dev:

```
Subject: [SECURITY] Price manipulation in checkout

Severity: Critical
Impact: Direct financial loss

Steps to reproduce:
1. ...
2. ...
3. ...

Suggested fix:
[Code example]

Reference:
[Internal ticket, OWASP link, etc.]

Timeline:
- Fix required within: 48 hours
- Verification: After deployment
```

**2. Empathy:**

Devs work hard, no malice in flaws
Frame as collaborative
Focus on system, not person

**3. Concrete examples:**

Show:
- Exact code path
- Exact request/response
- Visual demonstration
- Real impact

**4. Suggested fixes:**

Not just "fix this"
Provide:
- Code suggestions
- Pattern examples
- Library recommendations

**5. Pair programming:**

Sometimes:
- Sit with dev
- Walk through fix
- Verify together

**6. Testing assistance:**

Help create:
- Unit tests
- Integration tests
- Security regression tests

**7. Verification:**

After fix:
- Re-test
- Confirm closure
- Document
- Update threat model

**8. Praise and acknowledgment:**

Public recognition for security-conscious work
Celebrate fixes
Share lessons (without blame)

**9. Continuous learning:**

After incidents:
- Share knowledge
- Update training
- Improve processes

**10. Build relationships:**

Long-term:
- Be available for questions
- Share knowledge proactively
- Be the "security friend"

### Q81-100: Continuing with advanced scenarios and career

### Q81: Career growth in business logic security
**A:**

**Career path:**

**Entry (0-2 years):**
- Learn fundamentals
- Practice on bug bounties
- Find your first BL flaws
- Build reputation

**Mid (2-5 years):**
- Specialize (fintech, healthcare, etc.)
- Lead pentests
- Senior bug bounty hunter
- Speak at meetups

**Senior (5-10 years):**
- Architect security solutions
- Threat modeling expert
- Train others
- Conference speaker

**Principal (10+ years):**
- Industry leader
- Set standards
- Mentor
- Write books, courses

**For your trajectory:**

You're at mid-level. Next steps:
1. Continue bug bounty (build portfolio)
2. Specialize in fintech (Zorvyn helps)
3. Public speaking (Encrypticle)
4. Write detailed blog posts
5. Conferences (BSides India, c0c0n, Nullcon)

**Income potential:**

- Junior Pentester: ₹5-10 LPA
- Mid Pentester: ₹10-20 LPA
- Senior AppSec: ₹20-40 LPA
- Principal AppSec: ₹40-100 LPA+
- Bug bounty (top hunters): $100K-$1M/year

**Skills to develop:**

- Business domain knowledge (fintech, healthcare)
- Cloud security
- DevSecOps
- AI security (emerging)
- Cryptography fundamentals
- Compliance frameworks

### Q82: Common BL flaws in messaging apps
**A:**

**WhatsApp/Telegram/Signal style apps:**

**1. Read receipts:**

```
Read receipt sent when message viewed
Manipulate to not send receipt
Or send receipt without reading
```

**2. Online status:**

```
Show as offline while online
Or appear online during specific times only
```

**3. Last seen:**

```
Last seen visible to contacts
Modify timestamps
Hide actual activity
```

**4. Group membership:**

```
Add yourself to private groups
Or remove others maliciously
Admin permission abuse
```

**5. Channel monetization:**

```
Premium channels pay creator
Subscribe and immediately unsubscribe
Multiple times → manipulate stats
```

**6. Message deletion:**

```
Delete message
But others may have read
Or backup exists
"Deleted" but recoverable
```

**7. Forwarding tags:**

```
Messages marked "forwarded"
Modify to hide forwarding
Spread misinformation appearing original
```

**8. Bot interactions:**

```
Bots have permissions
Some bots over-privileged
Find bot to gain access
```

**9. Sticker/media abuse:**

```
Premium stickers
Get stickers without payment
Resell or share
```

**10. Backup encryption:**

```
End-to-end encryption
But backups stored
Backup encryption potentially weaker
Server access = some data exposure
```

### Q83: Online voting/governance platform BL
**A:**

**Voting platform flaws:**

**1. Vote duplication:**

```
One vote per user
Modify vote count manually
Or vote multiple times across sessions
```

**2. Vote modification:**

```
Vote cast
Modify after casting (some systems allow editing)
But polls maybe closed
Or modify after close
```

**3. Voter eligibility:**

```
Eligibility check
Modify eligibility in profile
Vote where not allowed
```

**4. Vote weighting:**

```
Some users have higher weight (admins?)
Modify weight in your account
```

**5. Anonymous voting:**

```
Voting anonymous
But logs identify voter
Privacy claim false
```

**6. Poll creation:**

```
Create poll
Modify options after voting started
Mislead voters
```

**7. Tally manipulation:**

```
Real-time tally shown
Manipulate display
Don't affect actual count
But affect public perception
```

**8. Poll closing:**

```
Poll closes at certain time
Vote after close (race)
Or modify close time
```

**9. Result interpretation:**

```
Plurality vs majority
Different counting methods
Manipulate which method counts
```

**10. Verification systems:**

```
Vote verification via receipt
Manipulate receipts
Or create fake receipts
```

### Q84: Multi-step authentication BL flaws
**A:**

**Multi-step auth:**

**1. Step bypass:**

```
Step 1: Username/password
Step 2: 2FA
Step 3: Verify email
Step 4: Security questions
Step 5: Dashboard

Bypass: Go directly to dashboard
Or modify step parameter
```

**2. Step replay:**

```
Complete step 2 (2FA) yesterday
Capture token
Replay today to skip 2FA
```

**3. Step from different account:**

```
Step 2 verification token
Use token from different account's flow
Cross-flow contamination
```

**4. Step result manipulation:**

```
Step returns "success" or "fail"
Modify response in transit
Force success
```

**5. Optional step skipping:**

```
"You can skip this step"
But step actually required for security
Skip causes weakness
```

**6. Step timing:**

```
Steps must complete within X minutes
Take longer
Continue anyway
Time check broken
```

**7. Concurrent step submission:**

```
Submit multiple steps simultaneously
Race condition: completion confusion
```

**8. Step parameters:**

```
Steps receive parameters
Modify parameters
Affect later steps
```

**9. Step order manipulation:**

```
Defined order (1 → 2 → 3)
Try (2 → 1 → 3)
Or (1 → 3 → 2)
```

**10. State persistence:**

```
Save progress mid-flow
Resume later
But save modifiable
```

### Q85: Token-based authorization business logic
**A:**

**Token-based BL flaws:**

**1. Token in URL:**

```
http://app.com/page?token=abc123
- Logged in history
- Referer leaks
- Shared accidentally
```

**2. Token reuse across services:**

```
Token for service A
Use on service B
Should be service-specific
But works on B → cross-service vulnerability
```

**3. Token elevation:**

```
Token for read-only operations
Use for write operations
Permission check inadequate
```

**4. Token expiration bypass:**

```
Token expires
Refresh mechanism
Modify expiration time in token
Use indefinitely
```

**5. Token impersonation:**

```
Token contains user_id
Modify user_id
Authenticate as different user
(If signature not validated)
```

**6. Token in caching layers:**

```
Token sent
Cached by CDN
Other users get cached responses
Including authenticated data
```

**7. Token in logs:**

```
Token in URL
Server logs URL with token
Log analysis reveals tokens
Replay attacks
```

**8. Token in error messages:**

```
Token rejected
Error includes token (for debugging)
Stolen via error log
```

**9. Token enumeration:**

```
Token format: prefix + sequential
Predict next tokens
Or brute force
```

**10. Token type confusion:**

```
Access token used as refresh token
Or vice versa
Different validation rules
Use wrong context
```

### Q86: BL flaws in mobile-first apps
**A:**

**Mobile-specific BL:**

**1. Offline mode:**

```
App works offline
Sync when online
Modify state during offline period
Sync conflicts in attacker's favor
```

**2. Local storage manipulation:**

```
Data stored locally (SQLite, NSDictionary)
Modify directly on device
App trusts local data
```

**3. Mock locations:**

```
GPS-based features (delivery, geo-fencing)
Mock location
Appear elsewhere
Bypass geographic restrictions
```

**4. Mock time:**

```
Time-based features (subscriptions, daily rewards)
Change device time
Trigger daily rewards multiple times
Or extend subscriptions
```

**5. App version manipulation:**

```
Feature flags per version
Modify reported version
Access features not available
```

**6. In-app purchases:**

```
Purchase items in app
Validate receipts
Modify receipt or skip validation
Free items
```

**7. Push notifications:**

```
Sensitive actions via push
Intercept notifications
Trigger actions on others' devices
```

**8. Background sync:**

```
App syncs in background
Manipulate sync intervals
Or content
```

**9. Local certificate pinning:**

```
App pins server certificate
Bypass pinning (some libraries)
MITM attacks
Modify in-flight requests
```

**10. Native features:**

```
Camera, mic, location
Override what app sees
Send fake camera input
Geo-fool location
```

### Q87: BL flaws involving third-party integrations
**A:**

**Third-party integration BL:**

**1. OAuth scope abuse:**

```
App requests OAuth scopes
Grants minimal scopes
But uses for more (logic flaw)
```

**2. Webhook manipulation:**

```
Third-party sends webhooks
Replay webhooks
Or send fake webhooks (no signature verification)
```

**3. API key sharing:**

```
Shared API keys between services
Steal from one → access others
```

**4. Service-to-service trust:**

```
Service A trusts Service B (internal IP)
Spoof internal IP
Access B as if from A
```

**5. Single sign-on flaws:**

```
SSO assertion accepted
Modify assertion
Or replay
Authenticate as different user
```

**6. Payment processor integration:**

```
Stripe/PayPal callback
"Payment success"
Modify callback to claim success without payment
```

**7. Email provider integration:**

```
SendGrid/Mailgun
Sending emails on behalf of users
Modify "from" address
Spoof legitimate senders
```

**8. Analytics integration:**

```
Google Analytics
Send custom events
Modify analytics to mislead business decisions
```

**9. CDN trust:**

```
CDN caches content
Modify content via CDN admin
Serve modified version
```

**10. Cloud provider integration:**

```
AWS/Azure integration
Stolen credentials
Used as legitimate service
Privilege escalation
```

### Q88: BL flaws in development tools and CI/CD
**A:**

**DevOps BL flaws:**

**1. Pipeline trigger manipulation:**

```
CI/CD triggered by code push
Modify webhook
Trigger deployment without code change
Or with malicious code injected
```

**2. Secret leakage:**

```
Secrets in environment
Tests log environment for debugging
Test logs accessible
Secrets exposed
```

**3. Branch protection bypass:**

```
Main branch protected
Required reviews
But settings modifiable
Or different paths to merge
```

**4. Deployment approval:**

```
Production deploy requires approval
Bypass approval workflow
Self-approve via different role
```

**5. Artifact tampering:**

```
Built artifacts (Docker images, binaries)
Modify after build
Before deployment
Tampered artifact deployed
```

**6. Dependency confusion:**

```
Internal package name
Public package created with same name
CI/CD pulls from public (precedence)
Malicious code in build
```

**7. PR review gaming:**

```
Required: 2 reviewers
Get 2 friendly reviewers
Or self-review via alt accounts
```

**8. Test bypass:**

```
Tests required to merge
Modify tests to always pass
Or skip tests in pipeline
```

**9. Audit log gap:**

```
Audit logs for operations
Some operations not logged (deployment scripts?)
Use unlogged paths
```

**10. Sandbox escape:**

```
CI/CD runs in sandbox
Some commands escape sandbox
Access host system
Pivot to other resources
```

### Q89: BL flaws in IoT device cloud platforms
**A:**

**IoT cloud BL flaws:**

**1. Device pairing:**

```
QR code pairing
Generate fake codes
Pair with attacker's device
Receive sensitive data
```

**2. Firmware update authority:**

```
Devices accept firmware from cloud
Compromise cloud → push malicious firmware
Mass device compromise
```

**3. Telemetry manipulation:**

```
Devices send data to cloud
Manipulate telemetry
Cloud bills based on data
Or alerts based on data
```

**4. Device command authorization:**

```
Commands sent to devices
Modify command target
Send commands to others' devices
```

**5. Family sharing:**

```
Share device access with family
Modify family list
Add yourself to others' families
Access their devices
```

**6. Geofence manipulation:**

```
Some commands only when home
Manipulate geofence
Trigger remotely
```

**7. Voice assistant integration:**

```
Voice commands trigger actions
Replay voice samples
Or spoof voice signatures
```

**8. Cloud-to-cloud integration:**

```
Smart home hubs integrate
Trust between hubs
Spoof one to control another
```

**9. Mobile app to cloud:**

```
Mobile app commands cloud
Cloud commands device
Compromise app → control device
```

**10. Subscription tier features:**

```
Premium features cloud-side
Free tier limited
Bypass subscription check
```

### Q90: Modern BL flaws emerging in 2026
**A:**

**Emerging BL trends:**

**1. AI/ML integration flaws:**

```
ML models for decisions
Manipulate training data
Or evade detection
Specifically craft inputs
```

**2. Generative AI manipulation:**

```
AI assistants in apps
Prompt injection
Make AI do unauthorized actions
Leak data via AI
```

**3. Blockchain integration:**

```
Apps with blockchain components
Smart contract vulnerabilities
Bridge attacks
DeFi exploits
```

**4. Quantum-resistant crypto transitions:**

```
Mixing old and new crypto
Vulnerabilities in transition
Algorithm confusion
```

**5. WebAssembly attacks:**

```
WASM in browsers
Side-channel attacks
Or BL flaws in WASM code
```

**6. Edge computing:**

```
Logic distributed to edges
Different rules at different edges
Inconsistent enforcement
```

**7. Privacy regulations evolving:**

```
New privacy laws
Apps adapting
Edge cases in compliance
Right to delete vs business need
```

**8. Decentralized identity:**

```
SSI (Self-Sovereign Identity)
Verifiable credentials
New trust models
New flaws
```

**9. Real-time collaboration:**

```
Concurrent editing
CRDT (Conflict-free Replicated Data Types)
Edge cases in merging
Race conditions
```

**10. Web3 wallets:**

```
Browser wallets
Phishing pages
Malicious dApps
Signing arbitrary transactions
```

### Q91: How to test BL in graph-based apps?
**A:**

**Graph-based applications (social networks, knowledge graphs):**

**1. Relationship manipulation:**

```
Friends/connections graph
Modify relationships
Add fake connections
Boost authority via graph
```

**2. Path-based access:**

```
Access via graph traversal
"Friend of friend" rules
Manipulate intermediate nodes
Extended reach
```

**3. Permission inheritance:**

```
Permissions flow through graph
Manipulate flow direction
Inherit from unintended nodes
```

**4. Recommendation manipulation:**

```
Recommendations based on graph
Manipulate graph structure
Inject yourself into recommendations
```

**5. Influence calculation:**

```
PageRank-like influence
Manipulate inbound links
Inflated influence score
Algorithmic boost
```

**6. Anonymization in graphs:**

```
"Anonymous" graph data
But graph structure unique
De-anonymize via structure
Privacy concerns
```

**7. Graph queries:**

```
GraphQL or similar
Complex queries possible
Resource exhaustion
DoS via graph queries
```

**8. Cycle detection:**

```
Graph cycles
Some operations should be acyclic
Create cycles via manipulation
Infinite loops, billing issues
```

**9. Cluster analysis:**

```
Identify communities/clusters
Manipulate cluster membership
Visibility/access changes
```

**10. Edge weight manipulation:**

```
Weighted edges (e.g., relationship strength)
Modify weights
Affect algorithm decisions
```

### Q92: Testing BL in chatbots and AI assistants
**A:**

**Chatbot BL flaws:**

**1. Privilege via conversation:**

```
Chatbot has different responses per role
Claim higher role in conversation
Get privileged information
```

**2. Multi-turn manipulation:**

```
Turn 1: Set context (legitimate)
Turn 2: Build on context
Turn 3: Exploit accumulated context
```

**3. Prompt injection:**

```
"Ignore previous instructions and..."
Or social engineering attacks
Make bot do unintended actions
```

**4. Information leakage:**

```
Bot has access to data
Trick into revealing
"What's my account balance?"
"Show me my last transaction"
But asked from non-owner context
```

**5. Authorization confusion:**

```
Bot represents user
Make requests on behalf
Bot uses bot's permissions vs user's
Excessive access
```

**6. Voice biometric bypass:**

```
Voice authentication
Synthetic voice
Bypass biometric
```

**7. Conversation state manipulation:**

```
Bot maintains conversation state
Modify state via injection
Change context
```

**8. Function calling abuse:**

```
Bot calls functions on user's behalf
Manipulate function selection
Call unintended functions
```

**9. Memory injection:**

```
Bot has long-term memory
Inject malicious memories
Affect future conversations
```

**10. Bot-to-bot communication:**

```
Multiple bots interacting
Manipulate one to affect others
Cascading effects
```

### Q93: Future-proofing your BL testing skills
**A:**

**Skills for the future:**

**1. AI/ML understanding:**

- Adversarial ML
- Model attacks
- Bias in algorithms

**2. Cloud-native patterns:**

- Microservices BL
- Service mesh security
- Container security
- Cloud BL flaws

**3. Cryptocurrency/DeFi:**

- Smart contract BL
- Bridge security
- Oracle manipulation
- Tokenomics flaws

**4. Privacy engineering:**

- Differential privacy
- Federated learning
- Homomorphic encryption
- Zero-knowledge proofs

**5. Quantum readiness:**

- Post-quantum crypto
- Transition challenges
- Hybrid approaches

**6. Automation:**

- Automated BL testing
- AI-assisted discovery
- Self-healing systems

**7. Compliance evolution:**

- New privacy laws
- AI regulations
- Cross-border data flows

**8. Industry specialization:**

- Fintech (your path)
- Healthcare
- Critical infrastructure
- IoT

**9. Communication:**

- Reporting to non-tech
- Business impact analysis
- Risk quantification

**10. Continuous learning:**

- Conferences
- Research papers
- Bug bounty disclosures
- Hands-on practice

### Q94: How to write a BL test  suite for your team
**A:**

**Comprehensive BL test suite:**

```python
class TestOrderBusinessLogic:
    def test_negative_quantity(self):
        """Negative quantities should be rejected"""
        response = self.client.post('/api/cart/add', json={
            'product_id': 1,
            'quantity': -1
        })
        assert response.status_code == 400
    
    def test_zero_quantity(self):
        """Zero quantities should be rejected"""
        response = self.client.post('/api/cart/add', json={
            'product_id': 1,
            'quantity': 0
        })
        assert response.status_code == 400
    
    def test_max_quantity_overflow(self):
        """Integer overflow attempts should be rejected"""
        response = self.client.post('/api/cart/add', json={
            'product_id': 1,
            'quantity': 2147483648  # > MAX_INT
        })
        assert response.status_code == 400
    
    def test_price_manipulation(self):
        """Client-supplied total should be ignored"""
        # Add product to cart (actual price: $100)
        self.client.post('/api/cart/add', json={
            'product_id': 1,
            'quantity': 1
        })
        
        # Try checkout with manipulated total
        response = self.client.post('/api/checkout', json={
            'total': 1,  # Manipulated
            'items': [{'product_id': 1, 'quantity': 1}]
        })
        
        # Should reject or recompute
        assert response.status_code == 400 or response.json()['total'] == 100
    
    def test