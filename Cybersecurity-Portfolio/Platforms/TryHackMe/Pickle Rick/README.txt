# Penetration Testing Lab Report: Pickle Rick

Platform: TryHackMe

Target IP: 10.48.136.186

Severity: High (Full System Compromise)

Executive Summary

The "Pickle Rick" laboratory is an offensive security challenge based on a web application vulnerability leading to Remote Code Execution (RCE). During the assessment, initial reconnaissance uncovered hardcoded credentials in the web source and `robots.txt`. While SSH access was restricted via public-key authentication, a web-based command execution portal allowed for direct system interaction. Security restrictions filtering standard commands (e.g., `cat`) were successfully bypassed using alternative file-viewing utilities (`less`) to retrieve the objective flags.

---

Tools & Technologies Used

Reconnaissance: Web Browser Developer Tools, URL Inspection (`robots.txt`)
Exploitation: Web Command Execution Portal
Bypassing Mechanisms: Alternative Linux binaries (`less`)

---

Technical Walkthrough

Phase 1: Reconnaissance & Enumeration

1. Source Code Inspection: Initial inspection of the web application's homepage source code revealed a hidden username comment:
text
Username: R1ckRul3s

2. Robots.txt Discovery: Navigating to `http://10.48.136.186/robots.txt` exposed a strange string acting as a potential password:Wubbalubbadubdub




Phase 2: Exploitation & Access Attempts

Attempted SSH Access

An attempt was made to establish a direct secure shell connection using the discovered credentials:

bash
ssh R1ckRul3s@10.48.136.186



Result: Failed. The server rejected the connection with a `Permission denied (publickey)` error, indicating that password authentication over SSH was disabled and an authorized SSH key pair was required.

Web Portal Authentication

The credentials (`R1ckRul3s` / `Wubbalubbadubdub`) were successfully entered into the web portal's login panel, granting access to a Command Execution panel capable of running system commands directly on the server.

Phase 3: Restriction Bypass & Flag Retrieval

The web panel executed commands directly, but implementers placed a blacklist filter on standard file-reading commands like `cat`.

To bypass this restriction, alternative Linux utilities were utilized. Instead of `cat`, the `less` command was issued to stream and read the contents of the target files successfully without triggering the filter detection.

# Bypassing the 'cat' filter to view the ingredient file
less Sup3rS3cretPickl3Ingred.txt

---

💡 Key Lessons & Areas for Improvement

 What Went Right:

* **Creative Evasion:** Recognizing that a blocked command (`cat`) doesn't mean the file is unreadable. Utilizing `less` showed strong critical thinking and knowledge of alternative Linux binaries.
* **Thorough Source Code Review:** Finding hidden credentials in HTML comments is a fundamental pentesting win.

### Lessons Learned (Addressing Feedback):

* **The Importance of Context (`whoami` / `id`):** > 📝 **Note:** During the initial access phase, running `whoami` and `id` should always be the absolute first step upon achieving command execution. This establishes exactly *which* user account has been compromised (e.g., `www-data` vs `root`) and defines the baseline privileges available for subsequent privilege escalation attempts. I will ensure this situational awareness check is integrated into my immediate post-exploitation checklist in future labs.

---

### How to use this on GitHub:

1. Create a folder named `Pickle-Rick` inside your repository.
2. Save this text as `README.md` inside that folder.
3. If you have screenshots of the webpage source code or the web panel running `less`, place them in an `img/` subfolder and link them directly into this report!