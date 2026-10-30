# ProcessTrust Auditor

**A beginner-friendly Windows process and network security auditing tool built with PowerShell.**

ProcessTrust Auditor helps Windows users investigate running processes, examine digital signatures, identify active TCP connections, and collect information about remote IP addresses.

This project is part of **HereTryingToProvideSolutions (HTTPS)**, a hands-on cybersecurity portfolio focused on investigating real problems and developing practical solutions.

## Why I Built This

While investigating processes and network connections on my own Windows computer, I found that identifying unfamiliar activity often requires several PowerShell commands and manual lookups. I wanted to combine those steps into one tool that collects useful evidence and makes investigation easier, especially for people learning cybersecurity.

## Features

- Lists running Windows processes and process IDs (PIDs).
- Checks accessible executable files for digital signatures.
- Collects associated Windows service information when available.
- Records established TCP connections, including remote IP addresses and ports.
- Performs reverse DNS and RDAP lookups for destination context.
- Assigns preliminary review scores and priorities based on defined indicators.
- Exports separate process and network connection CSV reports.
- Includes a double-click Windows launcher.

## Getting Started

### Requirements

- Windows with PowerShell 5.1 or later
- Internet connection for network enrichment
- Permissions to inspect processes and connections
- Excel or another CSV viewer (optional)

### How to Run

**1. Download:** Above the repository file list, click **Code → Download ZIP**.

**2. Extract:** In Downloads, right-click `ProcessTrust-Auditor-main.zip`, choose **Extract All**, and open the extracted folder. **Do not run the launcher from inside the ZIP.**

**3. Run:** Double-click `Run_ProcessTrust.bat`, read the startup notice, and press a key when prompted. Wait for the audit to finish.

**4. Review:** When prompted, enter **Y** to open the reports folder. Open the newly generated CSV files and check their timestamps and the command window for errors.

Running as administrator may provide more complete information. Review scripts before running them, and only run software you trust.

## What to Expect: Screenshots

These are screenshots from a real Windows 11 test. Your results will vary.

### 1. Extracted files

Locate `Run_ProcessTrust.bat` in the extracted folder.

![Extracted ProcessTrust files](01-extracted-files.png)

### 2. Audit startup

Read the notice and follow the prompt.

![ProcessTrust startup screen](02-audit-start.png)

### 3. Audit summary

This example recorded **224 processes**, **19 established TCP connections**, **219 `NoFlags`**, and **5 `Informational`** process findings.

![ProcessTrust completed audit summary](03-audit-summary.png)

### 4. A finding worth investigating

McAfee-related processes received a score of **10** because their individual executable signature checks returned `NotSigned`.

![McAfee entries flagged for review](04-mcafee-review-finding.png)

**A score of 10 is not a 10/10 malware rating.** It indicates a scoring condition that deserves context, not confirmed malicious activity. I investigated the finding using PowerShell to check executable paths, Microsoft Store package signing, Windows Defender status, and application provisioning.

**[Read the McAfee investigation and PowerShell commands](McAfee-Investigation.md)**

## Understanding the Reports

ProcessTrust generates two CSV files:

- **Process report:** Process names, PIDs, executable paths, signature results, associated services, connection counts, risk scores, and review priorities.
- **Network connection report:** Processes, local and remote IP addresses and ports, TCP states, reverse DNS, and RDAP information.

Open the CSV files in Excel or another spreadsheet viewer. Widen columns and use filters to examine specific rows.

## Understanding Review Scores

- **`NoFlags`:** None of the current defined indicators were triggered. This does **not** guarantee safety.
- **`Informational`:** A condition was detected that may merit further review.
- **Higher-priority findings:** Stronger or combined indicators may deserve closer attention, depending on the current scoring rules.

Scores help **prioritize investigation**. They are not malware verdicts or percentages of danger. An unsigned executable is not automatically malicious.

## Another Investigation: LockApp.exe

During development, ProcessTrust identified an established TCP connection involving the Windows lock-screen application, `LockApp.exe`, and a public IP address on port 80.

I checked the executable path, verified its Microsoft signature, and used RDAP to identify Fastly as the remote network operator. The available evidence did not establish malicious activity. RDAP network ownership does not identify the exact requested website or content.

## Limitations

- Not antivirus software or an intrusion detection system.
- Reports show a **snapshot**, not continuous monitoring.
- Protected processes may not expose all information.
- Valid signatures do not guarantee safe behavior; unsigned files are not automatically malicious.
- RDAP shows registration context, not necessarily the exact website contacted.
- Reverse DNS may be missing; URLs and network content are not collected.
- Review scores depend on the current rules.
- The launcher may display a completion message even after a script failure; verify the command output and timestamps of newly generated reports.

## Skills Demonstrated

PowerShell automation · Windows process investigation · Digital signatures · TCP/IP analysis · DNS and RDAP · Security triage · Evidence-based assessment · CSV reporting

## Future Improvements

Possible enhancements include package-level signature checks, clearer review-score terminology, parent-process context, improved launcher error handling, and optional network monitoring. These are **not** current features.

## License

Distributed under the MIT License.

---

**HereTryingToProvideSolutions (HTTPS)**

*Learning cybersecurity by investigating problems, building tools, and testing practical solutions.*
