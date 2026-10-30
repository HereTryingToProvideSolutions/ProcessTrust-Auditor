ProcessTrust Auditor

A beginner friendly Windows process and network security auditing tool built with PowerShell.

ProcessTrust Auditor helps Windows users investigate running processes, examine digital signatures, identify active network connections, and collect supporting information about remote IP addresses.

The project was developed as part of HereTryingToProvideSolutions (HTTPS), a hands on cybersecurity portfolio focused on investigating real problems and developing practical solutions.

Why I Built This
While investigating running processes and network connections on my own Windows computer, I discovered that identifying unfamiliar activity often requires several PowerShell commands and manual lookups.
I wanted to combine those steps into one tool that could collect useful evidence and make the investigation process easier, especially for people who are still learning cybersecurity.

Features
-Enumerates running Windows processes and records their process IDs.
-Checks accessible executable files for digital signatures.
-Collects associated Windows service information when available.
-Identifies established TCP connections and their remote IP addresses and ports.
-Performs reverse DNS and RDAP lookups for additional destination context.
-Assigns preliminary review priorities based on defined security indicators.
-Exports process and network connection reports as CSV files.
-Includes a simple Windows launcher for users unfamiliar with PowerShell.

Getting Started
Requirements
-Windows with PowerShell 5.1 or later
-Internet connectivity for RDAP and reverse DNS enrichment
-Appropriate permissions to inspect processes and network connections
-Microsoft Excel or another CSV viewer (optional)

How to Run

Step 1 — Download ProcessTrust
At the top of this repository, find the Code dropdown above the file list.
Select Download ZIP.

Step 2 — Extract the files
Find `ProcessTrust-Auditor-main.zip` in your Downloads folder.
Right-click it, choose Extract All..., then click Extract.
Open the extracted folder containing `Run_ProcessTrust.bat`.
Important: Do not run the launcher from inside the ZIP. Extract the files first.

Step 3 — Run the audit
Double-click `Run_ProcessTrust.bat` in the extracted folder.
Review the startup information and press a key when prompted.
Wait for the audit to finish. Network lookups may take some time.

Step 4 — View the reports
When prompted, type Y and press Enter to open the reports folder.
Open the newly generated process and connection CSV files in Excel or another spreadsheet application.
Check the timestamps and any error messages to confirm the run completed successfully.
Running as administrator may provide more complete process information. Only run scripts you trust, and review their contents before execution.

See ProcessTrust in Action
These screenshots are from a real Windows 11 test. Your results will vary.
1. Extracted files — locate the launcher
![Extracted ProcessTrust files](01-extracted-files.png)
2. Startup screen — read the audit notice
![ProcessTrust startup screen](02-audit-start.png)
3. Audit summary — review the totals
![ProcessTrust completed audit summary](03-audit-summary.png)
In this example, ProcessTrust recorded 224 processes, 19 established TCP connections, 219 `NoFlags`, and 5 `Informational` process findings. This is a snapshot, not continuous monitoring.
4. Process report — investigate flagged entries
![McAfee review findings in the process report](04-mcafee-review-finding.png)
The McAfee-related entries scored `10` because the individual executable signature check returned `NotSigned`. A score of 10 is not a 10/10 malware rating, and `Informational` does not mean malicious activity was confirmed.
I investigated these findings with additional PowerShell commands to check running processes, Microsoft Store package signing, Windows Defender status, and Windows application provisioning. The evidence was consistent with legitimate packaged software, but it did not establish the original installer or independently authenticate every executable.
Read the full McAfee investigation and PowerShell commands
Understanding the Reports
ProcessTrust generates two CSV reports:
Process Report: Process names, PIDs, executable paths, signature status, associated services, network connection counts, risk scores, and review priorities.
Network Connection Report: Process information, local and remote IP addresses, ports, TCP connection states, reverse DNS results, and RDAP network information.
You can open the CSV files in Excel, widen columns, and filter rows for further investigation.
Understanding Review Priorities
NoFlags: No defined indicators were triggered. This does not guarantee a process is safe.
Informational: A defined condition was detected and may deserve review.
Higher-priority findings: Stronger or combined indicators may warrant more immediate investigation, depending on the script's scoring rules.
Risk scores are investigation aids, not malware verdicts or percentages of danger. In v1.3, an unsigned executable can receive a score of `10` even when additional context suggests a legitimate application.
Example Investigation: LockApp.exe
During development, ProcessTrust identified a connection involving the Windows lock-screen application, `LockApp.exe`, communicating with a public IP address over TCP port 80.
I investigated the executable path and command line, verified its Microsoft Windows digital signature, checked the remote IP address, and performed an RDAP lookup that identified Fastly as the network operator.
The investigation did not establish malicious activity. It demonstrated how combining process and network evidence can help an analyst make a better-informed assessment. RDAP ownership alone does not identify the exact website or content requested.
Limitations
ProcessTrust is not antivirus software or an intrusion detection system.
Network connections are collected as a snapshot, not continuously monitored.
Some protected Windows processes cannot be inspected completely.
An unsigned executable is not automatically malicious.
A valid signature does not guarantee that a process is behaving safely.
RDAP identifies network registration information, not necessarily the exact website contacted.
Reverse DNS records may be unavailable.
Exact requested URLs and network content are not collected.
Risk classifications depend on the script's current detection rules.
The launcher may display a completion message even after a script failure; check for errors and freshly timestamped reports.
Skills Demonstrated
Windows process investigation
PowerShell scripting and automation
Digital signature verification
TCP/IP connection analysis
DNS and RDAP investigation
Security triage and evidence-based assessment
False-positive investigation
CSV evidence collection and reporting
Future Improvements
Potential improvements include application package signature verification, clearer scoring terminology, additional process context, improved launcher error handling, and optional network monitoring. These are possible future enhancements rather than features currently implemented.
License
This project is distributed under the MIT License.
---
HereTryingToProvideSolutions (HTTPS)
Learning cybersecurity by investigating problems, building tools, and testing practical solutions.
