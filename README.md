
# ProcessTrust Auditor

**A beginner friendly Windows process and network security auditing tool built with PowerShell.**

ProcessTrust Auditor helps Windows users investigate running processes, examine digital signatures, identify active network connections, and collect supporting information about remote IP addresses.

The project was developed as part of **HereTryingToProvideSolutions (HTTPS)**, a hands-on cybersecurity portfolio focused on investigating real problems and developing practical solutions.

## Why I Built This

While investigating running processes and network connections on my own Windows computer, I discovered that identifying unfamiliar activity often requires several PowerShell commands and manual lookups.

I wanted to combine those steps into one tool that could collect useful evidence and make the investigation process easier, especially for people who are still learning cybersecurity.

## Features

- Enumerates running Windows processes and records their process IDs.
- Checks accessible executable files for digital signatures.
- Collects associated Windows service information when available.
- Identifies established TCP connections and their remote IP addresses and ports.
- Performs reverse DNS and RDAP lookups for additional destination context.
- Assigns preliminary review priorities based on defined security indicators.
- Exports process and network connection reports as CSV files.
- Includes a simple Windows launcher for users unfamiliar with PowerShell.

## Getting Started

### Requirements

- Windows with PowerShell 5.1 or later
- Internet connectivity for RDAP and reverse DNS enrichment
- Appropriate permissions to inspect processes and network connections
- Microsoft Excel or another CSV viewer (optional)

### How to Run

Step 1 — Download ProcessTrust
Scroll to the top of this repository.
Find the Code dropdown above the file list.
Click Code → Download ZIP.

Step 2 — Extract the Files
Find ProcessTrust-Auditor-main.zip in your Downloads folder.
Right-click the ZIP file and select Extract All...
Click Extract.
Open the newly extracted folder.

Important: Do not run ProcessTrust directly from inside the ZIP file. Extract the files first.

Step 3 — Run ProcessTrust
Double-click Run_ProcessTrust.bat inside the extracted folder.
Follow the instructions in the Command Prompt window.
Wait for the audit to finish.

Step 4 — View Your Results

When prompted, type Y and press Enter to open the reports folder.
Open the generated CSV reports in Excel or another spreadsheet application.
Review the process information, network connections, and informational findings.

## Understanding the Reports

ProcessTrust generates two reports:

**Process Report**

Includes process names, PIDs, executable paths, signature status, associated services, network connection counts, risk scores, and review priorities.

**Network Connection Report**

Includes process information, local and remote IP addresses, ports, TCP connection states, reverse DNS results, and RDAP network information.

Reports can be opened in Excel for filtering and investigation.

## Understanding Review Priorities

- **NoFlags:** No defined risk indicators were triggered. This does not guarantee that a process is safe.
- **Informational:** A low-level indicator was detected and may deserve additional review.
- **Higher-priority findings:** Stronger or combined indicators may warrant more immediate investigation, depending on the scoring rules.

Risk scores are investigative aids, not definitive malware classifications.

## Example Investigation

During development, ProcessTrust identified a connection involving the Windows lock-screen application, `LockApp.exe`, communicating with a public IP address over TCP port 80.

The investigation involved:

1. Identifying the executable path and command line.
2. Verifying its Microsoft Windows digital signature.
3. Checking the remote IP address.
4. Performing an RDAP lookup, which identified Fastly as the network operator.
5. Evaluating the evidence without automatically treating the connection as malicious.

The investigation did not establish malicious activity. It demonstrated how combining process and network evidence can help analysts make better-informed decisions.

## Limitations

- ProcessTrust is not antivirus software or an intrusion detection system.
- Network connections are collected as a snapshot, not continuously monitored.
- Some protected Windows processes cannot be inspected completely.
- An unsigned executable is not automatically malicious.
- A valid signature does not guarantee that a process is behaving safely.
- RDAP identifies network registration information, not necessarily the exact website contacted.
- Reverse DNS records may be unavailable.
- Exact requested URLs and network content are not collected.
- Risk classifications depend on the script's current detection rules.

## Skills Demonstrated

- Windows process investigation
- PowerShell scripting and automation
- Digital signature verification
- TCP/IP connection analysis
- DNS and RDAP investigation
- Security event triage
- False-positive analysis
- CSV evidence collection and reporting

## Future Improvements

Potential improvements include application package signature verification, additional process context, more detailed risk indicators, and optional network monitoring.

These are possible future enhancements rather than features currently implemented.

## License

This project is distributed under the MIT License.

---

**HereTryingToProvideSolutions (HTTPS)**

*Learning cybersecurity by investigating problems, building tools, and testing practical solutions.*
