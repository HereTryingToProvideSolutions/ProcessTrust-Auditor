# McAfee Investigation: Why Did ProcessTrust Give It a Score of 10?

## What I Found

While testing ProcessTrust Auditor v1.3 on my Windows 11 computer, I noticed two processes, `mcafee-security` and `mcafee-security-ft`, in the report. Both had a `RiskScore` of `10` and an `Informational` review priority because the individual executable signature checks returned `NotSigned`.

I wasn't using McAfee as my main antivirus, so I wanted to know why those processes were running and whether there was actually a security problem.

![McAfee entries in the process report](04-mcafee-review-finding.png)

**The score is a reason to investigate, not proof of malware.**

## 1. Find the Processes

I started by checking their names, process IDs, and executable paths.

```powershell
Get-Process *mcafee* -ErrorAction SilentlyContinue | Select-Object ProcessName, Id, Path
```

**Result:** Both processes were running from a McAfeeSecurity application package directory under `C:\Program Files\WindowsApps`.

## 2. Check the Windows Application Package

Next, I looked at the installed application package information.

```powershell
Get-AppxPackage *McAfee* | Select-Object Name, Version, Publisher, InstallLocation, SignatureKind, Status
```

**Results:**

- Package name: `5A894077.McAfeeSecurity`
- Version: `2.1.68.0`
- `SignatureKind`: `Store`
- `Status`: `Ok`

Windows reported that the package used Microsoft Store signing and had an `Ok` status. That gave me useful context, but it didn't independently verify every executable or tell me who originally installed the application.

It also showed why I shouldn't assume that a `NotSigned` result for one file means the entire application is malicious.

## 3. Check Which Antivirus Windows Is Using

I wanted to know whether McAfee was registered as the computer's antivirus.

```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState, pathToSignedProductExe
```

**Result:** Windows Defender was the only antivirus listed by Windows Security Center.

I also checked whether Defender was running:

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
```

**Result:** All three values were `True`. Defender's antivirus service and real time protection were enabled.

This didn't mean the McAfee processes weren't running. It meant McAfee wasn't listed as the registered antivirus in that query.

## 4. Look Into How McAfee Got There

I checked whether the application was provisioned in Windows. This command required an administrator PowerShell window.

```powershell
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Match "McAfee" | Select-Object DisplayName, PackageName
```

**Result:** `5A894077.McAfeeSecurity` was provisioned in Windows.

I checked the computer model:

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model
```

**Result:** Dell Inc., Inspiron 3501.

I checked the Windows installation date:

```powershell
(Get-CimInstance Win32_OperatingSystem).InstallDate
```

**Result:** February 22, 2025.

The package directory showed a creation date of June 7, 2022, and a last modified date of February 11, 2025. Those dates don't prove when the application was originally installed.

I also searched the most recent 3,000 Windows application deployment events for McAfee:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppXDeploymentServer/Operational" -MaxEvents 3000 |
    Where-Object { $_.Message -match "McAfee|5A894077" } |
    Select-Object TimeCreated, Id, Message
```

**Result:** No matching events appeared in that search. That doesn't prove the application wasn't installed normally. The relevant events could be older or no longer available.

## My Assessment

The evidence was consistent with McAfee being included in Dell's software setup or a Windows provisioning image. I couldn't confirm the original installer or exact installation date, so I wouldn't call that explanation proven.

The application package reported Store signing and an `Ok` status. Defender was also enabled with real time protection. **These checks did not establish malicious activity**, although they were not a complete forensic examination.

## What I Learned

The biggest lesson for me was that a finding from a script is only the start of an investigation.

At first, I saw `NotSigned` and a score of 10. After checking the package information, executable paths, antivirus registration, and Windows provisioning, I had a much better explanation for what I was seeing.

**One improvement for ProcessTrust:** I want to check Windows application package signing alongside individual file signatures and make it clearer that `RiskScore` is a review score, not a malware rating.
