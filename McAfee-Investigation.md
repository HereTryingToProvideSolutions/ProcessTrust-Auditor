# Case Study: Why Did McAfee Score 10?

## Initial finding

While testing ProcessTrust Auditor v1.3 on my own Windows 11 computer, I found `mcafee-security` and `mcafee-security-ft` listed as `Informational`, each with a `RiskScore` of `10` after an individual executable signature result of `NotSigned`.

I wasn't intentionally using McAfee as my antivirus, so I wanted to find out what those processes were and whether the score indicated an actual security problem.

![McAfee entries in the process report](04-mcafee-review-finding.png)

**Important:** ProcessTrust's score is a prompt to investigate, **not a malware diagnosis or probability**.

## 1. Identify the running processes

```powershell
Get-Process *mcafee* -ErrorAction SilentlyContinue | Select-Object ProcessName, Id, Path
```

**Observed:** Both McAfee named processes had executable paths inside a `McAfeeSecurity` package directory under `C:\Program Files\WindowsApps`.

## 2. Inspect the Windows application package

```powershell
Get-AppxPackage *McAfee* | Select-Object Name, Version, Publisher, InstallLocation, SignatureKind, Status
```

**Observed:**
- Package name: `5A894077.McAfeeSecurity`
- Version: `2.1.68.0`
- SignatureKind: `Store`
- Status: `Ok`

The package reported Store signing and a healthy package status. This is reassuring package level context, but **it does not by itself independently authenticate every executable or explain the original installation source**. It also helps explain why a file level `NotSigned` result shouldn't automatically be treated as a threat.

## 3. Determine the registered antivirus

```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState, pathToSignedProductExe
```

**Observed:** Windows Defender was the only antivirus listed by Windows Security Center.

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
```

**Observed:** All three values were `True`. Microsoft Defender's antivirus service and real time protection were enabled. This doesn't mean the McAfee processes weren't running; it means they weren't shown as the registered antivirus in that query.

## 4. Investigate how McAfee got there

```powershell
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Match "McAfee" | Select-Object DisplayName, PackageName
```

**Observed:** `5A894077.McAfeeSecurity` was provisioned in Windows. This command required an elevated PowerShell session.

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model
```

**Observed:** Dell Inc., Inspiron 3501.

```powershell
(Get-CimInstance Win32_OperatingSystem).InstallDate
```

**Observed:** February 22, 2025.

I also inspected the package directory timestamps. Its creation time was June 7, 2022, and last write time was February 11, 2025. Those filesystem dates are **not proof of the application's original installation date**.

A search of the most recent 3,000 AppX deployment events returned no matching McAfee entries:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppXDeploymentServer/Operational" -MaxEvents 3000 |
    Where-Object { $_.Message -match "McAfee|5A894077" } |
    Select-Object TimeCreated, Id, Message
```

That absence doesn't establish how the app was installed; the relevant event may be older or absent from that log.

## Assessment

The available evidence is **consistent with McAfee having been included in Dell's software configuration or a Windows provisioning image**, but I could not identify the original installer or exact installation date.

The McAfee package was Store signed and reported `Ok`, and Microsoft Defender was enabled with real time protection. **No malicious activity was established by these checks.** This is a limited assessment, not a complete malware forensic examination.

## What I learned

The most important lesson was to distinguish **a condition that needs verification** from **a confirmed threat**. A `NotSigned` file level result and a score of 10 did not tell the full story. Checking package metadata, executable paths, Windows Security Center, and provisioning provided context that the first scan lacked.

**Possible future improvement:** Check Store package context alongside individual executable signatures and label the score more explicitly as a *review score*.
