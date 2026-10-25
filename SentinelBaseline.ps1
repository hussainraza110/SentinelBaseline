# SentinelBaseline.ps1
# Read-only Windows infrastructure assessment, baseline comparison, and evidence-integrity metadata.
# Run only on systems you own or are explicitly authorized to assess.

[CmdletBinding()]
param(
    [ValidateSet('Capture','Compare')]
    [string]$Mode = 'Capture',

    [string]$BaselinePath,

    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot 'Evidence')

)

# Interactive startup: obtain explicit consent before collection.
$Banner = @'
  .oooooo.   .oooooo..o .oooooo..o .oooooo..o .oooooo..o
 d8P'  `Y8b d8P'    `Y8 d8P'    `Y8 d8P'    `Y8 d8P'
888      888 Y88bo.     Y88bo.     Y88bo.     Y88bo.
888      888  `Y8888o.   `Y8888o.   `Y8888o.   `Y8888o.
888      888      `Y88b      `Y88b      `Y88b      `Y88b
`88b    d88' oo     .d8P oo     .d8P oo     .d8P oo     .d8P
 `Y8bood8P'  88888888P'  88888888P'  88888888P'  88888888P'
'@

Clear-Host
Write-Host $Banner -ForegroundColor Cyan
Write-Host ''
Write-Host 'S E N T I N E L B A S E L I N E' -ForegroundColor Cyan
Write-Host 'Windows Security Baseline & Evidence Toolkit' -ForegroundColor White
Write-Host 'Capture. Compare. Verify.' -ForegroundColor DarkCyan
Write-Host ''
Write-Host 'SentinelBaseline collects Windows system inventory and selected security-posture indicators,' -ForegroundColor Gray
Write-Host 'creates timestamped reports and versioned snapshots, compares snapshots with a prior baseline,' -ForegroundColor Gray
Write-Host 'and records SHA-256 integrity metadata with a local hash-linked activity trail.' -ForegroundColor Gray
Write-Host 'It is not a complete compliance audit or a tamper-proof forensic acquisition system.' -ForegroundColor Yellow
Write-Host ''

$continue = Read-Host 'Type CONTINUE to proceed, or anything else to exit'
if ($continue -cne 'CONTINUE') {
    Write-Host 'User did not continue. No assessment was run.' -ForegroundColor Yellow
    exit 0
}

Write-Host ''
Write-Host 'LICENSE AGREEMENT — SENTINELBASELINE ATTRIBUTION-REQUIRED LICENSE v1.0' -ForegroundColor Yellow
Write-Host 'Copyright (c) 2026 Hussain Raza Naqvi' -ForegroundColor Gray
Write-Host ''
Write-Host 'Subject to these conditions, you may download, use, copy, share, redistribute, and modify' -ForegroundColor Gray
Write-Host 'SentinelBaseline for lawful purposes:' -ForegroundColor Gray
Write-Host '  1. Retain this license, copyright, and attribution notices with all copies.' -ForegroundColor Gray
Write-Host '  2. Provide visible credit when downloading, using, sharing, redistributing, publishing,' -ForegroundColor Gray
Write-Host '     or materially adapting the software, and link to the repository where practical.' -ForegroundColor Gray
Write-Host '  3. Identify modified versions and do not imply the original author endorses your changes.' -ForegroundColor Gray
Write-Host '  4. Use the software only where you have authorization; this license grants no access rights.' -ForegroundColor Gray
Write-Host '  5. The software is provided AS IS, without warranties, to the maximum extent permitted by law.' -ForegroundColor Gray
Write-Host ''
Write-Host 'Attribution: SentinelBaseline by Hussain Raza Naqvi — https://github.com/hussainraza110/SentinelBaseline' -ForegroundColor Cyan
Write-Host 'This is a custom license, not an OSI-approved standard open-source license.' -ForegroundColor Yellow
Write-Host ''
$licenseAccepted = Read-Host 'Do you accept the license agreement? Type ACCEPT to continue'
if ($licenseAccepted -cne 'ACCEPT') {
    Write-Host 'License not accepted. No assessment was run.' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host 'DISCLAIMER AND AUTHORIZED-USE NOTICE' -ForegroundColor Yellow
Write-Host 'SentinelBaseline is intended for authorized digital-forensics support, system assessment,' -ForegroundColor Gray
Write-Host 'evidence gathering, configuration-baseline comparison, and evidence-traceability purposes.' -ForegroundColor Gray
Write-Host 'Use it only on systems and networks you own or are explicitly authorized to assess.' -ForegroundColor Gray
Write-Host 'The script is provided AS IS. The author makes no warranty and, to the maximum extent' -ForegroundColor Gray
Write-Host 'permitted by applicable law, disclaims liability for damages arising from use or misuse.' -ForegroundColor Gray
Write-Host 'Nothing here excludes liability that cannot lawfully be excluded or overrides legal duties.' -ForegroundColor Gray
Write-Host 'Local hashes and logs do not guarantee forensic authenticity or immutability.' -ForegroundColor Gray
Write-Host ''
$disclaimerAccepted = Read-Host 'Do you accept this disclaimer and authorized-use restriction? Type ACCEPT to continue'
if ($disclaimerAccepted -cne 'ACCEPT') {
    Write-Host 'Disclaimer not accepted. No assessment was run.' -ForegroundColor Red
    exit 1
}

# Check elevation only after the user has accepted both the license and disclaimer.
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdministrator = $false
}
if (-not $isAdministrator) {
    Write-Host ''
    Write-Host 'Administrator privileges are required for the broadest collection coverage.' -ForegroundColor Red
    Write-Host 'No assessment was run. Reopen PowerShell using Run as administrator and try again.' -ForegroundColor Yellow
    exit 1
}
Write-Host ''
Write-Host 'Consent recorded for this run. Administrator privileges confirmed. Starting assessment...' -ForegroundColor Green
Write-Host ''

$ErrorActionPreference = 'SilentlyContinue'
$Start = Get-Date
$StartUtc = $Start.ToUniversalTime()
$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "$HostName-$Stamp"
if ($Mode -eq 'Compare' -and [string]::IsNullOrWhiteSpace($BaselinePath)) {
    throw "Mode Compare requires -BaselinePath pointing to a previously generated .snapshot.json file."
}

# Always save reports in the directory containing this PS1 file,
# regardless of the caller's current working directory.
$ScriptDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) {
    $ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) {
    $ScriptDirectory = (Get-Location).Path
}
$CsvPath = Join-Path $ScriptDirectory "$RunId.csv"
$TxtPath = Join-Path $ScriptDirectory "$RunId.txt"
$Rows = New-Object System.Collections.Generic.List[object]

function Add-Row {
    param([string]$Section,[string]$Item,[object]$Value,[string]$Status='INFO',[string]$Details='')
    $Rows.Add([pscustomobject]@{
        Section=$Section; Item=$Item; Value=[string]$Value; Status=$Status; Details=$Details
    })
}
function Safe-Cim { param([string]$Class,[string]$Namespace='root/cimv2'); try { Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop } catch { $null } }
function Size-MB { param([object]$Bytes); if ($null -eq $Bytes) { return '' }; return [math]::Round(([double]$Bytes/1MB),2) }
function Join-Values { param([object[]]$Values); if ($null -eq $Values) { return '' }; return (($Values | ForEach-Object {[string]$_}) -join '; ') }
function BoolText { param([object]$Value); if ($null -eq $Value) { return 'Unknown' }; if ($Value) {'Yes'} else {'No'} }
function Get-RegistryValueSafe { param([string]$Path,[string]$Name); try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null } }

Add-Row 'HOST' 'Computer Name' $HostName
Add-Row 'HOST' 'FQDN' ([System.Net.Dns]::GetHostEntry($HostName).HostName)
Add-Row 'HOST' 'Collection Time' $Start.ToString('s')
Add-Row 'HOST' 'PowerShell Version' $PSVersionTable.PSVersion.ToString()
Add-Row 'HOST' 'Run As Administrator' (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

# OS / host
$cs=Safe-Cim 'Win32_ComputerSystem'; $bios=Safe-Cim 'Win32_BIOS'; $os=Safe-Cim 'Win32_OperatingSystem'; $base=Safe-Cim 'Win32_BaseBoard'; $cpu=Safe-Cim 'Win32_Processor'
Add-Row 'OS' 'Manufacturer' $cs.Manufacturer
Add-Row 'OS' 'Model' $cs.Model
Add-Row 'OS' 'Serial Number' $bios.SerialNumber
Add-Row 'OS' 'Baseboard' ("{0} {1}" -f $base.Manufacturer,$base.Product)
Add-Row 'OS' 'BIOS Version' (Join-Values $bios.SMBIOSBIOSVersion)
Add-Row 'OS' 'OS Caption' $os.Caption
Add-Row 'OS' 'OS Version' $os.Version
Add-Row 'OS' 'OS Build' $os.BuildNumber
Add-Row 'OS' 'OS Architecture' $os.OSArchitecture
Add-Row 'OS' 'Install Date' ($(if($os.InstallDate){$os.InstallDate.ToString('s')}))
Add-Row 'OS' 'Last Boot' ($(if($os.LastBootUpTime){$os.LastBootUpTime.ToString('s')}))
Add-Row 'OS' 'Domain' $cs.Domain
Add-Row 'OS' 'Domain Joined' $cs.PartOfDomain
Add-Row 'OS' 'Windows 10 Standard Support' ($(if($os.Caption -match 'Windows 10'){'Ended 2025-10-14'}else{'N/A'}))
Add-Row 'OS' 'CPU' (Join-Values ($cpu | ForEach-Object {$_.Name}))
Add-Row 'OS' 'CPU Cores / Logical' ((Join-Values ($cpu | ForEach-Object {"$($_.NumberOfCores) / $($_.NumberOfLogicalProcessors)"})))

# Detailed hardware
$ram=Safe-Cim 'Win32_PhysicalMemory'; $disks=Safe-Cim 'Win32_DiskDrive'; $vols=Safe-Cim 'Win32_LogicalDisk'
foreach($r in $ram){ Add-Row 'HARDWARE' 'RAM Module' ("Slot=$($r.DeviceLocator); Capacity=$(Size-MB $r.Capacity) MB; Speed=$($r.Speed) MHz; Manufacturer=$($r.Manufacturer); Part=$($r.PartNumber)") }
foreach($d in $disks){ Add-Row 'HARDWARE' 'Physical Disk' ("Index=$($d.Index); Model=$($d.Model); Serial=$($d.SerialNumber); Size=$(Size-MB $d.Size) MB; Interface=$($d.InterfaceType); Media=$($d.MediaType)") }
foreach($v in $vols){ Add-Row 'HARDWARE' 'Logical Volume' ("Drive=$($v.DeviceID); Label=$($v.VolumeName); FileSystem=$($v.FileSystem); Size=$(Size-MB $v.Size) MB; Free=$(Size-MB $v.FreeSpace) MB") }

# Security posture
$sb=$null
$secureBootQueryStatus='UNKNOWN'
try {
    $sb=(Confirm-SecureBootUEFI -ErrorAction Stop)
    $secureBootQueryStatus='QUERIED'
} catch {
    $secureBootQueryStatus='UNAVAILABLE'
}
$tpm=Safe-Cim 'Win32_Tpm' 'root/cimv2/security/microsofttpm'; $fw=Get-NetFirewallProfile; $def=Get-MpComputerStatus
Add-Row 'SECURITY' 'Secure Boot' (BoolText $sb) ($(if($secureBootQueryStatus -eq 'UNAVAILABLE'){'UNKNOWN'}else{'INFO'})) 'Unavailable can mean legacy BIOS, unsupported cmdlet, or insufficient permissions; do not treat as disabled.'
Add-Row 'SECURITY' 'TPM Present' (BoolText ($null -ne $tpm))
if($tpm){ Add-Row 'SECURITY' 'TPM Version' $tpm.SpecVersion }
Add-Row 'SECURITY' 'Defender Antivirus Enabled' (BoolText $def.AntivirusEnabled)
Add-Row 'SECURITY' 'Defender Real-time Protection' (BoolText $def.RealTimeProtectionEnabled)
Add-Row 'SECURITY' 'Defender Signature Age (days)' $def.AntivirusSignatureAge
foreach($f in $fw){ Add-Row 'SECURITY' "Firewall $($f.Name)" (BoolText $f.Enabled) }
Add-Row 'SECURITY' 'UAC EnableLUA' (Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
Add-Row 'SECURITY' 'RDP Enabled' ($(if((Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0){'Yes'}else{'No'}))
Add-Row 'SECURITY' 'SMBv1 Feature' ($(try{(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State}catch{'Unknown'}))
Add-Row 'SECURITY' 'BitLocker OS Volume' ($(try{(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus}catch{'Unknown'}))
$gpus=Safe-Cim 'Win32_VideoController'; foreach($g in $gpus){ Add-Row 'HARDWARE' 'GPU' ("Name=$($g.Name); Driver=$($g.DriverVersion); VideoMemoryMB=$(Size-MB $g.AdapterRAM)") }
$ch=Safe-Cim 'Win32_SystemEnclosure'; Add-Row 'HARDWARE' 'Chassis Type' (Join-Values $ch.ChassisTypes)
Add-Row 'SECURITY' 'PowerShell Script Block Logging' (Get-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
Add-Row 'SECURITY' 'PowerShell Module Logging' (Get-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging')

# CIS-aligned checks (assessment indicators; not CIS-CAT replacement)
# Three-state checks prevent query failures from being reported as PASS.
function Add-AssessmentCheck {
    param([string]$Name,[object]$Observed,[string]$Expected,[string]$Details='')
    $status='UNKNOWN'
    if ($null -ne $Observed) {
        if ([string]$Observed -eq $Expected) { $status='PASS' } else { $status='FAIL/REVIEW' }
    }
    Add-Row 'CIS' $Name $status $status ("Observed=$Observed; Expected=$Expected. $Details")
}
$uacValue=Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Add-AssessmentCheck 'UAC enabled' $uacValue '1' 'Assessment indicator only; confirm applicable benchmark and policy.'
foreach($profileName in 'Domain','Private','Public') {
    $profile=$fw | Where-Object Name -eq $profileName | Select-Object -First 1
    $profileEnabled=$null
    if ($null -ne $profile) { $profileEnabled=[int][bool]$profile.Enabled }
    Add-AssessmentCheck "Firewall $profileName enabled" $profileEnabled '1' 'Firewall profile must be present and enabled.'
}
$smbState=$null
try {
    $smbFeature=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    if ($null -ne $smbFeature -and $smbFeature.State) {
        if ([string]$smbFeature.State -eq 'Disabled') { $smbState='Disabled' }
        elseif ([string]$smbFeature.State -eq 'Enabled') { $smbState='Enabled' }
        else { $smbState=[string]$smbFeature.State }
    }
} catch {}
$smbCheckStatus='UNKNOWN'
if ($smbState -eq 'Disabled' -or $smbState -eq 'DisabledWithPayloadRemoved') { $smbCheckStatus='PASS' }
elseif ($smbState -eq 'Enabled') { $smbCheckStatus='FAIL/REVIEW' }
Add-Row 'CIS' 'SMBv1 disabled' $smbCheckStatus $smbCheckStatus "Observed=$smbState; unknown/query failure is not treated as disabled."
$secureBootCheck='UNKNOWN'
if ($secureBootQueryStatus -eq 'QUERIED') {
    if ($sb -eq $true) { $secureBootCheck='PASS' } else { $secureBootCheck='FAIL/REVIEW' }
}
Add-Row 'CIS' 'Secure Boot enabled' $secureBootCheck $secureBootCheck "QueryStatus=$secureBootQueryStatus; validate firmware mode and platform support."
$tpmStatus='UNKNOWN'
if ($null -ne $tpm) { $tpmStatus='PASS' }
Add-Row 'CIS' 'TPM present' $tpmStatus $tpmStatus 'Presence check only; validate TPM version and organizational requirements.'
$scriptBlockValue=Get-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Add-AssessmentCheck 'PowerShell Script Block Logging enabled' $scriptBlockValue '1' 'Registry policy value indicates policy configuration, not necessarily effective logging.'
# Network
$adapters=Get-NetAdapter; $ips=Get-NetIPAddress; $routes=Get-NetRoute; $dns=Get-DnsClientServerAddress
foreach($a in $adapters){ Add-Row 'NETWORK' 'Adapter' ("Name=$($a.Name); Status=$($a.Status); MAC=$($a.MacAddress); Link=$($a.LinkSpeed); Type=$($a.InterfaceDescription)") }
foreach($i in $ips | Where-Object AddressFamily -eq 'IPv4'){ Add-Row 'NETWORK' 'IPv4 Address' ("Interface=$($i.InterfaceAlias); Address=$($i.IPAddress); Prefix=$($i.PrefixLength); Type=$($i.PrefixOrigin)") }
foreach($d in $dns){ Add-Row 'NETWORK' 'DNS Servers' ("Interface=$($d.InterfaceAlias); Servers=$(Join-Values $d.ServerAddresses)") }
foreach($r in $routes | Where-Object AddressFamily -eq 'IPv4'){ Add-Row 'NETWORK' 'Route' ("Interface=$($r.InterfaceAlias); Destination=$($r.DestinationPrefix); NextHop=$($r.NextHop); Metric=$($r.RouteMetric)") }
foreach($l in (Get-NetTCPConnection -State Listen)){ Add-Row 'NETWORK' 'Listening TCP Port' ("Local=$($l.LocalAddress):$($l.LocalPort); PID=$($l.OwningProcess); Process=$((Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName)") }
foreach($u in (Get-NetUDPEndpoint)){ Add-Row 'NETWORK' 'UDP Listener' ("Local=$($u.LocalAddress):$($u.LocalPort); PID=$($u.OwningProcess); Process=$((Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue).ProcessName)") }

# Removable media / USB / smartcard / phones / portable drives
$pnp=Get-PnpDevice -PresentOnly:$false
foreach($d in $pnp | Where-Object {$_.Class -match 'USB|SmartCard|WPD|Bluetooth' -or $_.InstanceId -match 'USBSTOR|VID_|PID_|WPDBUSENUM|SCSI\\Disk|SD|SMARTCARD'}){
    Add-Row 'REMOVABLE_MEDIA' 'Device' ("Status=$($d.Status); Class=$($d.Class); Name=$($d.FriendlyName); InstanceId=$($d.InstanceId); Manufacturer=$($d.Manufacturer)")
}
$usbStor=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue
foreach($x in $usbStor){ Add-Row 'REMOVABLE_MEDIA' 'USBSTOR Registry' ("Path=$($x.PSPath); FriendlyName=$($x.FriendlyName); Serial=$($x.SerialNumber)") }
$drives=$vols | Where-Object DriveType -eq 2
foreach($d in $drives){ Add-Row 'REMOVABLE_MEDIA' 'Removable Drive' ("Drive=$($d.DeviceID); Label=$($d.VolumeName); FileSystem=$($d.FileSystem); Size=$(Size-MB $d.Size) MB; Free=$(Size-MB $d.FreeSpace) MB") }
$sc=Get-PnpDevice -PresentOnly:$false | Where-Object {$_.Class -match 'SmartCard|SmartCardReader' -or $_.FriendlyName -match 'smart.?card|card reader'}
foreach($d in $sc){ Add-Row 'REMOVABLE_MEDIA' 'Smart Card / Reader' ("Status=$($d.Status); Name=$($d.FriendlyName); InstanceId=$($d.InstanceId); Manufacturer=$($d.Manufacturer)") }
$mobile=Get-PnpDevice -PresentOnly:$false | Where-Object {$_.FriendlyName -match 'Android|iPhone|iPad|MTP|Mobile|Phone|Portable' -or $_.InstanceId -match 'WPDBUSENUM'}
foreach($d in $mobile){ Add-Row 'REMOVABLE_MEDIA' 'Mobile / Portable Device' ("Status=$($d.Status); Name=$($d.FriendlyName); Class=$($d.Class); InstanceId=$($d.InstanceId); Manufacturer=$($d.Manufacturer)") }

# Windows 11 readiness checks intentionally excluded from this general-purpose assessment.

# Event log configuration and six-month estimate
# This remains a rough capacity indicator, not a measured forward-growth forecast.
foreach($name in 'Application','System','Security'){
    try {
        $log=Get-WinEvent -ListLog $name -ErrorAction Stop
        $actualMB=Size-MB $log.FileSize
        $configuredMB=Size-MB $log.MaximumSizeInBytes
        $old=$null;$new=$null
        try {$old=Get-WinEvent -LogName $name -Oldest -MaxEvents 1 -ErrorAction Stop | Select-Object -First 1}catch{}
        try {$new=Get-WinEvent -LogName $name -MaxEvents 1 -ErrorAction Stop | Select-Object -First 1}catch{}
        $spanDays=$null
        if($old -and $new -and $old.TimeCreated -and $new.TimeCreated) {
            $spanDays=[math]::Round([math]::Max(0,($new.TimeCreated-$old.TimeCreated).TotalDays),2)
        }
        $rate=$null
        $requiredMB=$null
        $capacityStatus='UNKNOWN'
        if($null -ne $spanDays -and $spanDays -gt 0 -and $null -ne $actualMB) {
            $rate=[math]::Round(([double]$actualMB/[double]$spanDays),2)
            $requiredMB=[math]::Ceiling($rate*182.5)
            if($null -ne $configuredMB) {
                $capacityStatus=if($configuredMB -ge $requiredMB){'PASS/INDICATIVE'}else{'FAIL/REVIEW'}
            }
        }
        Add-Row 'EVENT_LOGS' "$name Enabled" $log.IsEnabled
        Add-Row 'EVENT_LOGS' "$name Actual File Size MB" $actualMB
        Add-Row 'EVENT_LOGS' "$name Configured Maximum Size MB" $configuredMB
        Add-Row 'EVENT_LOGS' "$name Observed Log Span Days" $spanDays
        Add-Row 'EVENT_LOGS' "$name Rough Average MB per Observed Day" $rate
        Add-Row 'EVENT_LOGS' "$name Rough Six-Month Capacity Indicator MB" $requiredMB $capacityStatus 'Rough estimate only; log size divided by observed event span is not a measured growth rate. Validate with periodic size measurements and retention requirements.'
    } catch { Add-Row 'EVENT_LOGS' "$name" 'UNDETERMINED' 'UNKNOWN' 'Unable to query event log configuration.' }
}

# Evidence metadata and output directories
if (-not (Test-Path -LiteralPath $EvidenceDirectory)) {
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
}
$operatorName=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$scriptPath=$MyInvocation.MyCommand.Path
$scriptHash=$null
if ($scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
    try { $scriptHash=(Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
}
$metadata=[ordered]@{
    SchemaVersion='1.0'
    RunId=$RunId
    Mode=$Mode
    ComputerName=$HostName
    FQDN=([System.Net.Dns]::GetHostEntry($HostName).HostName)
    Domain=$cs.Domain
    Operator=$operatorName
    CollectionStartLocal=$Start.ToString('o')
    CollectionStartUtc=$StartUtc.ToString('o')
    CollectionEndUtc=(Get-Date).ToUniversalTime().ToString('o')
    PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    ScriptPath=$scriptPath
    ScriptSHA256=$scriptHash
    BaselinePath=$(if($Mode -eq 'Compare'){$BaselinePath}else{$null})
}
$RawRows=@($Rows | ForEach-Object { [pscustomobject]@{Section=$_.Section;Item=$_.Item;Value=$_.Value;Status=$_.Status;Details=$_.Details} })
$SnapshotPath=Join-Path $EvidenceDirectory "$RunId.snapshot.json"
$Snapshot=[ordered]@{ Metadata=$metadata; Rows=$RawRows }
$Snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SnapshotPath -Encoding UTF8

# Optional before/after comparison against a prior snapshot.
if ($Mode -eq 'Compare') {
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
        throw "Baseline snapshot not found: $BaselinePath"
    }
    try { $baseline=Get-Content -LiteralPath $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Unable to parse baseline snapshot JSON: $($_.Exception.Message)" }
    if ($null -eq $baseline.Rows) { throw "The supplied file does not contain a Rows array and is not a compatible snapshot." }

    function ConvertTo-KeyedRows {
        param([object[]]$InputRows)
        $result=@{}
        foreach($group in ($InputRows | Group-Object { "$($_.Section)|$($_.Item)|$($_.Details)" })) {
            $n=0
            foreach($row in ($group.Group | Sort-Object Value,Status)) {
                $key="$($group.Name)|$n"
                $result[$key]=$row
                $n++
            }
        }
        return $result
    }
    $before=ConvertTo-KeyedRows @($baseline.Rows)
    $after=ConvertTo-KeyedRows $RawRows
    $allKeys=@($before.Keys + $after.Keys | Sort-Object -Unique)
    foreach($key in $allKeys) {
        $b=$before[$key]; $a=$after[$key]
        if ($null -eq $b) {
            Add-Row 'BASELINE_COMPARISON' 'Added' "$($a.Section) | $($a.Item) | $($a.Value)" 'CHANGED' "RunId=$RunId; baseline=$BaselinePath"
        } elseif ($null -eq $a) {
            Add-Row 'BASELINE_COMPARISON' 'Removed' "$($b.Section) | $($b.Item) | $($b.Value)" 'CHANGED' "RunId=$RunId; baseline=$BaselinePath"
        } elseif ([string]$b.Value -ne [string]$a.Value -or [string]$b.Status -ne [string]$a.Status) {
            Add-Row 'BASELINE_COMPARISON' 'Changed' "$($a.Section) | $($a.Item) | Before=[$($b.Value)] After=[$($a.Value)]" 'CHANGED' "BeforeStatus=$($b.Status); AfterStatus=$($a.Status); baseline=$BaselinePath"
        }
    }
    if (-not ($Rows | Where-Object Section -eq 'BASELINE_COMPARISON')) {
        Add-Row 'BASELINE_COMPARISON' 'Result' 'No differences detected in comparable collected values.' 'INFO' "Baseline=$BaselinePath"
    }
}

# Export report files. Reports are written beside the script as before.
$Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
$txt=@()
$txt += 'SENTINELBASELINE — WINDOWS SECURITY BASELINE & EVIDENCE TOOLKIT'
$txt += ('='*80)
$txt += "Host       : $HostName"
$txt += "Collected  : $($Start.ToString('yyyy-MM-dd HH:mm:ss'))"
$txt += "Collected UTC: $($StartUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
$txt += "Run ID     : $RunId"
$txt += "Mode       : $Mode"
$txt += "Operator   : $operatorName"
$txt += "Snapshot   : $SnapshotPath"
$txt += "Output Folder: $ScriptDirectory"
$txt += ''
foreach($group in ($Rows | Group-Object Section)){
    $txt += "[$($group.Name)]"
    foreach($r in $group.Group){ $txt += ("{0} | {1} | {2} | {3}" -f $r.Item,$r.Value,$r.Status,$r.Details) }
    $txt += ''
}
$txt += 'Collection completed: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$txt | Set-Content -Path $TxtPath -Encoding UTF8

# SHA-256 manifest for snapshot and reports. The manifest intentionally does not hash itself.
$manifestPath=Join-Path $EvidenceDirectory "$RunId.manifest.json"
$hashEntries=@()
foreach($filePath in @($SnapshotPath,$CsvPath,$TxtPath,$scriptPath)) {
    if ($filePath -and (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        try {
            $item=Get-Item -LiteralPath $filePath
            $hash=(Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $hashEntries += [pscustomobject]@{
                FileName=$item.Name
                FullPath=$item.FullName
                SHA256=$hash
                LengthBytes=$item.Length
            }
        } catch {}
    }
}
$manifest=[ordered]@{
    ManifestSchemaVersion='1.0'
    RunId=$RunId
    CreatedUtc=(Get-Date).ToUniversalTime().ToString('o')
    EvidenceMetadata=$metadata
    Files=$hashEntries
    IntegrityLimitations='Hashes detect later changes only when the manifest is trusted. This local manifest is not digitally signed and does not prove source-system integrity, collector trustworthiness, or chain of custody.'
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

# Local hash-chained custody log. This provides traceability, not tamper-proof storage.
$custodyPath=Join-Path $EvidenceDirectory 'chain-of-custody.jsonl'
$previousRecordHash=$null
if (Test-Path -LiteralPath $custodyPath -PathType Leaf) {
    try {
        $lastLine=Get-Content -LiteralPath $custodyPath -Tail 1 -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($lastLine)) {
            $lastRecord=$lastLine | ConvertFrom-Json -ErrorAction Stop
            $previousRecordHash=[string]$lastRecord.RecordSHA256
        }
    } catch { $previousRecordHash='UNREADABLE_PREVIOUS_RECORD' }
}
$manifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
$custodyPayload=[ordered]@{
    EventType='AssessmentEvidenceCreated'
    RunId=$RunId
    TimestampUtc=(Get-Date).ToUniversalTime().ToString('o')
    ComputerName=$HostName
    Operator=$operatorName
    Mode=$Mode
    SnapshotPath=$SnapshotPath
    ManifestPath=$manifestPath
    ManifestSHA256=$manifestHash
    PreviousRecordSHA256=$previousRecordHash
}
$custodyCanonical=$custodyPayload | ConvertTo-Json -Depth 6 -Compress
$shaProvider=[System.Security.Cryptography.SHA256]::Create()
try {
    $payloadBytes=[System.Text.Encoding]::UTF8.GetBytes($custodyCanonical)
    $recordHash=([System.BitConverter]::ToString($shaProvider.ComputeHash($payloadBytes))).Replace('-','')
} finally { $shaProvider.Dispose() }
$custodyRecord=[ordered]@{}
foreach($key in $custodyPayload.Keys){ $custodyRecord[$key]=$custodyPayload[$key] }
$custodyRecord['RecordSHA256']=$recordHash
$custodyLine=$custodyRecord | ConvertTo-Json -Depth 6 -Compress
Add-Content -LiteralPath $custodyPath -Value $custodyLine -Encoding UTF8

Write-Host "Assessment complete.`nMode: $Mode`nOutput folder: $ScriptDirectory`nTXT: $TxtPath`nCSV: $CsvPath`nSnapshot: $SnapshotPath`nSHA-256 manifest: $manifestPath`nLocal custody log: $custodyPath" -ForegroundColor Green
if ($Mode -eq 'Capture') {
    Write-Host "For a comparison run, use: .\SentinelBaseline.ps1 -Mode Compare -BaselinePath `"$SnapshotPath`"" -ForegroundColor Cyan
}
