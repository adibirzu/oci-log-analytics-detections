<#
.SYNOPSIS
  Safe Windows-side helper for the OCI Log Analytics access-monitoring track.

.DESCRIPTION
  Plan is portable and read-only. Preflight inspects the Windows host. Install
  runs Oracle's extracted installer.bat only when all paths and -ConfirmInstall
  are supplied. Enable starts an existing mgmt_agent service with the same
  explicit confirmation. The response file is never printed.
#>

[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Preflight', 'Install', 'Enable')]
    [string]$Mode = 'Preflight',
    [ValidatePattern('^[a-z]{2}-[a-z]+-[0-9]+$')]
    [string]$Region,
    [string]$InstallerDirectory,
    [string]$ResponseFile,
    [switch]$ConfirmInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$channels = @('Security', 'System', 'Application')
$minimumFreeDiskMb = 300
$minimumJava8Update = 281
$plan = [ordered]@{
    schema_version = '1.0.0'
    mode = $Mode
    channels = $channels
    service_name = 'mgmt_agent'
    supported_windows_server_versions = @('2012 R2', '2016', '2019', '2022')
    minimum_free_disk_mb = $minimumFreeDiskMb
    minimum_java_8_update = $minimumJava8Update
    wmic_required = $true
    maximum_clock_skew_minutes = 5
    required_https_endpoints = @(
        'loganalytics.<region>.oci.oraclecloud.com:443',
        'telemetry-ingestion.<region>.oraclecloud.com:443'
    )
    required_response_file_setting = 'Service.plugin.logan.download=true'
    installation_command = 'installer.bat <full_path_of_response_file>'
    verification_command = 'sc.exe query mgmt_agent'
    agent_log = 'C:\Oracle\mgmt_agent\agent_inst\log\mgmt_agent.log'
    installer_log_directory = 'C:\Oracle\mgmt_agent\installer-logs'
    mutated_host = $false
}

if ($Mode -eq 'Plan') {
    $plan | ConvertTo-Json -Depth 6
    exit 0
}

$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if (-not $isWindowsHost) {
    throw 'Preflight, Install, and Enable modes must run on the target Windows host.'
}

$isAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$service = Get-Service -Name 'mgmt_agent' -ErrorAction SilentlyContinue
$channelChecks = foreach ($channel in $channels) {
    $log = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
    [ordered]@{
        channel = $channel
        exists = $null -ne $log
        enabled = if ($null -ne $log) { [bool]$log.IsEnabled } else { $false }
        record_count = if ($null -ne $log) { [long]$log.RecordCount } else { 0 }
    }
}
$wmic = Get-Command wmic.exe -ErrorAction SilentlyContinue
$java = Get-Command java.exe -ErrorAction SilentlyContinue
$javaVersionText = if ($null -ne $java) { (& $java.Source -version 2>&1 | Out-String) } else { '' }
$javaVersionMatch = [regex]::Match($javaVersionText, 'version\s+"1\.8\.0_(\d+)')
$java8Update = if ($javaVersionMatch.Success) { [int]$javaVersionMatch.Groups[1].Value } else { 0 }
$javaSupported = $java8Update -ge $minimumJava8Update

$systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -ErrorAction SilentlyContinue
$freeDiskMb = if ($null -ne $disk) { [math]::Floor([double]$disk.FreeSpace / 1MB) } else { 0 }
$diskSupported = $freeDiskMb -ge $minimumFreeDiskMb

$clockStatusText = (& w32tm.exe /query /status 2>&1 | Out-String)
$clockStatusAvailable = $LASTEXITCODE -eq 0
$endpointChecks = @()
if ($Region) {
    $endpointChecks = @(
        "loganalytics.$Region.oci.oraclecloud.com",
        "telemetry-ingestion.$Region.oraclecloud.com"
    ) | ForEach-Object {
        [ordered]@{
            endpoint = "${_}:443"
            reachable = [bool](Test-NetConnection -ComputerName $_ -Port 443 -InformationLevel Quiet)
        }
    }
}

$plan.administrator = $isAdministrator
$plan.wmic_available = $null -ne $wmic
$plan.java_command_available = $null -ne $java
$plan.java_8_update = $java8Update
$plan.java_supported = $javaSupported
$plan.system_drive = $systemDrive
$plan.free_disk_mb = $freeDiskMb
$plan.disk_supported = $diskSupported
$plan.clock_status_available = $clockStatusAvailable
$plan.clock_status_note = 'A successful w32tm status check does not by itself prove OCI clock skew is within five minutes.'
$plan.region = if ($Region) { $Region } else { '<NOT_SUPPLIED>' }
$plan.endpoint_checks = $endpointChecks
$plan.agent_installed = $null -ne $service
$plan.agent_status = if ($null -ne $service) { [string]$service.Status } else { 'NotInstalled' }
$plan.channel_checks = $channelChecks

if ($Mode -eq 'Preflight') {
    $plan | ConvertTo-Json -Depth 6
    $endpointFailure = $Region -and ($endpointChecks | Where-Object { -not $_.reachable })
    if (
        -not $isAdministrator -or
        -not $wmic -or
        -not $javaSupported -or
        -not $diskSupported -or
        -not $clockStatusAvailable -or
        ($channelChecks | Where-Object { -not $_.enabled }) -or
        $endpointFailure
    ) { exit 2 }
    exit 0
}

if (-not $isAdministrator) {
    throw 'Install and Enable modes require an elevated Administrator PowerShell session.'
}
if (-not $ConfirmInstall) {
    throw 'No host mutation performed. Re-run with -ConfirmInstall after reviewing Plan and Preflight output.'
}

if ($Mode -eq 'Enable') {
    if ($null -eq $service) { throw 'mgmt_agent is not installed; use Install mode with the Oracle package and response file.' }
    Start-Service -Name 'mgmt_agent'
    $plan.mutated_host = $true
    $plan.agent_status = [string](Get-Service -Name 'mgmt_agent').Status
    $plan | ConvertTo-Json -Depth 6
    exit 0
}

if ($service) {
    throw 'mgmt_agent is already installed. Use Enable mode or investigate the existing installation.'
}
if (-not $InstallerDirectory) { throw '-InstallerDirectory is required for Install mode.' }
if (-not $ResponseFile) { throw '-ResponseFile is required for Install mode.' }

$installer = Join-Path $InstallerDirectory 'installer.bat'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "installer.bat not found in $InstallerDirectory" }
if (-not (Test-Path -LiteralPath $ResponseFile -PathType Leaf)) { throw 'Response file not found.' }
$responseText = Get-Content -LiteralPath $ResponseFile -Raw
if ($responseText -notmatch '(?m)^\s*Service\.plugin\.logan\.download\s*=\s*true\s*$') {
    throw 'Response file must contain Service.plugin.logan.download=true so the Log Analytics plugin is deployed.'
}

& $installer $ResponseFile
if ($LASTEXITCODE -ne 0) { throw "Oracle Management Agent installer failed with exit code $LASTEXITCODE." }
$plan.mutated_host = $true
$plan.agent_installed = $null -ne (Get-Service -Name 'mgmt_agent' -ErrorAction SilentlyContinue)
$plan.agent_status = if ($plan.agent_installed) { [string](Get-Service -Name 'mgmt_agent').Status } else { 'NotInstalled' }
$plan | ConvertTo-Json -Depth 6
exit $(if ($plan.agent_installed) { 0 } else { 1 })
