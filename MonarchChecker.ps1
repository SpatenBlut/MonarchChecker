<#
  Monarch Checker - PowerShell version
  Read-only system check. Changes nothing.
  Run as Administrator for full results (TPM, Defender WMI).
  Usage: powershell -ExecutionPolicy Bypass -File MonarchChecker.ps1
#>

$Host.UI.RawUI.WindowTitle = "Monarch Checker"

function Write-C($text, $color = "Gray") { Write-Host $text -ForegroundColor $color -NoNewline }
function Write-CL($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }

function Show-Status($st, $name, $detail) {
    switch ($st) {
        "OK"   { Write-C "  [ OK ] " "Green" }
        "WARN" { Write-C "  [WARN] " "Yellow" }
        "FAIL" { Write-C "  [FAIL] " "Red" }
        "INFO" { Write-C "  [INFO] " "Cyan" }
    }
    Write-CL ("{0,-38} {1}" -f $name, $detail)
}

function Show-Section($title) {
    $pad = "=" * [Math]::Max(1, 70 - 5 - $title.Length - 1)
    Write-Host ""
    Write-CL ("  == {0} {1}" -f $title, $pad) "White"
}

# ============================================================ Results
$script:results = @()
$script:fixGuide = @()

function Add-Check($st, $name, $detail, $fix = "") {
    $script:results += [PSCustomObject]@{ St=$st; Name=$name; Detail=$detail; Fix=$fix }
    Show-Status $st $name $detail
}

# ============================================================ Banner
Write-Host ""
Write-CL "   __  __                              _" "DarkYellow"
Write-CL "  |  \/  | ___  _ __   __ _ _ __ ___| |__" "DarkYellow"
Write-CL "  | |\/| |/ _ \| '_ \ / _` | '__/ __| '_ \" "DarkYellow"
Write-CL "  | |  | | (_) | | | | (_| | | | (__| | | |" "DarkYellow"
Write-CL "  |_|  |_|\___/|_| |_|\__,_|_|  \___|_| |_|   Checker" "DarkYellow"
Write-Host ""
Write-CL "  System check tool. This tool only reads - it changes nothing." "Gray"
Write-CL "  Scanning..." "Gray"

# ============================================================ Hardware
Show-Section "Hardware"

# Windows
$ver = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
if ($ver) {
    Add-Check "INFO" "Windows" ("{0} {1} (Build {2}.{3})" -f $ver.ProductName, $ver.DisplayVersion, $ver.CurrentBuildNumber, $ver.UBR)
}

# CPU
try {
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    Add-Check "INFO" "CPU" ("{0} ({1} cores / {2} threads)" -f $cpu.Name.Trim(), $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)
} catch { Add-Check "WARN" "CPU" "could not query" }

# GPU
try {
    Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object {
        $drDate = if ($_.DriverDate) { $_.DriverDate.ToString("yyyy-MM-dd") } else { "?" }
        Add-Check "INFO" "GPU" ("{0} | Driver {1} ({2})" -f $_.Name, $_.DriverVersion, $drDate)
    }
} catch { Add-Check "WARN" "GPU" "could not query" }

# Mainboard
try {
    $mb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
    Add-Check "INFO" "Mainboard" ("{0} {1}" -f $mb.Manufacturer, $mb.Product)
} catch {}
try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -First 1
    $bd = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "?" }
    Add-Check "INFO" "BIOS" ("{0} ({1})" -f $bios.SMBIOSBIOSVersion, $bd)
} catch {}

# Disks
try {
    Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
        $type = switch ($_.MediaType) { "SSD" { if ($_.BusType -eq "NVMe") { "NVMe SSD" } else { "SATA SSD" } } "HDD" { "HDD" } default { "Unknown" } }
        $gb = [math]::Round($_.Size / 1GB, 0)
        $health = $_.HealthStatus
        $st = if ($health -eq "Healthy") { "INFO" } else { "WARN" }
        Add-Check $st "Disk" ("{0} | {1} | {2} GB | {3}" -f $_.FriendlyName, $type, $gb, $health) `
            $(if ($health -ne "Healthy") { "Check SMART values (e.g. CrystalDiskInfo). Back up your data." } else { "" })
    }
} catch { Add-Check "WARN" "Disk" "could not query" }

# RAM
try {
    $ram = (Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | Measure-Object -Property Capacity -Sum).Sum
    Add-Check "INFO" "RAM" ("{0:N1} GB" -f ($ram / 1GB))
} catch {}

# ============================================================ Security
Show-Section "Security"

# Antivirus
try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    $activeAV = @()
    foreach ($av in $avProducts) {
        $state = $av.productState
        $enabled = (($state -shr 12) -band 0xF) -ne 0
        if ($enabled) { $activeAV += $av.displayName }
    }
    if ($activeAV.Count -gt 0) {
        Add-Check "OK" "Antivirus" ("active ({0})" -f ($activeAV -join ", "))
    } else {
        Add-Check "FAIL" "Antivirus" "no active antivirus detected" `
            "Open Windows Security > Virus & threat protection and enable Real-time protection."
    }
} catch {
    # Fallback: check Defender directly
    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        if ($def.AntivirusEnabled -and $def.RealTimeProtectionEnabled) {
            Add-Check "OK" "Antivirus" "active (Windows Defender)"
        } else {
            Add-Check "FAIL" "Antivirus" "Defender present but not fully active" `
                "Open Windows Security > Virus & threat protection and enable Real-time protection."
        }
    } catch {
        Add-Check "WARN" "Antivirus" "could not query antivirus status"
    }
}

# dControl
$dctl = Get-Process -Name "dControl" -ErrorAction SilentlyContinue
if (-not $dctl) {
    Add-Check "OK" "Defender Control (dControl)" "not running"
} else {
    Add-Check "FAIL" "Defender Control (dControl)" "running (may interfere with Defender)" `
        "Close dControl.exe via Task Manager or its own UI."
}

# Memory Integrity (HVCI)
try {
    $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    $hvciRunning = $dg.SecurityServicesRunning -contains 2
    if ($hvciRunning) {
        Add-Check "OK" "Memory Integrity (HVCI)" "enabled"
    } else {
        $hvciCfg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1
        if ($hvciCfg) {
            Add-Check "WARN" "Memory Integrity (HVCI)" "configured but not running (reboot needed)" `
                "Restart your PC. If it still won't turn on: check for incompatible drivers in Windows Security > Device security > Core isolation."
        } else {
            Add-Check "FAIL" "Memory Integrity (HVCI)" "disabled" `
                "Windows Security > Device security > Core isolation > Memory integrity > On."
        }
    }
} catch {
    Add-Check "WARN" "Memory Integrity (HVCI)" "could not query DeviceGuard"
}

# Vulnerable Driver Blocklist
$blKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$blVal = (Get-ItemProperty $blKey -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
if ($null -eq $blVal -or $blVal -eq 1) {
    Add-Check "OK" "Vulnerable Driver Blocklist" "enabled"
} else {
    Add-Check "FAIL" "Vulnerable Driver Blocklist" "disabled" `
        "Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist > On."
}

# VT-x/VT-d / AMD-V/AMD-Vi
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $hypervisor = $cs.HypervisorPresent
    $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $isIntel = $cpuInfo.Manufacturer -like "*Intel*"
    $vtName = if ($isIntel) { "VT-x / VT-d (IOMMU)" } else { "AMD-V / AMD-Vi (IOMMU)" }
    $biosHint = if ($isIntel) { "Enable in BIOS: Intel Virtualization Technology (VT-x) and VT-d." } else { "Enable in BIOS: SVM Mode and IOMMU." }

    $virtEnabled = $cpuInfo.VirtualizationFirmwareEnabled

    if ($virtEnabled -or $hypervisor) {
        # If HVCI is running, IOMMU must be working
        if ($hvciRunning -or $hypervisor) {
            Add-Check "OK" $vtName "active"
        } else {
            Add-Check "WARN" $vtName "virtualization on, but IOMMU status unclear" $biosHint
        }
    } else {
        Add-Check "FAIL" $vtName "disabled" $biosHint
    }
} catch {
    Add-Check "WARN" "Virtualization (VT-d/AMD-Vi)" "could not query"
}

# Secure Boot
$sbKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
$sbVal = (Get-ItemProperty $sbKey -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue).UEFISecureBootEnabled
if ($sbVal -eq 1) {
    Add-Check "OK" "Secure Boot" "enabled"
} elseif ($null -ne $sbVal) {
    Add-Check "WARN" "Secure Boot" "disabled" "Enable in BIOS/UEFI: Boot > Secure Boot > Enabled."
} else {
    Add-Check "WARN" "Secure Boot" "not available (Legacy BIOS mode)" "Enable in BIOS/UEFI: Boot > Secure Boot > Enabled."
}

# TPM
try {
    $tpm = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
    if ($tpm) {
        $tpmEnabled = $tpm.IsEnabled_InitialValue
        $tpmSpec = $tpm.SpecVersion -replace ',.*', ''
        if ($tpmEnabled) {
            Add-Check "OK" "TPM" ("{0} | enabled" -f $tpmSpec)
        } else {
            Add-Check "WARN" "TPM" ("{0} | disabled" -f $tpmSpec) "Enable in BIOS or run tpm.msc > Actions > Prepare the TPM."
        }
    } else {
        Add-Check "WARN" "TPM" "not found or disabled" "Enable in BIOS: Intel PTT / AMD fTPM / Security Device Support."
    }
} catch {
    Add-Check "WARN" "TPM" "not found or disabled" "Enable in BIOS: Intel PTT / AMD fTPM / Security Device Support."
}

# UAC
$uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($uacVal -ne 0) {
    Add-Check "OK" "User Account Control (UAC)" "enabled"
} else {
    Add-Check "FAIL" "User Account Control (UAC)" "disabled" `
        "Settings > Accounts > Change User Account Control settings > set to at least level 2."
}

# Firewall
$fwOff = $false
foreach ($profile in @("StandardProfile", "DomainProfile", "PublicProfile")) {
    $fwKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$profile"
    $fwVal = (Get-ItemProperty $fwKey -Name EnableFirewall -ErrorAction SilentlyContinue).EnableFirewall
    if ($fwVal -eq 0) { $fwOff = $true }
}
if (-not $fwOff) {
    Add-Check "OK" "Windows Firewall" "all profiles active"
} else {
    Add-Check "FAIL" "Windows Firewall" "one or more profiles disabled" `
        "Run as admin: netsh advfirewall set allprofiles state on."
}

# ============================================================ Software
Show-Section "Software"

# VC++ Redistributable
foreach ($arch in @(
    @{ Label="x64"; RegKey="HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"; Dll="vcruntime140.dll" },
    @{ Label="x86"; RegKey="HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86"; Dll="vcruntime140.dll" }
)) {
    $reg = Get-ItemProperty $arch.RegKey -ErrorAction SilentlyContinue
    $sysDir = if ($arch.Label -eq "x86") { "$env:SystemRoot\SysWOW64" } else { "$env:SystemRoot\System32" }
    $dllExists = Test-Path "$sysDir\$($arch.Dll)"

    if ($reg -and $dllExists) {
        Add-Check "OK" ("VC++ Redist 2015-2022 ({0})" -f $arch.Label) ("installed ({0})" -f $reg.Version)
    } else {
        $url = if ($arch.Label -eq "x64") { "https://aka.ms/vs/17/release/vc_redist.x64.exe" } else { "https://aka.ms/vs/17/release/vc_redist.x86.exe" }
        Add-Check "FAIL" ("VC++ Redist 2015-2022 ({0})" -f $arch.Label) "not installed" `
            ("Download: {0}`n          or: winget install Microsoft.VCRedist.2015+.{1}" -f $url, $arch.Label)
    }
}

# DirectX 11
$d3d11 = Test-Path "$env:SystemRoot\System32\d3d11.dll"
if ($d3d11) {
    Add-Check "OK" "DirectX 11" "d3d11.dll present"
} else {
    Add-Check "FAIL" "DirectX 11" "d3d11.dll missing" `
        "Run Windows Update, then: sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth."
}

# ============================================================ Overlays
Show-Section "Overlays"

# Discord
if (Get-Process -Name "Discord" -ErrorAction SilentlyContinue) {
    Add-Check "WARN" "Discord Overlay" "running" `
        "Discord > Settings > Game Overlay > Enable in-game overlay > Off."
} else {
    Add-Check "OK" "Discord Overlay" "not running"
}

# Xbox Game Bar
$gbVal1 = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -ErrorAction SilentlyContinue).AppCaptureEnabled
$gbVal2 = (Get-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -ErrorAction SilentlyContinue).GameDVR_Enabled
if (($null -eq $gbVal1 -or $gbVal1 -eq 1) -or ($null -eq $gbVal2 -or $gbVal2 -eq 1)) {
    Add-Check "WARN" "Xbox Game Bar" "enabled" `
        "Settings > Gaming > Xbox Game Bar > Off. Also disable Game DVR in Settings > Gaming > Captures."
} else {
    Add-Check "OK" "Xbox Game Bar" "disabled"
}

# Steam Overlay
if (Get-Process -Name "GameOverlayUI" -ErrorAction SilentlyContinue) {
    Add-Check "WARN" "Steam Overlay" "running" `
        "Steam > Settings > In-Game > Enable the Steam Overlay while in-game > Off."
} else {
    Add-Check "OK" "Steam Overlay" "not running"
}

# SteelSeries GG
if (Get-Process -Name "SteelSeriesGG" -ErrorAction SilentlyContinue) {
    Add-Check "WARN" "SteelSeries GG" "running" `
        "SteelSeries GG > Settings > Disable overlay, or close SteelSeries GG."
} else {
    Add-Check "OK" "SteelSeries GG" "not running"
}

# NVIDIA Overlay
if ((Get-Process -Name "NVIDIA Share" -ErrorAction SilentlyContinue) -or (Get-Process -Name "nvspcaps64" -ErrorAction SilentlyContinue)) {
    Add-Check "WARN" "NVIDIA Overlay (ShadowPlay)" "running" `
        "GeForce Experience > Settings > In-Game Overlay > Off."
} else {
    Add-Check "OK" "NVIDIA Overlay (ShadowPlay)" "not running"
}

# AMD Adrenalin Overlay
if ((Get-Process -Name "AMDRSServ" -ErrorAction SilentlyContinue) -or (Get-Process -Name "RadeonSoftware" -ErrorAction SilentlyContinue)) {
    Add-Check "WARN" "AMD Adrenalin Overlay" "running" `
        "AMD Software > Settings > Preferences > In-Game Overlay > Off."
} else {
    Add-Check "OK" "AMD Adrenalin Overlay" "not running"
}

# ============================================================ Summary
Write-Host ""
$okCount   = ($script:results | Where-Object { $_.St -eq "OK" }).Count
$warnCount = ($script:results | Where-Object { $_.St -eq "WARN" }).Count
$failCount = ($script:results | Where-Object { $_.St -eq "FAIL" }).Count
$color = if ($failCount -gt 0) { "Red" } elseif ($warnCount -gt 0) { "Yellow" } else { "Green" }
Write-CL ("  Result: {0} OK, {1} warnings, {2} issues." -f $okCount, $warnCount, $failCount) $color

# Fix guide
$issues = $script:results | Where-Object { $_.St -in @("FAIL","WARN") -and $_.Fix -ne "" }
if ($issues.Count -gt 0) {
    Write-Host ""
    Write-C "  Press [F] to show fix instructions, or any other key to exit. " "White"
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    if ($key -eq 'f' -or $key -eq 'F') {
        Show-Section "How to Fix"
        foreach ($item in $issues) {
            $col = if ($item.St -eq "FAIL") { "Red" } else { "Yellow" }
            Write-Host ""
            Write-C "  " $col
            Write-C ("[{0}] " -f $item.St) $col
            Write-CL $item.Name "White"
            Write-CL ("          {0}" -f $item.Fix) "Gray"
        }
        Write-Host ""
        Write-C "  Press any key to exit..." "Gray"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} else {
    Write-Host ""
    Write-C "  Everything looks good! Press any key to exit..." "Green"
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
Write-Host ""
