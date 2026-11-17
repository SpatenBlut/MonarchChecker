# Monarch Checker

A read-only Windows system & security check tool. It only reads system state and
shows the results — it never changes anything. For non-OK items it can print
step-by-step instructions on how to fix the issue yourself.

Checks: Windows version, CPU, GPU, mainboard, BIOS, disks, RAM, antivirus,
Defender Control, Memory Integrity (HVCI), Vulnerable Driver Blocklist,
VT-x/VT-d or AMD-V/AMD-Vi, Secure Boot, TPM, UAC, firewall, VC++ Redistributable,
DirectX 11, and common overlays (Discord, Xbox Game Bar, Steam, SteelSeries,
NVIDIA, AMD).

## Files

- `main.cpp` — the tool's source code (C++17)
- `resource.rc` / `monarch.ico` — the app icon, embedded into the exe
- `build.bat` — builds `MonarchChecker.exe` with MSVC
- `MonarchChecker.ps1` — equivalent PowerShell version, no build required

## Building the exe

Requirements: [Visual Studio](https://visualstudio.microsoft.com/) (or the standalone
[Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio))
with the **Desktop development with C++** workload installed.

```bash
build.bat
```

This calls `cl.exe`/`rc.exe` directly (no `.vcxproj`/`.sln` needed) and produces
`build\MonarchChecker.exe`. The exe is statically linked, so it runs without
needing the VC++ Redistributable installed.

## Running the PowerShell version

No build step needed:

```powershell
powershell -ExecutionPolicy Bypass -File MonarchChecker.ps1
```

Run either version as Administrator for full results (TPM and some Defender
checks require elevation to read).
