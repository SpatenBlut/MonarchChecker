// Monarch Checker - System & security check tool (read-only, changes nothing).
#define IDI_MONARCH 101
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <wrl/client.h>
#include <intrin.h>
#include <conio.h>
#include <cstdarg>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

using Microsoft::WRL::ComPtr;
using std::wstring;

// ============================================================ Output helpers
enum Color : WORD { cGray = 7, cGreen = 10, cRed = 12, cYellow = 14, cCyan = 11, cWhite = 15 };

static void Put(const wstring& s, WORD color = cGray) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, color);
    DWORD n;
    WriteConsoleW(h, s.c_str(), (DWORD)s.size(), &n, nullptr);
    SetConsoleTextAttribute(h, cGray);
}

static wstring F(const wchar_t* f, ...) {
    va_list a; va_start(a, f);
    wchar_t b[2048];
    _vsnwprintf_s(b, _countof(b), _TRUNCATE, f, a);
    va_end(a);
    return b;
}

// ============================================================ Result model
enum class St { Ok, Warn, Fail, Info };

struct Item {
    St      st;
    wstring name;
    wstring detail;
    wstring howToFix;   // shown for non-OK items, explains how to fix manually
};

using Items = std::vector<Item>;

static void Add(Items& v, St st, wstring name, wstring detail, wstring howToFix = L"") {
    v.push_back({ st, std::move(name), std::move(detail), std::move(howToFix) });
}

// ============================================================ Registry helpers
static std::optional<DWORD> RegDword(HKEY r, const wchar_t* key, const wchar_t* val, REGSAM view = KEY_WOW64_64KEY) {
    HKEY h;
    if (RegOpenKeyExW(r, key, 0, KEY_READ | view, &h) != ERROR_SUCCESS) return {};
    DWORD t = 0, d = 0, sz = sizeof(d);
    LSTATUS s = RegQueryValueExW(h, val, nullptr, &t, (BYTE*)&d, &sz);
    RegCloseKey(h);
    if (s != ERROR_SUCCESS || t != REG_DWORD) return {};
    return d;
}

static std::optional<wstring> RegStr(HKEY r, const wchar_t* key, const wchar_t* val, REGSAM view = KEY_WOW64_64KEY) {
    HKEY h;
    if (RegOpenKeyExW(r, key, 0, KEY_READ | view, &h) != ERROR_SUCCESS) return {};
    wchar_t buf[512];
    DWORD t = 0, sz = sizeof(buf) - sizeof(wchar_t);
    LSTATUS s = RegQueryValueExW(h, val, nullptr, &t, (BYTE*)buf, &sz);
    RegCloseKey(h);
    if (s != ERROR_SUCCESS || t != REG_SZ) return {};
    buf[sz / sizeof(wchar_t)] = 0;
    return wstring(buf);
}

// ============================================================ Process / file helpers
static bool ProcessRunning(const wchar_t* exe) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W e{ sizeof(e) };
    bool found = false;
    for (BOOL ok = Process32FirstW(s, &e); ok; ok = Process32NextW(s, &e))
        if (_wcsicmp(e.szExeFile, exe) == 0) { found = true; break; }
    CloseHandle(s);
    return found;
}

static bool FileExists(const wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

// Read-only service state query. Returns SERVICE_RUNNING, SERVICE_STOPPED, ... or 0 if unknown.
static DWORD ServiceState(const wchar_t* name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    DWORD st = 0;
    if (SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS)) {
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(s, &ss)) st = ss.dwCurrentState;
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return st;
}

static wstring SysDir(bool wow) {
    wchar_t b[MAX_PATH];
    if (wow) GetSystemWow64DirectoryW(b, MAX_PATH); else GetSystemDirectoryW(b, MAX_PATH);
    return b;
}

// ============================================================ WMI
struct Bstr {
    BSTR b;
    explicit Bstr(const wchar_t* s) : b(SysAllocString(s)) {}
    ~Bstr() { SysFreeString(b); }
};

using Rows = std::vector<ComPtr<IWbemClassObject>>;

class Wmi {
    ComPtr<IWbemLocator> loc_;
public:
    Wmi() { CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&loc_)); }
    Rows Query(const wchar_t* ns, const wchar_t* wql) {
        Rows out;
        if (!loc_) return out;
        ComPtr<IWbemServices> svc;
        Bstr bns(ns);
        if (FAILED(loc_->ConnectServer(bns.b, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc))) return out;
        CoSetProxyBlanket(svc.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        ComPtr<IEnumWbemClassObject> en;
        Bstr lang(L"WQL"), q(wql);
        if (FAILED(svc->ExecQuery(lang.b, q.b, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)))
            return out;
        CoSetProxyBlanket(en.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        for (;;) {
            ComPtr<IWbemClassObject> o; ULONG n = 0;
            if (FAILED(en->Next(5000, 1, &o, &n)) || n == 0) break;
            out.push_back(o);
        }
        return out;
    }
};

static std::optional<long long> GetInt(IWbemClassObject* o, const wchar_t* p) {
    VARIANT v; VariantInit(&v);
    std::optional<long long> r;
    if (SUCCEEDED(o->Get(p, 0, &v, nullptr, nullptr))) {
        switch (v.vt) {
        case VT_I4:   r = v.lVal; break;
        case VT_UI4:  r = v.ulVal; break;
        case VT_I2:   r = v.iVal; break;
        case VT_UI2:  r = v.uiVal; break;
        case VT_UI1:  r = v.bVal; break;
        case VT_BOOL: r = v.boolVal ? 1 : 0; break;
        case VT_BSTR: r = _wtoi64(v.bstrVal); break;
        default: break;
        }
    }
    VariantClear(&v);
    return r;
}

static wstring GetStr(IWbemClassObject* o, const wchar_t* p) {
    VARIANT v; VariantInit(&v);
    wstring r;
    if (SUCCEEDED(o->Get(p, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal) r = v.bstrVal;
    VariantClear(&v);
    return r;
}

static std::vector<long long> GetIntArray(IWbemClassObject* o, const wchar_t* p) {
    VARIANT v; VariantInit(&v);
    std::vector<long long> r;
    VARTYPE et = VT_EMPTY;
    if (SUCCEEDED(o->Get(p, 0, &v, nullptr, nullptr)) && (v.vt & VT_ARRAY) && v.parray &&
        SUCCEEDED(SafeArrayGetVartype(v.parray, &et)) &&
        (et == VT_I4 || et == VT_UI4 || et == VT_INT || et == VT_UINT)) {  // only 4-byte ints: buffer always fits
        LONG lb = 0, ub = -1;
        SafeArrayGetLBound(v.parray, 1, &lb);
        SafeArrayGetUBound(v.parray, 1, &ub);
        for (LONG i = lb; i <= ub; ++i) {
            LONG x = 0;
            if (SUCCEEDED(SafeArrayGetElement(v.parray, &i, &x))) r.push_back(x);
        }
    }
    VariantClear(&v);
    return r;
}

static Wmi* g_wmi;

// ============================================================ Hardware checks (info only)
static void CheckHardware(Items& v) {
    // Windows version
    auto prod  = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
    auto disp  = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
    auto build = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    auto ubr   = RegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR");
    Add(v, St::Info, L"Windows",
        F(L"%s %s (Build %s.%lu)", prod.value_or(L"?").c_str(), disp.value_or(L"").c_str(),
          build.value_or(L"?").c_str(), ubr.value_or(0)));

    // CPU
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT Name,NumberOfCores,NumberOfLogicalProcessors FROM Win32_Processor"))
        Add(v, St::Info, L"CPU",
            F(L"%s (%lld cores / %lld threads)", GetStr(o.Get(), L"Name").c_str(),
              GetInt(o.Get(), L"NumberOfCores").value_or(0),
              GetInt(o.Get(), L"NumberOfLogicalProcessors").value_or(0)));

    // GPU
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT Name,DriverVersion,DriverDate FROM Win32_VideoController")) {
        wstring name = GetStr(o.Get(), L"Name");
        wstring date = GetStr(o.Get(), L"DriverDate");
        wstring d = date.size() >= 8 ? date.substr(0, 4) + L"-" + date.substr(4, 2) + L"-" + date.substr(6, 2) : L"?";
        Add(v, St::Info, L"GPU",
            F(L"%s | Driver %s (%s)", name.c_str(), GetStr(o.Get(), L"DriverVersion").c_str(), d.c_str()));
    }

    // Mainboard + BIOS
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT Manufacturer,Product FROM Win32_BaseBoard"))
        Add(v, St::Info, L"Mainboard",
            F(L"%s %s", GetStr(o.Get(), L"Manufacturer").c_str(), GetStr(o.Get(), L"Product").c_str()));
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT SMBIOSBIOSVersion,ReleaseDate FROM Win32_BIOS")) {
        wstring d = GetStr(o.Get(), L"ReleaseDate");
        wstring ds = d.size() >= 8 ? d.substr(0, 4) + L"-" + d.substr(4, 2) + L"-" + d.substr(6, 2) : L"?";
        Add(v, St::Info, L"BIOS", F(L"%s (%s)", GetStr(o.Get(), L"SMBIOSBIOSVersion").c_str(), ds.c_str()));
    }

    // Disks
    for (auto& o : g_wmi->Query(L"ROOT\\Microsoft\\Windows\\Storage",
                                L"SELECT FriendlyName,MediaType,BusType,HealthStatus,Size FROM MSFT_PhysicalDisk")) {
        long long mt = GetInt(o.Get(), L"MediaType").value_or(0);
        long long bus = GetInt(o.Get(), L"BusType").value_or(0);
        long long hs = GetInt(o.Get(), L"HealthStatus").value_or(0);
        double gb = (double)_wtoi64(GetStr(o.Get(), L"Size").c_str()) / 1e9;
        const wchar_t* type = mt == 4 ? (bus == 17 ? L"NVMe SSD" : L"SATA SSD") : mt == 3 ? L"HDD" : L"Unknown";
        wstring health = hs == 0 ? L"Healthy" : hs == 1 ? L"Warning" : L"Unhealthy";
        Add(v, hs == 0 ? St::Info : St::Warn, L"Disk",
            F(L"%s | %s | %.0f GB | %s", GetStr(o.Get(), L"FriendlyName").c_str(), type, gb, health.c_str()),
            hs != 0 ? L"Check SMART values (e.g. CrystalDiskInfo). Back up your data." : L"");
    }

    // RAM
    long long totalMB = 0;
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT Capacity FROM Win32_PhysicalMemory"))
        totalMB += GetInt(o.Get(), L"Capacity").value_or(0) / (1024 * 1024);
    if (totalMB > 0)
        Add(v, St::Info, L"RAM", F(L"%.1f GB", totalMB / 1024.0));
}

// ============================================================ Security checks
static void CheckSecurity(Items& v) {
    // --- Windows Defender ---
    bool defenderOn = false, otherAv = false;
    wstring otherNames;
    for (auto& o : g_wmi->Query(L"ROOT\\SecurityCenter2", L"SELECT displayName,productState FROM AntiVirusProduct")) {
        wstring name = GetStr(o.Get(), L"displayName");
        long long state = GetInt(o.Get(), L"productState").value_or(0);
        if (((state >> 12) & 0xF) == 0) continue;  // bits 12-15: scanner enabled
        if (name.find(L"Defender") != wstring::npos) defenderOn = true;
        else {
            otherAv = true;
            if (!otherNames.empty()) otherNames += L", ";
            otherNames += name;
        }
    }
    bool rtOn = false, mpQueried = false;
    for (auto& o : g_wmi->Query(L"ROOT\\Microsoft\\Windows\\Defender", L"SELECT RealTimeProtectionEnabled,AntivirusEnabled FROM MSFT_MpComputerStatus")) {
        mpQueried = true;
        rtOn = GetInt(o.Get(), L"AntivirusEnabled").value_or(0) && GetInt(o.Get(), L"RealTimeProtectionEnabled").value_or(0);
    }
    if (mpQueried) defenderOn = rtOn;  // MpComputerStatus is the more precise source when available
    if (ServiceState(L"WinDefend") != SERVICE_RUNNING) defenderOn = false;

    if (defenderOn)
        Add(v, St::Ok, L"Windows Defender", L"active (real-time protection on)");
    else if (otherAv)
        Add(v, St::Warn, L"Windows Defender", L"off (other antivirus active: " + otherNames + L")",
            L"Normal when another antivirus is installed. To use Defender, uninstall the other antivirus.");
    else
        Add(v, St::Fail, L"Windows Defender", L"disabled",
            L"Open Windows Security > Virus & threat protection and enable Real-time protection.");

    // --- dControl (Defender Control): are its changes currently active? ---
    // dControl disables Defender via registry/policy values and by disabling the Defender services.
    std::vector<wstring> found;
    const wchar_t* pol = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    const wchar_t* polRt = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
    const wchar_t* def = L"SOFTWARE\\Microsoft\\Windows Defender";
    const wchar_t* defRt = L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
    struct RegFlag { const wchar_t* key; const wchar_t* val; const wchar_t* label; };
    for (auto& r : std::initializer_list<RegFlag>{
             { pol,   L"DisableAntiSpyware",        L"policy DisableAntiSpyware" },
             { pol,   L"DisableAntiVirus",          L"policy DisableAntiVirus" },
             { polRt, L"DisableRealtimeMonitoring", L"policy DisableRealtimeMonitoring" },
             { polRt, L"DisableBehaviorMonitoring", L"policy DisableBehaviorMonitoring" },
             { polRt, L"DisableOnAccessProtection", L"policy DisableOnAccessProtection" },
             { def,   L"DisableAntiSpyware",        L"DisableAntiSpyware" },
             { def,   L"DisableAntiVirus",          L"DisableAntiVirus" },
             { defRt, L"DisableRealtimeMonitoring", L"DisableRealtimeMonitoring" } })
        if (RegDword(HKEY_LOCAL_MACHINE, r.key, r.val).value_or(0) == 1) found.push_back(r.label);
    for (const wchar_t* svc : { L"WinDefend", L"WdFilter", L"WdBoot", L"WdNisSvc", L"WdNisDrv" }) {
        wstring k = wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + svc;
        if (RegDword(HKEY_LOCAL_MACHINE, k.c_str(), L"Start").value_or(0) == 4)
            found.push_back(wstring(svc) + L" service disabled");
    }
    if (!otherAv && ServiceState(L"WinDefend") == SERVICE_STOPPED)
        found.push_back(L"WinDefend service stopped");
    if (ProcessRunning(L"dControl.exe"))
        found.push_back(L"dControl.exe running");

    if (found.empty())
        Add(v, St::Ok, L"Defender Control (dControl)", L"no changes active");
    else {
        wstring list;
        for (size_t i = 0; i < found.size(); ++i) list += L"\n            - " + found[i];
        Add(v, St::Fail, L"Defender Control (dControl)", F(L"active (%zu changes found)", found.size()),
            L"Open dControl and click \"Enable Windows Defender\", then restart your PC.\n"
            L"          Found:" + list);
    }

    // --- Memory Integrity (HVCI) ---
    bool hvciRunning = false;
    for (auto& o : g_wmi->Query(L"ROOT\\Microsoft\\Windows\\DeviceGuard", L"SELECT * FROM Win32_DeviceGuard"))
        for (auto s : GetIntArray(o.Get(), L"SecurityServicesRunning"))
            if (s == 2) hvciRunning = true;
    // Also check via NtQuerySystemInformation
    using NtQSI = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    DWORD ci = 0;
    if (auto nt = (NtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")) {
        struct { ULONG Length; ULONG Options; } info{ sizeof(info), 0 };
        ULONG ret = 0;
        if (nt(103, &info, sizeof(info), &ret) >= 0) ci = info.Options;
    }
    if (ci & 0x400) hvciRunning = true;

    if (hvciRunning)
        Add(v, St::Ok, L"Memory Integrity (HVCI)", L"enabled");
    else {
        bool hvCfg = RegDword(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            L"Enabled").value_or(0) == 1;
        if (hvCfg)
            Add(v, St::Warn, L"Memory Integrity (HVCI)", L"configured but not running (reboot needed)",
                L"Restart your PC. If it still won't turn on: check for incompatible drivers in\n"
                L"          Windows Security > Device security > Core isolation.");
        else
            Add(v, St::Fail, L"Memory Integrity (HVCI)", L"disabled",
                L"Windows Security > Device security > Core isolation > Memory integrity > On.");
    }

    // --- Vulnerable Driver Blocklist ---
    auto bl = RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable");
    if (bl.value_or(1) == 1)
        Add(v, St::Ok, L"Vulnerable Driver Blocklist", L"enabled");
    else
        Add(v, St::Fail, L"Vulnerable Driver Blocklist", L"disabled",
            L"Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist > On.");

    // --- Secure Boot ---
    auto sb = RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled");
    if (sb && *sb == 1)
        Add(v, St::Ok, L"Secure Boot", L"enabled");
    else
        Add(v, St::Warn, L"Secure Boot", sb ? L"disabled" : L"not available (Legacy BIOS mode)",
            L"Enable in BIOS/UEFI: Boot > Secure Boot > Enabled.");

    // --- TPM ---
    auto tpmRows = g_wmi->Query(L"ROOT\\CIMV2\\Security\\MicrosoftTpm", L"SELECT * FROM Win32_Tpm");
    if (tpmRows.empty())
        Add(v, St::Warn, L"TPM", L"not found or disabled",
            L"Enable in BIOS: Intel PTT / AMD fTPM / Security Device Support.");
    else {
        bool en = GetInt(tpmRows[0].Get(), L"IsEnabled_InitialValue").value_or(0) != 0;
        wstring spec = GetStr(tpmRows[0].Get(), L"SpecVersion");
        Add(v, en ? St::Ok : St::Warn, L"TPM", F(L"%s | %s", spec.c_str(), en ? L"enabled" : L"disabled"),
            en ? L"" : L"Enable in BIOS or run tpm.msc > Actions > Prepare the TPM.");
    }

    // --- VT-d / AMD-Vi (IOMMU) ---
    // Hypervisor must be present for VBS/HVCI to work, which requires VT-x + VT-d on Intel or SVM + AMD-Vi on AMD
    bool hypervisor = false;
    for (auto& o : g_wmi->Query(L"ROOT\\CIMV2", L"SELECT HypervisorPresent FROM Win32_ComputerSystem"))
        hypervisor = GetInt(o.Get(), L"HypervisorPresent").value_or(0) != 0;
    bool vtx = hypervisor || IsProcessorFeaturePresent(21 /*PF_VIRT_FIRMWARE_ENABLED*/);
    bool slat = IsProcessorFeaturePresent(20 /*PF_SECOND_LEVEL_ADDRESS_TRANSLATION*/);

    // Detect Intel vs AMD
    int cpuid[4] = {};
    __cpuid(cpuid, 0);
    char vendor[13] = {};
    *(int*)(vendor + 0) = cpuid[1];
    *(int*)(vendor + 4) = cpuid[3];
    *(int*)(vendor + 8) = cpuid[2];
    bool isIntel = strncmp(vendor, "GenuineIntel", 12) == 0;
    const wchar_t* vtName = isIntel ? L"VT-x / VT-d (IOMMU)" : L"AMD-V / AMD-Vi (IOMMU)";
    const wchar_t* biosHint = isIntel
        ? L"Enable in BIOS: Intel Virtualization Technology (VT-x) and VT-d."
        : L"Enable in BIOS: SVM Mode and IOMMU.";

    if (vtx && slat)
        Add(v, St::Ok, vtName, L"active");
    else if (vtx)
        Add(v, St::Warn, vtName, L"virtualization on, but SLAT/IOMMU missing", biosHint);
    else
        Add(v, St::Fail, vtName, L"disabled", biosHint);

    // --- UAC ---
    if (RegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA").value_or(1) == 1)
        Add(v, St::Ok, L"User Account Control (UAC)", L"enabled");
    else
        Add(v, St::Fail, L"User Account Control (UAC)", L"disabled",
            L"Settings > Accounts > Change User Account Control settings > set to at least level 2.");

    // --- Firewall ---
    bool fwAll = true;
    for (const wchar_t* p : { L"StandardProfile", L"DomainProfile", L"PublicProfile" }) {
        wstring k = F(L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\%s", p);
        if (RegDword(HKEY_LOCAL_MACHINE, k.c_str(), L"EnableFirewall").value_or(1) != 1) fwAll = false;
    }
    if (fwAll)
        Add(v, St::Ok, L"Windows Firewall", L"all profiles active");
    else
        Add(v, St::Fail, L"Windows Firewall", L"one or more profiles disabled",
            L"Run as admin: netsh advfirewall set allprofiles state on.");
}

// ============================================================ Software checks
static void CheckSoftware(Items& v) {
    // --- C++ Redistributable ---
    struct Arch { const wchar_t* label; bool wow; const wchar_t* regKey; };
    Arch archs[] = {
        { L"x64", false, L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64" },
        { L"x86", true,  L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86" },
    };
    for (auto& a : archs) {
        wstring dir = SysDir(a.wow) + L"\\";
        bool files = FileExists(dir + L"vcruntime140.dll") && FileExists(dir + L"msvcp140.dll");
        auto ver = RegStr(HKEY_LOCAL_MACHINE, a.regKey, L"Version", KEY_WOW64_64KEY);
        if (!ver) ver = RegStr(HKEY_LOCAL_MACHINE, a.regKey, L"Version", KEY_WOW64_32KEY);
        wstring name = F(L"VC++ Redist 2015-2022 (%s)", a.label);
        if (files)
            Add(v, St::Ok, name, F(L"installed (%s)", ver.value_or(L"?").c_str()));
        else
            Add(v, St::Fail, name, L"not installed",
                L"Download from https://aka.ms/vs/17/release/vc_redist.x64.exe\n"
                L"          or run: winget install Microsoft.VCRedist.2015+.x64");
    }

    // --- DirectX 11 ---
    // Only checks that the runtime files exist. No D3D device is created, so the GPU driver is never touched.
    wstring sys = SysDir(false) + L"\\";
    if (FileExists(sys + L"d3d11.dll") && FileExists(sys + L"dxgi.dll"))
        Add(v, St::Ok, L"DirectX 11", L"installed (d3d11.dll, dxgi.dll present)");
    else
        Add(v, St::Fail, L"DirectX 11", L"d3d11.dll / dxgi.dll missing",
            L"Run Windows Update, then: sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth.");
}

// ============================================================ Overlay checks
static void CheckOverlays(Items& v) {
    struct Overlay {
        const wchar_t* name;
        const wchar_t* exeName;
        const wchar_t* howToDisable;
    };
    Overlay overlays[] = {
        { L"Discord Overlay", L"Discord.exe", // Discord uses its main process
          L"Discord > Settings > Game Overlay > Enable in-game overlay > Off." },
        { L"Xbox Game Bar", nullptr, // check via registry
          L"Settings > Gaming > Xbox Game Bar > Off.\n"
          L"          Also disable Game DVR in Settings > Gaming > Captures." },
        { L"Steam Overlay", L"GameOverlayUI.exe",
          L"Steam > Settings > In-Game > Enable the Steam Overlay while in-game > Off." },
        { L"SteelSeries GG", L"SteelSeriesGG.exe",
          L"SteelSeries GG > Settings > Disable overlay, or close SteelSeries GG." },
    };

    for (auto& ol : overlays) {
        if (wcscmp(ol.name, L"Xbox Game Bar") == 0) {
            // Check via registry
            auto gb = RegDword(HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR", L"AppCaptureEnabled");
            auto gb2 = RegDword(HKEY_CURRENT_USER,
                L"System\\GameConfigStore", L"GameDVR_Enabled");
            bool enabled = gb.value_or(1) == 1 || gb2.value_or(1) == 1;
            if (!enabled)
                Add(v, St::Ok, ol.name, L"disabled");
            else
                Add(v, St::Warn, ol.name, L"enabled",  ol.howToDisable);
        } else {
            bool running = ol.exeName && ProcessRunning(ol.exeName);
            if (!running)
                Add(v, St::Ok, ol.name, L"not running");
            else
                Add(v, St::Warn, ol.name, L"running", ol.howToDisable);
        }
    }

    // NVIDIA GeForce Experience overlay
    if (ProcessRunning(L"NVIDIA Share.exe") || ProcessRunning(L"nvspcaps64.exe"))
        Add(v, St::Warn, L"NVIDIA Overlay (ShadowPlay)", L"running",
            L"GeForce Experience > Settings > In-Game Overlay > Off.");
    else
        Add(v, St::Ok, L"NVIDIA Overlay (ShadowPlay)", L"not running");

    // AMD Adrenalin overlay (ReLive)
    if (ProcessRunning(L"AMDRSServ.exe") || ProcessRunning(L"RadeonSoftware.exe"))
        Add(v, St::Warn, L"AMD Adrenalin Overlay", L"running",
            L"AMD Software > Settings > Preferences > In-Game Overlay > Off.");
    else
        Add(v, St::Ok, L"AMD Adrenalin Overlay", L"not running");
}

// ============================================================ Printing
static void Section(const wchar_t* t) {
    Put(F(L"\n  == %s ", t), cWhite);
    // fill with = to width 70
    int len = 5 + (int)wcslen(t) + 1;
    for (int i = len; i < 70; ++i) Put(L"=", cWhite);
    Put(L"\n");
}

static void Print(const Items& v) {
    for (auto& i : v) {
        switch (i.st) {
        case St::Ok:   Put(L"  [ OK ] ", cGreen);  break;
        case St::Warn: Put(L"  [WARN] ", cYellow); break;
        case St::Fail: Put(L"  [FAIL] ", cRed);    break;
        case St::Info: Put(L"  [INFO] ", cCyan);    break;
        }
        Put(F(L"%-38s %s\n", i.name.c_str(), i.detail.c_str()));
    }
}

static void PrintFixGuide(const Items& v) {
    bool any = false;
    for (auto& i : v) {
        if (i.howToFix.empty() || i.st == St::Ok) continue;
        if (!any) { any = true; }
        WORD col = i.st == St::Fail ? cRed : cYellow;
        Put(F(L"\n  "), col);
        Put(i.st == St::Fail ? L"[FAIL] " : L"[WARN] ", col);
        Put(i.name + L"\n", cWhite);
        Put(F(L"          %s\n", i.howToFix.c_str()), cGray);
    }
}

// ============================================================ Main
int wmain() {
    SetConsoleTitleW(L"Monarch Checker");
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    // Window icon
    if (HWND w = GetConsoleWindow()) {
        HINSTANCE hi = GetModuleHandleW(nullptr);
        HICON bigIco = (HICON)LoadImageW(hi, MAKEINTRESOURCEW(IDI_MONARCH), IMAGE_ICON, 32, 32, 0);
        HICON smallIco = (HICON)LoadImageW(hi, MAKEINTRESOURCEW(IDI_MONARCH), IMAGE_ICON, 16, 16, 0);
        SendMessageW(w, WM_SETICON, ICON_BIG, (LPARAM)bigIco);
        SendMessageW(w, WM_SETICON, ICON_SMALL, (LPARAM)smallIco);
    }

    // Enable ANSI colors
    HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(ho, &mode);
    SetConsoleMode(ho, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    const wchar_t* orange = L"\x1b[38;2;255;140;0m";
    const wchar_t* reset  = L"\x1b[0m";
    Put(F(L"%s\n"
          L"   __  __                              _\n"
          L"  |  \\/  | ___  _ __   __ _ _ __ ___| |__\n"
          L"  | |\\/| |/ _ \\| '_ \\ / _` | '__/ __| '_ \\\n"
          L"  | |  | | (_) | | | | (_| | | | (__| | | |\n"
          L"  |_|  |_|\\___/|_| |_|\\__,_|_|  \\___|_| |_|   Checker\n%s",
          orange, reset));
    Wmi wmi;
    g_wmi = &wmi;

    Put(L"\n  Scanning...", cGray);

    Items hw, sec, sw, ov;
    CheckHardware(hw);
    CheckSecurity(sec);
    CheckSoftware(sw);
    CheckOverlays(ov);

    Put(L"\r\x1b[2K\x1b[1A");  // remove the "Scanning..." line

    Section(L"Hardware");   Print(hw);
    Section(L"Security");   Print(sec);
    Section(L"Software");   Print(sw);
    Section(L"Overlays");   Print(ov);

    // Summary
    int ok = 0, warn = 0, fail = 0;
    for (auto* list : { &hw, &sec, &sw, &ov })
        for (auto& i : *list) {
            if (i.st == St::Ok) ++ok;
            else if (i.st == St::Warn) ++warn;
            else if (i.st == St::Fail) ++fail;
        }

    Put(F(L"\n  Result: %d OK, %d warnings, %d issues.\n", ok, warn, fail),
        fail ? cRed : warn ? cYellow : cGreen);

    // Collect all fixable items
    bool hasIssues = false;
    for (auto* list : { &sec, &sw, &ov, &hw })
        for (auto& i : *list)
            if (!i.howToFix.empty() && i.st != St::Ok) { hasIssues = true; break; }

    if (hasIssues) {
        Put(L"\n  Press [F] to show fix instructions, or any other key to exit.\n", cWhite);
        wchar_t c = (wchar_t)towupper(_getwch());
        if (c == L'F') {
            Section(L"How to Fix");
            PrintFixGuide(sec);
            PrintFixGuide(sw);
            PrintFixGuide(ov);
            PrintFixGuide(hw);
            Put(L"\n  Press any key to exit...");
            _getwch();
        }
    } else {
        Put(L"\n  Everything looks good! Press any key to exit...", cGreen);
        _getwch();
    }

    CoUninitialize();
    return 0;
}
