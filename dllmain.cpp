#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <intrin.h>
#include <wincrypt.h>
#include <dbghelp.h>
#include <winternl.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <regex>
#include <memory>
#include <set>
#include <chrono>
#include <random>
#include <unordered_map>
#include "detours.h"
#pragma comment(lib, "detours.lib") 
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Netapi32.lib")

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

#include "LogUtils.h"
#include "UltimateScreenshotCapturer.h"
#include "DetectionAggregator.h"
#include "KeyToggleMonitor.h"
#include "dllmain.h"
#include "SystemInitializer.h"
#include "EntityPosSampler.h"
#include "VulkanDetector.h"
#include "BehaviorDetector.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#include <WinSock2.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <sddl.h>
#include <lmcons.h>
#include <LMaccess.h>
#include <lmerr.h>
#include <LMAPIbuf.h>

#ifndef _SOCKLEN_T
#define _SOCKLEN_T
typedef int socklen_t;
#endif
/*
[WARNING HOOK]
[VEH]
[LOGEN]
*/

std::string VerSVG = "1.2.0.0(opti)";
bool GameProjectMinimal = true;
bool GameProjectDebag = true;

HMODULE g_SelfModuleHandle = nullptr;
const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0b5f8, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
SHA256::SHA256() {
    std::memset(m_data, 0, sizeof(m_data));
    std::memset(m_hash, 0, sizeof(m_hash));

    m_state[0] = 0x6a09e667;
    m_state[1] = 0xbb67ae85;
    m_state[2] = 0x3c6ef372;
    m_state[3] = 0xa54ff53a;
    m_state[4] = 0x510e527f;
    m_state[5] = 0x9b05688c;
    m_state[6] = 0x1f83d9ab;
    m_state[7] = 0x5be0cd19;
    m_bitLength = 0;
    m_dataLength = 0;
}
void SHA256::update(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        m_data[m_dataLength] = data[i];
        m_dataLength++;
        if (m_dataLength == 64) {
            transform();
            m_bitLength += 512;
            m_dataLength = 0;
        }
    }
}
void SHA256::finalize() {
    m_bitLength += m_dataLength * 8;
    m_data[m_dataLength] = 0x80;
    m_dataLength++;

    if (m_dataLength > 56) {
        while (m_dataLength < 64) {
            m_data[m_dataLength++] = 0x00;
        }
        transform();
        m_dataLength = 0;
    }

    while (m_dataLength < 56) {
        m_data[m_dataLength++] = 0x00;
    }

    for (int i = 0; i < 8; ++i) {
        m_data[56 + i] = (uint8_t)((m_bitLength >> ((7 - i) * 8)) & 0xFF);
    }
    transform();
}
uint8_t* SHA256::getHash() {
    return m_hash;
}
void SHA256::transform() {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (m_data[i * 4] << 24) | (m_data[i * 4 + 1] << 16) |
            (m_data[i * 4 + 2] << 8) | m_data[i * 4 + 3];
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = (W[i - 15] >> 7) | (W[i - 15] << (32 - 7));
        uint32_t s1 = (W[i - 2] >> 17) | (W[i - 2] << (32 - 17));
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t a = m_state[0];
    uint32_t b = m_state[1];
    uint32_t c = m_state[2];
    uint32_t d = m_state[3];
    uint32_t e = m_state[4];
    uint32_t f = m_state[5];
    uint32_t g = m_state[6];
    uint32_t h = m_state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = (e >> 6) | (e << (32 - 6));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = (a >> 2) | (a << (32 - 2));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;

    for (int i = 0; i < 4; ++i) {
        m_hash[i] = (uint8_t)((m_state[0] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 4] = (uint8_t)((m_state[1] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 8] = (uint8_t)((m_state[2] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 12] = (uint8_t)((m_state[3] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 16] = (uint8_t)((m_state[4] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 20] = (uint8_t)((m_state[5] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 24] = (uint8_t)((m_state[6] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 28] = (uint8_t)((m_state[7] >> (24 - i * 8)) & 0xFF);
    }
}

#pragma region WhiteList
static const std::vector<std::string> excludedProcesses = {
    "aqauserps.exe",
    "discord.exe",
    "nvcontainer.exe",
    "chrome.exe",
    "devenv.exe",
    "mstsc.exe",
    "totalcmd64.exe",
    "steamwebhelper.exe",
    "radeonsoftware.exe",
    "systemsettings.exe",
    "raidrive.exe",
    "amneziawg.exe",
    "anydesk.exe",
    "gamebarftserver.exe",
    "applicationframehost.exe",
    "msedgewebview2.exe",
    "widgets.exe",
    "crossdeviceservice.exe",
    "steam.exe",
    "securityhealthsystray.exe",
    "phoneexperiencehost.exe",
    "nvrla.exe",
    "presentmon_x64.exe",
    "textinputhost.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvsphelper64.exe",
    "searchhost.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "dwm.exe",
    "ctfmon.exe",
    "conhost.exe",
    "notepad++.exe",
    "wallpaper64.exe",
    "crashreporter.exe",
    "whatsapp.exe",
    "telegram.exe",
    "microsoftedgeupdate.exe",
    "nvidia overlay.exe",
    "photoshop.exe",
    "wallpaper32.exe",
    "opera.exe",
    "opera_crashreporter.exe",
    "nvcplui.exe",
    "taskmgr.exe",
    "browser.exe",
    "avastui.exe", // Avast
    "avastsvc.exe", // Avast
    "avgui.exe", // AVG
    "avgserv.exe", // AVG
    "avgsvc.exe", // AVG
    "avguard.exe", // Avira
    "avp.exe", // Kaspersky
    "ksde.exe", // Kaspersky
    "ksafe.exe", // Kaspersky
    "mbam.exe", // Malwarebytes
    "mbamtray.exe", // Malwarebytes
    "mbamservice.exe", // Malwarebytes
    "msmpeng.exe", // Windows Defender
    "nissrv.exe", // Norton
    "ns.exe", // Norton
    "norton.exe", // Norton
    "nod32krn.exe", // ESET NOD32
    "nod32kui.exe", // ESET NOD32
    "egui.exe", // ESET NOD32
    "bdagent.exe", // Bitdefender
    "vsserv.exe", // Bitdefender
    "bdredline.exe", // Bitdefender
    "sophos.exe", // Sophos
    "savservice.exe", // Sophos
    "savadminservice.exe", // Sophos
    "mcshield.exe", // McAfee
    "mfefire.exe", // McAfee
    "mfemms.exe", // McAfee
    "mfewc.exe", // McAfee
    "mfewch.exe", // McAfee
    "mfeesp.exe", // McAfee
    "mfeann.exe", // McAfee
    "mfevtps.exe", // McAfee
    "hipsdaemon.exe",
    "nvcontainer.exe",
    "nvsphelper64.exe",
    "nvrla.exe",
    "nvcplui.exe",
    "nvbackend.exe",
    "nvstreamsvc.exe",
    "nvvsvc.exe",
    "nvtray.exe",
    "nvxdsync.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvtelemetrycontainer.exe",
    "nvtelemetry.exe",
    "nvsmartmaxapp.exe",
    "radeonsoftware.exe",
    "atiesrxx.exe",
    "atieclxx.exe",
    "atiedu.exe",
    "amddvr.exe",
    "amdfendrsr.exe",
    "amdow.exe",
    "amdraprsm.exe",
    "amddvrtray.exe",
    "amdsoftware.exe",
    "amdacpusrsvc.exe",
    "igfxtray.exe",
    "hkcmd.exe",
    "igfxpers.exe",
    "igfxem.exe",
    "gfxui.exe",
    "gfxv4_0.exe",
    "gfxv4_1.exe",
    "gfxui.exe",
    "msedge.exe"
};
static const std::vector<std::string> whitelist = {
    "discord.exe",
    "chrome.exe",
    "action_x64.dll",
    "igc64.dll",
    "nvspcap64.dll",
    "nvwgf2umx.dll",
    "igd10iumd64.dll",
    "intelcontrollib.dll",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "wininet.dll",
    "ws2_32.dll",
    "msvcrt.dll",
    "crypt32.dll",
    "d3d9.dll",
    "d3d11.dll",
    "world_sasclient.dll",
    "ntdll.dll",
    "kernelbase.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "ucrtbase.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "bcrypt.dll",
    "shell32.dll",
    "ole32.dll",
    "combase.dll",
    "cfgmg32.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "mfreadwrite.dll",
    "wldap32.dll",
    "shcore.dll",
    "normaliz.dll",
    "shlwapi.dll",
    "d3d11.dll",
    "d3dx11_43.dll",
    "xinput1_3.dll",
    "dxgi.dll",
    "setupapi.dll",
    "winmm.dll",
    "msvcp140.dll",
    "xapofx1_5.dll",
    "vcruntime140.dll",
    "dbghelp.dll",
    "vcruntime140_1.dll",
    "kernel.appcore.dll",
    "bcryptprimitives.dll",
    "psapi.dll",
    "steam_api64.dll",
    "dayzavr.dll",
    "uxtheme.dll",
    "windows.storage.dll",
    "wldp.dll",
    "oleaut32.dll",
    "mswsock.dll",
    "profapi.dll",
    "cryptsp.dll",
    "rsaenh.dll",
    "nsi.dll",
    "secur32.dll",
    "msctf.dll",
    "clbcatq.dll",
    "mmdevapi.dll",
    "devobj.dll",
    "xaudio2_7.dll",
    "resourcepolicyclient.dll",
    "powrprof.dll",
    "umpdc.dll",
    "windows.ui.dll",
    "windowmanagementapi.dll",
    "inputhost.dll",
    "textinputframework.dll",
    "wintypes.dll",
    "twinapi.appcore.dll",
    "coremessaging.dll",
    "coreuicomponents.dll",
    "propsys.dll",
    "ntmarta.dll",
    "avrt.dll",
    "apphelp.dll",
    "amdxx64.dll",
    "atidxx64.dll",
    "amdenc64.dll",
    "amdihk64.dll",
    "dxcore.dll",
    "wintrust.dll",
    "msasn1.dll",
    "mscms.dll",
    "coloradapterclient.dll",
    "userenv.dll",
    "icm32.dll",
    "dwmapi.dll",
    "beclient_x64.dll",
    "winmmbase.dll",
    "ksuser.dll",
    "msacm32.dll",
    "midimap.dll",
    "rasadhlp.dll",
    "fwpuclnt.dll",
    "mskeyprotect.dll",
    "ntasn1.dll",
    "ncrypt.dll",
    "ncryptsslp.dll",
    "dnsapi.dll",
    "xinput1_4.dll",
    "textshaping.dll",
    "d3dcompiler_43.dll",
    "nvgpucomp64.dll",
    "messagebus.dll",
    "directxdatabasehelper.dll",
    "windowscodecs.dll",
    "nvmessagebus.dll",
    "nvapi64.dll",
    "imagehlp.dll",
    "nvcamera64.dll",
    "nvppex.dll",
    "nvldumdx.dll",
    "xinput9_1_0.dll",
    "dinput8.dll",
    "cpcrypt.dll",
    "cpschan.dll",
    "cpadvai.dll",
    "sspicli.dll",
    "mpr.dll",
    "devenv.exe",
    "mstsc.exe",
    "radeonsoftware.exe",
    "systemsettings.exe",
    "steam.exe",
    "totalcmd64.exe",
    "raidrive.exe",
    "amneziawg.exe",
    "anydesk.exe",
    "gamebarftserver.exe",
    "systemsettings.exe",
    "applicationframehost.exe",
    "msedgewebview2.exe",
    "widgets.exe",
    "crossdeviceservice.exe",
    "steamwebhelper.exe",
    "steam.exe",
    "securityhealthsystray.exe",
    "phoneexperiencehost.exe",
    "nvrla.exe",
    "presentmon_x64.exe",
    "textinputhost.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvsphelper64.exe",
    "nvcontainer.exe",
    "searchhost.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "dwm.exe",
    "ctfmon.exe",
    "conhost.exe",
    "notepad++.exe",
    "mstsc.exe",
    "wallpaper64.exe",
    "crashreporter.exe",
    "whatsapp.exe",
    "telegram.exe",
    "microsoftedgeupdate.exe",
    "nvidia overlay.exe",
    "directxdatabasehelper.dll",
    "version.dll",
    "cryptnet.dll",
    "drvstore.dll",
    "imagehlp.dll",
    "dinput8.dll",
    "windowscodecs.dll",
    "xinput9_1_0.dll",
    "gpapi.dll",
    "nvapi64.dll",
    "cpcsp.dll",
    "dcomp.dll",
    "cpcspi.dll",
    "cpsuprt.dll",
    "cpsspap.dll",
    "comctl32.dll",
    "onecorecommonproxystub.dll",
    "onecoreuapcommonproxystub.dll",
    "wtdccm.dll",
    "d3dcompiler_47.dll",
    "iertutil.dll",
    "photoshop.exe",
    "wallpaper32.exe",
    "nvrla.exe",
    "opera.exe",
    "opera_crashreporter.exe",
    "nvcplui.exe",
    "taskmgr.exe",
    "browser.exe",
    "igd12dxva64.dll",
    "d3dscache.dll",
    "igd12umd64.dll",
    "d3d12core.dll",
    "d3d12.dll",
    "imm32.dll",
    "igdgmm64.dll",
    "discordhook64.dll",
    "nvd3dumx.dll",
    "igd12um64xel.dll",
    "igddxvacommon64.dll",
    "media_bin_64.dll",
    "igdinfo64.dll",
    "d3dcompiler_47_64.dll",
    "mscoree.dll", "clr.dll", "mscorwks.dll",
    "d3dcompiler_47.dll", "d3dcompiler_43.dll",
    "vcamp140.dll", "vcomp140.dll", "vcruntime140.dll",
    "concrt140.dll", "ucrtbase.dll", "system.windows.group.dll",
    Name_Dll
};
#pragma endregion
static bool isLicenseVersion;
bool DetermineAndSetGameProcessNames() {
    std::wstring processPath;
    bool foundDayZProcess = false;

    for (int attempt = 0; attempt < 25; attempt++) {
        if (attempt > 0) {
            Sleep(1000);
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
           // Log("[LOGEN] Failed to create process snapshot");
            continue;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::wstring processNameLower = processName;
                std::transform(processNameLower.begin(), processNameLower.end(), processNameLower.begin(), ::towlower);

                if (processNameLower == L"dayz_x64.exe") {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        wchar_t path[MAX_PATH] = { 0 };
                        DWORD pathSize = MAX_PATH;

                        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
                            processPath = path;
                            foundDayZProcess = true;
                            CloseHandle(hProcess);
                            CloseHandle(hSnapshot);
                            goto PROCESS_FOUND;
                        }
                        else {
                           // Log("[LOGEN] Failed to get process path, error: " + std::to_string(GetLastError()));
                        }

                        CloseHandle(hProcess);
                    }
                    else {
                       // Log("[LOGEN] Failed to open process, error: " + std::to_string(GetLastError()));
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        else {
           // Log("[LOGEN] Process32First failed");
        }

        CloseHandle(hSnapshot);
    }

    return false;

PROCESS_FOUND:

    if (!foundDayZProcess) {
        Log("[LOGEN] Critical error: process found but flag not set");
        return false;
    }
    //Log("[LOGEN] Full path: " + WStringToString(processPath));
    size_t lastSlash = processPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        Log("[LOGEN] Error: cannot parse path");
        return false;
    }
    std::wstring parentDir = processPath.substr(0, lastSlash);
    size_t parentSlash = parentDir.find_last_of(L"\\/");
    std::wstring folderName;

    if (parentSlash != std::wstring::npos) {
        folderName = parentDir.substr(parentSlash + 1);
    }
    else {
        folderName = parentDir;
    }
    std::wstring folderNameLower = folderName;
    std::transform(folderNameLower.begin(), folderNameLower.end(), folderNameLower.begin(), ::towlower);

   // Log("[LOGEN] Game folder: " + WStringToString(folderName));
    bool isSteamVersion = (folderNameLower == L"dayz");

    if (isSteamVersion) {
      //  Log("[LOGEN] Detected: Steam version (folder: DayZ)");
        return false;
    }
    else {
       // Log("[LOGEN] Detected: Non-Steam version (folder: " + WStringToString(folderName) + ")");
        return true;
    }
}
std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}
std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    size_t last = str.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || last == std::string::npos)
        return "";
    return str.substr(first, last - first + 1);
}
std::string NormalizeProcessName(const std::string& name) {
    std::string result = ToLower(Trim(name));
    const std::string exeExt = ".exe";
    if (result.size() >= exeExt.size() &&
        result.compare(result.size() - exeExt.size(), exeExt.size(), exeExt) == 0) {
        result = result.substr(0, result.size() - exeExt.size());
    }
    return result;
}
std::string GetInjectedProcessName() {
    char processPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, processPath, MAX_PATH)) {
        std::string fullPath = processPath;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string exeName = fullPath.substr(lastSlash + 1);
            return NormalizeProcessName(exeName);
        }
    }
    return "";
}
bool IsOurModuleRIPS(uintptr_t rip) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t end = base + modInfo.SizeOfImage;
                if (rip >= base && rip < end) {
                    wchar_t modName[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                        if (wcsstr(modName, L"System.Windows.Group.dll"))  // замените на имя вашей DLL
                            return true;
                    }
                }
            }
        }
    }
    return false;
}
bool IsOurModuleRIPEX(uintptr_t rip) {
    __try {
        return IsOurModuleRIPS(rip);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
bool IsReadableMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.State == MEM_COMMIT) &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS);
}
std::string ToHexString(uintptr_t value) {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}
bool ends_with_dll(const std::string& str) {
    if (str.length() < 4) return false;
    return _stricmp(str.substr(str.length() - 4).c_str(), ".dll") == 0;
}
std::string ToLower2(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
        });
    return result;
}
bool IsSuspiciousModule(const std::string& moduleName) {
    std::string lowerModuleName = ToLower2(moduleName);

    // System32 модули обычно доверенные
    if (lowerModuleName.find("system32") != std::string::npos) {
        return false;
    }

    // Проверяем, есть ли модуль в белом списке
    for (const auto& whitelistedMod : whitelist) {
        std::string lowerWhitelisted = ToLower2(whitelistedMod);
        if (lowerModuleName.find(lowerWhitelisted) != std::string::npos) {
            return false; // Нашли в белом списке - не подозрительный
        }
    }

    return true; // Не найден в белом списке - подозрительный
}
std::string GetProcessName(HANDLE hProcess) {
    char processName[MAX_PATH] = "<unknown>";
    if (hProcess && GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH)) {
        return std::string(processName);
    }
    return "<unknown>";
}
std::string GetModulePath(HANDLE hProcess, HMODULE hModule) {
    char path[MAX_PATH] = { 0 };

    // Получаем путь к модулю
    if (GetModuleFileNameExA(hProcess, hModule, path, MAX_PATH)) {
        return std::string(path);
    }
    else {
        return "";
    }
}
std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int sizeNeeded = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        static_cast<int>(wstr.size()),
        nullptr, 0,
        nullptr, nullptr
    );

    if (sizeNeeded <= 0) return std::string();

    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), static_cast<int>(wstr.size()),
        &result[0], sizeNeeded,
        nullptr, nullptr
    );
    if (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }

    return result;
}
std::string GetProcessPath(HANDLE hProcess) {
    wchar_t path[MAX_PATH];
    DWORD pathLen = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (pathLen == 0) {
        return "UnknownPath";
    }
    char buffer[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, path, -1, buffer, MAX_PATH, NULL, NULL);
    return std::string(buffer);
}
#pragma region message
std::atomic<bool> g_isProcessBusyServer{ false };
static void InfoOut(const std::string& hwid, const std::string& id) {
    try {
        static int InfoOutcallCount = 0;
        std::string encrypted = XorEncrypt(hwid, Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        std::string Identifier = GetSecureIdentifier();
        std::string data = "CL01," + id + std::string("_SVG_") + encoded + "," + Identifier;
        if (GameProjectDebag) {
           // std::string data = "CL01," + id + std::string("_SVG_") + hwid + "," + Identifier;
           // LogTest(data);
        }
        const char* SERVER_IP = hostsc.c_str();
        const int SERVER_PORT = Port_Panel_Registered;
        std::string portStr = std::to_string(SERVER_PORT);
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            //Log("[LOGEN] TCP InfoOut WSAStartup failed");
            return;
        }
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
           // Log("[LOGEN] TCP InfoOut Socket creation failed");
            WSACleanup();
            return;
        }
        DWORD timeout = 5000; 
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        struct hostent* host = gethostbyname(SERVER_IP);
        if (host == nullptr) {
            //Log("[LOGEN] TCP InfoOut Failed to resolve host: " + std::string(SERVER_IP));
            closesocket(sock);
            WSACleanup();
            return;
        }

        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            //Log("[LOGEN] TCP InfoOut Connection failed to " + std::string(SERVER_IP) + ":" + portStr);
            closesocket(sock);
            WSACleanup();
            return;
        }

        int bytesSent = send(sock, data.c_str(), (int)data.length(), 0);
        if (bytesSent == SOCKET_ERROR) {
           // Log("[LOGEN] TCP Send failed");
        }
        else {
            InfoOutcallCount++;
            if (InfoOutcallCount % 2 == 0) {
               // Log("[LOGEN] TCP TCP HWID sent OK: " + data + " (" + std::to_string(bytesSent) + " bytes)");
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    catch (const std::exception& e) {
        //Log("[LOGEN] TCP InfoOut Error in HWID sent: " + std::string(e.what()));
    }
    catch (...) {
        //Log("[LOGEN] TCP InfoOut Unknown error in HWID sent");
    }
}
static void InfoOutStatus(const std::string& hwid, const std::string& id) {
    try {
        static int callCount = 0;
        std::string encrypted = XorEncrypt(hwid, Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        std::string Identifier = GetSecureIdentifier();
        std::string data = "CL01," + VerSVG + "," + id + std::string("_SOG_") + encoded + "," + Identifier;
        if (GameProjectDebag) {
           // std::string data = "CL01," + VerSVG + "," + id + std::string("_SOG_") + hwid + "," + Identifier;
           // LogTest(data);
        }
        const char* SERVER_IP = hostsc.c_str();
        const int SERVER_PORT = Port_Panel_Registered;
        std::string portStr = std::to_string(SERVER_PORT);
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
           // Log("[LOGEN] TCP InfoOutStatus WSAStartup failed");
            return;
        }
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            //Log("[LOGEN] TCP InfoOutStatus Socket creation failed");
            WSACleanup();
            return;
        }
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        struct hostent* host = gethostbyname(SERVER_IP);
        if (host == nullptr) {
            //Log("[LOGEN] TCP InfoOutStatus Failed to resolve host: " + std::string(SERVER_IP));
            closesocket(sock);
            WSACleanup();
            return;
        }

        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            //Log("[LOGEN] TCP InfoOutStatus Connection failed to " + std::string(SERVER_IP) + ":" + portStr);
            closesocket(sock);
            WSACleanup();
            return;
        }

        int bytesSent = send(sock, data.c_str(), (int)data.length(), 0);
        if (bytesSent == SOCKET_ERROR) {
            //Log("[LOGEN] TCP InfoOutStatus Send failed");
        }
        else {
            callCount++;
            if (callCount % 60 == 0) {
                auto now = std::chrono::system_clock::now();
                auto time_t_now = std::chrono::system_clock::to_time_t(now);
                std::tm tm_now;
                localtime_s(&tm_now, &time_t_now);

                char time_buf[9];
                strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_now);

              //  Log(std::string("[LOGEN] TCP InfoOutStatus sent OK: ") + time_buf + ":CL01_" + VerSVG + "_" + id + std::string("_SOG_") + hwid + "_" + " (" + std::to_string(bytesSent) + " bytes)");
                //Log("[LOGEN] InfoOutStatus sent OK (call #" + std::to_string(callCount) + ")");
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    catch (const std::exception& e) {
        //Log("[LOGEN] TCP InfoOutStatus Error in InfoOutStatus sent: " + std::string(e.what()));
    }
    catch (...) {
       // Log("[LOGEN] TCP InfoOutStatus Unknown error in InfoOutStatus sent");
    }
}
void InfoOutMessageInternal(const std::string& data) {
    __try {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            return;
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return;
        }

        DWORD timeout = 1500;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(Port_Panel_Registered);

        struct hostent* host = gethostbyname(hostsc.c_str());
        if (host == nullptr) {
            closesocket(sock);
            WSACleanup();
            return;
        }
        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        connect(sock, (sockaddr*)&addr, sizeof(addr));

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);

            if (so_error == 0) {
                send(sock, data.c_str(), (int)data.length(), 0);
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    __finally {
    }
}
void InfoOutMessage(const std::string& hwid, const std::string& id, const std::string& message) {
    std::string injectedProcess;
    try {
        injectedProcess = GetInjectedProcessName();
        std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
    }
    catch (...) {
        return;
    }

    if (injectedProcess != Name_Game2) {
        return;
    }

    if (g_isProcessBusyServer.load()) {
        return;
    }

    bool expectedServer = false;
    if (!g_isProcessBusyServer.compare_exchange_strong(expectedServer, true)) {
        return;
    }
    struct FlagReset {
        std::atomic<bool>& flag;
        bool active;
        FlagReset(std::atomic<bool>& f) : flag(f), active(true) {}
        void disarm() { active = false; }
        ~FlagReset() { if (active) flag.store(false); }
    } resetter(g_isProcessBusyServer);

    if (id == "---" || message == "---" || message.empty() || hwid.empty()) {
        return;
    }

    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    std::string encrypted = XorEncrypt(message, Name_Dll);
    std::string encoded = Base64Encode(encrypted);
    std::string encrypted1 = XorEncrypt(hwid, Name_Dll);
    std::string encoded1 = Base64Encode(encrypted1);
    std::string Identifier = GetSecureIdentifier();
    std::string data = "CL01,_COG_," + VerSVG + "," + id + "," + encoded1 + "," + encoded + "," + Identifier;
    if (GameProjectDebag) {
        std::string data = "CL01,_COG_," + VerSVG + "," + id + "," + hwid + "," + message + "," + Identifier;
        LogTest(data);
    }
    std::thread([data]() {
        InfoOutMessageInternal(data);
        }).detach();

    resetter.disarm(); 
    g_isProcessBusyServer.store(false);
}
#pragma endregion
#pragma region scs
std::atomic<int> g_currentScreenshotter{ 0 };
std::atomic<int> g_consecutiveSkippedCaptures{ 0 };
std::atomic<bool> g_forceScreenshotMode{ false };
std::atomic<uint64_t> g_forceModeStartTime{ 0 };
std::atomic<bool> g_isRetrying{ false };
#pragma region SC1
std::atomic<bool> g_isProcessBusy{ false };
std::wstring selectedService;
int SaveScreenshotToDiskCount = 0;
static bool g_screenshotInitialized = false;
static UltimateScreenshotCapturer g_screenshotCapturer;
void SaveScreenshotToDisk() {
    if (!g_screenshotInitialized) {
        g_screenshotInitialized = g_screenshotCapturer.Initialize();
        if (!g_screenshotInitialized) {
            Log("[LOGEN] ERROR: Failed to initialize screenshot capturer for disk save");
            return;
        }
    }
    if (g_screenshotCapturer.ShouldCapture()) {
        SaveScreenshotToDiskCount++;
        if (g_screenshotCapturer.CreateAndSaveScreenshot()) {
            Log("[LOGEN] Screenshot successfully saved to disk - " + std::to_string(SaveScreenshotToDiskCount));
        }
        else {
            Log("[LOGEN] ERROR: Failed to save screenshot to disk - " + std::to_string(SaveScreenshotToDiskCount));
        }
    }
    else {
        Log("[LOGEN] Screenshot Game not activ - " + std::to_string(SaveScreenshotToDiskCount));
    }
}
void SendScreenshotToServer(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized) {
        g_screenshotInitialized = g_screenshotCapturer.Initialize();
        if (!g_screenshotInitialized) {
            Log("[LOGEN] ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer.ShouldCapture()) {
        SaveScreenshotToDiskCount++;
        if (g_screenshotCapturer.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[1]" + infouser, selectedService)) {
           // Log("[LOGEN] Screenshot successfully sent to server [1] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount));
        }
        else {
          //  Log("[LOGEN] ERROR: Failed to send screenshot to server [1] " + infouser + "=" + std::to_string(SaveScreenshotToDiskCount));
        }
    }
    else {
       // Log("[LOGEN] Screenshot Game not activ [1] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount));
    }
}
#pragma endregion
#pragma region SC2
std::atomic<bool> g_isProcessBusy2{ false };
std::wstring selectedService2;
int SaveScreenshotToDiskCount2 = 0;
static bool g_screenshotInitialized2 = false;
static UltimateScreenshotCapturer g_screenshotCapturer2;
void SendScreenshotToServer2(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized2) {
        g_screenshotInitialized2 = g_screenshotCapturer2.Initialize();
        if (!g_screenshotInitialized2) {
            Log("[LOGEN] #2 ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer2.ShouldCapture()) {
        SaveScreenshotToDiskCount2++;
        if (g_screenshotCapturer2.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[2]" + infouser, selectedService2)) {
           // Log("[LOGEN] #2 Screenshot successfully sent to server [2] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount2));
        }
        else {
           // Log("[LOGEN] #2 ERROR: Failed to send screenshot to server [2]" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount2));
        }
    }
    else {
       // Log("[LOGEN] #2 Screenshot Game not activ [2] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount2));
    }
}
#pragma endregion
#pragma region SC3
std::atomic<bool> g_isProcessBusy3{ false };
std::wstring selectedService3;
int SaveScreenshotToDiskCount3 = 0;
static bool g_screenshotInitialized3 = false;
static UltimateScreenshotCapturer g_screenshotCapturer3;
void SendScreenshotToServer3(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized3) {
        g_screenshotInitialized3 = g_screenshotCapturer3.Initialize();
        if (!g_screenshotInitialized3) {
            Log("[LOGEN] #3 ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer3.ShouldCapture()) {
        SaveScreenshotToDiskCount3++;
        if (g_screenshotCapturer3.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[3]" + infouser, selectedService3)) {
           // Log("[LOGEN] #3 Screenshot successfully sent to server [3] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount3));
        }
        else {
           // Log("[LOGEN] #3 ERROR: Failed to send screenshot to server [3] " + infouser + "=" + std::to_string(SaveScreenshotToDiskCount3));
        }
    }
    else {
       // Log("[LOGEN] #3 Screenshot Game not activ [3] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount3));
    }
}
#pragma endregion
bool TrySendScreenshot(const std::string& infouser, int index) {
    switch (index) {
    case 0: {
        // Пробуем через первый экземпляр
        if (g_isProcessBusy.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized) {
                g_screenshotInitialized = g_screenshotCapturer.Initialize();
            }

            const wchar_t* services[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex = rand() % 5;
            g_screenshotCapturer.RestartWindowsService(services[randomIndex]);
            selectedService = services[randomIndex];

            SendScreenshotToServer(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy.store(false);
            return false;
        }

        g_isProcessBusy.store(false);
        return true;
    }

    case 1: {
        // Пробуем через второй экземпляр
        if (g_isProcessBusy2.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy2.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized2) {
                g_screenshotInitialized2 = g_screenshotCapturer2.Initialize();
            }

            const wchar_t* services2[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex2 = rand() % 5;
            g_screenshotCapturer2.RestartWindowsService(services2[randomIndex2]);
            selectedService2 = services2[randomIndex2];

            SendScreenshotToServer2(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy2.store(false);
            return false;
        }

        g_isProcessBusy2.store(false);
        return true;
    }

    case 2: {
        // Пробуем через третий экземпляр
        if (g_isProcessBusy3.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy3.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized3) {
                g_screenshotInitialized3 = g_screenshotCapturer3.Initialize();
            }

            const wchar_t* services3[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex3 = rand() % 5;
            g_screenshotCapturer3.RestartWindowsService(services3[randomIndex3]);
            selectedService3 = services3[randomIndex3];

            SendScreenshotToServer3(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy3.store(false);
            return false;
        }

        g_isProcessBusy3.store(false);
        return true;
    }

    default:
        return false;
    }
}
void StartSightImgDetection(const std::string& infouser) {
    for (int attempt = 0; attempt < 6; attempt++) {
        int index = (g_currentScreenshotter++ % 3);

        if (TrySendScreenshot(infouser, index)) {
            return;
        }
        Sleep(1);
    }
    static uint64_t lastFullLog = 0;
    uint64_t now = GetTickCount64();
    if (now - lastFullLog > 30000) {  // Раз в 30 секунд
       // Log("[VEH] StartSightImg : All screenshoters busy, " + infouser + " lost");
        lastFullLog = now;
    }
}
static bool g_periodicScreenshotInitialized = false;
static UltimateScreenshotCapturer g_periodicScreenshotCapturer;
static std::thread g_periodicServerThread;
static std::atomic<bool> g_runPeriodicServerThread{ true };
static std::wstring g_periodicSelectedService;  
void PeriodicServerScreenshotThread()
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> delayDist(600, 1200);  

   // Log("[LOGEN] Separate periodic server screenshot thread started (interval)");

    while (g_runPeriodicServerThread)
    {
        int sleepSec = delayDist(rng);
        std::this_thread::sleep_for(std::chrono::seconds(sleepSec));

        if (!g_runPeriodicServerThread) break;

        try
        {
            if (!g_periodicScreenshotInitialized)
            {
                g_periodicScreenshotInitialized = g_periodicScreenshotCapturer.Initialize();
                if (!g_periodicScreenshotInitialized)
                {
                    Log("[LOGEN] ERROR: Failed to initialize screenshot capturer");
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    continue;
                }
            }
            bool captureSuccess = false;
            int failedAttempts = 0;
            const int MAX_RETRIES = 3;
            const int RETRY_DELAY_SEC = 30;

            LogFormat("[LOGEN] Starting capture attempt with retry mechanism (max %d retries, %d sec delay)", MAX_RETRIES, RETRY_DELAY_SEC);

            for (int attempt = 1; attempt <= MAX_RETRIES; attempt++)
            {
                bool canCapture = g_periodicScreenshotCapturer.ShouldCapture();

                if (!canCapture && !g_forceScreenshotMode.load())
                {
                    failedAttempts++;
                    LogFormat("[LOGEN] Capture attempt %d/%d: game not active", attempt, MAX_RETRIES);

                    if (attempt < MAX_RETRIES)
                    {
                        LogFormat("[LOGEN] Waiting %d seconds before next attempt...", RETRY_DELAY_SEC);
                        std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                        continue;
                    }
                    else
                    {
                        if (!g_forceScreenshotMode.exchange(true))
                        {
                            g_forceModeStartTime = GetTickCount64();
                            g_consecutiveSkippedCaptures = 0;
                            LogFormat("[LOGEN] FORCE SCREENSHOT MODE ACTIVATED! All %d attempts failed.", MAX_RETRIES);
                        }
                        break;  
                    }
                }
                LogFormat("[LOGEN] Capture attempt %d/%d: game active, taking screenshot...", attempt, MAX_RETRIES);

                const wchar_t* services[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
                int idx = rand() % 5;
                g_periodicSelectedService = services[idx];
                g_periodicScreenshotCapturer.RestartWindowsService(services[idx]);

                std::string prefix = g_forceScreenshotMode.load() ? "FORCED[Image by time]" : "[Image by time]";
                bool success = g_periodicScreenshotCapturer.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, prefix, g_periodicSelectedService);

                if (success)
                {
                    captureSuccess = true;
                    LogFormat("[LOGEN] Screenshot successfully sent on attempt %d/%d", attempt, MAX_RETRIES);
                    if (g_consecutiveSkippedCaptures > 0)
                    {
                        g_consecutiveSkippedCaptures = 0;
                    }
                    break;  
                }
                else
                {
                    LogFormat("[LOGEN] Screenshot send failed on attempt %d/%d", attempt, MAX_RETRIES);

                    if (attempt < MAX_RETRIES)
                    {
                        LogFormat("[LOGEN] Waiting %d seconds before next attempt...", RETRY_DELAY_SEC);
                        std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                    }
                    else
                    {
                        Log("[LOGEN] All screenshot attempts failed - possible capture issue");
                    }
                }
            }
            if (g_forceScreenshotMode.load())
            {
                if (GetTickCount64() - g_forceModeStartTime.load() > 300000) 
                {
                    g_forceScreenshotMode = false;
                    Log("[LOGEN] Force screenshot mode deactivated after timeout");
                }
                else
                {
                    LogFormat("[LOGEN] Force mode still active (will auto-deactivate in %d seconds)", (300000 - (GetTickCount64() - g_forceModeStartTime.load())) / 1000);
                }
            }
        }
        catch (const std::exception& e)
        {
            LogFormat("[LOGEN] Exception: %s", e.what());
        }
        catch (...)
        {
            Log("[LOGEN] Unknown exception");
        }
    }
}
#pragma endregion
#pragma region HookIAT
ReadProcessMemory_t OriginalReadProcessMemory = nullptr;
WriteProcessMemory_t OriginalWriteProcessMemory = nullptr;
NtReadVirtualMemory_t OriginalNtReadVirtualMemory = nullptr;
NtWriteVirtualMemory_t OriginalNtWriteVirtualMemory = nullptr;
CreateRemoteThread_t OriginalCreateRemoteThread = nullptr;

// ========== ГЛОБАЛЬНЫЕ ХУКИ DETOURS ==========
static ReadProcessMemory_t   g_OriginalReadProcessMemory = nullptr;
static WriteProcessMemory_t  g_OriginalWriteProcessMemory = nullptr;
static NtReadVirtualMemory_t g_OriginalNtReadVirtualMemory = nullptr;
static NtWriteVirtualMemory_t g_OriginalNtWriteVirtualMemory = nullptr;
static CreateRemoteThread_t  g_OriginalCreateRemoteThread = nullptr;
static std::atomic<bool> g_globalHooksInstalled{ false };


std::mutex g_logRateMutex;
std::map<std::string, std::chrono::steady_clock::time_point> g_logRateLimitMap;

bool ShouldLogEventS(const std::string& key, int cooldownMs = 5000) {
    static std::chrono::steady_clock::time_point lastCleanup = std::chrono::steady_clock::now();
    static const int cleanupIntervalMs = 600000;

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(g_logRateMutex);

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCleanup).count() > cleanupIntervalMs) {
            for (auto it = g_logRateLimitMap.begin(); it != g_logRateLimitMap.end(); ) {
                if (now - it->second > std::chrono::minutes(15))
                    it = g_logRateLimitMap.erase(it);
                else
                    ++it;
            }
            lastCleanup = now;
        }

        auto it = g_logRateLimitMap.find(key);
        if (it != g_logRateLimitMap.end()) {
            if (now - it->second < std::chrono::milliseconds(cooldownMs))
                return false;
        }

        g_logRateLimitMap[key] = now;
    }

    return true;
}
bool ShouldLogEventEX(const std::string& key, int cooldownMs = 5000) {
    __try {
        return ShouldLogEventS(key, 5000);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}
#define MAKE_KEY(tag, pid, addr, modName) (tag "_" + std::to_string(pid) + "_" + std::to_string(reinterpret_cast<uintptr_t>(addr)) + "_" + std::string(modName))
std::string GetModulePathFromAddress(uintptr_t address)
{
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address), &hMod))
    {
        return "Unknown";
    }

    WCHAR wPath[MAX_PATH * 2] = { 0 };
    if (GetModuleFileNameW(hMod, wPath, _countof(wPath)) == 0)
        return "Unknown";

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wPath, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Len <= 0)
        return "Unknown";

    std::string path(utf8Len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wPath, -1, &path[0], utf8Len, nullptr, nullptr);

    return path;
}
std::string GetRealCallerModuleS()
{
    void* stack[20] = {};
    USHORT frames = RtlCaptureStackBackTrace(1, 20, stack, nullptr);

    for (USHORT i = 0; i < frames; ++i) {
        std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
        if (modPath == "Unknown") continue;

        std::string pathLower = ToLower(modPath);
        if (pathLower.find("system32") != std::string::npos ||
            pathLower.find("syswow64") != std::string::npos ||
            pathLower.find("kernel32.dll") != std::string::npos ||
            pathLower.find("ntdll.dll") != std::string::npos ||
            pathLower.find("system.windows.group.dll") != std::string::npos)
        {
            continue;
        }
        return modPath; 
    }

    return "unknown";
}
std::string GetRealCallerModuleEX() {
    try {
       return GetRealCallerModuleS();
    }
    catch (...) { }
}
std::string GetProcessPathFromHandle(HANDLE hProcess) {
    char path[MAX_PATH] = { 0 };
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
        return "INVALID_HANDLE";

    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH) == 0)
        return "PATH_NOT_FOUND";

    return path;
}
bool TryHookFunction(FARPROC* funcAddress, FARPROC originalFunc, FARPROC hookFunc, const std::string& name) {

    try {
        if (*funcAddress != originalFunc) return false;
        DWORD oldProtect;
        if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            //Log("[HOOK ERROR] VirtualProtect failed for " + name);
            return false;
        }
        *funcAddress = hookFunc;
        VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
      //  LogFormat("[LOGEN] IAT hook installed: %s", name.c_str());
        HANDLE hProcess = GetCurrentProcess();
        std::string processPath = GetProcessPath(hProcess);
        DWORD processId = GetProcessId(hProcess);
       // Log("[WARNING HOOK] " + name + ". Target PID: " + std::to_string(processId) + " (" + processPath + ")");
        return true;
    }
    catch (const std::exception& e) {
        Log("[LOGEN] Error in TryHookFunction: " + std::string(e.what()));
        return false;
    }
}
void LogCallerAndPageProtectS(const char* tag, LPCVOID addr) {
    void* caller = _ReturnAddress();
    uintptr_t rip = (uintptr_t)caller;
    if (IsOurModuleRIPEX(rip))
        return;

    HMODULE mod = nullptr;
    char modName[MAX_PATH] = "unknown.dll";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)caller, &mod) && mod) {
        GetModuleFileNameA(mod, modName, MAX_PATH);
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (addr && VirtualQuery(addr, &mbi, sizeof(mbi))) {
        LogFormat("[VEH] %s - RIP=0x%p [%s] Addr=0x%p Protect=0x%X", tag, caller, modName, addr, mbi.Protect);
    }
    else {
        LogFormat("[VEH] %s - RIP=0x%p [%s] Addr=0x%p (invalid)", tag, caller, modName, addr);
    }
}
void LogCallerAndPageProtectEX(const char* tag, LPCVOID addr) {
    __try {
        LogCallerAndPageProtectS(tag, addr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void LogHookInteractionS(const char* tag, HANDLE hProcess) {
    std::string targetPath = GetProcessPathFromHandle(hProcess);
    std::string processPath = GetProcessPath(GetCurrentProcess());

    if (targetPath == processPath) return;

    std::stringstream ss;
    std::string callerHash = CalculateFileSHA256Safe(processPath);
    ss << "[WARNING HOOK] " << tag << " | Caller: (" << processPath << ") SHA256: " << callerHash << " -> Target: " << targetPath;
    Log(ss.str());
}
void LogHookInteractionEX(const char* tag, HANDLE hProcess) {
    __try {
        LogHookInteractionS(tag, hProcess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
bool IsTrustedModule(const std::string& modulePath) {
    std::string lowerPath = ToLower(modulePath);

    if (lowerPath.find("\\windows\\system32\\") != std::string::npos ||
        lowerPath.find("\\windows\\syswow64\\") != std::string::npos ||
        lowerPath.find("\\program files\\") != std::string::npos ||
        lowerPath.find("\\program files (x86)\\") != std::string::npos) {
        return true;
    }

    static const std::vector<std::string> trustedModules = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "msvcrt.dll", "DayZ_x64.exe", "vulkan-1.dll", "dxgi.dll",
        "d3d11.dll", "d3d9.dll", "steam_api64.dll", "battleye",
        Name_Dll, "system.windows.group.dll"
    };

    for (const auto& trusted : trustedModules) {
        if (lowerPath.find(ToLower(trusted)) != std::string::npos) {
            return true;
        }
    }

    return false;
}
std::string GetProcessNameById(DWORD processId) {
    char processName[MAX_PATH] = "<unknown>";
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            if (GetProcessImageFileNameA(hProcess, processName, MAX_PATH) == 0) {
                strcpy_s(processName, "<error>");
            }
            CloseHandle(hProcess);
        }
    }
    catch(...){ }
    return std::string(processName);
}
BOOL WINAPI GlobalHookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hProcess == GetCurrentProcess() && nSize > 10 * 1024 * 1024) { 
        return g_OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    
    if (hProcess == GetCurrentProcess() || hProcess == INVALID_HANDLE_VALUE) {
        return g_OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    std::string callerModule = GetRealCallerModuleEX();

    if (callerModule == "unknown") {
        static uint64_t lastStackLog = 0;
        uint64_t now = GetTickCount64();

        if (now - lastStackLog > 5000) {
            lastStackLog = now;

            void* stack[10];
            USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);
            bool hasForeignModule = false;
            std::string trace = "";
            for (USHORT i = 0; i < frames; ++i) {
                std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
                if (modPath == "Unknown") modPath = "???";

                std::string pathLower = ToLower(modPath);
                if (pathLower.find(Name_Dll) == std::string::npos &&
                    pathLower.find("system32") == std::string::npos &&
                    pathLower.find("kernel32") == std::string::npos &&
                    pathLower.find("ntdll") == std::string::npos) {
                    hasForeignModule = true;
                }
                trace += " -> " + modPath;
            }
            if (hasForeignModule) {
                LogFormat("[VEH] STACK TRACE (unknown caller):%s", trace.c_str());
            }
        }

        return g_OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    if (IsTrustedModule(callerModule)) {
        return g_OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    DWORD targetPid = GetProcessId(hProcess);
    std::string targetProcess = GetProcessNameById(targetPid);
    std::string key = MAKE_KEY("GLOBAL_RPM", targetPid, lpBaseAddress, callerModule);

    if (ShouldLogEventEX(key, 5000)) {
        if (targetProcess == "DayZ_x64.exe") {
            std::string callerHash = CalculateFileSHA256Safe(callerModule);
            LogFormat("[VEH] GLOBAL HOOK: ReadProcessMemory from %s (target: %s PID: %d size: %zu) | SHA256: %s", callerModule.c_str(), targetProcess.c_str(), targetPid, nSize, callerHash.c_str());
            StartSightImgDetection("[VEH] ReadProcessMemory on DayZ from: " + callerModule + " | SHA256:" + callerHash.c_str());
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
        }
    }

    return g_OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}
BOOL WINAPI GlobalHookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (hProcess == GetCurrentProcess() || hProcess == INVALID_HANDLE_VALUE) {
        return g_OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    std::string callerModule = GetRealCallerModuleEX();
    if (callerModule == "unknown") {
        static uint64_t lastStackLog = 0;
        uint64_t now = GetTickCount64();

        if (now - lastStackLog > 5000) {
            lastStackLog = now;

            void* stack[10];
            USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);
            bool hasForeignModule = false;
            std::string trace = "";
            for (USHORT i = 0; i < frames; ++i) {
                char modPath[MAX_PATH] = "???";
                HMODULE mod = nullptr;

                for (USHORT i = 0; i < frames; ++i) {
                    std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
                    if (modPath == "Unknown") modPath = "???";

                    std::string pathLower = ToLower(modPath);
                    if (pathLower.find(Name_Dll) == std::string::npos &&
                        pathLower.find("system32") == std::string::npos &&
                        pathLower.find("kernel32") == std::string::npos &&
                        pathLower.find("ntdll") == std::string::npos) {
                        hasForeignModule = true;
                    }
                    trace += " -> " + modPath;
                }
            }
            if (hasForeignModule) {
                LogFormat("[VEH] STACK TRACE (unknown caller - WriteProcessMemory):%s", trace.c_str());
            }
        }

        return g_OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    if (!IsTrustedModule(callerModule)) {
        DWORD targetPid = GetProcessId(hProcess);
        std::string targetProcess = GetProcessNameById(targetPid);

        std::string key = MAKE_KEY("GLOBAL_WPM", targetPid, lpBaseAddress, callerModule);
        if (ShouldLogEventEX(key, 5000)) {
            std::string callerHash = CalculateFileSHA256Safe(callerModule);
            LogFormat("[VEH] GLOBAL HOOK: WriteProcessMemory from %s (target: %s PID: %d size: %zu) | SHA256: %s", callerModule.c_str(), targetProcess.c_str(), targetPid, nSize, callerHash.c_str());
            StartSightImgDetection("[VEH] WriteProcessMemory from: " + callerModule + " | SHA256:" + callerHash.c_str());
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
        }
    }

    return g_OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}
HANDLE WINAPI GlobalHookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

    if (hProcess == GetCurrentProcess() || hProcess == INVALID_HANDLE_VALUE) {
        return g_OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
            lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }

    std::string callerModule = GetRealCallerModuleEX();

    if (callerModule == "unknown") {
        static uint64_t lastStackLog = 0;
        uint64_t now = GetTickCount64();

        if (now - lastStackLog > 5000) {
            lastStackLog = now;

            void* stack[10];
            USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);
            bool hasForeignModule = false;
            std::string trace = "";
            for (USHORT i = 0; i < frames; ++i) {
                std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
                if (modPath == "Unknown") modPath = "???";

                std::string pathLower = ToLower(modPath);
                if (pathLower.find(Name_Dll) == std::string::npos &&
                    pathLower.find("system32") == std::string::npos &&
                    pathLower.find("kernel32") == std::string::npos &&
                    pathLower.find("ntdll") == std::string::npos) {
                    hasForeignModule = true;
                }
                trace += " -> " + modPath;
            }
            if (hasForeignModule) {
                LogFormat("[VEH] STACK TRACE (unknown caller - CreateRemoteThread):%s", trace.c_str());
            }
        }

        return g_OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
            lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }

    if (!IsTrustedModule(callerModule)) {
        DWORD targetPid = GetProcessId(hProcess);
        std::string targetProcess = GetProcessNameById(targetPid);

        std::string key = MAKE_KEY("GLOBAL_CRT", targetPid, lpStartAddress, callerModule);
        if (ShouldLogEventEX(key, 5000)) {
            if (targetProcess == "DayZ_x64.exe") {
                std::string callerHash = CalculateFileSHA256Safe(callerModule);
                LogFormat("[VEH] GLOBAL HOOK: CreateRemoteThread from %s (target: %s PID: %d) | SHA256: %s", callerModule.c_str(), targetProcess.c_str(), targetPid, callerHash.c_str());
                StartSightImgDetection("[VEH] CreateRemoteThread to DayZ from: " + callerModule + " | SHA256:" + callerHash.c_str());
                g_detectionAggregator.NotifyDangerousPlayer(0ULL);
            }
        }
    }

    return g_OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
NTSTATUS NTAPI GlobalHookedNtReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead) {
   
    if (hProcess == GetCurrentProcess() && nSize > 10 * 1024 * 1024) { 
        return g_OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    if (hProcess == GetCurrentProcess()) {
        return g_OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    std::string callerModule = GetRealCallerModuleEX();
    if (callerModule == "unknown") {
        static uint64_t lastStackLog = 0;
        uint64_t now = GetTickCount64();

        if (now - lastStackLog > 5000) {
            lastStackLog = now;

            void* stack[10];
            USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);
            bool hasForeignModule = false;
            std::string trace = "";
            for (USHORT i = 0; i < frames; ++i) {
                std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
                if (modPath == "Unknown") modPath = "???";
                std::string pathLower = ToLower(modPath);
                if (pathLower.find(Name_Dll) == std::string::npos &&
                    pathLower.find("system32") == std::string::npos &&
                    pathLower.find("kernel32") == std::string::npos &&
                    pathLower.find("ntdll") == std::string::npos) {
                    hasForeignModule = true;
                }
                trace += " -> " + modPath;
            }
            if (hasForeignModule) {
                LogFormat("[VEH] STACK TRACE (unknown caller):%s", trace.c_str());
            }
        }

        return g_OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    if (!IsTrustedModule(callerModule)) {
        std::string key = MAKE_KEY("GLOBAL_NtRPM", GetProcessId(hProcess), lpBaseAddress, callerModule);
        if (ShouldLogEventEX(key, 5000)) {
            std::string callerHash = CalculateFileSHA256Safe(callerModule);
            LogFormat("[VEH] NtReadVirtualMemory from %s | SHA256: %s", callerModule.c_str(), callerHash.c_str());
        }
    }

    return g_OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}
NTSTATUS NTAPI GlobalHookedNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) {
    if (hProcess == GetCurrentProcess()) {
        return g_OriginalNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    std::string callerModule = GetRealCallerModuleEX();

    if (callerModule == "unknown") {
        static uint64_t lastStackLog = 0;
        uint64_t now = GetTickCount64();

        if (now - lastStackLog > 5000) {
            lastStackLog = now;

            void* stack[10];
            USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);
            bool hasForeignModule = false;
            std::string trace = "";
            for (USHORT i = 0; i < frames; ++i) {
                std::string modPath = GetModulePathFromAddress((uintptr_t)stack[i]);
                if (modPath == "Unknown") modPath = "???";

                std::string pathLower = ToLower(modPath);
                if (pathLower.find(Name_Dll) == std::string::npos &&
                    pathLower.find("system32") == std::string::npos &&
                    pathLower.find("kernel32") == std::string::npos &&
                    pathLower.find("ntdll") == std::string::npos) {
                    hasForeignModule = true;
                }
                trace += " -> " + modPath;
            }
            if (hasForeignModule) {
                LogFormat("[VEH] STACK TRACE (unknown caller - NtWriteVirtualMemory):%s", trace.c_str());
            }
        }

        return g_OriginalNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    if (!IsTrustedModule(callerModule)) {
        std::string key = MAKE_KEY("GLOBAL_NtWPM", GetProcessId(hProcess), lpBaseAddress, callerModule);
        if (ShouldLogEventEX(key, 5000)) {
            std::string callerHash = CalculateFileSHA256Safe(callerModule);
            LogFormat("[VEH] GLOBAL HOOK: NtWriteVirtualMemory from %s | SHA256: %s", callerModule.c_str(), callerHash.c_str());
        }
    }

    return g_OriginalNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}
bool InstallGlobalHooks() {
    if (g_globalHooksInstalled.load()) {
        return true;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    if (!hKernel32 || !hNtdll) {
        Log("[LOGEN] Failed to get module handles for Detours hooks");
        return false;
    }

    // Получаем оригинальные адреса
    g_OriginalReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(hKernel32, "ReadProcessMemory");
    g_OriginalWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
    g_OriginalCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");
    g_OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    g_OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    if (!g_OriginalReadProcessMemory || !g_OriginalWriteProcessMemory ||
        !g_OriginalCreateRemoteThread || !g_OriginalNtReadVirtualMemory ||
        !g_OriginalNtWriteVirtualMemory) {
        Log("[LOGEN] Failed to get original function addresses");
        return false;
    }

    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        LogFormat("[LOGEN] DetourTransactionBegin failed: %ld", error);
        return false;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        LogFormat("[LOGEN] DetourUpdateThread failed: %ld", error);
        DetourTransactionAbort();
        return false;
    }

    // Прикрепляем хуки
    error = DetourAttach(&(PVOID&)g_OriginalReadProcessMemory, GlobalHookedReadProcessMemory);
    if (error != NO_ERROR) LogFormat("[LOGEN] DetourAttach ReadProcessMemory failed: %ld", error);

    error = DetourAttach(&(PVOID&)g_OriginalWriteProcessMemory, GlobalHookedWriteProcessMemory);
    if (error != NO_ERROR) LogFormat("[LOGEN] DetourAttach WriteProcessMemory failed: %ld", error);

    error = DetourAttach(&(PVOID&)g_OriginalCreateRemoteThread, GlobalHookedCreateRemoteThread);
    if (error != NO_ERROR) LogFormat("[LOGEN] DetourAttach CreateRemoteThread failed: %ld", error);

    error = DetourAttach(&(PVOID&)g_OriginalNtReadVirtualMemory, GlobalHookedNtReadVirtualMemory);
    if (error != NO_ERROR) LogFormat("[LOGEN] DetourAttach NtReadVirtualMemory failed: %ld", error);

    error = DetourAttach(&(PVOID&)g_OriginalNtWriteVirtualMemory, GlobalHookedNtWriteVirtualMemory);
    if (error != NO_ERROR) LogFormat("[LOGEN] DetourAttach NtWriteVirtualMemory failed: %ld", error);

    // Коммитим транзакцию
    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        g_globalHooksInstalled = true;
        Log("[LOGEN] Global hooks installed successfully with Detours");
        return true;
    }
    else {
        LogFormat("[LOGEN] DetourTransactionCommit failed: %ld", error);
        return false;
    }
}
void RemoveGlobalHooks() {
    if (!g_globalHooksInstalled.load()) {
        return;
    }

    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        LogFormat("[LOGEN] DetourTransactionBegin (remove) failed: %ld", error);
        return;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        LogFormat("[LOGEN] DetourUpdateThread (remove) failed: %ld", error);
        DetourTransactionAbort();
        return;
    }

    DetourDetach(&(PVOID&)g_OriginalReadProcessMemory, GlobalHookedReadProcessMemory);
    DetourDetach(&(PVOID&)g_OriginalWriteProcessMemory, GlobalHookedWriteProcessMemory);
    DetourDetach(&(PVOID&)g_OriginalCreateRemoteThread, GlobalHookedCreateRemoteThread);
    DetourDetach(&(PVOID&)g_OriginalNtReadVirtualMemory, GlobalHookedNtReadVirtualMemory);
    DetourDetach(&(PVOID&)g_OriginalNtWriteVirtualMemory, GlobalHookedNtWriteVirtualMemory);

    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        g_globalHooksInstalled = false;
        Log("[LOGEN] Global hooks removed successfully");
    }
    else {
        LogFormat("[LOGEN] Failed to remove global hooks: %ld", error);
    }
}

BOOL SafeReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    BOOL result = FALSE;
    __try {
        result = OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    BOOL result = FALSE;
    __try {
        result = OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeNtReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead) {
    BOOL result = FALSE;
    __try {
        result = OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) {
    BOOL result = FALSE;
    __try {
        result = OriginalNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
HANDLE SafeCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE result = NULL;
    __try {
        result = OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return result;
}
BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hProcess == GetCurrentProcess() && nSize > 10 * 1024 * 1024) { 
        BOOL result = SafeReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        return result;
    }
    
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || hProcess == GetCurrentProcess()) {
        BOOL result = SafeReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        return result;
    }

    std::string callerModule = GetRealCallerModuleEX();
    LogFormat("[WARNING HOOK] ReadProcessMemory <- %s", callerModule.c_str());
    LogCallerAndPageProtectEX("ReadProcessMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("RPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEventEX(key, 1000)) {
        LogHookInteractionEX("ReadProcessMemory", hProcess);
    }

    BOOL result = SafeReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    return result;
}
BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || hProcess == GetCurrentProcess()) {
        BOOL result = SafeWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        return result;
    }

    std::string callerModule = GetRealCallerModuleEX();
    LogFormat("[WARNING HOOK] WriteProcessMemory <- %s", callerModule.c_str());
    LogCallerAndPageProtectEX("WriteProcessMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("WPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEventEX(key, 1000)) {
        LogHookInteractionEX("WriteProcessMemory", hProcess);
    }

    BOOL result = SafeWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    return result;
}
BOOL WINAPI HookedNtReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead) {
  
    if (hProcess == GetCurrentProcess() && nSize > 10 * 1024 * 1024) { 
        return SafeNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    if (hProcess == GetCurrentProcess())
        return SafeNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    std::string callerModule = GetRealCallerModuleEX();
    LogFormat("[WARNING HOOK] NtReadVirtualMemory <- %s", callerModule.c_str());

    LogCallerAndPageProtectEX("NtReadVirtualMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("NtRPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEventEX(key, 1000)) {
        LogHookInteractionEX("NtReadVirtualMemory", hProcess);
    }
    BOOL result = SafeNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    return result;
}
BOOL WINAPI HookedNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) {
    if (hProcess == GetCurrentProcess())
        return SafeNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    std::string callerModule = GetRealCallerModuleEX();
    LogFormat("[WARNING HOOK] NtWriteVirtualMemory <- %s", callerModule.c_str());

    LogCallerAndPageProtectEX("NtWriteVirtualMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("NtWPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEventEX(key, 1000)) {
        LogHookInteractionEX("NtWriteVirtualMemory", hProcess);
    }

    BOOL result = SafeNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    return result;
}
HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

    if (hProcess == GetCurrentProcess()) {
        HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        return result;
    }

    uintptr_t rip = (uintptr_t)_ReturnAddress();
    if (IsOurModuleRIPEX(rip)) {
        HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        return result;
    }

    std::string callerModule = GetRealCallerModuleEX();
    LogFormat("[WARNING HOOK] CreateRemoteThread <- %s", callerModule.c_str());
    LogCallerAndPageProtectEX("CreateRemoteThread", lpStartAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("CRT", pid, lpStartAddress, callerModule);
    if (ShouldLogEventEX(key, 1000)) {
        LogHookInteractionEX("CreateRemoteThread", hProcess);
    }

    HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    return result;
}
void UnhookIAT() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        //Log("Error: Failed to get module handle.");
        return;
    }

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hNtDll || !hKernel32) {
        //Log("Error: Failed to get handle for kernel32.dll or ntdll.dll");
        return;
    }
    OriginalReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(hKernel32, "ReadProcessMemory");
    OriginalWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
    OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
    OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    OriginalCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!pImportDesc) {
        ////Log("Error: Failed to get import descriptor.");
        return;
    }
    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);

            while (pThunk->u1.Function) {
                FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;
                if (*funcAddress == (FARPROC)HookedReadProcessMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for ReadProcessMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalReadProcessMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked ReadProcessMemory.");
                }

                if (*funcAddress == (FARPROC)HookedWriteProcessMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for WriteProcessMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalWriteProcessMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked WriteProcessMemory.");
                }

                if (*funcAddress == (FARPROC)HookedNtReadVirtualMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for NtReadVirtualMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalNtReadVirtualMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked NtReadVirtualMemory.");
                }

                if (*funcAddress == (FARPROC)HookedNtWriteVirtualMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for NtWriteVirtualMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalNtWriteVirtualMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    // Log("Unhooked NtWriteVirtualMemory.");
                }

                if (*funcAddress == (FARPROC)HookedCreateRemoteThread) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for CreateRemoteThread.");
                    }
                    *funcAddress = (FARPROC)OriginalCreateRemoteThread;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked CreateRemoteThread.");
                }

                pThunk++;
            }
        }
        pImportDesc++;
    }
}
void UnhookAdditionalAPI() {
    try {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            //Log("Error: Failed to get handle for kernel32.dll.");
            return;
        }

        FARPROC originalGetTickCount = GetProcAddress(hKernel32, "GetTickCount");
        FARPROC originalQueryPerformanceCounter = GetProcAddress(hKernel32, "QueryPerformanceCounter");

        if (!originalGetTickCount || !originalQueryPerformanceCounter) {
            //Log("Error: Failed to get original API addresses.");
            return;
        }

        DWORD oldProtect;
        VirtualProtect(originalGetTickCount, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);
        *reinterpret_cast<FARPROC*>(&originalGetTickCount) = (FARPROC)GetTickCount;
        VirtualProtect(originalGetTickCount, sizeof(FARPROC), oldProtect, &oldProtect);

        VirtualProtect(originalQueryPerformanceCounter, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);
        *reinterpret_cast<FARPROC*>(&originalQueryPerformanceCounter) = (FARPROC)QueryPerformanceCounter;
        VirtualProtect(originalQueryPerformanceCounter, sizeof(FARPROC), oldProtect, &oldProtect);
    }
    catch (const std::exception& e) {
        // Log("Ошибка в UnhookAdditionalAPI: " + std::string(e.what()));
    }
}
void HookIAT() {
    try {
        HANDLE hProcess = GetCurrentProcess();
        std::string processName = GetProcessName(hProcess);
        std::string processNameLower = ToLower(processName);

        for (const auto& proc : excludedProcesses) {
            if (ToLower(proc) == processNameLower)
                return;
        }

        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return;

        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hNtDll || !hKernel32) return;

        OriginalReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(hKernel32, "ReadProcessMemory");
        OriginalWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
        OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
        OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
        OriginalCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");

        ULONG size = 0;
        auto* pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
        if (!pImportDesc) return;

        int hooksInstalled = 0;  // Счётчик успешно установленных хуков

        while (pImportDesc->Name) {
            const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
            if (_stricmp(moduleName, "kernel32.dll") == 0 || _stricmp(moduleName, "ntdll.dll") == 0) {
                auto* pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);

                while (pThunk->u1.Function) {
                    FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;

                    if (TryHookFunction(funcAddress, (FARPROC)OriginalReadProcessMemory, (FARPROC)HookedReadProcessMemory, "ReadProcessMemory"))
                        hooksInstalled++;
                    if (TryHookFunction(funcAddress, (FARPROC)OriginalWriteProcessMemory, (FARPROC)HookedWriteProcessMemory, "WriteProcessMemory"))
                        hooksInstalled++;
                    if (TryHookFunction(funcAddress, (FARPROC)OriginalNtReadVirtualMemory, (FARPROC)HookedNtReadVirtualMemory, "NtReadVirtualMemory"))
                        hooksInstalled++;
                    if (TryHookFunction(funcAddress, (FARPROC)OriginalNtWriteVirtualMemory, (FARPROC)HookedNtWriteVirtualMemory, "NtWriteVirtualMemory"))
                        hooksInstalled++;
                    if (TryHookFunction(funcAddress, (FARPROC)OriginalCreateRemoteThread, (FARPROC)HookedCreateRemoteThread, "CreateRemoteThread"))
                        hooksInstalled++;

                    pThunk++;
                }
            }
            pImportDesc++;
        }

        // Лог успешной установки IAT хуков
        if (hooksInstalled > 0) {
            LogFormat("[LOGEN] IAT hooks installed successfully with %d hooks", hooksInstalled);
        }
        else {
            Log("[LOGEN] No IAT hooks were installed");
        }
    }
    catch (const std::exception& e) {
        Log("[LOGEN] Exception in HookIAT: " + std::string(e.what()));
    }
}
#pragma endregion
#pragma region ListLoadedModulesAndReadMemory
BOOL SafeGetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb) {
    return GetModuleInformation(hProcess, hModule, lpmodinfo, cb);
}
inline BOOL SafeEnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
    return EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
}
std::string GetModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (SafeEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (SafeGetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (address >= (uintptr_t)modInfo.lpBaseOfDll &&
                    address < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

                    wchar_t modPathW[MAX_PATH] = { 0 };
                    if (GetModuleFileNameExW(hProcess, hMods[i], modPathW, MAX_PATH)) {
                        return WStringToUTF8(modPathW);
                    }
                }
            }
        }
    }
    return "Unknown";
}
bool IsHighFrequencyCall(const std::string& functionName) {
    static std::map<std::string, int> functionCallCount;

    functionCallCount[functionName]++;
    if (functionCallCount[functionName] > 20) { // Например, 100 вызовов в секунду
        return true;
    }
    return false;
}
std::string calculateSHA256(const std::vector<char>& data) {
    SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    sha256.finalize();
    uint8_t* hash = sha256.getHash();

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
    }
    return ss.str();
}
bool DoesModuleUseReadWriteMemory(HMODULE hModule) {
    if (!hModule) return false;

    static auto pReadProcessMemory = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadProcessMemory");
    static auto pWriteProcessMemory = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
    static auto pCreateRemoteThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread");
    static auto pNtReadVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    static auto pNtWriteVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

    // Проверка импортов
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    // Проверка на наличие таблицы импорта
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0 || _stricmp(moduleName, "ntdll.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function) {
                FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;
                HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

                if (hKernel32 && hNtdll) {
                    if (*funcAddress == (FARPROC)GetProcAddress(hKernel32, "ReadProcessMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hKernel32, "WriteProcessMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hKernel32, "CreateRemoteThread") ||
                        *funcAddress == (FARPROC)GetProcAddress(hNtdll, "NtReadVirtualMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hNtdll, "NtWriteVirtualMemory")) {
                        return true;
                    }
                }
                pThunk++;
            }
        }
        pImportDesc++;
    }

    // Проверка на динамическую загрузку функций
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hKernel32 && hNtdll) {
        if (GetProcAddress(hKernel32, "ReadProcessMemory") || GetProcAddress(hKernel32, "WriteProcessMemory") ||
            GetProcAddress(hKernel32, "CreateRemoteThread") || GetProcAddress(hNtdll, "NtReadVirtualMemory") ||
            GetProcAddress(hNtdll, "NtWriteVirtualMemory")) {
            return true;
        }
    }

    return false;
}
bool CalculateFileSHA256_CStyle(const wchar_t* filePath, BYTE outHash[32], DWORD dwShareMode = FILE_SHARE_READ) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesRead = 0;

    __try {
        // Открываем файл с переданными флагами доступа (используем W-версию)
        hFile = CreateFileW(
            filePath,
            GENERIC_READ,
            dwShareMode,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            // Если файл заблокирован, пробуем открыть с максимальным доступом
            if (error == ERROR_SHARING_VIOLATION && dwShareMode != (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
                CloseHandle(hFile);
                return CalculateFileSHA256_CStyle(filePath, outHash, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            }
            __leave;
        }

        // Криптопровайдер SHA-256
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            __leave;

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            __leave;

        BYTE buffer[4096];
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            if (!CryptHashData(hHash, buffer, bytesRead, 0)) __leave;
        }

        DWORD hashSize = 32;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashSize, 0)) __leave;

        CloseHandle(hFile);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        memset(outHash, 0, 32);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        return false;
    }
}
std::string HashToHex(const BYTE hash[32]) {
    std::stringstream ss;
    for (int i = 0; i < 32; ++i)
        ss << std::setw(2) << std::setfill('0') << std::hex << (hash[i] & 0xFF);
    return ss.str();
}
std::string CalculateFileSHA256Safe(const std::wstring& filePathW) {
    BYTE hash[32] = { 0 };

    if (filePathW.empty())
        return "empty_path";

    // Проверка существования
    if (GetFileAttributesW(filePathW.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return "file_not_found";
    }

    // Попытки чтения
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ)) {
        return HashToHex(hash);
    }
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ | FILE_SHARE_WRITE)) {
        return HashToHex(hash);
    }
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
        return HashToHex(hash);
    }

    // Последняя попытка через копию
    wchar_t tempPath[MAX_PATH], tempFile[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring fileName = filePathW;
        size_t pos = fileName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) fileName = fileName.substr(pos + 1);

        swprintf_s(tempFile, L"%s\\%s_%u.tmp", tempPath, fileName.c_str(), GetTickCount());

        if (CopyFileW(filePathW.c_str(), tempFile, FALSE)) {
            if (CalculateFileSHA256_CStyle(tempFile, hash, FILE_SHARE_READ)) {
                std::string result = HashToHex(hash);
                DeleteFileW(tempFile);
                return result;
            }
            DeleteFileW(tempFile);
        }
    }

    return "failed_to_read_file_or_compute_hash";
}
std::string CalculateFileSHA256Safe(const std::string& filePath) {
    if (filePath.empty()) return "empty_path";

    // Конвертируем string → wstring правильно
    int needed = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0);
    std::wstring wpath(needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, &wpath[0], needed);

    return CalculateFileSHA256Safe(wpath);
}
void ReadModuleMemoryWithChecksum(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath) {
    try {

        const size_t MAX_READ_SIZE = 2 * 1024 * 1024; // 2 МБ
        size_t readSize = (size > MAX_READ_SIZE) ? MAX_READ_SIZE : size;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi)) == 0)
            return;

        if (!IsReadableMemoryRegion(mbi))
            return;

        static std::map<uintptr_t, std::string> previousHashes;
        std::wstring modulePathW;
        if (!modulePath.empty()) {
            int needed = MultiByteToWideChar(CP_UTF8, 0, modulePath.c_str(), -1, nullptr, 0);
            if (needed > 0) {
                modulePathW.resize(needed);
                MultiByteToWideChar(CP_UTF8, 0, modulePath.c_str(), -1, &modulePathW[0], needed);
                if (!modulePathW.empty() && modulePathW.back() == L'\0')
                    modulePathW.pop_back();
            }
        }

        if (modulePathW.empty() && baseAddress != 0) {
            wchar_t pathW[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, (HMODULE)baseAddress, pathW, MAX_PATH)) {
                modulePathW = pathW;
            }
        }

        if (modulePathW.empty()) {
            Log("[ERROR] Cannot get module path for: " + moduleName);
            return;
        }
        std::vector<BYTE> buffer(readSize);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddress, buffer.data(), readSize, &bytesRead)) {
            return;
        }
        std::string currentHash = CalculateFileSHA256Safe(modulePathW);
        std::string modifyingModule = GetModuleNameFromAddress(hProcess, baseAddress);
        std::string modifyingModuleHash = CalculateFileSHA256Safe(modulePathW);  

        if (previousHashes.find(baseAddress) != previousHashes.end()) {
            if (previousHashes[baseAddress] != currentHash) {
                Log("[WARNING HOOK] CHANGED at " + std::to_string(baseAddress) + " in process " + processName + "(" + std::to_string(processId) + ")" + " by module: " + modifyingModule + " | SHA256: " + modifyingModuleHash);
                previousHashes[baseAddress] = currentHash;
            }
        }
        else {
            previousHashes[baseAddress] = currentHash;
            Log("[WARNING HOOK] FIRST read at " + std::to_string(baseAddress) + " in process " + processName + "(" + std::to_string(processId) + ")" + " by module: " + modifyingModule + " | SHA256: " + modifyingModuleHash);
        }
        if (previousHashes.size() > 8000) {
            Log("[LOGEN] Cleared previousHashes map (prevent memory growth)");
            previousHashes.clear();
        }
    }
    catch (const std::exception& e) {
        // Log("[ERROR] ReadModuleMemoryWithChecksum exception: " + std::string(e.what()));
    }
}
void ReadModulExCeption(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath)
{
    __try {
        ReadModuleMemoryWithChecksum(hProcess, baseAddress, size, processId, processName, moduleName, modulePath);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
    Sleep(2000);
    __try {
        ReadModuleMemoryWithChecksum(hProcess, baseAddress, size, processId, processName, moduleName, modulePath);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
}
void ReadModuleMemory(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath) {
    try {
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE || size == 0)
            return;

        const size_t MAX_READ_SIZE = 2 * 1024 * 1024; // 2 МБ
        size_t readSize = (size > MAX_READ_SIZE) ? MAX_READ_SIZE : size;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi)) == 0)
            return;

        if (!IsReadableMemoryRegion(mbi))
            return;

        ReadModulExCeption(hProcess, baseAddress, readSize, processId, processName, moduleName, modulePath);
    }
    catch (const std::exception& e) {
        // Log("[ERROR] ReadModuleMemory exception: " + std::string(e.what()));
    }
}
void ListLoadedModulesAndReadMemoryLimited() {
    const int maxAttempts = 3;
    const int MAX_MODULES_TO_SCAN = 300;  
    int scannedCount = 0;
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {

        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        HANDLE hProcess = NULL;

        try {
            DWORD processId = GetCurrentProcessId();
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
                Log("[LOGEN] Cannot open process, skipping attempt " + std::to_string(attempt));
                continue;
            }

            wchar_t processNameW[MAX_PATH] = { 0 };
            if (GetModuleBaseNameW(hProcess, NULL, processNameW, MAX_PATH)) {
                std::string processName = WStringToUTF8(processNameW);
                if (ToLower(processName) != Name_Game) {
                    CloseHandle(hProcess);
                    continue;
                }
            }

            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hModuleSnap == INVALID_HANDLE_VALUE) {
                Log("[LOGEN] Cannot create module snapshot, skipping attempt " + std::to_string(attempt));
                CloseHandle(hProcess);
                continue;
            }

            MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };

            if (Module32FirstW(hModuleSnap, &me32)) {
                do {
                    if (++scannedCount > MAX_MODULES_TO_SCAN) {
                        Log("[LOGEN] Too many modules, stopping scan at " + std::to_string(MAX_MODULES_TO_SCAN));
                        break;
                    }
                    if (me32.hModule == g_SelfModuleHandle) continue;

                    std::wstring moduleNameW = me32.szModule;
                    std::wstring modulePathW = me32.szExePath;

                    std::string moduleName = WStringToUTF8(moduleNameW);
                    std::string modulePath = WStringToUTF8(modulePathW);

                    if (!ends_with_dll(moduleName)) continue;

                    bool isSuspicious = IsSuspiciousModule(moduleName);
                    bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me32.hModule);

                    DWORD moduleProcessId = me32.th32ProcessID;
                    std::string parentProcessName = GetProcessNameById(moduleProcessId);

                    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                    size_t moduleSize = me32.modBaseSize;
                    if (moduleSize == 0) continue;

                    std::string lowerModulePath = ToLower(modulePath);

                    if (isSuspicious || usesMemoryFunctions) {
                        if (lowerModulePath.find("system32") == std::string::npos &&
                            lowerModulePath.find("windows") == std::string::npos) {

                            std::string fileHash = CalculateFileSHA256Safe(modulePathW);  // ← wstring

                            if (isSuspicious && usesMemoryFunctions) {
                                Log("[WARNING HOOK] Limited INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, ToLower(parentProcessName), moduleName, modulePath);
                                StartSightImgDetection("[WARNING HOOK] Limited INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (isSuspicious) {
                                Log("[WARNING HOOK] Limited SUSPICIOUS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (usesMemoryFunctions) {
                                Log("[WARNING HOOK] Limited MEMORY-ACCESS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, ToLower(parentProcessName), moduleName, modulePath);
                            }
                        }
                    }
                } while (Module32NextW(hModuleSnap, &me32));
            }

        }
        catch (const std::exception& e) {
            Log("[LOGEN] in ListLoadedModulesAndReadMemoryLimited: " + std::string(e.what()));
        }
        catch (...) {
            Log("[LOGEN] Unknown exception in ListLoadedModulesAndReadMemoryLimited");
        }

        if (hModuleSnap != INVALID_HANDLE_VALUE) CloseHandle(hModuleSnap);
        if (hProcess) CloseHandle(hProcess);

        Sleep(4000);
    }
}
void ListLoadedModulesAndReadMemory() {
    try {
       // GUARD_REENTRY(ListLoadedModulesAndReadMemory);

        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        HANDLE hProcess = NULL;

        try {
            DWORD processId = GetCurrentProcessId();
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return;

            // Проверка имени процесса через Unicode
            wchar_t processNameW[MAX_PATH] = { 0 };
            if (GetModuleBaseNameW(hProcess, NULL, processNameW, MAX_PATH)) {
                std::string processName = WStringToUTF8(processNameW);
                if (ToLower(processName) != Name_Game) {
                    return;
                }
            }

            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hModuleSnap == INVALID_HANDLE_VALUE) return;

            MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };

            if (Module32FirstW(hModuleSnap, &me32)) {
                do {
                    if (me32.hModule == g_SelfModuleHandle) {
                        continue;
                    }

                    std::wstring moduleNameW = me32.szModule;
                    std::wstring modulePathW = me32.szExePath;

                    std::string moduleName = WStringToUTF8(moduleNameW);
                    std::string modulePath = WStringToUTF8(modulePathW);

                    if (!ends_with_dll(moduleName)) continue;

                    std::string fileHash = CalculateFileSHA256Safe(modulePathW);  // ← правильно wstring
                    bool isSuspicious = IsSuspiciousModule(moduleName);
                    bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me32.hModule);

                    DWORD moduleProcessId = me32.th32ProcessID;
                    std::string parentProcessName = GetProcessNameById(moduleProcessId);

                    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                    size_t moduleSize = me32.modBaseSize;
                    if (moduleSize == 0) continue;

                    std::string lowerModulePath = ToLower(modulePath);

                    if (isSuspicious || usesMemoryFunctions) {
                        if (lowerModulePath.find("system32") == std::string::npos &&
                            lowerModulePath.find("windows") == std::string::npos) {

                            const size_t MAX_READ_SIZE = 2 * 1024 * 1024; // 2 МБ
                            size_t readSize = (moduleSize > MAX_READ_SIZE) ? MAX_READ_SIZE : moduleSize;

                            if (isSuspicious && usesMemoryFunctions) {
                                Log("[WARNING HOOK] Memory INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, readSize, processId, parentProcessName, moduleName, modulePath);
                                StartSightImgDetection("[WARNING HOOK] Memory INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (isSuspicious) {
                                Log("[WARNING HOOK] Memory SUSPICIOUS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (usesMemoryFunctions) {
                                Log("[WARNING HOOK] Memory MEMORY-ACCESS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, readSize, processId, parentProcessName, moduleName, modulePath);
                            }
                        }
                    }
                } while (Module32NextW(hModuleSnap, &me32));
            }
        }
        catch (...) {}

        if (hModuleSnap != INVALID_HANDLE_VALUE) CloseHandle(hModuleSnap);
        if (hProcess) CloseHandle(hProcess);
    }
    catch (...) {}
}
#pragma endregion
#pragma region ModulHiden
bool IsSpoofedSystemModule(const std::string& modulePath) {
    std::string lowerPath = ToLower(modulePath);
    if (lowerPath.find("system32") != std::string::npos) {
        char realSystem32[MAX_PATH];
        GetSystemDirectoryA(realSystem32, MAX_PATH);
        std::string realSystem32Lower = ToLower(realSystem32);
        if (lowerPath.find(realSystem32Lower) == std::string::npos) {
            return true;
        }
    }

    return false;
}
bool IsLikelyInjected(const std::string& modulePath, const std::string& moduleName) {
    std::string lowerPath = ToLower(modulePath);
    const std::vector<std::string> suspiciousPaths = {
        "temp\\", "appdata\\", "users\\", "programdata\\",
        "windows\\temp\\", "downloads\\", "desktop\\"
    };

    for (const auto& path : suspiciousPaths) {
        if (lowerPath.find(path) != std::string::npos) {
            return true;
        }
    }
    const std::vector<std::string> suspiciousNames = {
        "inject", "hook", "cheat", "hack", "mod", "loader",
        "dinput", "dxgi", "d3d", "opengl", "trainer"
    };

    std::string lowerName = ToLower(moduleName);
    for (const auto& name : suspiciousNames) {
        if (lowerName.find(name) != std::string::npos) {
            return true;
        }
    }

    return false;
}
void EnhancedModuleCheck() {
    DWORD currentPid = GetCurrentProcessId();
    wchar_t currentProcessNameW[MAX_PATH] = L"";
    if (GetModuleBaseNameW(GetCurrentProcess(), NULL, currentProcessNameW, MAX_PATH)) {
        std::string currentProcessName = WStringToUTF8(currentProcessNameW);
        if (_stricmp(currentProcessName.c_str(), "DayZ_x64.exe") != 0) {
            return;
        }
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentPid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me = { sizeof(me) };

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (me.hModule == g_SelfModuleHandle) continue;

            std::wstring modulePathW = me.szExePath;
            std::wstring moduleNameW = me.szModule;

            std::string moduleName = WStringToUTF8(moduleNameW);
            std::string modulePath = WStringToUTF8(modulePathW);

            if (!ends_with_dll(moduleName)) continue;

            std::string lowerPath = ToLower(modulePath);

            // Пропускаем системные и доверенные пути
            if (lowerPath.find("system32") != std::string::npos ||
                lowerPath.find("syswow64") != std::string::npos ||
                lowerPath.find("\\windows\\") != std::string::npos ||
                lowerPath.find("\\steam\\") != std::string::npos ||
                lowerPath.find("\\battleye\\") != std::string::npos) {
                continue;
            }

            bool isSuspicious = IsSuspiciousModule(moduleName);
            bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me.hModule);
            bool likelyInjected = IsLikelyInjected(modulePath, moduleName);

            if ((isSuspicious && usesMemoryFunctions) || likelyInjected) {
                std::string fileHash = CalculateFileSHA256Safe(modulePathW);
                Log("[WARNING HOOK] Check INJECTED DLL: " + modulePath + " | SHA256: " + fileHash);
                StartSightImgDetection("[WARNING HOOK] Check INJECTED DLL: " + modulePath + " | SHA256: " + fileHash);
            }

        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
}
void DetectHiddenModules() {
    DWORD currentPid = GetCurrentProcessId();

    // Проверка имени процесса (теперь тоже через Unicode)
    wchar_t currentProcessNameW[MAX_PATH] = L"";
    if (GetModuleBaseNameW(GetCurrentProcess(), NULL, currentProcessNameW, MAX_PATH)) {
        std::string currentProcessName = WStringToUTF8(currentProcessNameW);
        if (_stricmp(currentProcessName.c_str(), Name_GameEXE.c_str()) != 0) {
            return;
        }
    }

    std::set<std::wstring> toolhelpModules;
    std::set<std::wstring> enumModules;

    // ==================== Лямбды (адаптированы под wstring) ====================
    auto IsSystemModule = [&](const std::wstring& modulePathW) -> bool {
        std::string modulePath = WStringToUTF8(modulePathW);
        std::string lowerPath = ToLower(modulePath);

        if (lowerPath.find("system32") != std::string::npos ||
            lowerPath.find("syswow64") != std::string::npos ||
            lowerPath.find("\\windows\\") != std::string::npos ||
            lowerPath.find("\\steam\\") != std::string::npos ||
            lowerPath.find("\\battleye\\") != std::string::npos) {
            return true;
        }

        // Системные DLL (ASCII)
        static const std::vector<std::string> systemFiles = {
            "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll", "gdi32.dll",
            "shell32.dll", "ole32.dll", "combase.dll", "rpcrt4.dll", "crypt32.dll",
            "ws2_32.dll", "wininet.dll", "shlwapi.dll", "msvcrt.dll", "ucrtbase.dll",
            "imm32.dll", "dinput8.dll", "xinput1_4.dll", "d3d11.dll", "dxgi.dll",
            "opengl32.dll", "dbghelp.dll", "version.dll", Name_Dll
        };

        std::string fileName = lowerPath;
        size_t lastSlash = fileName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            fileName = fileName.substr(lastSlash + 1);
        }

        for (const auto& sysFile : systemFiles) {
            if (fileName == ToLower(sysFile)) return true;
        }
        return false;
        };

    auto IsSuspiciousHiddenModule = [&](const std::wstring& modulePathW) -> bool {
        std::string modulePath = WStringToUTF8(modulePathW);
        std::string lowerPath = ToLower(modulePath);

        // Только исполняемые файлы
        static const std::vector<std::string> executableExtensions = { ".dll", ".exe", ".node" };
        bool isExecutable = false;
        for (const auto& ext : executableExtensions) {
            if (lowerPath.length() >= ext.length() &&
                lowerPath.substr(lowerPath.length() - ext.length()) == ext) {
                isExecutable = true;
                break;
            }
        }
        if (!isExecutable) return false;

        // Подозрительные названия
        static const std::vector<std::string> cheatPatterns = {
            "dayzint", "cheat", "hack", "inject", "trigger", "aimbot",
            "wallhack", "esp", "memory", "trainer", "loader", "dayzavr"
        };

        std::string fileName = lowerPath;
        size_t lastSlash = fileName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            fileName = fileName.substr(lastSlash + 1);
        }

        for (const auto& pattern : cheatPatterns) {
            if (fileName.find(pattern) != std::string::npos) {
                return true;
            }
        }

        // Подозрительные пути
        static const std::vector<std::string> suspiciousPaths = {
            "\\desktop\\", "\\downloads\\", "\\documents\\",
            "\\cheats\\", "\\hacks\\", "\\trainers\\",
            "c:\\users\\", "d:\\users\\", "\\appdata\\local\\dayzavr\\"
        };

        for (const auto& path : suspiciousPaths) {
            if (lowerPath.find(path) != std::string::npos) {
                return true;
            }
        }
        return false;
        };

    // ==================== Toolhelp32 (Unicode) ====================
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentPid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(hSnapshot, &me)) {
            do {
                if (me.th32ProcessID == currentPid) {
                    if (me.hModule == g_SelfModuleHandle) continue;

                    std::wstring modulePathW = me.szExePath;
                    if (!IsSystemModule(modulePathW)) {
                        toolhelpModules.insert(modulePathW);
                    }
                }
            } while (Module32NextW(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }

    // ==================== EnumProcessModules + GetModuleFileNameExW ====================
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (hMods[i] == g_SelfModuleHandle) continue;

            wchar_t modPathW[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modPathW, MAX_PATH)) {
                std::wstring modulePathW = modPathW;
                if (!IsSystemModule(modulePathW)) {
                    enumModules.insert(modulePathW);
                }
            }
        }
    }

    // ==================== Сравнение и логирование ====================
    for (const auto& mod : enumModules) {
        if (toolhelpModules.find(mod) == toolhelpModules.end()) {
            if (IsSuspiciousHiddenModule(mod)) {
                std::string fileHash = CalculateFileSHA256Safe(mod);
                std::string logPath = WStringToUTF8(mod);
                Log("[WARNING HOOK] HIDDEN SUSPICIOUS MODULE: " + logPath + " SHA256: " + fileHash);
            }
        }
    }

    for (const auto& mod : toolhelpModules) {
        if (enumModules.find(mod) == enumModules.end()) {
            if (IsSuspiciousHiddenModule(mod)) {
                std::string fileHash = CalculateFileSHA256Safe(mod);
                std::string logPath = WStringToUTF8(mod);
                Log("[WARNING HOOK] HIDDEN SUSPICIOUS MODULE (Toolhelp only): " + logPath + " SHA256: " + fileHash);
            }
        }
    }
}
void DetectExternalCheatProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };

    auto IsCheatProcess = [&](const std::wstring& processNameW, const std::wstring& processPathW) -> bool {
        std::string processName = WStringToUTF8(processNameW);
        std::string processPath = WStringToUTF8(processPathW);

        std::string lowerName = ToLower(processName);
        std::string lowerPath = ToLower(processPath);

        // Пропускаем системные и легитимные пути
        if (lowerPath.find("\\windows\\") != std::string::npos ||
            lowerPath.find("\\program files") != std::string::npos ||
            lowerPath.find("\\steam\\") != std::string::npos) {
            return false;
        }

        static const std::vector<std::string> cheatPatterns = {
            "dayzint", "cheat", "hack", "inject", "trigger", "aimbot",
            "wallhack", "esp", "memory", "trainer", "loader", "dayzavr"
        };

        for (const auto& pattern : cheatPatterns) {
            if (lowerName.find(pattern) != std::string::npos ||
                lowerPath.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
        };

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring exeNameW = pe.szExeFile;

            if (_wcsicmp(exeNameW.c_str(), L"DayZ_x64.exe") == 0)
                continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                wchar_t processPathW[MAX_PATH] = { 0 };

                if (GetModuleFileNameExW(hProcess, NULL, processPathW, MAX_PATH)) {
                    if (IsCheatProcess(exeNameW, processPathW)) {
                        std::string fileHash = CalculateFileSHA256Safe(processPathW); 
                        std::string processPathUTF8 = WStringToUTF8(processPathW);

                        Log("[WARNING HOOK] EXTERNAL PROCESS: " + processPathUTF8 + " | SHA256: " + fileHash);
                        StartSightImgDetection("[WARNING HOOK] EXTERNAL PROCESS: " + processPathUTF8 + " | SHA256: " + fileHash);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}
#pragma endregion
#pragma region PcPlayer
std::string hwid = "---";
static std::string BuildMonitorsCompactString() {
    std::ostringstream out;
    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);

    bool addedAny = false;
    for (DWORD i = 0; EnumDisplayDevicesA(nullptr, i, &dd, 0); ++i) {
        DEVMODEA dm;
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);

        if (dd.DeviceName && dd.DeviceName[0]) {
            if (EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) {
                uint64_t pixels = uint64_t(dm.dmPelsWidth) * uint64_t(dm.dmPelsHeight);
                if (addedAny) out << "|";
                out << pixels << ":" << dm.dmPelsWidth << "x" << dm.dmPelsHeight << ":"
                    << (dm.dmDisplayFrequency ? dm.dmDisplayFrequency : 0);
                addedAny = true;
            }
        }
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
    }
    return addedAny ? out.str() : "";
}
std::string GetSMBIOS_UUID() {
    const DWORD BufferSize = 4096;
    std::vector<BYTE> buffer(BufferSize);
    DWORD retSize = GetSystemFirmwareTable('RSMB', 0, buffer.data(), BufferSize);
    if (retSize == 0 || retSize > BufferSize) return "";

    for (size_t i = 0; i + 24 <= retSize; ++i) {
        if (buffer[i] == 0x01 && buffer[i + 1] >= 0x12) {
            std::stringstream ss;
            for (int j = 8; j < 24; ++j) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i + j];
            }
            return ss.str();
        }
    }
    return "";
}
std::string GetSIDForUser(const std::wstring& userName) {
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    WCHAR domainName[256];
    DWORD domainSize = (DWORD)(sizeof(domainName) / sizeof(WCHAR));
    SID_NAME_USE sidType;

    BOOL success = LookupAccountNameW(nullptr, userName.c_str(), sidBuffer, &sidSize, domainName, &domainSize, &sidType);
    if (!success) return "";

    LPSTR stringSid = nullptr;
    if (ConvertSidToStringSidA(sidBuffer, &stringSid)) {
        std::string sidStr(stringSid);
        LocalFree(stringSid);
        return sidStr;
    }
    return "";
}
std::string GetPrimaryUserSID() {
    DWORD level = 0;
    DWORD prefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD entriesread = 0, totalentries = 0, resume_handle = 0;
    USER_INFO_0* pBuf = nullptr;

    NET_API_STATUS nStatus = NetUserEnum(nullptr, level, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf,
        prefmaxlen, &entriesread, &totalentries, &resume_handle);

    std::vector<std::string> userSIDs;
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entriesread; ++i) {
            std::wstring wUserName = pBuf[i].usri0_name;
            std::string sid = GetSIDForUser(wUserName);
            if (!sid.empty() && sid.find("-500") == std::string::npos) 
                userSIDs.push_back(sid);
        }
        if (pBuf) NetApiBufferFree(pBuf);
    }

    std::sort(userSIDs.begin(), userSIDs.end());
    for (const auto& sid : userSIDs) {
        if (sid.find("-1000") != std::string::npos) return sid;
    }
    return !userSIDs.empty() ? userSIDs.front() : "";
}
unsigned GetCpuMaxMHzNormalized() {
    int r[4] = { 0 };
    __cpuid(r, 0x16);
    unsigned baseMHz = (unsigned)r[0];
    unsigned maxMHz = (unsigned)r[1];
    unsigned freq = (maxMHz != 0 ? maxMHz : baseMHz);
    return (freq / 100) * 100;
}
uint64_t ReadRamMiBNormalized() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms))
        return (ms.ullTotalPhys / (1024ull * 1024ull)); // уже в MiB
    return 0;
}
uint64_t SumFixedDisksGiBNormalized() {
    char buf[4096];
    DWORD n = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (!n || n > sizeof(buf)) return 0;

    uint64_t sumBytes = 0;
    for (char* p = buf; *p; p += lstrlenA(p) + 1) {
        if (GetDriveTypeA(p) != DRIVE_FIXED) continue;
        ULARGE_INTEGER totalBytes{};
        if (GetDiskFreeSpaceExA(p, nullptr, &totalBytes, nullptr))
            sumBytes += totalBytes.QuadPart;
    }
    return (sumBytes / (1024ull * 1024 * 1024 * 10)) * 10; // округление до 10 ГБ
}
std::string GenerateStableHWID()
{
    try {
        std::string smbios = GetSMBIOS_UUID();
        std::string primarySID = GetPrimaryUserSID();
        unsigned cpu = GetCpuMaxMHzNormalized();
        uint64_t ram = ReadRamMiBNormalized();
        uint64_t dsk = SumFixedDisksGiBNormalized();

        std::ostringstream raw;
        if (!smbios.empty())      raw << "B:" << smbios << "|";
        if (!primarySID.empty())  raw << "S:" << primarySID << "|";
        if (cpu)                  raw << "CPUFREQ:" << cpu << "MHz|";
        if (ram)                  raw << "RAM:" << ram << "|";
        if (dsk)                  raw << "DSK:" << dsk << "|";

        std::string monitorsCompact = BuildMonitorsCompactString();
        if (!monitorsCompact.empty())
            raw << monitorsCompact << "|";

        std::string rawStr = raw.str();
        if (rawStr.empty())
            rawStr = "FallbackHWID";
        SHA256 sha;
        sha.update(reinterpret_cast<const uint8_t*>(rawStr.data()), rawStr.size());
        sha.finalize();

        uint8_t* hash = sha.getHash();

        std::ostringstream hexHash;
        hexHash << std::hex << std::setfill('0');
        for (int i = 0; i < 32; ++i) {
            hexHash << std::setw(2) << static_cast<unsigned int>(hash[i]);
        }

        std::string finalHWID = hexHash.str();
        hwid = finalHWID;
        Log("[LOGEN] HWID: " + finalHWID);
        return finalHWID;
    }
    catch (...) {
        Log("[LOGEN] HWID: HWID_ERROR");
        hwid = "HWID_ERROR";
        return hwid;
    }
}
void Check() {
    hwid = GenerateStableHWID();
}
void HWID() {
    __try {
        Check();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
#pragma endregion
#pragma region Vulkan
std::unique_ptr<VulkanDetector> g_vulkanDetector;
void InitializeVulkanDetection() {
    if (!g_vulkanDetector) {
        g_vulkanDetector = std::make_unique<VulkanDetector>();

        // Настройка конфигурации
        VulkanDetectorConfig config;
        config.enableHookDetection = true;
        config.enableModuleScan = true;
        config.enableSignatureCheck = true;
        config.enableScreenshotOnDetection = true;
        config.hookConfidenceThreshold = 80;

        // Специфичные для DayZ настройки
        config.whitelistedModules.push_back("dayz_x64.exe");
        config.whitelistedPaths.push_back("\\dayz\\");
        config.whitelistedPaths.push_back("\\steamapps\\common\\dayz");

        g_vulkanDetector->SetConfig(config);

        if (g_vulkanDetector->Initialize()) {
            g_vulkanDetector->Start();
            Log("[LOGEN] Vulkan detector started for DayZ");
        }
    }
}
std::atomic<bool> g_vulkanMonitorRunning{ false };
std::thread g_vulkanMonitorThread;
void CheckProcessForVulkan(HANDLE hProcess, const std::string& processName, DWORD pid) {
    HMODULE hMods[256];
    DWORD cbNeeded;

    // ===== RATE LIMITER =====
    static std::map<std::string, uint64_t> lastLogTime;
    static std::map<std::string, int> logCounter;
    static std::mutex rateMutex;
    const uint64_t COOLDOWN_MS = 60000; 
    const int MAX_SCREENSHOTS_PER_HOUR = 5; 

    auto ShouldLog = [&](const std::string& key, const std::string& hash, bool takeScreenshot = false) -> bool {
        std::lock_guard<std::mutex> lock(rateMutex);
        uint64_t now = GetTickCount64();

        std::string fullKey = key + "_" + hash;
        auto it = lastLogTime.find(fullKey);

        if (it == lastLogTime.end() || (now - it->second) > COOLDOWN_MS) {
            lastLogTime[fullKey] = now;
            logCounter[fullKey] = 1;
            static int screenshotCount = 0;
            static uint64_t screenshotHourStart = now;

            if (takeScreenshot) {
                if (now - screenshotHourStart > 3600000) {
                    screenshotCount = 0;
                    screenshotHourStart = now;
                }
                if (screenshotCount < MAX_SCREENSHOTS_PER_HOUR) {
                    screenshotCount++;
                    return true; 
                }
                return false; 
            }
            return true;
        }

        logCounter[fullKey]++;
        return false; 
        };

    auto IsWhitelistedProcess = [](const std::string& name) -> bool {
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        size_t lastSlash = lowerName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            lowerName = lowerName.substr(lastSlash + 1);
        }

        static const std::set<std::string> whitelist = {
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
            "svchost.exe", "dwm.exe", "conhost.exe", "ctfmon.exe",
            "taskhostw.exe", "runtimebroker.exe", "searchhost.exe",
            "sihost.exe", "fontdrvhost.exe", "smss.exe", "system",
            "system idle process", "winlogon.exe",
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
            "discord.exe", "discordptb.exe", "discordcanary.exe",
           Name_Game, "dayz.exe",
        Name_Dll
        };

        return whitelist.find(lowerName) != whitelist.end();
        };
    auto IsSystemPath = [](const std::wstring& path) -> bool {
        std::wstring lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"\\windows\\") == 0 ||
            lower.find(L"\\program files") == 0 ||
            lower.find(L"\\program files (x86)") == 0 ||
            lower.find(L"\\system32\\") != std::wstring::npos ||
            lower.find(L"\\syswow64\\") != std::wstring::npos) {
            return true;
        }
        if (lower.find(L"\\windowsapps\\") != std::wstring::npos) {
            return true;
        }

        return false;
        };
    if (IsWhitelistedProcess(processName)) {
        return;
    }

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return;
    }

    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        WCHAR modPathW[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, hMods[i], modPathW, MAX_PATH) == 0) {
            continue;
        }
        if (IsSystemPath(modPathW)) {
            continue;
        }
        char modPathUTF8[MAX_PATH * 2] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, modPathW, -1, modPathUTF8, sizeof(modPathUTF8), NULL, NULL);
        std::wstring modPathStr = modPathW;
        size_t lastSlash = modPathStr.find_last_of(L"\\/");
        std::wstring fileName = (lastSlash != std::wstring::npos) ?
            modPathStr.substr(lastSlash + 1) : modPathStr;

        std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);
        if (fileName == L"vulkan-1.dll") {
            std::wstring lowerPath = modPathStr;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

            if (lowerPath.find(L"discord") != std::wstring::npos) {
                continue;
            }
            std::string hash = CalculateFileSHA256Safe(modPathUTF8);
            std::string key = "vulkan_non_system_" + std::string(modPathUTF8);

            if (ShouldLog(key, hash, true)) { 
                Log("[VEH] Vulkan detected in process: " + processName +" (PID: " + std::to_string(pid) + ")" + " | Path: " + std::string(modPathUTF8) + " | SHA256: " + hash);
                StartSightImgDetection("[VEH] Vulkan process: " + processName);
            }
            continue;
        }

        // ===== Подозрительные ключевые слова =====
        bool hasSuspiciousKeyword =
            fileName.find(L"hook") != std::wstring::npos ||
            fileName.find(L"inject") != std::wstring::npos ||
            fileName.find(L"cheat") != std::wstring::npos ||
            fileName.find(L"hack") != std::wstring::npos;

        if (hasSuspiciousKeyword) {
            // Игнорируем, если это Discord hook (легитимный)
            if (fileName.find(L"discord") != std::wstring::npos) {
                continue;
            }

            std::string hash = CalculateFileSHA256Safe(modPathUTF8);
            std::string key = "suspicious_" + std::string(modPathUTF8);

            // Для подозрительных модулей логируем, но скриншоты делаем реже
            bool takeScreenshot = (fileName.find(L"hook.dll") != std::wstring::npos); // только hook.dll
            if (ShouldLog(key, hash, takeScreenshot)) {
                Log("[VEH] Suspicious module in " + processName + ": " + modPathUTF8 + " | SHA256: " + hash);
            }
            continue;
        }
    }
}
void VulkanProcessMonitor() {
    Log("[LOGEN] Vulkan process monitor started");

    std::set<DWORD> knownPids;

    while (g_vulkanMonitorRunning) {
        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe; // Используем W версию
                pe.dwSize = sizeof(pe);

                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ProcessID == GetCurrentProcessId()) continue;

                        std::wstring moduleNameW = pe.szExeFile;
                        std::string processName = WStringToUTF8(moduleNameW);

                        if (knownPids.find(pe.th32ProcessID) == knownPids.end()) {
                            knownPids.insert(pe.th32ProcessID);

                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);

                            if (hProcess) {
                                CheckProcessForVulkan(hProcess, processName, pe.th32ProcessID);
                                CloseHandle(hProcess);
                            }
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }

            static uint64_t lastCleanup = GetTickCount64();
            uint64_t now = GetTickCount64();
            if (now - lastCleanup > 60000) {
                knownPids.clear();
                lastCleanup = now;
            }

            Sleep(15000);
        }
        catch (...) {
            Sleep(10000);
        }
    }
}
void StartVulkanMonitor() {
    if (g_vulkanMonitorRunning.exchange(true)) return;

    try {
        g_vulkanMonitorThread = std::thread(VulkanProcessMonitor);
        Log("[LOGEN] Vulkan process monitor thread created");
    }
    catch (const std::exception& e) {
        Log("[LOGEN] Failed to start Vulkan monitor: " + std::string(e.what()));
        g_vulkanMonitorRunning = false;
    }
}
void StopVulkanMonitor() {
    if (!g_vulkanMonitorRunning.exchange(false)) return;

    if (g_vulkanMonitorThread.joinable()) {
        g_vulkanMonitorThread.join();
    }
}
#pragma endregion
#pragma region Cleanup
SIZE_T GetCurrentMemoryUsageMB() {
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}
void ForceFullSystemReset() {
    //LogFormat("[LOGEN] ForceFullSystemReset START - Current memory: %zu MB", GetCurrentMemoryUsageMB());
    BD_ResetSuspicionMetrics();
    BD_ClearLogData();
    if (g_keyMonitor) {
        g_keyMonitor->ClearAllData();
        g_keyMonitor->ResetStats();
    }
    if (g_vulkanDetector) {
        g_vulkanDetector->ClearDetectedHooks();
        g_vulkanDetector->CleanupOldData();
    }
    g_logRateLimitMap.clear();

    if (messageCache.size() > 0) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        messageCache.clear();
    }
    //EPS::CleanupMemory(false);
    BD_ApplySmartReset();
    SaveScreenshotToDiskCount = 0;
    SaveScreenshotToDiskCount2 = 0;
    SaveScreenshotToDiskCount3 = 0;
    SIZE_T afterMemoryMB = GetCurrentMemoryUsageMB();
    LogFormat("[LOGEN] ForceFullSystemReset END - Memory: %zu MB (freed %zu MB)", afterMemoryMB, (afterMemoryMB < GetCurrentMemoryUsageMB() ? GetCurrentMemoryUsageMB() - afterMemoryMB : 0));
}
void CheckMemoryAndCleanup() {
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        SIZE_T memoryMB = pmc.WorkingSetSize / (1024 * 1024);

        static SIZE_T lastMemoryMB = 0;
        static int cleanupCount = 0;
        if (memoryMB > 22000) {
            LogFormat("[LOGEN] CRITICAL: Memory at %zu MB - FORCING CLEANUP", memoryMB);
            ForceFullSystemReset();
            cleanupCount++;
            if (cleanupCount > 3 && memoryMB > 23000) {
                LogFormat("[LOGEN] EXTREME: Memory still at %zu MB after %d cleanups", memoryMB, cleanupCount);

                // Экстренные меры
                BD_ResetSuspicionMetrics();
                if (g_keyMonitor) {
                    g_keyMonitor->ClearAllData();
                }
                messageCache.clear();
                cleanupCount = 0;
            }
        }
        else {
            cleanupCount = 0;
        }
        if (memoryMB > lastMemoryMB + 1000) {
            LogFormat("[LOGEN] Memory milestone: %zu MB", memoryMB);
            lastMemoryMB = memoryMB;
        }
    }
}
void CheckMemoryAndCleanupStart() {
    __try {
        CheckMemoryAndCleanup();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
#pragma endregion
void InstallGlobalHooksStart() {
    __try {
        InstallGlobalHooks();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void InfoOutStatusStart(const std::string& hwid, const std::string& Goldberg_UID_SC) {
    __try {
        InfoOutStatus(hwid, Goldberg_UID_SC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void InfoOutStart(const std::string& hwid, const std::string& Goldberg_UID_SC) {
    __try {
        InfoOut(hwid, Goldberg_UID_SC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void HookIATStart() {
    __try {
        HookIAT();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void ListLoadedModulesAndReadMemoryLimitedStart() {
    __try {
        ListLoadedModulesAndReadMemoryLimited();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void DetectHiddenModulesStart() {
    __try {
        DetectHiddenModules();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void EnhancedModuleCheckStart() {
    __try {
        EnhancedModuleCheck();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void DetectExternalCheatProcessesStart() {
    __try {
        DetectExternalCheatProcesses();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

void TrimProcessWorkingSet() {
    HANDLE hProcess = GetCurrentProcess();
    ULONG oldPriority = 0;
    SIZE_T oldMin = 0, oldMax = 0;

    if (GetProcessWorkingSetSize(hProcess, &oldMin, &oldMax)) {
        SetProcessWorkingSetSize(hProcess, (SIZE_T)-1, (SIZE_T)-1);
        Sleep(50);
        SetProcessWorkingSetSize(hProcess, oldMin, oldMax);
    }
    SetPriorityClass(hProcess, PROCESS_MODE_BACKGROUND_BEGIN);
    Sleep(10);
    SetPriorityClass(hProcess, PROCESS_MODE_BACKGROUND_END);

    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        SIZE_T memMB = pmc.WorkingSetSize / (1024 * 1024);
        LogFormat("[LOGEN] TrimProcessWorkingSet: Working Set reduced to %zu MB", memMB);
    }
}
DWORD WINAPI InitializeSystemsCycle(LPVOID) {
    try {
        int errorCount = 0;
        static uint64_t lastResetTime = GetTickCount64();
        static uint64_t lastForceReset = 0;      // Отдельный таймер для ForceFullSystemReset
        static uint64_t lastWorkingSetTrim = 0;  // Отдельный таймер для TrimProcessWorkingSet
        static uint64_t lastCommitCheck = 0;
        int cycleCount = 0;

        Log("[LOGEN] Waiting 60 seconds for game to stabilize...");
        Sleep(60000);

        while (true) {
            try {
                cycleCount++;
                uint64_t now = GetTickCount64();

                // ===== МОНИТОРИНГ COMMIT SIZE (каждые 5 минут) =====
                if (now - lastCommitCheck > 300000) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    pmc.cb = sizeof(pmc);
                    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
                        SIZE_T commitMB = pmc.PagefileUsage / (1024 * 1024);
                        SIZE_T workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
                        LogFormat("[LOGEN] Memory: WorkingSet=%zu MB, Commit=%zu MB", workingSetMB, commitMB);
                        if (commitMB > 20000) {
                            LogFormat("[LOGEN] WARNING: Commit size %zu MB is critical!", commitMB);
                        }
                    }
                    lastCommitCheck = now;
                }

                // ===== ЛЁГКИЕ ПРОВЕРКИ (каждый цикл) =====
                ListLoadedModulesAndReadMemoryLimitedStart();
                LogFormat("[LOGEN] ListLoadedModulesAndReadMemoryLimitedStart... END (cycle %d)", cycleCount);
                Sleep(5000);

                if (cycleCount % 3 == 0) {
                    DetectHiddenModulesStart();
                    LogFormat("[LOGEN] DetectHiddenModulesStart... END (cycle %d)", cycleCount);
                    Sleep(5000);
                }
                if (cycleCount % 4 == 0) {
                    EnhancedModuleCheckStart();
                    LogFormat("[LOGEN] EnhancedModuleCheckStart... END (cycle %d)", cycleCount);
                    Sleep(5000);
                }
                if (cycleCount % 8 == 0) {
                    DetectExternalCheatProcessesStart();
                    LogFormat("[LOGEN] DetectExternalCheatProcessesStart... END (cycle %d)", cycleCount);
                    Sleep(5000);
                }

                // ===== ПОЛНЫЙ СБРОС СИСТЕМЫ (каждые 10 минут) =====
                if (now - lastForceReset > 600000) {
                    ForceFullSystemReset();
                    lastForceReset = now;
                    LogFormat("[LOGEN] ForceFullSystemReset... END (cycle %d)", cycleCount);
                    Sleep(5000);
                }

                // ===== ОЧИСТКА WORKING SET (каждые 5 минут) =====
                if (now - lastWorkingSetTrim > 300000) {
                   // TrimProcessWorkingSet();  // РАСКОММЕНТИРОВАТЬ!
                    lastWorkingSetTrim = now;
                    LogFormat("[LOGEN] TrimProcessWorkingSet... END (cycle %d)", cycleCount);
                    Sleep(5000);
                }

                if (cycleCount >= 100) {
                    cycleCount = 0;
                }

                Sleep(10000);
                errorCount = 0;
            }
            catch (...) {
                errorCount++;
                LogFormat("[LOGEN] InitializeSystemsCycle exception #%d", errorCount);
                if (errorCount == 1) Sleep(10000);
                else if (errorCount == 2) Sleep(30000);
                else Sleep(60000);
            }
        }
    }
    catch (...) {}
    return 0;
}
#pragma region Monitor_Only
bool ValidateWorldPtr(uintptr_t worldPtr) {
    if (!worldPtr || worldPtr < 0x10000 || worldPtr == 0xFFFFFFFFFFFFFFFF || !IsValidAddress(worldPtr)) {
        return false;
    }

    uintptr_t entityArray = 0;
    SIZE_T bytesRead = 0;

    // Проверяем NearEntList (OFFSET_WORLD_ENTITYARRAY)
    if (!IsValidAddress(worldPtr + OFFSET_WORLD_ENTITYARRAY)) return false;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(worldPtr + OFFSET_WORLD_ENTITYARRAY), &entityArray, sizeof(entityArray), &bytesRead) ||
        bytesRead != sizeof(entityArray)) {
        return false;
    }

    if (!IsValidAddress(entityArray)) return false;

    LogFormat("[LOGEN] ValidateWorldPtr Validated: 0x%p (NearEntList: 0x%p)",
        (void*)worldPtr, (void*)entityArray);

    return true;
}
uintptr_t FindWorldByStaticOffsetWorker128() {
    static uintptr_t g_FirstValidWorldPtr = 0;

    if (g_FirstValidWorldPtr != 0)
        return g_FirstValidWorldPtr;

    uintptr_t base = (uintptr_t)GetModuleHandleA("DayZ_x64.exe");
    if (!base) return 0;

    uintptr_t offsets[] = { OFFSET_WORLD_STATIC }; //0xF4B0A0, 0xF4A0D0 //0xF4B0A0
    for (uintptr_t offset : offsets) {
        uintptr_t address = base + offset;
        if (IsValidAddress(address)) {
            uintptr_t candidate = *(uintptr_t*)address;
            if (IsValidAddress(candidate)) {
                g_FirstValidWorldPtr = candidate;
                return g_FirstValidWorldPtr;
            }
        }
    }
    return 0;
}
DWORD WINAPI InitializeSystemsThread(LPVOID lpParam) {
    if (!lpParam) {
        Log("[LOGEN] CRITICAL: lpParam is NULL!");
        return 0;
    }
    auto* args = static_cast<std::pair<uintptr_t, uintptr_t>*>(lpParam);
    uintptr_t world = args->first;
    uintptr_t entityArray = args->second;
    delete args;
    bool epsRunning = false;
    try {
        epsRunning = EPS::IsRunning();
        LogFormat("[LOGEN] EPS::IsRunning = %d", epsRunning);
    }
    catch (...) {
        Log("[LOGEN] EPS::IsRunning EXCEPTION!");
        return 0;
    }
    bool ok = false;
    try {
        Log("[LOGEN] Calling InitializeSystemsWithStability...");
        ok = InitializeSystemsWithStability(world, entityArray);
        LogFormat("[LOGEN] InitializeSystemsWithStability returned: %d", ok);
    }
    catch (const std::exception& e) {
        LogFormat("[LOGEN] EXCEPTION: %s", e.what());
    }
    catch (...) {
        Log("[LOGEN] UNKNOWN EXCEPTION");
    }
    Log("[LOGEN] Thread finished");
    return 0;
}
void InitializeProtection() {
    static std::atomic<bool> g_ProtectionInitialized{ false };
    if (g_ProtectionInitialized) {
        Log("[LOGEN] InitializeProtection already running, skipping...");
        return;
    }
    g_ProtectionInitialized = true;
    try {
        Log("[LOGEN] InitializeProtection ...");
        uintptr_t world = 0;
        for (int i = 0; i < 10; ++i) {
            world = FindWorldByStaticOffsetWorker128();
            if (IsValidAddress(world)) break;
            Log("[LOGEN] World not found, retrying...");
            Sleep(500);
        }
        if (!IsValidAddress(world)) {
            Log("[LOGEN] World not found after retries, skipping protection.");
            return;
        }
        LogFormat("[LOGEN] World found @ 0x%p", (void*)world);
        if (!ValidateWorldPtr(world)) {
            Log("[LOGEN] Invalid World ptr aborting protection.");
            return;
        }
        uintptr_t entityArray = 0;
        if (!SafeReadPtr(world + OFFSET_WORLD_ENTITYARRAY, entityArray) || !IsValidAddress(entityArray)) {
            Log("[LOGEN] Invalid EntityArray (NearEntList), aborting protection.");
            return;
        }
        LogFormat("[LOGEN] EntityArray read OK @ 0x%p", (void*)entityArray);
        Sleep(10000);
        auto* systemsArgs = new std::pair<uintptr_t, uintptr_t>(world, entityArray);
        HANDLE systemsThread = CreateThread(nullptr, 0, InitializeSystemsThread, systemsArgs, 0, nullptr);
        if (!systemsThread) {
            Log("[LOGEN] Failed to create InitializeSystems thread");
        }
        else {
            Log("[LOGEN] InitializeSystems thread created");
        }
        Log("[LOGEN] InitializeProtection succesful");
    }
    catch (...) {
        Log("[LOGEN] InitializeProtection crashed");
    }
}
#pragma endregion
void InitializeMonitoring() {
    try {
        SelectAvailableRegion();
        isLicenseVersion = DetermineAndSetGameProcessNames();
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
        HWID();
        InstallGlobalHooksStart();
        HookIATStart();
        InfoOutStart(hwid, Goldberg_UID_SC);
        if (!GameProjectMinimal) {
            try {
                std::string injectedProcess = GetInjectedProcessName();
                std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
                if (injectedProcess == Name_Game2) {
                    std::thread([]() {
                        for (int i = 0; i < 60; i++) {
                            Sleep(1000);
                            if (i % 60 == 0) {
                                int remaining = 60 - i;
                                LogFormat("[LOGEN] StartKeyToggleMonitoring starts in %d:%02d", remaining / 60, remaining % 60);
                            }
                        }
                        Log("[LOGEN] Starting KeyToggleMonitoring...");
                        StartKeyToggleMonitoring();
                        Sleep(2000);
                        while (true) {
                            Sleep(120000);
                            if (IsKeyMonitoringActive()) {
                                Log("[LOGEN] KeyMonitor stats: " + GetKeyMonitorStats());
                            }
                        }
                        }).detach();
                }
            }
            catch (const std::exception& e) {
                Log("[LOGEN] KeyToggleMonitoring: " + std::string(e.what()));
            }
        }
        try {
            std::string injectedProcess = GetInjectedProcessName();
            std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
            if (injectedProcess == Name_Game2) {
                Log("[LOGEN] SVG START :" + Name_Game2);
                if (!GameProjectMinimal) {
                    for (int i = 0; i < 240; i++) {
                        Sleep(1000);
                        if (i % 60 == 0) {
                            int remaining = 240 - i;
                            LogFormat("[LOGEN] Protection starts in %d:%02d", remaining / 60, remaining % 60);
                        }
                    }
                    InitializeProtection();
                    Sleep(1000);
                    if (g_screenshotCapturer.IsOverlayUnderAttack()) {
                        Log("[LOGEN] Overlay debug mode activated due to attack");
                    }
                    Sleep(1000);
                    InitializeVulkanDetection();
                    Sleep(5000);
                    StartVulkanMonitor();
                }
                if (GameProjectMinimal) {
                    for (int i = 0; i < 120; i++) {
                        Sleep(1000);
                        if (i % 60 == 0) {
                            int remaining = 120 - i;
                            LogFormat("[LOGEN] Protection starts in %d:%02d", remaining / 60, remaining % 60);
                        }
                    }
                }

                HANDLE systemsThreadCycle = CreateThread(nullptr, 0, InitializeSystemsCycle, nullptr, 0, nullptr);
                if (!systemsThreadCycle) {
                    Log("[LOGEN] Failed to create systemsThreadCycle thread");
                }
                else {
                    Log("[LOGEN] systemsThreadCycle thread created");
                    CloseHandle(systemsThreadCycle);
                }

                std::thread([]() {
                    while (true) {
                        try {
                            Sleep(10000);
                            InfoOutStatusStart(hwid, Goldberg_UID_SC);
                            Sleep(10000);
                            CheckMemoryAndCleanupStart();
                        }
                        catch (const std::exception& e) {
                            Log("[LOGEN] InfoOutStatus update failed: " + std::string(e.what()));
                        };
                    }
                    }).detach();

                g_runPeriodicServerThread = true;
                g_periodicServerThread = std::thread(PeriodicServerScreenshotThread);
                Log("[LOGEN] PeriodicServerScreenshotThread Started");
            }
        }
        catch (const std::exception& e) {
            Log("[LOGEN] injectedProcess: " + std::string(e.what()));
        }
    }
    catch (...) {}
}
DWORD WINAPI SafeInitialize(LPVOID) {
    __try {
       InitializeMonitoring();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
    if (ulReason == DLL_PROCESS_ATTACH) {
        g_SelfModuleHandle = hModule;
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread = CreateThread(nullptr, 0, SafeInitialize, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    else if (ulReason == DLL_PROCESS_DETACH) {
        g_runPeriodicServerThread = false;
        if (g_periodicServerThread.joinable()) {
            g_periodicServerThread.join();
        }
        RemoveGlobalHooks();
        UnhookIAT();
        UnhookAdditionalAPI();
    }
    return TRUE;
}
