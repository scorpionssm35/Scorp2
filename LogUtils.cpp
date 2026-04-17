#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <winternl.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <intrin.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <regex>
#include <chrono>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#include "LogUtils.h"
#include "dllmain.h"

// ========== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ==========
std::string Name_Dll = "system.windows.group.dll";
std::string hostsc = "region1.registration.dayzavr.ru";//"78.136.220.94"//dayzzona
std::string Name_Launcher = "dayzavr dayz.exe";
std::string Name_Launcher2 = "dayzzona launcher.exe";
std::string Name_Window = "DayZ";
int hostport = 18000;
int Port_Panel_Registered = 17000;
std::string Name_Game = "dayz_x64.exe";
std::string Name_Game2 = "dayz_x64";
std::string Name_GameEXE = "DayZ_x64.exe";
std::string Name_GameEXE2 = "DayZ_x64";

std::string Goldberg_UID_SC = "---";

// ========== КЭШ СООБЩЕНИЙ ==========
std::unordered_map<size_t, CachedMessage> messageCache;
std::mutex cacheMutex;
static const size_t MAX_CACHE_SIZE = 5000;
static const auto CACHE_DURATION = std::chrono::minutes(5);
static std::chrono::steady_clock::time_point lastCleanup = std::chrono::steady_clock::now();

// ========== REGION SELECTION ==========
bool TestConnection(const std::string& host, int port, int timeoutMs) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent* hostEntry = gethostbyname(host.c_str());
    if (hostEntry == nullptr) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    addr.sin_addr.s_addr = *((unsigned long*)hostEntry->h_addr);
    connect(sock, (sockaddr*)&addr, sizeof(addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    bool connected = false;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        connected = (so_error == 0);
    }

    closesocket(sock);
    WSACleanup();
    return connected;
}
void SelectAvailableRegion() {
    const char* regions[] = {
        "region1.registration.dayzavr.ru",
        "region2.registration.dayzavr.ru",
        "region3.registration.dayzavr.ru"
        //"78.136.220.94"//dayzzona
    };

    for (int i = 0; i < 3; i++) {
       // LogFormat("[LOGEN] Testing %s...", regions[i]);
        if (TestConnection(regions[i], Port_Panel_Registered, 2000)) {
            hostsc = regions[i];
            std::string injectedProcess = GetInjectedProcessName();
            std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
            if (injectedProcess == Name_Game2) {
                LogFormat("[LOGEN] SELECTED: %s", hostsc.c_str());
            }
            return;
        }
    }
  //  Log("[LOGEN] No region available, using default region1");
    hostsc = "region1.registration.dayzavr.ru";
}

// ========== BASE64 & XOR ==========
std::string Base64Encode(const std::string& in) {
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
std::string XorEncrypt(const std::string& input, const std::string& key) {
    std::string result = input;
    for (size_t i = 0; i < input.size(); ++i)
        result[i] ^= key[i % key.size()];
    return result;
}

// ========== DLL IDENTIFIER ==========
static std::string GetCurrentName() {
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)&GetCurrentName, &hModule);

    if (!hModule) return "Unknown.dll";

    WCHAR dllPathW[MAX_PATH];
    DWORD result = GetModuleFileNameW(hModule, dllPathW, MAX_PATH);
    if (result == 0 || result == MAX_PATH) return "Unknown.dll";

    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, dllPathW, -1, NULL, 0, NULL, NULL);
    if (bufferSize <= 0) return "Unknown.dll";

    std::string path(bufferSize - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, dllPathW, -1, &path[0], bufferSize, NULL, NULL);

    size_t pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}
static std::string GetDLLSHA256() {
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)&GetCurrentName, &hModule);
    if (!hModule) return "";

    WCHAR dllPathW[MAX_PATH];
    GetModuleFileNameW(hModule, dllPathW, MAX_PATH);

    HANDLE hFile = CreateFileW(dllPathW, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR tempPath[MAX_PATH], tempFile[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath)) {
            const WCHAR* fileName = wcsrchr(dllPathW, L'\\');
            if (!fileName) fileName = wcsrchr(dllPathW, L'/');
            if (!fileName) fileName = dllPathW;
            else fileName++;
            if (GetTempFileNameW(tempPath, L"DLL", 0, tempFile)) {
                if (CopyFileW(dllPathW, tempFile, FALSE)) {
                    hFile = CreateFileW(tempFile, GENERIC_READ,
                        FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_FLAG_DELETE_ON_CLOSE, NULL);
                }
            }
        }
        if (hFile == INVALID_HANDLE_VALUE) return "";
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return "";
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return "";
    }
    CloseHandle(hFile);

    SHA256 sha;
    sha.update(buffer.data(), bytesRead);
    sha.finalize();

    uint8_t* hash = sha.getHash();
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << (int)hash[i];
    }
    return ss.str();
}
std::string GetSecureIdentifier() {
    std::string dllName = GetCurrentName();
    std::string sha256Hash = GetDLLSHA256();

    if (sha256Hash.empty()) {
        std::string encrypted = XorEncrypt(dllName + "|", Name_Dll);
        return Base64Encode(encrypted);
    }
    std::string identifier = dllName + "|" + sha256Hash;
    std::string encrypted = XorEncrypt(identifier, Name_Dll);
    return Base64Encode(encrypted);
}

// ========== STEAM ID ==========
uint64_t Steam2ToSteam64(const std::string& steam2) {
    try {
        if (steam2.empty()) return 0;
        size_t pos1 = steam2.find('_');
        size_t pos2 = steam2.find(':');
        size_t pos3 = steam2.find(':', pos2 + 1);
        if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos)
            return 0;

        int universe = std::stoi(steam2.substr(pos1 + 1, pos2 - pos1 - 1));
        int accountType = std::stoi(steam2.substr(pos2 + 1, pos3 - pos2 - 1));
        int accountNumber = std::stoi(steam2.substr(pos3 + 1));
        return (uint64_t)accountNumber * 2 + (uint64_t)accountType + 76561197960265728ULL;
    }
    catch (...) { return 0; }
}
uint64_t Steam32ToSteam64(uint32_t steam32) {
    return steam32 + 76561197960265728ULL;
}
void ReadGoldbergUID(const std::string& relativePath) {
    try {
        char appDataPath[MAX_PATH] = {};
        if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) != S_OK) return;

        std::string fullPath = std::string(appDataPath) + "\\" + relativePath;
        std::ifstream file(fullPath);
        if (!file.is_open()) return;

        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                Goldberg_UID_SC = line;
                break;
            }
        }
    }
    catch (...) {}
}
void ReadGoldbergUIDSteam() {
    try {
        HKEY hKey;
        char steamPath[MAX_PATH] = {};
        DWORD bufferSize = sizeof(steamPath);
        bool foundPath = false;

        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufferSize = sizeof(steamPath);
            if (RegQueryValueExA(hKey, "SteamPath", NULL, NULL, (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS)
                foundPath = true;
            RegCloseKey(hKey);
        }

        if (!foundPath && RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufferSize = sizeof(steamPath);
            if (RegQueryValueExA(hKey, "InstallPath", NULL, NULL, (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS)
                foundPath = true;
            RegCloseKey(hKey);
        }

        if (!foundPath && RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufferSize = sizeof(steamPath);
            if (RegQueryValueExA(hKey, "InstallPath", NULL, NULL, (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS)
                foundPath = true;
            RegCloseKey(hKey);
        }

        if (!foundPath) {
            Goldberg_UID_SC = "---";
            return;
        }

        std::string possiblePaths[] = {
            std::string(steamPath) + "\\config\\loginusers.vdf",
            std::string(steamPath) + "\\config\\config.vdf",
            std::string(steamPath) + "\\logs\\connection_log.txt"
        };

        bool foundSteamID = false;
        std::string foundInFile = "";

        for (int i = 0; i < 3; i++) {
            std::string filePath = possiblePaths[i];
            std::string fileName = (i == 0 ? "loginusers.vdf" : (i == 1 ? "config.vdf" : "connection_log.txt"));

            DWORD fileAttrib = GetFileAttributesA(filePath.c_str());
            if (fileAttrib == INVALID_FILE_ATTRIBUTES || (fileAttrib & FILE_ATTRIBUTE_DIRECTORY))
                continue;

            std::ifstream file(filePath);
            if (!file.is_open()) continue;

            std::string fileContent;
            std::string line;
            while (std::getline(file, line)) fileContent += line + "\n";
            file.close();

            if (fileName == "loginusers.vdf") {
                std::regex steamIdPattern("\"SteamID\"\\s+\"(\\d{17})\"");
                std::smatch match;
                if (std::regex_search(fileContent, match, steamIdPattern) && match.size() > 1) {
                    std::string steamId = match[1].str();
                    if (steamId.length() == 17 && steamId.substr(0, 7) == "7656119") {
                        Goldberg_UID_SC = steamId;
                        foundSteamID = true;
                        foundInFile = fileName;
                        break;
                    }
                }
            }
            else if (fileName == "config.vdf") {
                std::regex patterns[] = {
                    std::regex("\"SteamID\"\\s*\"(\\d{17})\""),
                    std::regex("\"AccountID\"\\s*\"(\\d+)\"")
                };
                for (const auto& pattern : patterns) {
                    std::smatch match;
                    if (std::regex_search(fileContent, match, pattern) && match.size() > 1) {
                        std::string steamId = match[1].str();
                        if (steamId.length() <= 10 && std::all_of(steamId.begin(), steamId.end(), ::isdigit)) {
                            try {
                                uint32_t accountId = std::stoul(steamId);
                                uint64_t steam64 = Steam32ToSteam64(accountId);
                                if (steam64 > 76561197960265728ULL) {
                                    Goldberg_UID_SC = std::to_string(steam64);
                                    foundSteamID = true;
                                    foundInFile = fileName;
                                    break;
                                }
                            }
                            catch (...) {}
                        }
                        else if (steamId.length() == 17 && steamId.substr(0, 7) == "7656119") {
                            Goldberg_UID_SC = steamId;
                            foundSteamID = true;
                            foundInFile = fileName;
                            break;
                        }
                    }
                    if (foundSteamID) break;
                }
            }
            else if (fileName == "connection_log.txt") {
                std::vector<std::string> lines;
                std::istringstream iss(fileContent);
                std::string singleLine;
                while (std::getline(iss, singleLine)) lines.push_back(singleLine);

                for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
                    std::string lineContent = *it;
                    bool hasLoginIndicator = lineContent.find("LogOnResponse") != std::string::npos ||
                        lineContent.find("logged on OK") != std::string::npos ||
                        lineContent.find("7656119") != std::string::npos;

                    if (hasLoginIndicator) {
                        std::regex steam64Pattern("\\b(7656119\\d{10})\\b");
                        std::smatch match;
                        if (std::regex_search(lineContent, match, steam64Pattern) && match.size() > 1) {
                            std::string steamId = match[1].str();
                            if (steamId.length() == 17) {
                                Goldberg_UID_SC = steamId;
                                foundSteamID = true;
                                foundInFile = fileName;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (!foundSteamID) Goldberg_UID_SC = "---";
        else LogFormat("[LOGEN] Steam ID found in %s: %s", foundInFile.c_str(), Goldberg_UID_SC.c_str());
    }
    catch (...) { Goldberg_UID_SC = "---"; }
}
void ReadGoldbergUIDStart(const std::string& relativePath) {
    __try { ReadGoldbergUID(relativePath); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void ReadSteamUIDStart() {
    __try { ReadGoldbergUIDSteam(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ========== LOGGING ==========
void LogTest(const std::string& message) {
    try {
        if (message.empty()) return;
        if (message.find("[LOGEN] TCP") != std::string::npos) return;

        wchar_t appDataPath[MAX_PATH] = {};
        if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath) != S_OK) {
            std::ofstream fallback("C:\\dlc_test.tmp", std::ios::app);
            if (fallback.is_open()) fallback << message << "\n";
            return;
        }

        std::wstring tempDir = std::wstring(appDataPath) + L"\\Temp\\";
        CreateDirectoryW(tempDir.c_str(), NULL);
        std::wstring finalPath = tempDir + L"dlc_test.tmp";
        std::string narrowPath(finalPath.begin(), finalPath.end());
        std::ofstream logFile(narrowPath, std::ios::app);
        if (logFile.is_open()) logFile << message << "\n";
    }
    catch (...) {}
}
size_t HashMessage(const std::string& msg) {
    return std::hash<std::string>{}(msg);
}
void CleanupOldMessages() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - CACHE_DURATION;
    for (auto it = messageCache.begin(); it != messageCache.end(); ) {
        if (it->second.time < cutoff) it = messageCache.erase(it);
        else ++it;
    }
}
bool IsMessageCached(const std::string& message) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    return messageCache.find(HashMessage(message)) != messageCache.end();
}
void CacheMessage(const std::string& message) {
    size_t hash = HashMessage(message);
    std::lock_guard<std::mutex> lock(cacheMutex);
    messageCache[hash] = { std::chrono::steady_clock::now() };
    if (messageCache.size() > MAX_CACHE_SIZE) {
        CleanupOldMessages();
        if (messageCache.size() > MAX_CACHE_SIZE) messageCache.clear();
    }
}
void LogTXT(const std::string& message) {
    try {
        if (message.empty()) return;
        if (message.find("[LOGEN] TCP") != std::string::npos) return;
        /*
        std::string uidPrefix = VerSVG + "[Goldberg-" + Goldberg_UID_SC + "] ";
        std::string fullMessage = uidPrefix + processedMessage;
        LogTest(fullMessage);
        */
        InfoOutMessage(hwid, Goldberg_UID_SC, message);
    }
    catch (...) {}
}
void LogAdd(const std::string& message) {
    __try {
        LogTXT(message);
        CacheMessage(message);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void Log(const std::string& message) {
    if (message.empty()) return;
    if (IsMessageCached(message)) return;
    LogAdd(message);

    auto now = std::chrono::steady_clock::now();
    if (now - lastCleanup > std::chrono::minutes(1)) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        CleanupOldMessages();
        lastCleanup = now;
    }
}
void LogFormat(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    Log(buffer);
}

// ========== MEMORY VALIDATION ==========
bool IsValidAddress(uintptr_t addr) {
    if (addr == 0 || addr < 0x10000 || addr > 0x7FFFFFFFFFFF) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) return false;
    return mbi.State == MEM_COMMIT;
}
bool SafeReadPtr(uintptr_t addr, uintptr_t& out) {
    if (addr == 0 || addr == 0xFFFFFFFFFFFFFFFF || addr < 0x10000 || !IsValidAddress(addr))
        return false;

    if (addr > 0x00007FFFFFFFFFFF) {
        LogFormat("[LOGEN] Skipped invalid high address: 0x%p", (void*)addr);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) return false;

    bool restoreProt = false;
    DWORD oldProt = 0;
    if (mbi.Protect & PAGE_NOACCESS) {
        if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt))
            restoreProt = true;
        else return false;
    }

    bool success = false;
    __try {
        out = *(volatile uintptr_t*)addr;
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { success = false; }

    if (restoreProt) VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
    return success;
}
bool IsGameRIP(uintptr_t rip) {
    static uintptr_t gameBase = 0, gameEnd = 0;
    if (gameBase == 0) {
        HMODULE gameModule = GetModuleHandleA(Name_GameEXE.c_str());
        if (gameModule) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), gameModule, &modInfo, sizeof(modInfo))) {
                gameBase = (uintptr_t)modInfo.lpBaseOfDll;
                gameEnd = gameBase + modInfo.SizeOfImage;
            }
        }
    }
    return (rip >= gameBase && rip < gameEnd);
}