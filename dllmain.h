#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <atomic>
extern bool GameProjectMinimal;
extern std::string hwid;
extern std::atomic<int> g_currentScreenshotter;
extern void StartSightImgDetection(const std::string& infouser);
void InfoOutMessage(const std::string& hwid, const std::string& id, const std::string& message);
extern bool DetermineAndSetGameProcessNames();
extern int SaveScreenshotToDiskCount;
extern std::string CalculateFileSHA256Safe(const std::string& filePath);
class SHA256 {
public:
    SHA256();
    void update(const uint8_t* data, size_t length);
    void finalize();
    uint8_t* getHash();

private:
    void transform();
    uint32_t m_state[8];
    uint64_t m_bitLength;
    uint32_t m_dataLength;
    uint8_t m_data[64];
    uint8_t m_hash[32];
    static const uint32_t K[64];  // ← только объявление, без инициализации
};
void UnhookIAT();
void UnhookAdditionalAPI();
void ReadModuleMemory(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath);
typedef BOOL(WINAPI* ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef BOOL(WINAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

extern std::atomic<int> g_consecutiveSkippedCaptures;
extern std::atomic<bool> g_forceScreenshotMode;
extern std::atomic<uint64_t> g_forceModeStartTime;
std::string GetInjectedProcessName();
std::string WStringToUTF8(const std::wstring& wstr);