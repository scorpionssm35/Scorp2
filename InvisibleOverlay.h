#pragma once

#include <Windows.h>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <chrono>
#include <functional>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <unordered_map>
#include <tlhelp32.h>
#include <shlobj.h>

class InvisibleOverlay {
private:
    HWND m_hwnd = nullptr;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_zorderGuardRunning{ false };
    std::thread m_zorderGuardThread;
    std::mutex m_captureMutex;

    // Уровни защиты Z-order
    enum ZOrderDefenseLevel {
        DEFENSE_NORMAL = 0,      // Базовая защита
        DEFENSE_AGGRESSIVE,      // Агрессивные меры
        DEFENSE_NUCLEAR          // Экстремальные меры
    };

    ZOrderDefenseLevel m_defenseLevel = DEFENSE_NORMAL;

    // Настройки защиты
    bool m_enableZOrderProtection = true;
    int m_zorderCheckInterval = 33; // мс
    int m_maxZOrderAttacks = 10;

    bool m_kernelLevelProtection = false;
    std::vector<std::pair<HWND, std::string>> m_detectedOverlays;
    std::vector<HWND> m_blockedWindows;
    static const int MAX_BLOCKED_WINDOWS = 50;

    // Статистика атак
    int m_zorderAttackCount = 0;
    std::string m_lastAttackWindow;
    std::atomic<bool> m_underAttack{ false };

    // Временные метки
    std::chrono::steady_clock::time_point m_lastAttackTime;
    std::chrono::steady_clock::time_point m_lastDefenseChange;

    // Безопасные пути для исключения
    std::vector<std::wstring> m_safePaths;

    // Структура информации о процессе
    struct ProcessInfo {
        DWORD pid = 0;
        std::wstring path;
        std::wstring name;
        DWORD parentPid = 0;
        bool isSigned = false;
        std::wstring companyName;
        std::wstring productName;
        std::wstring description;
    };

    // Пороги подозрительности
    static constexpr int SUSPICION_THRESHOLD = 15;
    static constexpr int HIGH_SUSPICION_THRESHOLD = 25;

    // Кэш для уже проверенных процессов
    mutable std::unordered_map<DWORD, bool> m_suspiciousProcessCache;
    mutable std::chrono::steady_clock::time_point m_lastCacheCleanup;

    // Популярные оверлей-процессы (исключения по именам)
    std::unordered_set<std::wstring> m_safeOverlayProcesses = {
        L"explorer.exe",
        L"dwm.exe",
        L"taskhostw.exe",
        L"sihost.exe",
        L"ctfmon.exe",
        L"nvcontainer.exe",
        L"nvidia broadcast.exe",
        L"radeonsoftware.exe",
        L"discord.exe",
        L"discordptb.exe",
        L"discordcanary.exe",
        L"overwolf.exe",
        L"rtss.exe",
        L"msiafterburner.exe",
        L"fraps.exe",
        L"obs.exe",
        L"obs64.exe",
        L"streamlabs obs.exe",
        L"xsplit.core.exe",
        L"gamecaster.exe",
        L"plays.tv.exe",
        L"medal.exe",
        L"outplayed.exe",
        L"shadowplay.exe",
        L"geforce experience.exe",
        L"razer cortex.exe",
        L"steam.exe",
        L"steamwebhelper.exe",
        L"battle.net.exe",
        L"origin.exe",
        L"epicgameslauncher.exe",
        L"ubisoftconnect.exe",
        L"uplay.exe",
        L"goggalaxy.exe",
        L"ea.exe",
        L"eadesktop.exe",
        L"rockstarwarehouse.exe",
        L"rockstar games launcher.exe",
        L"teamspeak3.exe",
        L"ts3client_win64.exe",
        L"mumble.exe",
        L"skype.exe",
        L"zoom.exe",
        L"slack.exe",
        L"bandicam.exe",
        L"dxtory.exe",
        L"action.exe",
        L"playclaw.exe",
        L"logitechg403.exe",
        L"lghub.exe",
        L"corsairicue.exe",
        L"asus aura sync.exe",
        L"msi mysticlight.exe",
        L"steelseriesengine.exe",
        L"steelseriesengine3.exe",
        L"alienware command center.exe",
        L"avastui.exe",
        L"avgui.exe",
        L"ekrn.exe",
        L"kaspersky.exe",
        L"windowsdefender.exe",
        L"malwarebytes.exe"
    };

    // Подозрительные оверлей-процессы
    std::unordered_set<std::wstring> m_suspiciousOverlayProcesses = {
        L"cheatengine.exe",
        L"cheatengine-x86_64.exe",
        L"artmoney.exe",
        L"gameguardian.exe",
        L"wemod.exe",
        L"fling trainer.exe",
        L"plitch trainer.exe",
        L"processhacker.exe",
        L"processhacker2.exe",
        L"systemexplorer.exe",
        L"procexp.exe",
        L"procexp64.exe",
        L"pchunter.exe",
        L"pchunter64.exe",
        L"xuetr.exe",
        L"gm9.exe",
        L"tsb.exe",
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ollydbg.exe",
        L"ollyice.exe",
        L"ida.exe",
        L"ida64.exe",
        L"ghidra.exe",
        L"windbg.exe",
        L"immunitydebugger.exe",
        L"hxd.exe",
        L"hxd64.exe",
        L"winhex.exe",
        L"hexworkshop.exe",
        L"010editor.exe",
        L"wireshark.exe",
        L"fiddler.exe",
        L"charles.exe",
        L"burpsuite.exe",
        L"httpdebugger.exe",
        L"dotpeek.exe",
        L"dnspy.exe",
        L"autohotkey.exe",
        L"autohotkeyu64.exe",
        L"pulsoverlay.exe",
        L"macro.exe",
        L"macrocreator.exe",
        L"tinytask.exe",
        L"jitbit.exe",
        L"injector.exe",
        L"dllinject.exe",
        L"extreme injector.exe",
        L"sinject.exe"
    };

public:
    // Конструктор/деструктор
    InvisibleOverlay();
    ~InvisibleOverlay();

    // Основные методы
    bool Create();
    void Destroy();
    bool IsCreated() const { return m_hwnd != nullptr; }
    HWND GetWindowHandle() const { return m_hwnd; }

    // Захват экрана через оверлей
    bool CaptureThroughOverlay(std::vector<BYTE>& output, int width = 0, int height = 0);

    // Управление защитой Z-order
    void StartZOrderProtection();
    void StopZOrderProtection();
    bool IsUnderAttack() const { return m_underAttack.load(); }
    int GetAttackCount() const { return m_zorderAttackCount; }
    int GetDefenseLevel() const { return static_cast<int>(m_defenseLevel); }
    std::string GetLastAttackInfo() const { return m_lastAttackWindow; }

    // Настройки
    void EnableZOrderProtection(bool enable) { m_enableZOrderProtection = enable; }
    void SetZOrderCheckInterval(int ms) { m_zorderCheckInterval = ms; }
    void SetMaxZOrderAttacks(int max) { m_maxZOrderAttacks = max; }

    bool ForceTopMostUltimate();
    void ScanForHiddenOverlays();
    void BlockCompetitorWindow(HWND competitor);
    void SetKernelLevelProtection(bool enable) { m_kernelLevelProtection = enable; }
    const std::vector<std::pair<HWND, std::string>>& GetDetectedOverlays() const { return m_detectedOverlays; }

    // Информация о статусе
    std::string GetStatus() const;

private:
    // Window procedure
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // Захват экрана
    bool CaptureUsingBitBlt(std::vector<BYTE>& output, int width, int height);

    // Z-order защита - основной цикл
    void ZOrderGuardLoop();

    // Методы определения окон
    bool IsSuspiciousWindow(HWND hwnd) const;
    bool IsSystemWindow(HWND hwnd) const;
    bool IsOverlayProcess(DWORD pid) const;
    bool IsSafePath(const std::wstring& path) const;
    std::string GetWindowInfo(HWND hwnd) const;
    std::string GetProcessInfo(DWORD pid) const;

    // Усиленные методы Z-order защиты
    bool ForceTopMost();               // Нормальный режим
    bool ForceTopMostAggressive();     // Агрессивный режим
    bool ForceTopMostNuclear();        // Ядерный режим

    // Вспомогательные методы защиты
    HWND GetRealTopmostWindow();
    HWND GetWindowAboveUs() const;
    void HandleZOrderAttack(HWND attacker);
    void LogAttackDetails(HWND attacker, const std::string& reason);

    // Эскалация/снижение защиты
    void EscalateDefense();
    void DemoteDefense();

    // Активные меры против конкурентов
    void RemoveCompetitorsFromTopmost();
    void AnalyzeCompetitor(HWND competitor);

    // Вспомогательные
    void ApplyWindowAttributes();
    bool VerifyTopMostStatus() const;
    void InitializeSafePaths();

    // НОВЫЕ МЕТОДЫ для детекта читов с рандомными именами
    bool IsSuspiciousProcess(DWORD pid) const;
    bool IsKnownCheatProcess(DWORD pid) const;
    bool IsRunningFromTemp(const std::wstring& path) const;
    bool IsRunningFromDesktop(const std::wstring& path) const;
    bool IsRunningFromDownloads(const std::wstring& path) const;
    bool HasSuspiciousParent(DWORD pid) const;
    ProcessInfo GetDetailedProcessInfo(DWORD pid) const;
    HWND GetWindowByPID(DWORD pid) const;

    // Работа с кэшем
    void CleanupProcessCache() const;
    bool IsProcessCached(DWORD pid) const;
    void CacheProcessResult(DWORD pid, bool isSuspicious) const;

    // Логирование
    void LogWarning(const std::string& message) const;
    void LogError(const std::string& message) const;
    void LogAttack(const std::string& message) const;
};