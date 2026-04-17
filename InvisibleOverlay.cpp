#include "InvisibleOverlay.h"
#include <dwmapi.h>
#include <VersionHelpers.h>
#include <psapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <ranges>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "LogUtils.h"
#include "dllmain.h"

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
static const wchar_t* OVERLAY_CLASS_NAME = L"DzOverlayUA";
static const wchar_t* OVERLAY_WINDOW_NAME = L"DzOverlayWindowUA";
std::wstring to_lower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(),
        NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(),
        &str[0], size_needed, NULL, NULL);
    return str;
}
void InvisibleOverlay::LogWarning(const std::string& message) const {
    LogError("[VEH] " + message);
}
void InvisibleOverlay::LogError(const std::string& message) const {
    Log("[LOGEN] " + message);
}
void InvisibleOverlay::LogAttack(const std::string& message) const {
    LogError("[VEH] " + message);
    StartSightImgDetection("[VEH] " + message);
}
InvisibleOverlay::InvisibleOverlay()
    : m_lastAttackTime(std::chrono::steady_clock::now())
    , m_lastDefenseChange(std::chrono::steady_clock::now())
    , m_lastCacheCleanup(std::chrono::steady_clock::now()) {

    m_zorderCheckInterval = 16; // Проверка каждые 16мс (было 33)
    m_enableZOrderProtection = true;

    LogError("InvisibleOverlay constructor - AGGRESSIVE MODE");
    InitializeSafePaths();
}
InvisibleOverlay::~InvisibleOverlay() {
    LogError("InvisibleOverlay destructor");
    Destroy();
}
void InvisibleOverlay::InitializeSafePaths() {
    // Системные пути Windows
    m_safePaths.push_back(L"\\windows\\system32\\");
    m_safePaths.push_back(L"\\windows\\syswow64\\");
    m_safePaths.push_back(L"\\windows\\system\\");
    m_safePaths.push_back(L"\\windows\\");

    // Program Files (стандартные)
    m_safePaths.push_back(L"\\program files\\");
    m_safePaths.push_back(L"\\program files (x86)\\");

    // Program Files - конкретные папки производителей
    m_safePaths.push_back(L"\\program files\\nvidia corporation\\");
    m_safePaths.push_back(L"\\program files\\amd\\");
    m_safePaths.push_back(L"\\program files\\intel\\");
    m_safePaths.push_back(L"\\program files\\msi\\");
    m_safePaths.push_back(L"\\program files\\asus\\");
    m_safePaths.push_back(L"\\program files\\gigabyte\\");
    m_safePaths.push_back(L"\\program files\\corsair\\");
    m_safePaths.push_back(L"\\program files\\logitech\\");
    m_safePaths.push_back(L"\\program files\\razer\\");
    m_safePaths.push_back(L"\\program files\\steelseries\\");

    // Program Files (x86) - конкретные папки
    m_safePaths.push_back(L"\\program files (x86)\\steam\\");
    m_safePaths.push_back(L"\\program files (x86)\\discord\\");
    m_safePaths.push_back(L"\\program files (x86)\\origin\\");
    m_safePaths.push_back(L"\\program files (x86)\\ubisoft\\");
    m_safePaths.push_back(L"\\program files (x86)\\epic games\\");
    m_safePaths.push_back(L"\\program files (x86)\\battle.net\\");
    m_safePaths.push_back(L"\\program files (x86)\\overwolf\\");
    m_safePaths.push_back(L"\\program files (x86)\\obs-studio\\");
    m_safePaths.push_back(L"\\program files (x86)\\msi afterburner\\");
    m_safePaths.push_back(L"\\program files (x86)\\rivatuner\\");

    // Пользовательские AppData пути (безопасные программы)
    m_safePaths.push_back(L"\\appdata\\local\\discord\\");
    m_safePaths.push_back(L"\\appdata\\local\\steam\\");
    m_safePaths.push_back(L"\\appdata\\local\\epicgameslauncher\\");
    m_safePaths.push_back(L"\\appdata\\local\\ubisoft game launcher\\");
    m_safePaths.push_back(L"\\appdata\\local\\battle.net\\");
    m_safePaths.push_back(L"\\appdata\\local\\origin\\");
    m_safePaths.push_back(L"\\appdata\\local\\overwolf\\");

    m_safePaths.push_back(L"\\appdata\\roaming\\discord\\");
    m_safePaths.push_back(L"\\appdata\\roaming\\steam\\");
    m_safePaths.push_back(L"\\appdata\\roaming\\obs-studio\\");
    m_safePaths.push_back(L"\\appdata\\roaming\\msi afterburner\\");
    m_safePaths.push_back(L"\\appdata\\roaming\\rivatuner\\");
    m_safePaths.push_back(L"\\appdata\\roaming\\overwolf\\");

    // ProgramData пути
    m_safePaths.push_back(L"\\programdata\\nvidia corporation\\");
    m_safePaths.push_back(L"\\programdata\\amd\\");
    m_safePaths.push_back(L"\\programdata\\intel\\");
    m_safePaths.push_back(L"\\programdata\\microsoft\\windows\\");

    // Временные папки
    m_safePaths.push_back(L"\\windows\\temp\\nvidia\\");
    m_safePaths.push_back(L"\\windows\\temp\\amd\\");
    m_safePaths.push_back(L"\\windows\\temp\\intel\\");
    m_safePaths.push_back(L"\\temp\\discord\\");

    // Драйверы и системные службы
    m_safePaths.push_back(L"\\windows\\system32\\drivers\\");
    m_safePaths.push_back(L"\\windows\\system32\\driverstore\\");

    // Утилиты производителей
    m_safePaths.push_back(L"\\windows\\system32\\nvidia\\");
    m_safePaths.push_back(L"\\windows\\system32\\amd\\");
    m_safePaths.push_back(L"\\windows\\system32\\intel\\");

    // Игровые директории
    m_safePaths.push_back(L"\\steamapps\\common\\");
    m_safePaths.push_back(L"\\epic games\\");
    m_safePaths.push_back(L"\\ubisoft game launcher\\games\\");
    m_safePaths.push_back(L"\\battle.net\\games\\");
    m_safePaths.push_back(L"\\gog galaxy\\games\\");
    m_safePaths.push_back(L"\\origin games\\");
    m_safePaths.push_back(L"\\ea games\\");
    m_safePaths.push_back(L"\\windowsapps\\");

    LogError("Safe paths initialized: " + std::to_string(m_safePaths.size()) + " paths");
}
bool InvisibleOverlay::Create() {
    if (m_hwnd) {
        return true;
    }

    LogError("Creating overlay window...");

    // Создаем класс окна
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_NOCLOSE;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = OVERLAY_CLASS_NAME;

    if (!RegisterClassExW(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LogError("Failed to register window class. Error: " + std::to_string(err));
            return false;
        }
    }

    // Получаем размеры экрана
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Создаем окно
    m_hwnd = CreateWindowExW(
        WS_EX_TOPMOST |
        WS_EX_TRANSPARENT |
        WS_EX_LAYERED |
        WS_EX_TOOLWINDOW |
        WS_EX_NOACTIVATE |
        WS_EX_NOREDIRECTIONBITMAP |
        WS_EX_COMPOSITED,

        OVERLAY_CLASS_NAME,
        OVERLAY_WINDOW_NAME,

        WS_POPUP,

        0, 0, screenWidth, screenHeight,

        nullptr,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );

    if (!m_hwnd) {
        DWORD err = GetLastError();
        LogError("Failed to create overlay window. Error: " + std::to_string(err));
        return false;
    }

    LogError("Window created successfully");

    // Применяем атрибуты окна
    ApplyWindowAttributes();

    // Показываем окно
    ShowWindow(m_hwnd, SW_SHOWNOACTIVATE);
    UpdateWindow(m_hwnd);

    // Запускаем защиту
    if (m_enableZOrderProtection) {
        StartZOrderProtection();
    }

    LogError("Overlay creation complete");
    return true;
}
void InvisibleOverlay::Destroy() {
    LogError("Destroying overlay...");

    StopZOrderProtection();

    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_HIDE);
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
        LogError("Window destroyed");
    }

    UnregisterClassW(OVERLAY_CLASS_NAME, GetModuleHandle(nullptr));
    LogError("Overlay destroyed");
}
bool InvisibleOverlay::CaptureThroughOverlay(std::vector<BYTE>& output, int width, int height) {
    std::lock_guard<std::mutex> lock(m_captureMutex);

    if (!m_hwnd) {
        LogError("Capture failed: overlay not created");
        return false;
    }

    if (width <= 0 || height <= 0) {
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
    }

    return CaptureUsingBitBlt(output, width, height);
}
bool InvisibleOverlay::CaptureUsingBitBlt(std::vector<BYTE>& output, int width, int height) {
    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) {
        LogError("GetDC failed");
        return false;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(nullptr, hdcScreen);
        LogError("CreateCompatibleDC failed");
        return false;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        LogError("CreateCompatibleBitmap failed");
        return false;
    }

    SelectObject(hdcMem, hBitmap);

    // Используем CAPTUREBLT для захвата layered окон
    BOOL result = BitBlt(hdcMem, 0, 0, width, height,
        hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);

    if (!result) {
        DWORD err = GetLastError();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        LogError("BitBlt failed. Error: " + std::to_string(err));
        return false;
    }

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = width * height * 4;

    output.resize(width * height * 4);

    int getResult = GetDIBits(hdcMem, hBitmap, 0, height,
        output.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    if (getResult == 0) {
        LogError("GetDIBits failed");
        output.clear();
        return false;
    }

    return true;
}
void InvisibleOverlay::StartZOrderProtection() {
    if (!m_enableZOrderProtection) {
        LogWarning("Z-order protection disabled");
        return;
    }

    if (m_zorderGuardRunning) {
        return;
    }

    LogError("Starting Z-order protection...");

    m_zorderGuardRunning = true;
    m_zorderGuardThread = std::thread([this]() {
        ZOrderGuardLoop();
        });

    LogError("Z-order protection started");
}
void InvisibleOverlay::StopZOrderProtection() {
    LogError("Stopping Z-order protection...");

    m_zorderGuardRunning = false;

    if (m_zorderGuardThread.joinable()) {
        m_zorderGuardThread.join();
        LogError("Z-order protection thread stopped");
    }

    m_running = false;
}
void InvisibleOverlay::ZOrderGuardLoop() {
    m_running = true;
    int consecutiveAttacks = 0;
    int checkCounter = 0;

    LogError("Z-order guard loop started");

    while (m_zorderGuardRunning) {
        if (!m_hwnd) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Очищаем кэш процессов раз в минуту
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::minutes>(now - m_lastCacheCleanup).count() >= 1) {
            CleanupProcessCache();
            m_lastCacheCleanup = now;
        }

        // Проверяем реальный Z-order
        HWND realTopmost = GetRealTopmostWindow();
        bool weAreTopmost = (realTopmost == m_hwnd);

        static auto lastOverlayScan = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastOverlayScan).count() >= 300) {  // 5 минут
            ScanForHiddenOverlays();
            lastOverlayScan = now;
        }

        if (!weAreTopmost && realTopmost) {
            // АТАКА ОБНАРУЖЕНА!
            auto timeSinceLastAttack = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - m_lastAttackTime).count();

            if (timeSinceLastAttack < 1000) {
                consecutiveAttacks++;
            }
            else {
                consecutiveAttacks = 1;
            }

            m_lastAttackTime = now;

            // Анализируем атакующее окно
            AnalyzeCompetitor(realTopmost);
            LogAttackDetails(realTopmost, "Z-order attack detected");

            // УСИЛЕННЫЙ РЕЖИМ: даже одна атака - сразу агрессивный режим
            if (consecutiveAttacks >= 1) {
                LogAttack("Attack detected - activating aggressive defense");
                ForceTopMostAggressive();
            }

            // Если атаки повторяются - переходим в ядерный режим
            if (consecutiveAttacks >= 3) {
                LogAttack("Multiple attacks - activating NUCLEAR defense!");
                ForceTopMostNuclear();
            }

            HandleZOrderAttack(realTopmost);

            // После атаки проверяем чаще
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        else {
            // ВСЁ СПОКОЙНО
            consecutiveAttacks = 0;

            // Периодическое обслуживание (каждые 10 итераций вместо 30)
            if (checkCounter++ % 10 == 0) {  // БЫЛО 30, СТАЛО 10
                auto timeSinceLastAttack = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - m_lastAttackTime).count();

                // Дольше ждем перед понижением защиты (10 секунд вместо 5)
                if (timeSinceLastAttack > 10000 && m_defenseLevel > DEFENSE_NORMAL) {
                    DemoteDefense();
                    LogError("Defense demoted - no attacks for 10 seconds");
                }

                // Профилактическое восстановление
                ForceTopMost();
            }

            // Нормальный интервал проверки
            std::this_thread::sleep_for(std::chrono::milliseconds(m_zorderCheckInterval));
        }
    }

    LogError("Z-order guard loop stopped");
    m_running = false;
}
bool InvisibleOverlay::IsSafePath(const std::wstring& path) const {
    if (path.empty()) return false;

    std::wstring lowerPath = to_lower(path);

    // Проверяем по всем безопасным путям
    for (const auto& safePath : m_safePaths) {
        if (lowerPath.find(safePath) != std::wstring::npos) {
            return true;
        }
    }

    // Дополнительные проверки для особых случаев
    // Проверка на наличие в системных папках
    if (lowerPath.find(L"\\windows\\") != std::wstring::npos) {
        // В системных папках Windows большинство файлов безопасны
        // Но нужно исключить подозрительные имена
        std::wstring fileName = lowerPath.substr(lowerPath.find_last_of(L"\\/") + 1);

        // Если файл в system32 и не является явно подозрительным
        if ((lowerPath.find(L"\\system32\\") != std::wstring::npos ||
            lowerPath.find(L"\\syswow64\\") != std::wstring::npos)) {

            // Список системных файлов, которые могут быть оверлеями
            std::vector<std::wstring> safeSystemFiles = {
                L"dwm.exe",
                L"explorer.exe",
                L"taskhostw.exe",
                L"sihost.exe",
                L"ctfmon.exe",
                L"searchapp.exe",
                L"runtimebroker.exe",
                L"applicationframehost.exe",
                L"shellexperiencehost.exe",
                L"startmenuexperiencehost.exe"
            };

            for (const auto& safeFile : safeSystemFiles) {
                if (fileName == safeFile) {
                    return true;
                }
            }
        }
    }

    return false;
}
bool InvisibleOverlay::ForceTopMost() {
    if (!m_hwnd) return false;

    // Убираем TOPMOST у конкурентов
    RemoveCompetitorsFromTopmost();

    // Делаем себя TOPMOST
    bool result = SetWindowPos(m_hwnd, HWND_TOPMOST,
        0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);

    // Проверяем
    LONG exStyle = GetWindowLongW(m_hwnd, GWL_EXSTYLE);
    bool isTopMost = (exStyle & WS_EX_TOPMOST) != 0;

    if (!isTopMost) {
        LogWarning("Normal ForceTopMost failed, escalating to aggressive mode");
        return ForceTopMostAggressive();
    }

    return result;
}
bool InvisibleOverlay::ForceTopMostAggressive() {
    if (!m_hwnd) return false;

    LogError("Activating aggressive defense mode");
    m_defenseLevel = DEFENSE_AGGRESSIVE;
    m_lastDefenseChange = std::chrono::steady_clock::now();

    // Метод 1: Многократные попытки
    for (int i = 0; i < 10; i++) {
        SetWindowPos(m_hwnd, HWND_TOPMOST,
            0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

        if (i % 3 == 0) {
            LONG exStyle = GetWindowLongW(m_hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_TOPMOST) {
                LogError("Aggressive mode succeeded on attempt " + std::to_string(i + 1));
                return true;
            }
        }

        Sleep(1);
    }

    // Метод 2: Временное скрытие
    ShowWindow(m_hwnd, SW_HIDE);
    Sleep(5);
    ShowWindow(m_hwnd, SW_SHOWNOACTIVATE);

    // Метод 3: DeferWindowPos
    HDWP hdwp = BeginDeferWindowPos(1);
    if (hdwp) {
        hdwp = DeferWindowPos(hdwp, m_hwnd, HWND_TOPMOST,
            0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        EndDeferWindowPos(hdwp);
    }

    // Проверяем результат
    LONG exStyle = GetWindowLongW(m_hwnd, GWL_EXSTYLE);
    bool isTopMost = (exStyle & WS_EX_TOPMOST) != 0;

    if (!isTopMost) {
        LogWarning("Aggressive mode failed, escalating to nuclear defense");
        return ForceTopMostNuclear();
    }

    LogError("Aggressive defense mode succeeded");
    return true;
}
bool InvisibleOverlay::ForceTopMostNuclear() {
    if (!m_hwnd) return false;

    LogError("Activating nuclear defense mode - extreme measures");
    m_defenseLevel = DEFENSE_NUCLEAR;
    m_lastDefenseChange = std::chrono::steady_clock::now();

    // 1. Снимаем TOPMOST со всех окон
    HWND hwnd = GetTopWindow(nullptr);
    while (hwnd) {
        if (hwnd != m_hwnd) {
            LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_TOPMOST && !IsSystemWindow(hwnd)) {
                // Проверяем путь перед снятием
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProcess) {
                    WCHAR exePath[MAX_PATH] = { 0 };
                    if (GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
                        std::wstring wpath = exePath;
                        // Не снимаем с безопасных путей
                        if (!IsSafePath(wpath)) {
                            SetWindowPos(hwnd, HWND_NOTOPMOST,
                                0, 0, 0, 0,
                                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        hwnd = GetWindow(hwnd, GW_HWNDNEXT);
    }

    // 2. Множественные SetWindowPos
    for (int i = 0; i < 20; i++) {
        SetWindowPos(m_hwnd, HWND_TOPMOST,
            0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

        if (i % 5 == 0) {
            SetWindowPos(m_hwnd, HWND_TOP,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }

        Sleep(2);
    }

    // 3. Финальная проверка
    HWND topmost = GetRealTopmostWindow();
    bool success = (topmost == m_hwnd);

    if (success) {
        LogError("Nuclear defense mode SUCCESS - We are on top!");
    }
    else {
        std::string attackerInfo = GetWindowInfo(topmost);
        LogAttack("Nuclear defense mode FAILED - Top window: " + attackerInfo);
    }

    return success;
}
bool InvisibleOverlay::ForceTopMostUltimate() {
    if (!m_hwnd) return false;

    LogError("[LOGEN] ACTIVATING ULTIMATE TOPMOST MODE");
    m_defenseLevel = DEFENSE_NUCLEAR;

    // 1. Получаем все TOPMOST окна и принудительно убираем у всех флаг
    HWND hwnd = GetTopWindow(nullptr);
    while (hwnd) {
        if (hwnd != m_hwnd && IsWindow(hwnd) && IsWindowVisible(hwnd)) {
            LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_TOPMOST) {
                // Проверяем, не системное ли это окно
                if (!IsSystemWindow(hwnd) && IsSuspiciousWindow(hwnd)) {
                    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

                    // Запоминаем заблокированное окно
                    if (m_blockedWindows.size() < MAX_BLOCKED_WINDOWS) {
                        m_blockedWindows.push_back(hwnd);
                    }
                }
            }
        }
        hwnd = GetWindow(hwnd, GW_HWNDNEXT);
    }

    // 2. Устанавливаем наше окно с флагом TOPMOST
    for (int i = 0; i < 50; i++) {
        SetWindowPos(m_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);

        // Каждые 10 попыток применяем DeferWindowPos
        if (i % 10 == 0) {
            HDWP hdwp = BeginDeferWindowPos(1);
            if (hdwp) {
                hdwp = DeferWindowPos(hdwp, m_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                EndDeferWindowPos(hdwp);
            }
        }

        // Короткая пауза для применения изменений
        if (i < 10) Sleep(1);
    }

    // 3. Дополнительно: временно скрываем и показываем окно
    ShowWindow(m_hwnd, SW_HIDE);
    Sleep(5);
    ShowWindow(m_hwnd, SW_SHOWNOACTIVATE);

    // 4. Проверяем результат
    HWND topmost = GetRealTopmostWindow();
    bool success = (topmost == m_hwnd);

    if (success) {
        LogError("[LOGEN] ULTIMATE MODE SUCCESS - We are on top!");
    }
    else {
        std::string attackerInfo = GetWindowInfo(topmost);
        LogAttack("[LOGEN] ULTIMATE MODE FAILED - Top window: " + attackerInfo);
    }

    return success;
}
void InvisibleOverlay::ScanForHiddenOverlays() {
    struct EnumData {
        std::vector<std::pair<HWND, std::string>> overlays;
        DWORD ourPid;
    } data;

    data.ourPid = GetCurrentProcessId();
    m_detectedOverlays.clear();

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<EnumData*>(lParam);

        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == data->ourPid) return TRUE; // Пропускаем себя

        LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

        // Критерии оверлея:
        bool isOverlay = (exStyle & WS_EX_LAYERED) ||
            (exStyle & WS_EX_TRANSPARENT) ||
            (exStyle & WS_EX_TOPMOST);

        if (isOverlay) {
            char className[256] = { 0 };
            char windowTitle[256] = { 0 };
            GetClassNameA(hwnd, className, sizeof(className));
            GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

            // Получаем путь к процессу
            std::string processPath = "unknown";
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                char path[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
                    processPath = path;
                }
                CloseHandle(hProcess);
            }

            std::stringstream info;
            info << "Class: " << className
                << " | Title: " << windowTitle
                << " | PID: " << pid
                << " | Path: " << processPath;

            data->overlays.push_back({ hwnd, info.str() });

            LogFormat("[VEH] HIDDEN OVERLAY DETECTED: %s", info.str().c_str());
        }

        return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

    m_detectedOverlays = data.overlays;

    // Если нашли подозрительные оверлеи, блокируем их
    for (const auto& overlay : m_detectedOverlays) {
        BlockCompetitorWindow(overlay.first);
    }
}
void InvisibleOverlay::BlockCompetitorWindow(HWND competitor) {
    if (!competitor || !IsWindow(competitor)) return;

    // 1. Убираем TOPMOST
    SetWindowPos(competitor, HWND_NOTOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    // 2. Пробуем скрыть
    ShowWindow(competitor, SW_HIDE);

    LogAttack("[LOGEN] COMPETITOR WINDOW BLOCKED: " + GetWindowInfo(competitor));
}
HWND InvisibleOverlay::GetRealTopmostWindow() {
    struct TopmostData {
        HWND topmost = nullptr;
        HWND ourHwnd = nullptr;
    } data;

    data.ourHwnd = m_hwnd;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        TopmostData* pData = reinterpret_cast<TopmostData*>(lParam);

        // Пропускаем невидимые и свёрнутые
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
            return TRUE;
        }

        // Пропускаем окна с нулевым размером
        RECT rect;
        if (!GetWindowRect(hwnd, &rect)) {
            return TRUE;
        }

        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;
        if (width <= 0 || height <= 0) {
            return TRUE;
        }

        // Это мы?
        if (hwnd == pData->ourHwnd) {
            pData->topmost = hwnd;
            return FALSE;
        }

        // Другое окно поверх нас
        pData->topmost = hwnd;
        return FALSE;

        }, reinterpret_cast<LPARAM>(&data));

    return data.topmost;
}
HWND InvisibleOverlay::GetWindowAboveUs() const {
    if (!m_hwnd) return nullptr;

    HWND current = GetTopWindow(nullptr);
    HWND previous = nullptr;

    while (current) {
        if (current == m_hwnd) {
            return previous;
        }

        if (IsWindowVisible(current) && !IsIconic(current)) {
            previous = current;
        }

        current = GetWindow(current, GW_HWNDNEXT);
    }

    return nullptr;
}
void InvisibleOverlay::HandleZOrderAttack(HWND attacker) {
    m_zorderAttackCount++;
    m_underAttack = true;
    m_lastAttackWindow = GetWindowInfo(attacker);

    std::stringstream ss;
    ss << "Z-order attack handled. Total attacks: " << m_zorderAttackCount
        << " Attacker: " << m_lastAttackWindow;
    LogAttack(ss.str());

    if (m_zorderAttackCount >= m_maxZOrderAttacks) {
        LogAttack("Maximum Z-order attacks reached. Activating permanent nuclear defense.");
        m_defenseLevel = DEFENSE_NUCLEAR;
    }
}
bool InvisibleOverlay::IsRunningFromTemp(const std::wstring& path) const {
    std::wstring lowerPath = to_lower(path);

    // Временные папки
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\users\\") != std::wstring::npos &&
        (lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos)) {
        return true;
    }

    return false;
}
bool InvisibleOverlay::IsRunningFromDesktop(const std::wstring& path) const {
    std::wstring lowerPath = to_lower(path);

    // Получаем путь к рабочему столу текущего пользователя
    WCHAR desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        std::wstring desktop = to_lower(desktopPath);
        if (lowerPath.find(desktop) != std::wstring::npos) {
            return true;
        }
    }

    // Также проверяем "Desktop" в пути
    if (lowerPath.find(L"\\desktop\\") != std::wstring::npos) {
        return true;
    }

    return false;
}
bool InvisibleOverlay::IsRunningFromDownloads(const std::wstring& path) const {
    std::wstring lowerPath = to_lower(path);

    WCHAR downloadsPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, downloadsPath))) {
        std::wstring downloads = to_lower(downloadsPath) + L"\\downloads\\";
        if (lowerPath.find(downloads) != std::wstring::npos) {
            return true;
        }
    }

    if (lowerPath.find(L"\\downloads\\") != std::wstring::npos) {
        return true;
    }

    return false;
}
bool InvisibleOverlay::HasSuspiciousParent(DWORD pid) const {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Находим наш процесс
    DWORD ourParentPid = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ourParentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    if (ourParentPid == 0) {
        CloseHandle(hSnapshot);
        return false;
    }

    // Проверяем родительский процесс
    std::wstring parentName;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == ourParentPid) {
                parentName = to_lower(pe.szExeFile);
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    if (parentName.empty()) return true;

    // Проверяем, не запущен ли из браузера (скачанный файл)
    if (parentName.find(L"chrome.exe") != std::wstring::npos ||
        parentName.find(L"firefox.exe") != std::wstring::npos ||
        parentName.find(L"msedge.exe") != std::wstring::npos ||
        parentName.find(L"opera.exe") != std::wstring::npos ||
        parentName.find(L"brave.exe") != std::wstring::npos) {
        return true;  // Запущен из браузера - подозрительно
    }

    // Проверяем, не запущен ли из командной строки
    if (parentName.find(L"cmd.exe") != std::wstring::npos ||
        parentName.find(L"powershell.exe") != std::wstring::npos ||
        parentName.find(L"wscript.exe") != std::wstring::npos ||
        parentName.find(L"cscript.exe") != std::wstring::npos) {
        return true;  // Запущен из скрипта - подозрительно
    }

    return false;
}
InvisibleOverlay::ProcessInfo InvisibleOverlay::GetDetailedProcessInfo(DWORD pid) const {
    ProcessInfo info;
    info.pid = pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return info;

    WCHAR exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH)) {
        info.path = exePath;

        size_t pos = info.path.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            info.name = info.path.substr(pos + 1);
        }
    }

    // Получаем информацию о файле (версия, компания и т.д.)
    DWORD dummy;
    DWORD verSize = GetFileVersionInfoSizeW(info.path.c_str(), &dummy);
    if (verSize > 0) {
        std::vector<BYTE> verData(verSize);
        if (GetFileVersionInfoW(info.path.c_str(), 0, verSize, verData.data())) {
            struct LANGANDCODEPAGE {
                WORD wLanguage;
                WORD wCodePage;
            } *lpTranslate;

            UINT cbTranslate;
            if (VerQueryValueW(verData.data(), L"\\VarFileInfo\\Translation",
                (LPVOID*)&lpTranslate, &cbTranslate)) {

                for (UINT i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
                    WCHAR subBlock[MAX_PATH];

                    // CompanyName
                    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName",
                        lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

                    WCHAR* buffer;
                    UINT len;
                    if (VerQueryValueW(verData.data(), subBlock, (LPVOID*)&buffer, &len)) {
                        info.companyName = buffer;
                    }

                    // ProductName
                    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\ProductName",
                        lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

                    if (VerQueryValueW(verData.data(), subBlock, (LPVOID*)&buffer, &len)) {
                        info.productName = buffer;
                    }

                    // FileDescription
                    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
                        lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);

                    if (VerQueryValueW(verData.data(), subBlock, (LPVOID*)&buffer, &len)) {
                        info.description = buffer;
                    }
                }
            }
        }
    }

    // Проверяем наличие подписи
    info.isSigned = false; // Здесь можно добавить проверку цифровой подписи

    CloseHandle(hProcess);

    // Получаем родительский PID
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    info.parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    return info;
}
bool InvisibleOverlay::IsKnownCheatProcess(DWORD pid) const {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    WCHAR exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH)) {
        std::wstring wpath = exePath;
        std::wstring wexeName = wpath;
        size_t pos = wexeName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            wexeName = wexeName.substr(pos + 1);
        }
        wexeName = to_lower(wexeName);

        // Список известных читов (даже если имя рандомное, они часто содержат ключевые слова)
        std::vector<std::wstring> cheatKeywords = {
            L"cheat", L"hack", L"aim", L"esp", L"wallhack", L"trigger",
            L"inject", L"loader", L"crack", L"keygen", L"bypass",
            L"modmenu", L"mod menu", L"external", L"internal",
            L"osiris", L"otc", L"fatality", L"aimware", L"gamesense",
            L"neverlose", L"onetap", L"memesense", L"phook"
        };

        // Проверяем имя файла на наличие ключевых слов
        for (const auto& keyword : cheatKeywords) {
            if (wexeName.find(keyword) != std::wstring::npos) {
                CloseHandle(hProcess);
                return true;
            }
        }

        // Также проверяем полный путь
        std::wstring lowerPath = to_lower(wpath);
        for (const auto& keyword : cheatKeywords) {
            if (lowerPath.find(keyword) != std::wstring::npos) {
                CloseHandle(hProcess);
                return true;
            }
        }

        // Проверяем описание и название продукта
        ProcessInfo info = GetDetailedProcessInfo(pid);

        std::wstring lowerDesc = to_lower(info.description);
        std::wstring lowerProduct = to_lower(info.productName);
        std::wstring lowerCompany = to_lower(info.companyName);

        for (const auto& keyword : cheatKeywords) {
            if (lowerDesc.find(keyword) != std::wstring::npos ||
                lowerProduct.find(keyword) != std::wstring::npos ||
                lowerCompany.find(keyword) != std::wstring::npos) {
                CloseHandle(hProcess);
                return true;
            }
        }
    }

    CloseHandle(hProcess);
    return false;
}
bool InvisibleOverlay::IsSuspiciousProcess(DWORD pid) const {
    // Проверяем кэш
    if (IsProcessCached(pid)) {
        return m_suspiciousProcessCache.at(pid);
    }

    ProcessInfo info = GetDetailedProcessInfo(pid);

    int suspicionScore = 0;

    // 1. Проверка пути (откуда запущен)
    if (IsRunningFromTemp(info.path)) {
        suspicionScore += 10;  // Очень подозрительно
    }

    if (IsRunningFromDesktop(info.path)) {
        suspicionScore += 5;   // Подозрительно (читы часто с рабочего стола)
    }

    if (IsRunningFromDownloads(info.path)) {
        suspicionScore += 8;   // Очень подозрительно (только что скачали)
    }

    // 2. Проверка родительского процесса
    if (HasSuspiciousParent(pid)) {
        suspicionScore += 7;
    }

    // 3. Проверка имени процесса (даже если рандомное, может содержать паттерны)
    if (info.name.length() > 0) {
        // Рандомные имена часто содержат только буквы/цифры без пробелов
        bool hasOnlyAlphaNum = true;
        int digitCount = 0;
        for (wchar_t c : info.name) {
            if (!iswalnum(c) && c != L'.' && c != L'-' && c != L'_') {
                hasOnlyAlphaNum = false;
                break;
            }
            if (iswdigit(c)) digitCount++;
        }

        // Если имя состоит только из букв/цифр и много цифр - подозрительно
        if (hasOnlyAlphaNum && info.name.length() > 8 && digitCount > info.name.length() / 2) {
            suspicionScore += 6;  // Похоже на рандомное имя
        }
    }

    // 4. Проверка метаданных файла
    if (info.companyName.empty() && info.productName.empty()) {
        suspicionScore += 4;  // Нет информации о компании/продукте
    }

    // 5. Проверка на известные читы
    if (IsKnownCheatProcess(pid)) {
        suspicionScore += 20;  // Почти точно чит
    }

    // 6. Анализ поведения (если окно поверх нашего)
    HWND hwnd = GetWindowByPID(pid);
    if (hwnd) {
        if (IsSuspiciousWindow(hwnd)) {
            suspicionScore += 5;
        }
    }

    bool isSuspicious = suspicionScore >= SUSPICION_THRESHOLD;
    CacheProcessResult(pid, isSuspicious);

    return isSuspicious;
}
HWND InvisibleOverlay::GetWindowByPID(DWORD pid) const {
    struct FindWindowData {
        DWORD pid;
        HWND hwnd;
    } data = { pid, nullptr };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<FindWindowData*>(lParam);
        DWORD windowPid;
        GetWindowThreadProcessId(hwnd, &windowPid);
        if (windowPid == data->pid) {
            data->hwnd = hwnd;
            return FALSE;
        }
        return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

    return data.hwnd;
}
void InvisibleOverlay::CleanupProcessCache() const {
    auto now = std::chrono::steady_clock::now();
    auto it = m_suspiciousProcessCache.begin();
    while (it != m_suspiciousProcessCache.end()) {
        // Проверяем, существует ли еще процесс
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, it->first);
        if (!hProcess) {
            it = m_suspiciousProcessCache.erase(it);
        }
        else {
            CloseHandle(hProcess);
            ++it;
        }
    }
}
bool InvisibleOverlay::IsProcessCached(DWORD pid) const {
    return m_suspiciousProcessCache.find(pid) != m_suspiciousProcessCache.end();
}
void InvisibleOverlay::CacheProcessResult(DWORD pid, bool isSuspicious) const {
    m_suspiciousProcessCache[pid] = isSuspicious;
}
void InvisibleOverlay::AnalyzeCompetitor(HWND competitor) {
    if (!competitor) return;

    DWORD pid = 0;
    GetWindowThreadProcessId(competitor, &pid);

    if (pid == 0 || pid == GetCurrentProcessId()) {
        return;
    }

    // Получаем детальную информацию
    ProcessInfo info = GetDetailedProcessInfo(pid);

    if (info.path.empty()) return;

    std::wstring wexeName = to_lower(info.name);

    // 1. Сначала проверяем безопасные пути (белый список)
    if (IsSafePath(info.path)) {
        LogError("Safe path process detected: " + wstring_to_string(info.path) +
            " (" + wstring_to_string(wexeName) + ")");
        return;  // Не атакуем
    }

    if (m_safeOverlayProcesses.find(wexeName) != m_safeOverlayProcesses.end()) {
        // Проверяем, не маскируется ли чит
        if (!IsSafePath(info.path) && IsSuspiciousProcess(pid)) {
            LogAttack("CHEAT MASKING AS SAFE PROCESS: " +
                wstring_to_string(wexeName) + " at " + wstring_to_string(info.path));
            // НЕ ВОЗВРАЩАЕМ - продолжаем проверку
        }
        else {
            LogWarning("Safe process name from suspicious path: " +
                wstring_to_string(wexeName) + " at " + wstring_to_string(info.path));
            return;  // Всё равно безопасен (нет других признаков)
        }
    }

    // 3. Комплексная проверка на подозрительность
    bool isSuspicious = IsSuspiciousProcess(pid);
    bool isKnownCheat = IsKnownCheatProcess(pid);

    if (isKnownCheat || isSuspicious) {
        std::stringstream ss;
        ss << "[VEH] SUSPICIOUS PROCESS DETECTED: " << wstring_to_string(wexeName);
        ss << " | Path: " << wstring_to_string(info.path);
        ss << " | Parent PID: " << info.parentPid;

        if (!info.companyName.empty()) {
            ss << " | Company: " << wstring_to_string(info.companyName);
        }

        ss << " | Suspicion Score: " << (isKnownCheat ? 20 : 15);

        if (IsRunningFromTemp(info.path)) ss << " [FROM_TEMP]";
        if (IsRunningFromDesktop(info.path)) ss << " [FROM_DESKTOP]";
        if (IsRunningFromDownloads(info.path)) ss << " [FROM_DOWNLOADS]";
        if (HasSuspiciousParent(pid)) ss << " [SUSPICIOUS_PARENT]";

        LogAttack(ss.str());
    }
    else {
        // Неизвестный процесс
        std::stringstream ss;
        ss << "[VEH] UNKNOWN PROCESS: " << wstring_to_string(wexeName)
            << " at: " << wstring_to_string(info.path);

        if (IsSuspiciousWindow(competitor)) {
            ss << " [SUSPICIOUS WINDOW ATTRIBUTES]";
            LogAttack(ss.str());
        }
        else {
            LogWarning(ss.str());
        }
    }
}
void InvisibleOverlay::LogAttackDetails(HWND attacker, const std::string& reason) {
    std::stringstream ss;
    ss << "[VEH] " << reason
        << " | Attacker: " << GetWindowInfo(attacker)
        << " | Defense level: " << m_defenseLevel
        << " | Total attacks: " << m_zorderAttackCount;

    DWORD pid = 0;
    GetWindowThreadProcessId(attacker, &pid);
    if (pid > 0) {
        ss << " | PID: " << pid
            << " | Process: " << GetProcessInfo(pid);
    }

    LogAttack(ss.str());
}
void InvisibleOverlay::RemoveCompetitorsFromTopmost() {
    int removedCount = 0;

    HWND hwnd = GetTopWindow(nullptr);
    while (hwnd && removedCount < 50) {
        if (hwnd != m_hwnd && IsWindowVisible(hwnd) && !IsIconic(hwnd)) {
            LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

            if ((exStyle & WS_EX_TOPMOST) && IsSuspiciousWindow(hwnd) && !IsSystemWindow(hwnd)) {
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);

                // Проверяем путь процесса
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProcess) {
                    WCHAR exePath[MAX_PATH] = { 0 };
                    if (GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
                        std::wstring wpath = exePath;

                        // НЕ удаляем, если процесс из безопасного пути
                        if (!IsSafePath(wpath) && IsSuspiciousProcess(pid)) {
                            SetWindowPos(hwnd, HWND_NOTOPMOST,
                                0, 0, 0, 0,
                                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
                            removedCount++;

                            std::string processInfo = GetProcessInfo(pid);
                            LogError("Removed competitor from TOPMOST: " + processInfo +
                                " (unsafe path)");
                        }
                        else {
                            LogError("Preserved competitor from safe path: " +
                                wstring_to_string(wpath));
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        hwnd = GetWindow(hwnd, GW_HWNDNEXT);
    }

    if (removedCount > 0) {
        LogError("Removed " + std::to_string(removedCount) + " competitors from TOPMOST");
    }
}
bool InvisibleOverlay::IsOverlayProcess(DWORD pid) const {
    if (pid == 0 || pid == GetCurrentProcessId()) return true;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    WCHAR exePath[MAX_PATH] = { 0 };
    bool isOverlay = false;

    if (GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
        std::wstring wpath = exePath;
        std::wstring wexeName = wpath;
        size_t pos = wexeName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            wexeName = wexeName.substr(pos + 1);
        }
        wexeName = to_lower(wexeName);

        // Проверяем списки безопасных процессов и путь
        if (m_safeOverlayProcesses.find(wexeName) != m_safeOverlayProcesses.end() ||
            IsSafePath(wpath)) {
            isOverlay = true;
        }
    }

    CloseHandle(hProcess);
    return isOverlay;
}
bool InvisibleOverlay::IsSuspiciousWindow(HWND hwnd) const {
    if (!hwnd || !IsWindow(hwnd)) return false;

    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // Критерии оверлейного окна:
    int suspiciousPoints = 0;

    // 1. Layered окна (обычно для оверлеев)
    if (exStyle & WS_EX_LAYERED) {
        suspiciousPoints += 2;

        BYTE alpha = 255;
        DWORD flags = 0;
        COLORREF colorKey = 0;

        if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
            if (alpha < 255) suspiciousPoints += 2;  // Прозрачное
            if (flags & LWA_COLORKEY) suspiciousPoints += 1;  // Цветовой ключ
        }
    }

    // 2. Transparent окна
    if (exStyle & WS_EX_TRANSPARENT) suspiciousPoints += 2;

    // 3. Tool windows (часто для оверлеев)
    if (exStyle & WS_EX_TOOLWINDOW) suspiciousPoints += 1;

    // 4. No activate окна
    if (exStyle & WS_EX_NOACTIVATE) suspiciousPoints += 1;

    // 5. Размер окна (оверлеи часто на весь экран)
    RECT rect;
    if (GetWindowRect(hwnd, &rect)) {
        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);

        // Почти на весь экран
        if (width >= screenWidth - 100 && height >= screenHeight - 100) {
            suspiciousPoints += 3;
        }
        // Очень маленькие окна (пиксельные хоткеи)
        else if (width < 50 && height < 50) {
            suspiciousPoints += 2;
        }
    }

    // 6. Проверка класса окна (оверлеи часто имеют специфические классы)
    WCHAR className[256] = { 0 };
    if (GetClassNameW(hwnd, className, 256)) {
        std::wstring wclass = to_lower(className);

        // Классы, типичные для оверлеев
        if (wclass.find(L"overlay") != std::wstring::npos ||
            wclass.find(L"layer") != std::wstring::npos ||
            wclass.find(L"transparent") != std::wstring::npos) {
            suspiciousPoints += 2;
        }

        // Классы, типичные для читов
        if (wclass.find(L"cheat") != std::wstring::npos ||
            wclass.find(L"hack") != std::wstring::npos ||
            wclass.find(L"inject") != std::wstring::npos) {
            suspiciousPoints += 5;  // Почти точно чит
        }
    }

    return suspiciousPoints >= 4;  // Порог подозрительности
}
bool InvisibleOverlay::IsSystemWindow(HWND hwnd) const {
    if (!hwnd) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    // Системные процессы
    if (pid == 0 || pid == 4) return true;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    WCHAR exePath[MAX_PATH] = { 0 };
    bool isSystem = false;

    if (GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
        std::wstring path = to_lower(exePath);

        if (path.find(L"\\windows\\") != std::wstring::npos ||
            path.find(L"\\program files") != std::wstring::npos ||
            path.find(L"system32") != std::wstring::npos ||
            path.find(L"syswow64") != std::wstring::npos) {
            isSystem = true;
        }
    }

    CloseHandle(hProcess);
    return isSystem;
}
std::string InvisibleOverlay::GetWindowInfo(HWND hwnd) const {
    if (!hwnd) return "NULL";

    std::stringstream ss;
    ss << "HWND:0x" << std::hex << reinterpret_cast<long long>(hwnd) << std::dec;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    ss << " PID:" << pid;

    WCHAR className[256] = { 0 };
    if (GetClassNameW(hwnd, className, 256)) {
        ss << " Class:" << wstring_to_string(className);
    }

    WCHAR title[256] = { 0 };
    if (GetWindowTextW(hwnd, title, 256) && wcslen(title) > 0) {
        ss << " Title:" << wstring_to_string(title);
    }

    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    if (exStyle & WS_EX_TOPMOST) ss << " TOPMOST";

    RECT rect;
    if (GetWindowRect(hwnd, &rect)) {
        ss << " Size:" << (rect.right - rect.left) << "x" << (rect.bottom - rect.top);
    }

    return ss.str();
}
std::string InvisibleOverlay::GetProcessInfo(DWORD pid) const {
    std::stringstream ss;
    ss << "PID:" << pid;

    ProcessInfo info = GetDetailedProcessInfo(pid);

    if (!info.name.empty()) {
        ss << " Process:" << wstring_to_string(info.name);
        ss << " Path:" << wstring_to_string(info.path);
    }

    // Проверяем тип процесса
    std::wstring wexeName = to_lower(info.name);
    if (m_safeOverlayProcesses.find(wexeName) != m_safeOverlayProcesses.end()) {
        ss << " [SAFE_OVERLAY]";
    }
    else if (m_suspiciousOverlayProcesses.find(wexeName) != m_suspiciousOverlayProcesses.end()) {
        ss << " [SUSPICIOUS_OVERLAY]";
    }

    // Проверяем безопасность пути
    if (IsSafePath(info.path)) {
        ss << " [SAFE_PATH]";
    }
    else {
        ss << " [UNSAFE_PATH]";
    }

    // Добавляем информацию о подозрительности
    if (IsSuspiciousProcess(pid)) {
        ss << " [SUSPICIOUS]";
    }

    if (!info.companyName.empty()) {
        ss << " | Company:" << wstring_to_string(info.companyName);
    }

    return ss.str();
}
std::string InvisibleOverlay::GetStatus() const {
    std::stringstream ss;
    ss << "Overlay:" << (m_hwnd ? "CREATED" : "NOT_CREATED");

    if (m_hwnd) {
        LONG exStyle = GetWindowLongW(m_hwnd, GWL_EXSTYLE);
        ss << " TOPMOST:" << ((exStyle & WS_EX_TOPMOST) ? "YES" : "NO");
    }

    ss << " ZorderAttacks:" << m_zorderAttackCount;
    ss << " DefenseLevel:" << m_defenseLevel;
    ss << " Protection:" << (m_running ? "ACTIVE" : "INACTIVE");
    ss << " UnderAttack:" << (m_underAttack ? "YES" : "NO");

    if (!m_lastAttackWindow.empty()) {
        ss << " LastAttack:" << m_lastAttackWindow;
    }

    auto now = std::chrono::steady_clock::now();
    auto timeSinceAttack = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_lastAttackTime).count();
    ss << " SecSinceAttack:" << timeSinceAttack;

    ss << " SafePaths:" << m_safePaths.size();
    ss << " CacheSize:" << m_suspiciousProcessCache.size();

    return ss.str();
}
void InvisibleOverlay::EscalateDefense() {
    if (m_defenseLevel < DEFENSE_NUCLEAR) {
        m_defenseLevel = static_cast<ZOrderDefenseLevel>(m_defenseLevel + 1);
        m_lastDefenseChange = std::chrono::steady_clock::now();
        LogError("Defense escalated to level: " + std::to_string(m_defenseLevel));
    }
}
void InvisibleOverlay::DemoteDefense() {
    if (m_defenseLevel > DEFENSE_NORMAL) {
        m_defenseLevel = static_cast<ZOrderDefenseLevel>(m_defenseLevel - 1);
        m_lastDefenseChange = std::chrono::steady_clock::now();
        LogError("Defense demoted to level: " + std::to_string(m_defenseLevel));
    }
}
void InvisibleOverlay::ApplyWindowAttributes() {
    if (!m_hwnd) return;

    // Прозрачность
    SetLayeredWindowAttributes(m_hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY | LWA_ALPHA);

    // Отключаем эффекты Aero
    if (IsWindowsVistaOrGreater()) {
        DWMNCRENDERINGPOLICY policy = DWMNCRP_DISABLED;
        DwmSetWindowAttribute(m_hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));

        BOOL disableTransitions = TRUE;
        DwmSetWindowAttribute(m_hwnd, DWMWA_TRANSITIONS_FORCEDISABLED,
            &disableTransitions, sizeof(disableTransitions));
    }
}
bool InvisibleOverlay::VerifyTopMostStatus() const {
    if (!m_hwnd) return false;

    LONG exStyle = GetWindowLongW(m_hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOPMOST) != 0;
}
LRESULT CALLBACK InvisibleOverlay::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    InvisibleOverlay* pThis = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = reinterpret_cast<InvisibleOverlay*>(pCreate->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    }
    else {
        pThis = reinterpret_cast<InvisibleOverlay*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }

    if (pThis) {
        switch (msg) {
        case WM_WINDOWPOSCHANGING:
        {
            WINDOWPOS* wp = reinterpret_cast<WINDOWPOS*>(lParam);
            if (!(wp->flags & SWP_NOZORDER)) {
                wp->hwndInsertAfter = HWND_TOPMOST;
            }
            break;
        }

        case WM_ACTIVATE:
            if (LOWORD(wParam) != WA_INACTIVE) {
                return 0;
            }
            break;

        case WM_ERASEBKGND:
            return TRUE;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rect;
            GetClientRect(hwnd, &rect);
            HBRUSH hBrush = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &rect, hBrush);
            DeleteObject(hBrush);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_DESTROY:
            pThis->m_hwnd = nullptr;
            PostQuitMessage(0);
            return 0;
        }
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}