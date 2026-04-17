#include "UltimateScreenshotCapturer.h"
#include "InvisibleOverlay.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <shlobj.h>
#include <algorithm>
#include <random>
#include <thread>
#include <dwmapi.h>
#include <Gdiplus.h>
#include "LogUtils.h"
#include "dllmain.h"
#include "DetectionAggregator.h"
#include <WinTrust.h>
#include <SoftPub.h>
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")

static ULONG_PTR g_gdiplusToken = 0;
static bool g_gdiplusInitialized = false;
bool InitializeGDIPlus() {
    if (g_gdiplusInitialized) return true;

    GdiplusStartupInput gdiplusStartupInput;
    if (GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL) == Ok) {
        g_gdiplusInitialized = true;
        return true;
    }
    return false;
}
void ShutdownGDIPlus() {
    if (g_gdiplusInitialized) {
        GdiplusShutdown(g_gdiplusToken);
        g_gdiplusInitialized = false;
    }
}
inline std::string HResultToString(HRESULT hr)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << hr;
    return ss.str();
}
UltimateScreenshotCapturer::UltimateScreenshotCapturer()
    : m_gameWindow(nullptr),
    m_d3dDevice(nullptr),
    m_d3dContext(nullptr),
    m_dxgiDuplication(nullptr),
    m_dxgiInitialized(false),
    m_screenWidth(0),
    m_screenHeight(0)
{
    InitializeGDIPlus();
}
UltimateScreenshotCapturer::~UltimateScreenshotCapturer() {
    Shutdown();
    ShutdownGDIPlus();
}
bool UltimateScreenshotCapturer::Initialize() {
    if (m_initialized) return true;

   // Log("[LOGEN] Screenshot capturer: looking for DayZ window...");

    // Пытаемся найти окно несколько раз
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) {
           // LogFormat("[LOGEN] Window not found, retry %d/5...", attempt + 1);
            Sleep(2000);
        }

        if (!m_gameWindow) {
            m_gameWindow = FindDayZWindow();
        }

        if (m_gameWindow) {
            m_initialized = true;
           // Log("[LOGEN] Screenshot capturer initialized: Window found");
            return true;
        }
    }
    Log("[LOGEN] WARNING: DayZ window not found, but trying fallback capture");
    m_initialized = true; 
    return true;         
}
void UltimateScreenshotCapturer::Shutdown() {
    m_initialized = false;

    if (m_overlay) {
        m_overlay->Destroy();
        m_overlay.reset();  
    }
    ReleaseDXGIResources();     
}
bool UltimateScreenshotCapturer::InitializeDXGICapture()
{
    ReleaseDXGIResources();  // всегда полный сброс

   // Log("[LOGEN] Initializing DXGI Desktop Duplication...");

    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0
    };

    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        featureLevels, ARRAYSIZE(featureLevels),
        D3D11_SDK_VERSION, &m_d3dDevice, nullptr, &m_d3dContext);

    if (FAILED(hr)) {
        Log("[LOGEN] Failed to create D3D11 device: " + HResultToString(hr));
        return false;
    }

    IDXGIDevice* dxgiDevice = nullptr;
    hr = m_d3dDevice->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGI device: " + HResultToString(hr));
        return false;
    }

    IDXGIAdapter* dxgiAdapter = nullptr;
    hr = dxgiDevice->GetAdapter(&dxgiAdapter);
    dxgiDevice->Release();
    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGI adapter: " + HResultToString(hr));
        return false;
    }

    // Выбор монитора по окну DayZ
    IDXGIOutput* dxgiOutput = nullptr;
    RECT gameRect = {};
    bool foundCorrectOutput = false;

    if (m_gameWindow && GetWindowRect(m_gameWindow, &gameRect)) {
        for (UINT i = 0; dxgiAdapter->EnumOutputs(i, &dxgiOutput) != DXGI_ERROR_NOT_FOUND; ++i) {
            DXGI_OUTPUT_DESC desc;
            if (SUCCEEDED(dxgiOutput->GetDesc(&desc))) {
                POINT center = { (gameRect.left + gameRect.right) / 2, (gameRect.top + gameRect.bottom) / 2 };
                if (PtInRect(&desc.DesktopCoordinates, center)) {
                    Log("[LOGEN] Found correct output for DayZ window (monitor " + std::to_string(i) + ")");
                    foundCorrectOutput = true;
                    break;
                }
            }
            dxgiOutput->Release();
            dxgiOutput = nullptr;
        }
    }

    if (!foundCorrectOutput) {
        dxgiAdapter->EnumOutputs(0, &dxgiOutput);
        Log("[LOGEN] Using primary monitor as fallback");
    }

    if (!dxgiOutput) {
        Log("[LOGEN] Failed to get any DXGI output");
        dxgiAdapter->Release();
        return false;
    }

    DXGI_OUTPUT_DESC outputDesc;
    dxgiOutput->GetDesc(&outputDesc);
    m_screenWidth = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
    m_screenHeight = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;

    IDXGIOutput1* dxgiOutput1 = nullptr;
    hr = dxgiOutput->QueryInterface(__uuidof(IDXGIOutput1), (void**)&dxgiOutput1);
    dxgiOutput->Release();
    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGIOutput1: " + HResultToString(hr));
        dxgiAdapter->Release();
        return false;
    }
    for (int initAttempt = 0; initAttempt < 4; ++initAttempt)   // +1 попытка
    {
        if (initAttempt > 0) {
            Log("[LOGEN] DuplicateOutput failed, retry " + std::to_string(initAttempt + 1) + " after extra sleep");
            std::this_thread::sleep_for(std::chrono::milliseconds(600));  // ← увеличил с 350 до 600
        }

        hr = dxgiOutput1->DuplicateOutput(m_d3dDevice, &m_dxgiDuplication);

        if (SUCCEEDED(hr))
        {
            DXGI_OUTDUPL_DESC duplDesc{};
            m_dxgiDuplication->GetDesc(&duplDesc);
            Log("[LOGEN] DXGI capture initialized: " + std::to_string(m_screenWidth) + "x" + std::to_string(m_screenHeight) +
                " (mode: " + std::to_string(duplDesc.ModeDesc.Width) + "x" + std::to_string(duplDesc.ModeDesc.Height) +
                ", rot: " + std::to_string((int)duplDesc.Rotation) + ", sysmem: " + (duplDesc.DesktopImageInSystemMemory ? "YES" : "NO") + ")");
            m_dxgiInitialized = true;
            dxgiOutput1->Release();
            dxgiAdapter->Release();
            return true;
        }

       // Log("[LOGEN] DuplicateOutput failed (attempt " + std::to_string(initAttempt + 1) + "): " + HResultToString(hr));
    }

    dxgiOutput1->Release();
    dxgiAdapter->Release();
    Log("[LOGEN] Desktop duplication failed after 4 attempts: " + HResultToString(hr));
    return false;
}
bool UltimateScreenshotCapturer::CaptureViaDXGI(std::vector<BYTE>& output)
{
    output.clear();
    if (!ShouldCapture()) return false;

    Log("[LOGEN] [DXGI FORCE FULL RESET] Releasing all resources before new capture");
    ReleaseDXGIResources();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200)); // ← главное изменение (было 800)

    if (!InitializeDXGICapture())
    {
        Log("[LOGEN] DXGI re-initialization failed even after full reset");
        return false;
    }

    if (!m_dxgiDuplication)
    {
        Log("[LOGEN] No duplication interface after init");
        return false;
    }

    DXGI_OUTDUPL_FRAME_INFO frameInfo{};
    IDXGIResource* desktopResource = nullptr;
    HRESULT hr = E_FAIL;

    const int MAX_ATTEMPTS = 5;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        hr = m_dxgiDuplication->AcquireNextFrame(2000, &frameInfo, &desktopResource); // таймаут увеличен

        if (SUCCEEDED(hr))
        {
            if (frameInfo.LastPresentTime.QuadPart == 0)
            {
                Log("[LOGEN] Stale frame detected, retrying...");
                if (m_dxgiDuplication) m_dxgiDuplication->ReleaseFrame();
                continue;
            }
            break;
        }

        if (m_dxgiDuplication)
            m_dxgiDuplication->ReleaseFrame();

        if (hr == DXGI_ERROR_ACCESS_LOST)
        {
            Log("[LOGEN] ACCESS_LOST → full reset");
            ReleaseDXGIResources();
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            if (!InitializeDXGICapture()) return false;
            continue;
        }
        else if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
        {
            Log("[LOGEN] Device removed/reset - critical");
            ReleaseDXGIResources();
            return false;
        }
        else if (hr == DXGI_ERROR_WAIT_TIMEOUT)
        {
            Log("[LOGEN] Timeout on attempt " + std::to_string(attempt));
        }
        else
        {
            Log("[LOGEN] Unexpected error " + HResultToString(hr) + " on attempt " + std::to_string(attempt));
        }

        if (attempt < MAX_ATTEMPTS)
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * attempt));
    }

    if (FAILED(hr))
    {
        Log("[LOGEN] All " + std::to_string(MAX_ATTEMPTS) + " DXGI attempts failed");
        return false;
    }

    // === КОПИРОВАНИЕ (без изменений) ===
    ID3D11Texture2D* desktopTexture = nullptr;
    hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
    desktopResource->Release();

    if (FAILED(hr)) {
        if (m_dxgiDuplication) m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    D3D11_TEXTURE2D_DESC desc{};
    desktopTexture->GetDesc(&desc);

    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.MiscFlags = 0;

    ID3D11Texture2D* stagingTexture = nullptr;
    hr = m_d3dDevice->CreateTexture2D(&desc, nullptr, &stagingTexture);
    if (FAILED(hr))
    {
        desktopTexture->Release();
        if (m_dxgiDuplication) m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    m_d3dContext->CopyResource(stagingTexture, desktopTexture);
    desktopTexture->Release();

    D3D11_MAPPED_SUBRESOURCE mapped{};
    hr = m_d3dContext->Map(stagingTexture, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr))
    {
        stagingTexture->Release();
        if (m_dxgiDuplication) m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    int width = desc.Width;
    int height = desc.Height;
    output.resize(static_cast<size_t>(width) * height * 4);

    const BYTE* src = static_cast<const BYTE*>(mapped.pData);
    for (int y = 0; y < height; ++y)
    {
        memcpy(output.data() + static_cast<size_t>(y) * width * 4,
            src + static_cast<size_t>(y) * mapped.RowPitch,
            static_cast<size_t>(width) * 4);
    }

    m_d3dContext->Unmap(stagingTexture, 0);
    stagingTexture->Release();

    if (m_dxgiDuplication) m_dxgiDuplication->ReleaseFrame();

    // <<<=== ГЛАВНОЕ ИСПРАВЛЕНИЕ ===
    Log("[LOGEN] DXGI captured " + std::to_string(width) + "x" + std::to_string(height) +
        " (" + std::to_string(output.size() / 1024 / 1024) + " MB) - windowed mode");

    ReleaseDXGIResources();        // ← полностью освобождаем после УСПЕШНОГО захвата
    return true;
}
void UltimateScreenshotCapturer::ReleaseDXGIResources()
{
    if (m_dxgiDuplication)
    {
        m_dxgiDuplication->ReleaseFrame();
        m_dxgiDuplication->Release();
        m_dxgiDuplication = nullptr;
    }
    if (m_d3dContext)
    {
        m_d3dContext->ClearState();
        m_d3dContext->Flush();          
        m_d3dContext->Release();
        m_d3dContext = nullptr;
    }
    if (m_d3dDevice)
    {
        m_d3dDevice->Release();
        m_d3dDevice = nullptr;
    }
    m_dxgiInitialized = false;
}
bool UltimateScreenshotCapturer::CaptureCombinedModern(std::vector<BYTE>& output) {
    output.clear();
    if (!ShouldCapture()) {
        return false;
    }
    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    const int SIGHT_SIZE = 400;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth)  startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    // === DXGI захват ===
    std::vector<BYTE> fullDXGI;
    bool dxgiSuccess = false;

    const int MAX_DXGI_ATTEMPTS = 6;
    const int BASE_SLEEP_MS = 1000;  

    for (int attempt = 0; attempt < MAX_DXGI_ATTEMPTS; ++attempt)
    {
        if (attempt > 0)
        {
            Log("[LOGEN] DXGI retry attempt " + std::to_string(attempt + 1) + " (sleep " + std::to_string(BASE_SLEEP_MS * (attempt + 1)) + "ms)...");
            std::this_thread::sleep_for(std::chrono::milliseconds(BASE_SLEEP_MS * (attempt + 1)));
        }

        if (CaptureViaDXGI(fullDXGI))
        {
            dxgiSuccess = true;
            //Log("[LOGEN] DXGI capture successful on attempt " + std::to_string(attempt + 1));
            break;
        }
    }

    if (!dxgiSuccess)
    {
       // Log("[LOGEN] All DXGI attempts failed, falling back to legacy");
        ReleaseDXGIResources();
        return CombinedCaptureLegacy(output);
    }

    // Extract sight area from DXGI capture
    std::vector<BYTE> sightArea(SIGHT_SIZE * SIGHT_SIZE * 4);
    ExtractRegion(fullDXGI, screenWidth, screenHeight, sightArea, startX, startY, SIGHT_SIZE);

    // Try legacy capture for comparison (тоже с ретраями)
    std::vector<BYTE> legacyArea;
    bool legacySuccess = false;

    // Try overlay first (с ретраями)
    for (int attempt = 0; attempt < 2; attempt++) {
        if (m_overlay && m_overlay->IsCreated()) {
            if (CaptureViaOverlay(legacyArea)) {
                legacySuccess = true;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    // If overlay failed, try GDI (с ретраями)
    if (!legacySuccess) {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (CaptureViaGDI(legacyArea)) {
                legacySuccess = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    // Create combined image
    const int PART_WIDTH = SIGHT_SIZE;
    const int PART_HEIGHT = SIGHT_SIZE;
    const int TOTAL_WIDTH = PART_WIDTH * (legacySuccess ? 2 : 1);

    output.resize(TOTAL_WIDTH * PART_HEIGHT * 4);

    // Modern capture (left side)
    for (int y = 0; y < PART_HEIGHT; y++) {
        int srcOffset = y * PART_WIDTH * 4;
        int dstOffset = y * TOTAL_WIDTH * 4;
        if (srcOffset < sightArea.size() && dstOffset < output.size()) {
            memcpy(&output[dstOffset], &sightArea[srcOffset], PART_WIDTH * 4);
        }
    }

    // Legacy capture (right side if available)
    if (legacySuccess) {
        for (int y = 0; y < PART_HEIGHT; y++) {
            int srcOffset = y * PART_WIDTH * 4;
            int dstOffset = y * TOTAL_WIDTH * 4 + PART_WIDTH * 4;

            if (srcOffset < legacyArea.size() && dstOffset < output.size()) {
                memcpy(&output[dstOffset], &legacyArea[srcOffset], PART_WIDTH * 4);
            }
        }

        // Detect differences between captures
        DetectOverlayCheats(sightArea, legacyArea);
    }

    // Log overlay attacks if any
    if (m_overlay && m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Modern capture during Z-order attack! Defense: " +  std::to_string(m_overlay->GetDefenseLevel()));
        StartSightImgDetection("[VEH] WARNING: Modern capture during Z-order attack!");
    }

    DetectForeignOverlays();

    return !output.empty();
}
bool IsLegitimateSystemOverlay(const std::wstring& processPathW, const std::string& className, HWND hwnd)
{
    if (processPathW.empty()) return false;

    std::wstring lowerPath = processPathW;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    wchar_t sysDir[MAX_PATH] = { 0 };
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring realSystem32(sysDir);
    std::transform(realSystem32.begin(), realSystem32.end(), realSystem32.begin(), ::towlower);

    wchar_t sysWow64[MAX_PATH] = { 0 };
    GetSystemWow64DirectoryW(sysWow64, MAX_PATH);
    std::wstring realSysWow64(sysWow64);
    std::transform(realSysWow64.begin(), realSysWow64.end(), realSysWow64.begin(), ::towlower);

    bool isRealSystemPath = (lowerPath.find(realSystem32) == 0) ||
        (lowerPath.find(realSysWow64) == 0) ||
        (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) ||
        (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos);

    if (!isRealSystemPath) {
        return false;
    }

    RECT rect = {};
    if (GetWindowRect(hwnd, &rect)) {
        int w = rect.right - rect.left;
        int h = rect.bottom - rect.top;
        if (w <= 4 && h <= 4) return true;
    }

    static const std::vector<std::string> legitClasses = {
        "ThumbnailDeviceHelperWnd", "WorkerW", "Progman", "Shell_TrayWnd",
        "Shell_SecondaryTrayWnd", "MSCTFMonitorWindow", "IME", "ApplicationFrameWindow",
        "Windows.UI.Core.CoreWindow", "XamlIslandWindow", "TaskManagerWindow"
    };

    for (const auto& legit : legitClasses) {
        if (className.find(legit) != std::string::npos) {
            return true;
        }
    }

    // Проверка цифровой подписи
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = processPathW.c_str();

    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    if (WinVerifyTrust(NULL, &policyGUID, &trustData) == ERROR_SUCCESS) {
        return true;
    }
    std::string hash = CalculateFileSHA256Safe(WStringToUTF8(processPathW)); 
    if (hash == "6d560ce5e75149dffe1b67f0a9f1a0717c9996d50ef2dbf3349b251b64c3a195") {
        return true;
    }

    return false;
}
void UltimateScreenshotCapturer::LogDetailedOverlaySource() {
    struct OverlaySearchData {
        std::vector<std::string> results;
        DWORD ourPid = GetCurrentProcessId();
        HWND ourHwnd = nullptr;
    } searchData;

    if (m_overlay && m_overlay->IsCreated()) {
        searchData.ourHwnd = m_overlay->GetWindowHandle();
    }

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<OverlaySearchData*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;
        if (hwnd == data->ourHwnd) return TRUE;                    // наше окно

        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        bool isOverlayStyle = (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST)) != 0;
        if (!isOverlayStyle) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == data->ourPid) return TRUE;

        WCHAR windowTitle[256] = { 0 };
        WCHAR classNameW[256] = { 0 };
        GetWindowTextW(hwnd, windowTitle, 256);
        GetClassNameW(hwnd, classNameW, 256);

        // Конвертация в UTF-8
        char classNameUTF8[512] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, classNameW, -1, classNameUTF8, sizeof(classNameUTF8), NULL, NULL);

        WCHAR processPathW[MAX_PATH] = { 0 };
        DWORD pathSize = MAX_PATH;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            QueryFullProcessImageNameW(hProcess, 0, processPathW, &pathSize);
            CloseHandle(hProcess);
        }

        // === ПРОВЕРКА НА ЛЕГИТИМНЫЕ СИСТЕМНЫЕ ОКНА ===
        if (IsLegitimateSystemOverlay(processPathW, classNameUTF8, hwnd)) {
            return TRUE;   // Легитимное системное окно — пропускаем
        }

        // ★★★ НОВАЯ ПРОВЕРКА: ЛОГГИРУЕМ ТОЛЬКО ЕСЛИ ОКНО АТАКУЕТ Z-ORDER ★★★
        bool isZOrderAttack = false;

        // Проверяем, находится ли это окно ПОВЕРХ нашего оверлея
        if (data->ourHwnd) {
            HWND current = GetWindow(data->ourHwnd, GW_HWNDPREV);
            while (current) {
                if (current == hwnd) {
                    isZOrderAttack = true;
                    break;
                }
                current = GetWindow(current, GW_HWNDPREV);
            }
        }

        // Если окно НЕ поверх нашего — не логгируем (это просто фоновая программа)
        if (!isZOrderAttack) {
            return TRUE;
        }

        // === ТОЛЬКО РЕАЛЬНЫЕ АТАКИ НА Z-ORDER ДОХОДЯТ ДО СЮДА ===
        std::stringstream ss;
        ss << "[VEH] Z-ORDER ATTACK DETECTED: ";

        char titleUTF8[512] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, windowTitle, -1, titleUTF8, sizeof(titleUTF8), NULL, NULL);

        ss << "Title=\"" << titleUTF8 << "\"";
        ss << " | Class=\"" << classNameUTF8 << "\"";

        RECT rect = {};
        if (GetWindowRect(hwnd, &rect)) {
            ss << " | Size=" << (rect.right - rect.left) << "x" << (rect.bottom - rect.top);
        }

        if (processPathW[0] != 0) {
            char pathUTF8[512] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, processPathW, -1, pathUTF8, sizeof(pathUTF8), NULL, NULL);
            ss << " | Path=" << pathUTF8;

            // Правильная конвертация wstring → string
            std::string utf8Path = WStringToUTF8(processPathW);
            std::string hash = CalculateFileSHA256Safe(utf8Path);

            if (!hash.empty() && hash != "failed_to_read_file_or_compute_hash" && hash != "file_not_found") {
                ss << " | SHA256=" << hash;
            }
        }

        data->results.push_back(ss.str());

        // ★★★ БЛОКИРУЕМ АТАКУЮЩЕЕ ОКНО ★★★
        // Убираем TOPMOST у атакующего окна
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

        return TRUE;
        }, reinterpret_cast<LPARAM>(&searchData));

    // ЛОГГИРУЕМ ТОЛЬКО РЕАЛЬНЫЕ АТАКИ
    if (!searchData.results.empty()) {
        for (const auto& result : searchData.results) {
            Log(result);  // Логируем в консоль
            StartSightImgDetection("[VEH] Z-ORDER ATTACK: " + result);  // Скриншот
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);  // Оповещение
        }
    }
}
void UltimateScreenshotCapturer::DetectOverlayCheats(const std::vector<BYTE>& modernCapture, const std::vector<BYTE>& legacyCapture) {

    if (modernCapture.size() != legacyCapture.size() || modernCapture.empty()) {
        return;
    }

    const int SIZE = 400;
    int differences = 0;
    const int PIXEL_COUNT = SIZE * SIZE;

    // Compare pixel by pixel
    for (int i = 0; i < modernCapture.size(); i += 4) {
        // Skip if alpha channel is 0 (fully transparent)
        if (modernCapture[i + 3] == 0 && legacyCapture[i + 3] == 0) {
            continue;
        }

        // Compare RGB (ignore slight alpha differences)
        if (abs((int)modernCapture[i] - (int)legacyCapture[i]) > 10 ||      // B
            abs((int)modernCapture[i + 1] - (int)legacyCapture[i + 1]) > 10 ||  // G
            abs((int)modernCapture[i + 2] - (int)legacyCapture[i + 2]) > 10) {  // R
            differences++;
        }
    }

    // Calculate difference percentage
    double diffPercent = (double)differences / PIXEL_COUNT;

    // Log if significant difference found
    if (diffPercent > 0.7) {
        LogDetailedOverlaySource();
    }
}
void UltimateScreenshotCapturer::DetectForeignOverlays() {
    struct OverlayInfo {
        HWND hwnd;
        RECT rect;
        std::string className;
    };

    std::vector<OverlayInfo> suspiciousWindows;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* windows = reinterpret_cast<std::vector<OverlayInfo>*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;

        // Check for layered or transparent windows
        DWORD exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

        if (isLayered || isTransparent) {
            char className[256] = { 0 };
            GetClassNameA(hwnd, className, sizeof(className));

            // Ignore known system windows
            if (strstr(className, "Progman") ||
                strstr(className, "WorkerW") ||
                strstr(className, "Shell_TrayWnd") ||
                strstr(className, "Button") ||
                strstr(className, "Static") ||
                strstr(className, "Toolbar")) {
                return TRUE;
            }

            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;

                // Only log windows of reasonable size
                if (width > 50 && height > 50 && width < 5000 && height < 5000) {
                    OverlayInfo info;
                    info.hwnd = hwnd;
                    info.rect = rect;
                    info.className = className;
                    windows->push_back(info);
                }
            }
        }
        return TRUE;
        }, reinterpret_cast<LPARAM>(&suspiciousWindows));

    // Log suspicious windows
    if (!suspiciousWindows.empty()) {
        //Log("[VEH] Found " + std::to_string(suspiciousWindows.size()) + " suspicious overlay windows:");

        for (const auto& info : suspiciousWindows) {
            char title[256] = { 0 };
            GetWindowTextA(info.hwnd, title, sizeof(title));

            //Log("[VEH] overlay Window: " + std::string(title) + " | Class: " + info.className + " | Size: " + std::to_string(info.rect.right - info.rect.left) +  "x" + std::to_string(info.rect.bottom - info.rect.top));
            //StartSightImg3("[VEH] overlay Window: " + std::string(title) + " | Class: " + info.className);
        }
    }
}
bool UltimateScreenshotCapturer::CombinedCapture(std::vector<BYTE>& output)
{
    if (std::rand() % 100 < 100)   // ← 100% шанс 
    {
        std::vector<BYTE> fullTiled;
        Log("[LOGEN] Using 3rd method: TiledSlowDXGI (slow anti-detect)");

        if (CaptureTiledSlowDXGI(fullTiled, 4, 4, 80, 250))
        {
            POINT cursorPos;
            if (!GetCursorPos(&cursorPos))
            {
                cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
                cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
            }

            const int SIGHT_SIZE = 400;
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            int startX = cursorPos.x - SIGHT_SIZE / 2;
            int startY = cursorPos.y - SIGHT_SIZE / 2;
            if (startX < 0) startX = 0;
            if (startY < 0) startY = 0;
            if (startX + SIGHT_SIZE > screenWidth)  startX = screenWidth - SIGHT_SIZE;
            if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

            std::vector<BYTE> sightArea(SIGHT_SIZE * SIGHT_SIZE * 4);
            ExtractRegion(fullTiled, screenWidth, screenHeight, sightArea, startX, startY, SIGHT_SIZE);

            std::vector<BYTE> legacyArea;
            bool legacySuccess = false;

            for (int attempt = 0; attempt < 2; ++attempt)
            {
                if (m_overlay && m_overlay->IsCreated() && CaptureViaOverlay(legacyArea))
                {
                    legacySuccess = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            if (!legacySuccess)
            {
                for (int attempt = 0; attempt < 2; ++attempt)
                {
                    if (CaptureViaGDI(legacyArea))
                    {
                        legacySuccess = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
            }
            const int PART_WIDTH = SIGHT_SIZE;
            const int PART_HEIGHT = SIGHT_SIZE;
            const int TOTAL_WIDTH = PART_WIDTH * (legacySuccess ? 2 : 1);
            output.resize(TOTAL_WIDTH * PART_HEIGHT * 4);
            for (int y = 0; y < PART_HEIGHT; ++y)
            {
                int srcOffset = y * PART_WIDTH * 4;
                int dstOffset = y * TOTAL_WIDTH * 4;
                if (srcOffset < sightArea.size() && dstOffset < output.size())
                    memcpy(&output[dstOffset], &sightArea[srcOffset], PART_WIDTH * 4);
            }
            if (legacySuccess)
            {
                for (int y = 0; y < PART_HEIGHT; ++y)
                {
                    int srcOffset = y * PART_WIDTH * 4;
                    int dstOffset = y * TOTAL_WIDTH * 4 + PART_WIDTH * 4;
                    if (srcOffset < legacyArea.size() && dstOffset < output.size())
                        memcpy(&output[dstOffset], &legacyArea[srcOffset], PART_WIDTH * 4);
                }
                DetectOverlayCheats(sightArea, legacyArea);
            }

            DetectForeignOverlays();

            Log("[LOGEN] TiledSlowDXGI completed successfully");
            return !output.empty();
        }
    }
    if (CaptureCombinedModern(output))
    {
        return true;
    }
    Log("[LOGEN] DXGI + Tiled failed, using legacy method");
    if (CombinedCaptureLegacy(output))
    {
        return true;
    }

    return false;
}
void UltimateScreenshotCapturer::DrawRectangle(std::vector<BYTE>& imageData, int x, int y, int w, int h, BYTE r, BYTE g, BYTE b, int thickness, int width, int height) {
    if (imageData.empty()) return;
    x = max(0, min(x, width - 1));
    y = max(0, min(y, height - 1));
    w = min(w, width - x);
    h = min(h, height - y);
    for (int t = 0; t < thickness; t++) {
        for (int ix = x; ix < x + w; ix++) {
            int yTop = y + t;
            if (yTop < height) {
                int idx = (yTop * width + ix) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;     // Blue
                    imageData[idx + 1] = g; // Green
                    imageData[idx + 2] = r; // Red
                }
            }

            // Нижняя
            int yBottom = y + h - 1 - t;
            if (yBottom >= 0 && yBottom < height) {
                int idx = (yBottom * width + ix) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }
        }

        // Левая и правая границы
        for (int iy = y; iy < y + h; iy++) {
            // Левая
            int xLeft = x + t;
            if (xLeft < width) {
                int idx = (iy * width + xLeft) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }

            // Правая
            int xRight = x + w - 1 - t;
            if (xRight >= 0 && xRight < width) {
                int idx = (iy * width + xRight) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }
        }
    }
}
void UltimateScreenshotCapturer::DrawText(std::vector<BYTE>& imageData, int x, int y, const std::string& text, BYTE r, BYTE g, BYTE b, int width, int height) {

    if (text.empty() || x >= width || y >= height) return;

    // Создаём временный DC
    HDC hdc = CreateCompatibleDC(nullptr);
    if (!hdc) return;

    // Создаём битмап из наших данных
    HBITMAP hbm = CreateBitmap(width, height, 1, 32, imageData.data());
    if (!hbm) {
        DeleteDC(hdc);
        return;
    }

    SelectObject(hdc, hbm);

    // Настройки текста
    SetBkMode(hdc, TRANSPARENT);  // Прозрачный фон
    SetTextColor(hdc, RGB(r, g, b));

    // Рисуем текст
    TextOutA(hdc, x, y, text.c_str(), text.length());

    // Забираем изменения обратно
    GetBitmapBits(hbm, imageData.size(), imageData.data());

    // Чистка
    DeleteObject(hbm);
    DeleteDC(hdc);
}
void UltimateScreenshotCapturer::DrawOverlayOnScreenshot(std::vector<BYTE>& imageData, int width, int height) {
    if (!m_overlay || !m_drawOverlayInfo) return;

    const auto& overlays = m_overlay->GetDetectedOverlays();

    int yOffset = 2;

    for (const auto& overlay : overlays) {
        HWND hwnd = overlay.first;
        const std::string& info = overlay.second;

        // Извлекаем имя файла из пути
        std::string fileName = "unknown";
        size_t pathPos = info.find("Path: ");
        if (pathPos != std::string::npos) {
            std::string fullPath = info.substr(pathPos + 6);
            size_t lastSlash = fullPath.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                fileName = fullPath.substr(lastSlash + 1);
            }
            else {
                fileName = fullPath;
            }
            // Обрезаем слишком длинные имена
            if (fileName.length() > 15) {
                fileName = fileName.substr(0, 12) + "...";
            }
        }

        // Рисуем только имя файла
        DrawText(imageData, 2, yOffset, fileName,
            255, 0, 0, width, height); // Красный для чита
        yOffset += 8;

        // Рамка если в кадре
        RECT rect;
        if (GetWindowRect(hwnd, &rect)) {
            POINT cursorPos;
            GetCursorPos(&cursorPos);

            int sightX = cursorPos.x - width / 2;
            int sightY = cursorPos.y - height / 2;

            int windowX = rect.left - sightX;
            int windowY = rect.top - sightY;
            int windowW = rect.right - rect.left;
            int windowH = rect.bottom - rect.top;

            if (windowX + windowW > 0 && windowX < width &&
                windowY + windowH > 0 && windowY < height) {

                int drawX = max(0, windowX);
                int drawY = max(0, windowY);
                int drawW = min(windowW, width - drawX);
                int drawH = min(windowH, height - drawY);

                DrawRectangle(imageData, drawX, drawY, drawW, drawH,
                    255, 0, 0, 2, width, height);
            }
        }
    }
}
bool UltimateScreenshotCapturer::CombinedCaptureLegacy(std::vector<BYTE>& output) {
    output.clear();

    if (!ShouldCapture()) {
        return false;
    }

    // 1. Get cursor position once
    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    const int SIGHT_SIZE = 400;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Adjust position
    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth) startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    // 2. Capture full screen
    std::vector<BYTE> fullScreen;
    if (!CaptureFullScreenRaw(fullScreen)) {
        Log("[LOGEN] Failed to capture full screen");
        return false;
    }

    // 3. Extract region
    std::vector<BYTE> sightArea(SIGHT_SIZE * SIGHT_SIZE * 4);
    ExtractRegionFromFullScreen(fullScreen, screenWidth, screenHeight,
        sightArea, startX, startY, SIGHT_SIZE);

    // 4. Create combined image
    const int PART_WIDTH = 400;
    const int PART_HEIGHT = 400;
    const int TOTAL_WIDTH = PART_WIDTH * 3;

    output.resize(TOTAL_WIDTH * PART_HEIGHT * 4);

    for (int y = 0; y < PART_HEIGHT; y++) {
        int srcOffset = y * PART_WIDTH * 4;
        int dstOffset = y * TOTAL_WIDTH * 4;

        // All three parts are the same (for compatibility)
        memcpy(&output[dstOffset], &sightArea[srcOffset], PART_WIDTH * 4);
        memcpy(&output[dstOffset + PART_WIDTH * 4], &sightArea[srcOffset], PART_WIDTH * 4);
        memcpy(&output[dstOffset + PART_WIDTH * 2 * 4], &sightArea[srcOffset], PART_WIDTH * 4);
    }

    // 5. Log overlay status
    if (m_overlay && m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Legacy capture during Z-order attack! Defense: " + std::to_string(m_overlay->GetDefenseLevel()));
        StartSightImgDetection("[VEH] WARNING: Legacy capture during Z-order attack!");
    }

    return !output.empty();
}
bool UltimateScreenshotCapturer::CreateAndSaveScreenshot() {
    if (!m_initialized && !Initialize()) {
        return false;
    }
    if (!ShouldCapture()) {
        return false;
    }
    AntiDetectionMeasures();

    for (int i = 0; i < 2; i++) {
        std::vector<BYTE> sightArea;

        // Используем обновленный CombinedCapture (сначала DXGI, потом legacy)
        if (!CombinedCapture(sightArea)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        std::vector<BYTE> jpgData;
        if (!SaveAsJPG(sightArea, jpgData)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        return SaveToDisk(jpgData);
    }

    return false;
}
bool UltimateScreenshotCapturer::CreateAndSendScreenshot(const std::string& serverIP, int port, const std::string& clientID, const std::string& infouser, const std::wstring& serviceName) {
    if (!m_initialized && !Initialize()) {
        return false;
    }
    if (!ShouldCapture()) {
        return false;
    }
    AntiDetectionMeasures();

    for (int i = 0; i < 2; i++) {
        std::vector<BYTE> sightArea;

        if (!CombinedCapture(sightArea)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        std::vector<BYTE> jpgData;
        if (!SaveAsJPG(sightArea, jpgData)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        return SendToServerSimple(jpgData, serverIP, port, clientID, infouser, serviceName);
    }

    return false;
}
bool UltimateScreenshotCapturer::InitializeOverlay() {
    if (!m_overlay) {
        m_overlay = std::make_unique<InvisibleOverlay>();
    }

    bool success = m_overlay->Create();
    if (success) {
        Log("[LOGEN] Overlay system initialized");

        // ===== НОВЫЙ КОД =====
        // Включаем ядерную защиту
        m_overlay->SetKernelLevelProtection(true);

        // Сканируем скрытые оверлеи
        m_overlay->ScanForHiddenOverlays();
    }
    else {
        Log("[LOGEN] WARNING Overlay initialization failed");
    }

    return success;
}
bool UltimateScreenshotCapturer::CaptureViaOverlay(std::vector<BYTE>& output) {
    if (!ShouldCapture()) {
        return false;
    }

    if (!m_overlay || !m_overlay->IsCreated()) {
        if (!InitializeOverlay()) {
            return false;
        }
    }

    // Проверяем, не атакуют ли оверлей
    if (m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Capturing during Z-order attack!");
        StartSightImgDetection("[VEH] WARNING: Capturing during Z-order attack!");
        HWND hwnd = m_overlay->GetWindowHandle();
        if (hwnd) {
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
    }

    const int SIGHT_SIZE = 400;

    std::vector<BYTE> fullScreen;
    if (!m_overlay->CaptureThroughOverlay(fullScreen, 0, 0)) {
        return false;
    }

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth) startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    output.resize(SIGHT_SIZE * SIGHT_SIZE * 4);

    ExtractRegion(fullScreen, screenWidth, screenHeight, output, startX, startY, SIGHT_SIZE);

    return !output.empty();
}
bool UltimateScreenshotCapturer::CaptureFullScreenRaw(std::vector<BYTE>& output) {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) {
        Log("[LOGEN] GetDC failed");
        return false;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] CreateCompatibleDC failed");
        return false;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] CreateCompatibleBitmap failed");
        return false;
    }

    SelectObject(hdcMem, hBitmap);

    // Используем CAPTUREBLT для захвата layered окон
    BOOL result = BitBlt(hdcMem, 0, 0, screenWidth, screenHeight,
        hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);

    if (!result) {
        DWORD err = GetLastError();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] BitBlt failed. Error: " + std::to_string(err));
        return false;
    }

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screenWidth;
    bi.biHeight = -screenHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(screenWidth * screenHeight * 4);

    int getResult = GetDIBits(hdcMem, hBitmap, 0, screenHeight,
        output.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    if (getResult == 0) {
        Log("[LOGEN] GetDIBits failed");
        output.clear();
    }

    return (getResult != 0);
}
void UltimateScreenshotCapturer::ExtractRegionFromFullScreen(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight, std::vector<BYTE>& dest, int startX, int startY, int size) {
    dest.resize(size * size * 4);

    for (int y = 0; y < size; y++) {
        int srcY = startY + y;
        if (srcY >= sourceHeight) continue;

        for (int x = 0; x < size; x++) {
            int srcX = startX + x;
            if (srcX >= sourceWidth) continue;

            int srcIdx = (srcY * sourceWidth + srcX) * 4;
            int dstIdx = (y * size + x) * 4;

            if (srcIdx + 4 <= source.size() && dstIdx + 4 <= dest.size()) {
                dest[dstIdx] = source[srcIdx];     // Blue
                dest[dstIdx + 1] = source[srcIdx + 1]; // Green
                dest[dstIdx + 2] = source[srcIdx + 2]; // Red
                dest[dstIdx + 3] = source[srcIdx + 3]; // Alpha
            }
        }
    }
}
void UltimateScreenshotCapturer::ExtractRegion(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight, std::vector<BYTE>& dest, int startX, int startY, int size) {
    dest.resize(size * size * 4);

    for (int y = 0; y < size; y++) {
        int srcY = startY + y;
        if (srcY >= sourceHeight) break;

        for (int x = 0; x < size; x++) {
            int srcX = startX + x;
            if (srcX >= sourceWidth) break;

            int srcIdx = (srcY * sourceWidth + srcX) * 4;
            int dstIdx = (y * size + x) * 4;

            if (srcIdx + 4 <= source.size() && dstIdx + 4 <= dest.size()) {
                memcpy(&dest[dstIdx], &source[srcIdx], 4);
            }
        }
    }
}
bool UltimateScreenshotCapturer::SendToServerSimple(const std::vector<BYTE>& jpgData, const std::string& serverIP, int port, const std::string& clientID, const std::string& infouser, const std::wstring& serviceName) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    hostent* host = gethostbyname(serverIP.c_str());
    if (!host) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    std::string serviceNameA(serviceName.begin(), serviceName.end());
    std::string filename = "CS2," + clientID + ".data," + " " + VerSVG + " " + infouser + " [" + serviceNameA + "]";
    int len = filename.length();
    std::vector<BYTE> header;
    while (len >= 0x80) {
        header.push_back((BYTE)(len | 0x80));
        len >>= 7;
    }
    header.push_back((BYTE)len);
    header.insert(header.end(), filename.begin(), filename.end());
    send(sock, (char*)header.data(), header.size(), 0);

    long long size = jpgData.size();
    send(sock, (char*)&size, sizeof(long long), 0);
    send(sock, (char*)jpgData.data(), jpgData.size(), 0);

    closesocket(sock);
    WSACleanup();
    return true;
}
bool UltimateScreenshotCapturer::CaptureFullScreen(std::vector<BYTE>& output) {
    const int SIGHT_WIDTH = 400;
    const int SIGHT_HEIGHT = 400;

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        return false;
    }

    int startX = cursorPos.x - SIGHT_WIDTH / 2;
    int startY = cursorPos.y - SIGHT_HEIGHT / 2;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_WIDTH > screenWidth) startX = screenWidth - SIGHT_WIDTH;
    if (startY + SIGHT_HEIGHT > screenHeight) startY = screenHeight - SIGHT_HEIGHT;

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, SIGHT_WIDTH, SIGHT_HEIGHT);

    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, SIGHT_WIDTH, SIGHT_HEIGHT, hdcScreen, startX, startY, SRCCOPY);

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = SIGHT_WIDTH;
    bi.biHeight = -SIGHT_HEIGHT;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(SIGHT_WIDTH * SIGHT_HEIGHT * 4);

    bool success = (GetDIBits(hdcMem, hBitmap, 0, SIGHT_HEIGHT, output.data(),
        (BITMAPINFO*)&bi, DIB_RGB_COLORS) != 0);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    return success && !output.empty();
}
bool UltimateScreenshotCapturer::CaptureViaGDI(std::vector<BYTE>& output) {
    const int SIGHT_WIDTH = 400;
    const int SIGHT_HEIGHT = 400;

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        return false;
    }

    int startX = cursorPos.x - SIGHT_WIDTH / 2;
    int startY = cursorPos.y - SIGHT_HEIGHT / 2;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_WIDTH > screenWidth) startX = screenWidth - SIGHT_WIDTH;
    if (startY + SIGHT_HEIGHT > screenHeight) startY = screenHeight - SIGHT_HEIGHT;

    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) {
        return false;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, SIGHT_WIDTH, SIGHT_HEIGHT);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    SelectObject(hdcMem, hBitmap);

    BOOL result = BitBlt(hdcMem, 0, 0, SIGHT_WIDTH, SIGHT_HEIGHT,
        hdcScreen, startX, startY, SRCCOPY);

    if (!result) {
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = SIGHT_WIDTH;
    bi.biHeight = -SIGHT_HEIGHT;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(SIGHT_WIDTH * SIGHT_HEIGHT * 4);

    if (GetDIBits(hdcMem, hBitmap, 0, SIGHT_HEIGHT, output.data(),
        (BITMAPINFO*)&bi, DIB_RGB_COLORS) == 0) {
        output.clear();
    }

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    return !output.empty();
}
bool UltimateScreenshotCapturer::SaveAsJPG(const std::vector<BYTE>& imageData, std::vector<BYTE>& jpgOutput) {
    if (imageData.empty()) {
        return false;
    }

    if (!g_gdiplusInitialized) {
        return false;
    }

    // Проверяем размер для современных скриншотов (800x400 или 1200x400)
    size_t width = 0;
    size_t height = 400;

    if (imageData.size() == 800 * 400 * 4) {
        width = 800;  // Современный захват (2 части)
    }
    else if (imageData.size() == 1200 * 400 * 4) {
        width = 1200; // Старый захват (3 части)
    }
    else {
        return false;
    }

    Bitmap bitmap(width, height, width * 4, PixelFormat32bppRGB, (BYTE*)imageData.data());

    if (bitmap.GetLastStatus() != Ok) {
        return false;
    }

    if (bitmap.GetWidth() == 0 || bitmap.GetHeight() == 0) {
        return false;
    }

    CLSID jpgClsid;
    if (GetEncoderClsid(L"image/jpeg", &jpgClsid) == -1) {
        return false;
    }

    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = EncoderQuality;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;

    ULONG quality = 70;
    encoderParams.Parameter[0].Value = &quality;

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        return false;
    }

    Status result = bitmap.Save(stream, &jpgClsid, &encoderParams);

    if (result != Ok) {
        stream->Release();
        return false;
    }

    HGLOBAL hGlobal = NULL;
    if (GetHGlobalFromStream(stream, &hGlobal) != S_OK) {
        stream->Release();
        return false;
    }

    BYTE* streamData = (BYTE*)GlobalLock(hGlobal);
    SIZE_T streamSize = GlobalSize(hGlobal);

    if (!streamData || streamSize == 0) {
        GlobalUnlock(hGlobal);
        stream->Release();
        return false;
    }

    jpgOutput.assign(streamData, streamData + streamSize);

    GlobalUnlock(hGlobal);
    stream->Release();

    return true;
}
bool UltimateScreenshotCapturer::SaveToDisk(const std::vector<BYTE>& jpgData) {
    if (jpgData.empty()) {
        return false;
    }

    std::string filePath = GetScreenshotPath();

    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(filePath.c_str());
    }

    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(jpgData.data()), jpgData.size());
    file.close();

    SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN);

    return true;
}
int UltimateScreenshotCapturer::GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;
    UINT size = 0;

    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)malloc(size);
    if (pImageCodecInfo == NULL) return -1;

    GetImageEncoders(num, size, pImageCodecInfo);

    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return i;
        }
    }

    free(pImageCodecInfo);
    return -1;
}
std::string UltimateScreenshotCapturer::GetScreenshotPath() {
    char localAppDataPath[MAX_PATH];
    std::string screenshotDir;

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath))) {
        screenshotDir = std::string(localAppDataPath) + "\\" + Name_Window;
    }

    CreateDirectoryA(screenshotDir.c_str(), nullptr);

    return screenshotDir + "\\DayZ.jpg";
}
void UltimateScreenshotCapturer::AntiDetectionMeasures() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));

    GetTickCount();
    GetCurrentThreadId();
}
BOOL CALLBACK UltimateScreenshotCapturer::EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    // Получаем указатель на текущий объект
    UltimateScreenshotCapturer* pThis = reinterpret_cast<UltimateScreenshotCapturer*>(lParam);
    if (!pThis) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;

    // Пропускаем оверлеи чита
    wchar_t className[256] = { 0 };
    GetClassNameW(hwnd, className, 256);
    if (wcsstr(className, L"HwndWrapper") ||
        wcsstr(className, L"GlowWindow") ||
        wcsstr(className, L"ThumbnailDeviceHelperWnd") ||
        wcsstr(className, L"XamlExplorerHostIslandWindow")) {
        return TRUE;
    }

    RECT rect;
    if (GetWindowRect(hwnd, &rect)) {
        int area = (rect.right - rect.left) * (rect.bottom - rect.top);
        if (area >= 800 * 600 && area > pThis->m_bestArea) {
            pThis->m_bestArea = area;
            pThis->m_bestWindow = hwnd;
        }
    }
    return TRUE;
}
HWND UltimateScreenshotCapturer::FindDayZWindow() {
    // Сброс временных переменных
    m_bestWindow = nullptr;
    m_bestArea = 0;

    // Быстрый поиск по-старому
    HWND hwnd = FindWindowA("DayZ", NULL);
    if (!hwnd && !Name_Window.empty()) {
        hwnd = FindWindowA(NULL, Name_Window.c_str());
    }
    if (hwnd && IsGameWindowValid(hwnd)) {
        LogFormat("[LOGEN] FindDayZWindow: fast search found valid window %p", hwnd);
        return hwnd;
    }

    // Робастный поиск через EnumWindows
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(this));

    if (m_bestWindow) {
        LogFormat("[LOGEN] FindDayZWindow: selected LARGE window %p (area %d px)", m_bestWindow, m_bestArea);
        return m_bestWindow;
    }

    Log("[LOGEN] FindDayZWindow: failed to find valid large game window");
    return nullptr;
}
bool UltimateScreenshotCapturer::IsGameActive() const {
    if (!m_initialized || !m_gameWindow) {
        return false;
    }

    // Защита от оверлеев чита
    wchar_t className[256] = { 0 };
    GetClassNameW(m_gameWindow, className, 256);
    if (wcsstr(className, L"HwndWrapper") || wcsstr(className, L"GlowWindow")) {
        Log("[LOGEN] IsGameActive: BAD window (GlowWindow/HwndWrapper detected)");
        return false;
    }

    if (!IsWindow(m_gameWindow) || !IsWindowVisible(m_gameWindow)) {
        return false;
    }
    if (IsIconic(m_gameWindow)) {
        return false;
    }

    RECT rect;
    if (!GetWindowRect(m_gameWindow, &rect)) {
        return false;
    }

    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    if (width < 800 || height < 600) {
        LogFormat("[LOGEN] IsGameActive: window too small (%dx%d)", width, height);
        return false;
    }

    LogFormat("[LOGEN] IsGameActive: OK - large window %dx%d", width, height);
    return true;
}
HWND UltimateScreenshotCapturer::FindSpecificDayZWindow() const {
    struct WindowSearchData {
        HWND result = nullptr;
        DWORD startTime = GetTickCount();
    } searchData;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<WindowSearchData*>(lParam);
        if (GetTickCount() - data->startTime > 1000) {
            return FALSE;
        }
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
            return TRUE;
        }
        char className[256] = { 0 };
        GetClassNameA(hwnd, className, sizeof(className));
        char windowTitle[256] = { 0 };
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        bool isLikelyDayZ = false;
        if (strstr(className, "DAYZ") != nullptr) {
            isLikelyDayZ = true;
        }
        else if (strstr(windowTitle, "DayZ") != nullptr ||
            strstr(windowTitle, "DAYZ") != nullptr) {
            isLikelyDayZ = true;
        }
        else if (!Name_Window.empty() &&
            strstr(windowTitle, Name_Window.c_str()) != nullptr) {
            isLikelyDayZ = true;
        }

        if (isLikelyDayZ) {
            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;

                if (width > 800 && height > 600) {
                    data->result = hwnd;
                    return FALSE;
                }
            }
        }

        return TRUE;
        }, reinterpret_cast<LPARAM>(&searchData));

    return searchData.result;
}
bool UltimateScreenshotCapturer::IsGameWindowValid(HWND hwnd) const {
    if (!hwnd || !IsWindow(hwnd)) return false;

    char className[256] = { 0 };
    GetClassNameA(hwnd, className, sizeof(className));

    char windowTitle[256] = { 0 };
    GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

    bool isDayZClass = (strstr(className, "DAYZ") != nullptr);
    bool isDayZTitle = (strstr(windowTitle, "DayZ") != nullptr ||
        strstr(windowTitle, "DAYZ") != nullptr);

    if (!isDayZClass && !isDayZTitle) {
        return false;
    }

    if (!IsWindowVisible(hwnd)) return false;

    if (IsIconic(hwnd)) return false;

    RECT rect;
    if (!GetWindowRect(hwnd, &rect)) return false;

    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    if (width < 800 || height < 600) {
        return false;
    }

    return true;
}
bool UltimateScreenshotCapturer::ShouldCapture() const {
    if (g_forceScreenshotMode.load()) {
        return true;
    }

    if (!m_initialized || !m_gameWindow) {
        return false;
    }

    if (!IsGameActive()) {
        return false;
    }

    if (!IsGameWindowValid(m_gameWindow)) {
        return false;
    }

    return true;
}
RECT UltimateScreenshotCapturer::GetGameWindowRect() {
    RECT rect = { 0, 0, 0, 0 };
    if (m_gameWindow && IsGameWindowValid(m_gameWindow)) {
        GetWindowRect(m_gameWindow, &rect);
    }
    else {
        rect.right = GetSystemMetrics(SM_CXSCREEN);
        rect.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    return rect;
}
POINT UltimateScreenshotCapturer::GetGameSightCenter() {
    POINT cursorPos;
    if (GetCursorPos(&cursorPos)) {
        RECT gameRect;
        if (m_gameWindow && GetWindowRect(m_gameWindow, &gameRect)) {
            if (cursorPos.x >= gameRect.left && cursorPos.x <= gameRect.right &&
                cursorPos.y >= gameRect.top && cursorPos.y <= gameRect.bottom) {
                return cursorPos;
            }
        }
        return cursorPos;
    }

    RECT windowRect = GetGameWindowRect();
    cursorPos.x = windowRect.left + (windowRect.right - windowRect.left) / 2;
    cursorPos.y = windowRect.top + (windowRect.bottom - windowRect.top) / 2;
    return cursorPos;
}
bool UltimateScreenshotCapturer::RestartWindowsService(LPCWSTR serviceName) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE service = OpenService(scm, serviceName,
        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    StartService(service, 0, NULL);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}
bool UltimateScreenshotCapturer::IsOverlayUnderAttack() const {
    return m_overlay && m_overlay->IsUnderAttack();
}

bool UltimateScreenshotCapturer::CaptureTiledSlowDXGI(std::vector<BYTE>& output, int tilesX, int tilesY, int minDelayMs, int maxDelayMs)
{
    if (tilesX < 2 || tilesY < 2) return false;

    if (!m_dxgiInitialized)
    {
        if (!InitializeDXGICapture()) return false;
    }

    if (m_screenWidth <= 0 || m_screenHeight <= 0) return false;

    std::vector<BYTE> fullBuffer(m_screenWidth * m_screenHeight * 4, 0);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> delayDist(minDelayMs, maxDelayMs);

    int tileW = (m_screenWidth + tilesX - 1) / tilesX;
    int tileH = (m_screenHeight + tilesY - 1) / tilesY;

    for (int ty = 0; ty < tilesY; ++ty)
    {
        for (int tx = 0; tx < tilesX; ++tx)
        {
            int x = tx * tileW;
            int y = ty * tileH;
            int w = (tileW < (m_screenWidth - x)) ? tileW : (m_screenWidth - x);
            int h = (tileH < (m_screenHeight - y)) ? tileH : (m_screenHeight - y);

            std::vector<BYTE> fullFrame;
            if (CaptureViaDXGI(fullFrame))
            {
                // Копируем только нужный тайл
                const int bpp = 4;
                for (int row = 0; row < h; ++row)
                {
                    int globalY = y + row;
                    if (globalY >= m_screenHeight) break;
                    BYTE* dest = fullBuffer.data() + (globalY * m_screenWidth * bpp) + (x * bpp);
                    BYTE* src = fullFrame.data() + (globalY * m_screenWidth * bpp) + (x * bpp);
                    memcpy(dest, src, static_cast<size_t>(w * bpp));
                }
            }

            if (ty * tilesY + tx < tilesX * tilesY - 1)
            {
                int delay = delayDist(rng);
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }
        }
    }

    output = std::move(fullBuffer);
    return true;
}