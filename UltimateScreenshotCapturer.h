#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <atomic>
#include <memory>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <d3d11.h>

class InvisibleOverlay;
extern std::string Name_Window;
extern int SaveScreenshotToDiskCount;

class UltimateScreenshotCapturer {
private:
    HWND m_gameWindow;
    std::atomic<bool> m_initialized{ false };
    std::unique_ptr<InvisibleOverlay> m_overlay;

    // DXGI Desktop Duplication
    ID3D11Device* m_d3dDevice;
    ID3D11DeviceContext* m_d3dContext;
    IDXGIOutputDuplication* m_dxgiDuplication;
    bool m_dxgiInitialized;
    int m_screenWidth;
    int m_screenHeight;
    // НОВЫЕ ПОЛЯ (добавить после существующих)
    bool m_overlayDebug = false;
    bool m_drawOverlayInfo = true;

    HWND m_bestWindow = nullptr; 
    int  m_bestArea = 0;         

    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);

    // НОВЫЕ МЕТОДЫ (добавить после существующих)
    void DrawOverlayOnScreenshot(std::vector<BYTE>& imageData, int width, int height);
    void DrawRectangle(std::vector<BYTE>& imageData, int x, int y, int w, int h,
        BYTE r, BYTE g, BYTE b, int thickness, int width, int height);
    void DrawText(std::vector<BYTE>& imageData, int x, int y, const std::string& text,
        BYTE r, BYTE g, BYTE b, int width, int height);
public:

    void ReleaseDXGIResources();

    UltimateScreenshotCapturer();
    ~UltimateScreenshotCapturer();

    bool Initialize();
    void Shutdown();

    bool CreateAndSaveScreenshot();
    bool CreateAndSendScreenshot(const std::string& serverIP, int port,
        const std::string& clientID, const std::string& infouser, const std::wstring& serviceName);

    bool RestartWindowsService(LPCWSTR serviceName);
    bool IsOverlayUnderAttack() const;
    void SetGameWindow(HWND window) { m_gameWindow = window; }
    bool ShouldCapture() const;
    bool IsGameActive() const;
    bool IsGameWindowValid(HWND hwnd) const;
    HWND FindDayZWindow();
    HWND FindSpecificDayZWindow() const;
    bool CaptureTiledSlowDXGI(std::vector<BYTE>& output, int tilesX = 4, int tilesY = 4, int minDelayMs = 80, int maxDelayMs = 250);
private:
    // DXGI методы
    bool InitializeDXGICapture();
    bool CaptureViaDXGI(std::vector<BYTE>& output);
    bool CaptureCombinedModern(std::vector<BYTE>& output);
    void DetectOverlayCheats(const std::vector<BYTE>& modernCapture, const std::vector<BYTE>& legacyCapture);
    void DetectForeignOverlays();

    // Legacy методы
    bool CaptureViaOverlay(std::vector<BYTE>& output);
    bool CaptureFullScreen(std::vector<BYTE>& output);
    bool CaptureViaGDI(std::vector<BYTE>& output);
    bool CombinedCapture(std::vector<BYTE>& output);
    bool CombinedCaptureLegacy(std::vector<BYTE>& output);
    bool CaptureFullScreenRaw(std::vector<BYTE>& output);

    // Helper методы
    void ExtractRegionFromFullScreen(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight,
        std::vector<BYTE>& dest, int startX, int startY, int size);
    void ExtractRegion(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight,
        std::vector<BYTE>& dest, int startX, int startY, int size);
    bool SaveAsJPG(const std::vector<BYTE>& imageData, std::vector<BYTE>& jpgOutput);
    bool SaveToDisk(const std::vector<BYTE>& jpgData);
    bool SendToServerSimple(const std::vector<BYTE>& jpgData, const std::string& serverIP, int port,
    const std::string& clientID, const std::string& infouser, const std::wstring& serviceName);
    int GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
    std::string GetScreenshotPath();
    void AntiDetectionMeasures();
    bool InitializeOverlay();
    RECT GetGameWindowRect();
    POINT GetGameSightCenter();

    void LogDetailedOverlaySource(); 
};