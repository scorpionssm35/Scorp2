#define NOMINMAX
#include <Windows.h>
#include <cmath>
#include <chrono>
#include "LocalProvider.h"
#include "LogUtils.h"
#include "EntityPosSampler.h"
#include <mutex>
#include "StabilityMonitor.h"

extern StabilityMonitor g_globalStabilityMonitor;
static uintptr_t g_world = 0;
static std::atomic<uintptr_t> g_currentWorld{ 0 };
static std::mutex g_cameraMutex;
static int g_prevAmmo = -1;
static bool g_havePrev = false;
extern std::atomic<float> g_playerX;
extern std::atomic<float> g_playerY;
extern std::atomic<float> g_playerZ;
static std::chrono::steady_clock::time_point g_lastFireTp{};
static constexpr int FIRE_DEBOUNCE_MS = 120;

void LP_SetWorld(uintptr_t world) {
    g_currentWorld.store(world);
}
void LP_ValidateWorldPointer(uintptr_t expectedWorld) {
    if (g_currentWorld.load() != expectedWorld && expectedWorld != 0) {
        g_currentWorld.store(expectedWorld);
    }
}
bool LP_GetCameraWithRetry(float outPos[3], float outFwd[3], int maxRetries) {
    std::lock_guard<std::mutex> lock(g_cameraMutex);

    for (int attempt = 0; attempt < maxRetries; attempt++) {
        if (LP_GetCamera(outPos, outFwd)) {
            g_globalStabilityMonitor.ReportCameraSuccess();
            return true;
        }

        if (attempt < maxRetries - 1) {
            if (g_globalStabilityMonitor.ShouldAttemptRecovery()) {
                uintptr_t currentWorld = g_currentWorld.load();
                if (IsValidAddress(currentWorld)) {
                    LP_SetWorld(currentWorld);
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5 * (attempt + 1)));
        }
    }

    g_globalStabilityMonitor.ReportCameraFailure();
    return false;
}
static inline bool ReadPtrX(uintptr_t addr, void* out, size_t sz) {
    SIZE_T br = 0; return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, out, sz, &br) && br == sz;
}
static bool ReadVec3(uintptr_t addr, float out[3]) { return ReadPtrX(addr, out, sizeof(float) * 3); }
static bool IsCenteredCoordinateSystem(const std::string& worldName) {
    const std::vector<std::string> zeroBasedMaps = {
        "alteria", "iztek", "chiemsee", "anastara", "banov", "enoch", "livonia"
    };

    for (const auto& map : zeroBasedMaps) {
        if (worldName.find(map) != std::string::npos) {
            return false;
        }
    }

    return true;
}
static bool IsValidPosition(float x, float y, float z) {
    static auto mapConfig = CreateMapConfig();
    static int coordinateSystem = -1;
    static std::string lastWorldName = "";

    std::string worldName = EPS::EPS_GetWorldName();
    float worldSize = EPS::EPS_GetWorldSize();

    if (worldName != lastWorldName) {
        coordinateSystem = -1;
        lastWorldName = worldName;
    }

    if (coordinateSystem == -1 && mapConfig.find(worldName) != mapConfig.end()) {
        coordinateSystem = (mapConfig[worldName] == "zero") ? 0 : 1;
    }

    if (coordinateSystem == -1) {
        if (x >= 0.0f && x <= worldSize && z >= 0.0f && z <= worldSize) {
            coordinateSystem = 0;
        }
        else {
            coordinateSystem = 1;
        }

        mapConfig[worldName] = (coordinateSystem == 0) ? "zero" : "centered";
    }

    if (coordinateSystem == 0) {
        return std::isfinite(x) && std::isfinite(y) && std::isfinite(z) &&
            x >= 0.0f && x <= worldSize &&
            y > -1000.0f && y < 10000.0f &&
            z >= 0.0f && z <= worldSize &&
            !(fabsf(x) < 0.1f && fabsf(z) < 0.1f);
    }
    else {
        float halfWorldSize = worldSize * 0.5f;
        return std::isfinite(x) && std::isfinite(y) && std::isfinite(z) &&
            x > -halfWorldSize && x < halfWorldSize &&
            y > -1000.0f && y < 10000.0f &&
            z > -halfWorldSize && z < halfWorldSize &&
            !(fabsf(x) < 0.1f && fabsf(z) < 0.1f);
    }
}
bool LP_GetCamera(float outPos[3], float outFwd[3]) {
    static int totalAttempts = 0;
    static int successCount = 0;

    uintptr_t world = g_currentWorld.load();
    totalAttempts++;

    if (!IsValidAddress(world)) {
        return false;
    }

    uintptr_t cam = 0;
    if (!ReadPtrX(world + OFFSET_WORLD_CAMERA, &cam, sizeof(cam)) || !IsValidAddress(cam)) {
        return false;
    }

    if (cam < 0x10000 || cam > 0x7FFFFFFFFFFF) {
        return false;
    }

    float invTrans[3] = { 0,0,0 }, invFwd[3] = { 1,0,0 };

    if (!ReadVec3(cam + OFFSET_CAMERA_INV_TRANSL, invTrans)) {
        return false;
    }

    if (!ReadVec3(cam + OFFSET_CAMERA_INV_FWD, invFwd)) {
        return false;
    }

    if (!IsValidPosition(invTrans[0], invTrans[1], invTrans[2])) {
        return false;
    }

    memcpy(outPos, invTrans, sizeof(float) * 3);

    float len2 = invFwd[0] * invFwd[0] + invFwd[1] * invFwd[1] + invFwd[2] * invFwd[2];
    if (len2 <= 1e-12f) {
        outFwd[0] = 1.0f; outFwd[1] = 0.0f; outFwd[2] = 0.0f;
    }
    else {
        float invLen = 1.0f / std::sqrt(len2);
        outFwd[0] = invFwd[0] * invLen;
        outFwd[1] = invFwd[1] * invLen;
        outFwd[2] = invFwd[2] * invLen;
    }
    successCount++;

    g_playerX.store(outPos[0]);
    g_playerY.store(outPos[1]);
    g_playerZ.store(outPos[2]);

    return true;
}
static void ForwardToYawPitch(const float fwd[3], float& yawDeg, float& pitchDeg) {
    const float x = fwd[0], y = fwd[1], z = fwd[2];
    const float yaw = std::atan2f(z, x);
    const float hz = std::sqrt(std::max(0.0f, x * x + z * z));
    const float pitch = std::atan2f(-y, hz);

    yawDeg = yaw * 180.0f / 3.14159265f;
    pitchDeg = pitch * 180.0f / 3.14159265f;

    if (yawDeg < -180.0f) yawDeg += 360.0f;
    if (yawDeg > 180.0f) yawDeg -= 360.0f;
}
static bool ReadInt32(uintptr_t addr, int& out) {
    SIZE_T br = 0;
    return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, &out, sizeof(out), &br) && br == sizeof(out);
}
static bool ReadLocalAmmoCount(int& ammoOut) {
    ammoOut = -1;
    if (!IsValidAddress(g_world)) return false;

    uintptr_t localPlayer = 0;
    if (!SafeReadPtr(g_world + OFFSET_LOCALPLAYER_PTR, localPlayer) || !IsValidAddress(localPlayer))
        return false;

    uintptr_t weapon = 0;
    if (!SafeReadPtr(localPlayer + OFFSET_PLAYER_ITEMINHANDS, weapon) || !IsValidAddress(weapon))
        return false;

    uintptr_t magRef = 0;
    if (!SafeReadPtr(weapon + OFFSET_WEAPONINV_MAGREF, magRef) || !IsValidAddress(magRef))
        return false;

    int ammo = -1;
    if (!ReadInt32(magRef + OFFSET_MAG_AMMOCOUNT, ammo))
        return false;

    ammoOut = ammo;
    return true;
}
static bool DetectFiredByAmmo() {
    int ammo = -1;
    if (!ReadLocalAmmoCount(ammo)) return false;

    auto now = std::chrono::steady_clock::now();
    if (!g_havePrev) {
        g_prevAmmo = ammo;
        g_havePrev = true;
        return false;
    }

    if (ammo > g_prevAmmo) {
        g_prevAmmo = ammo;
        return false;
    }

    if (ammo >= 0 && g_prevAmmo >= 0 && ammo < g_prevAmmo) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastFireTp).count();
        g_prevAmmo = ammo;
        if (elapsed >= FIRE_DEBOUNCE_MS) {
            g_lastFireTp = now;
            return true;
        }
        return false;
    }

    g_prevAmmo = ammo;
    return false;
}
bool GetLocalSnapshot(BDLocalSnapshot& out) {
    uintptr_t world = g_currentWorld.load();

    if (!IsValidAddress(world)) {
        g_globalStabilityMonitor.ReportCameraFailure();
        return false;
    }

    float pos[3], fwd[3];
    if (!LP_GetCameraWithRetry(pos, fwd, 2)) {
        g_globalStabilityMonitor.ReportCameraFailure();
        return false;
    }

    g_globalStabilityMonitor.ReportCameraSuccess();
    out.pos = { pos[0], pos[1], pos[2] };

    float yaw, pitch;
    ForwardToYawPitch(fwd, yaw, pitch);
    out.yaw = yaw;
    out.pitch = pitch;

    out.fired = DetectFiredByAmmo();
    out.weaponId = 0;
    out.ads = false;
    out.stance = 0;
    out.pingMs = 0;

    return true;
}
bool LP_IsZeroBasedMap(const std::string& worldName) {
    static auto config = CreateMapConfig();
    for (const auto& configEntry : config) {
        const std::string& mapName = configEntry.first;
        const std::string& coordSystem = configEntry.second;

        if (worldName.find(mapName) != std::string::npos) {
            return coordSystem == "zero";
        }
    }
    return false;
}