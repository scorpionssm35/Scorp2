#pragma once
#include <atomic>
#include <cstdint>
extern BDSuspicionMetrics g_suspicionMetrics;
extern std::atomic<int> g_cameraFailures;
extern std::atomic<uintptr_t> g_globalEntityArray; 