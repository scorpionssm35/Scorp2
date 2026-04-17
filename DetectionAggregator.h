#pragma once
#include <cstdint>
class DetectionAggregator {
public:
    enum class PlayerRiskLevel : uint8_t {
        Low = 0,      // 0Ц39   Ч ничего не делаем
        Medium = 1,   // 40Ц69  Ч просто логируем тихо
        High = 2      // 70+    Ч опасен: скрин + алерт + —Ѕ–ќ— скора
    };
    void NotifyDangerousPlayer(uint64_t entityId);
};
extern DetectionAggregator g_detectionAggregator;