package com.example.envscope.detection

enum class DetectionArea(val label: String) {
    FRIDA("Frida"),
    XPOSED("Xposed"),
    PROCESS("进程/调试"),
    SYSTEM("系统环境"),
    NATIVE("Native")
}

enum class Severity(val label: String, val score: Int) {
    INFO("信息", 0),
    LOW("低", 1),
    MEDIUM("中", 2),
    HIGH("高", 3),
    CRITICAL("严重", 4)
}

data class DetectionCheck(
    val id: String,
    val area: DetectionArea,
    val title: String,
    val detail: String,
    val severity: Severity,
    val hit: Boolean,
    val evidence: List<String> = emptyList(),
    val note: String? = null
)

data class ScanReport(
    val startedAtMillis: Long,
    val finishedAtMillis: Long,
    val checks: List<DetectionCheck>
) {
    val hits: List<DetectionCheck> = checks.filter { it.hit }
    val durationMillis: Long = finishedAtMillis - startedAtMillis

    val riskScore: Int = hits.sumOf { it.severity.score.coerceAtLeast(1) }

    val riskLabel: String = when {
        hits.any { it.severity == Severity.CRITICAL } || riskScore >= 10 -> "高危"
        riskScore >= 5 -> "高"
        riskScore >= 2 -> "中"
        riskScore == 1 -> "低"
        else -> "未发现明显风险"
    }
}
