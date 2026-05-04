package com.example.envscope

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.envscope.databinding.ActivityMainBinding
import com.example.envscope.detection.DetectionCheck
import com.example.envscope.detection.EnvironmentScanner
import com.example.envscope.detection.ScanReport
import com.example.envscope.detection.Severity
import com.google.android.material.R as MaterialR

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.scanButton.setOnClickListener { runScan() }
        runScan()
    }

    private fun runScan() {
        binding.scanButton.isEnabled = false
        binding.summaryText.text = "正在扫描当前运行环境..."
        binding.resultContainer.removeAllViews()

        Thread {
            val report = EnvironmentScanner.scan(this@MainActivity) {
                collectNativeSignals().toList()
            }
            runOnUiThread {
                renderReport(report)
                binding.scanButton.isEnabled = true
            }
        }.start()
    }

    private fun renderReport(report: ScanReport) {
        binding.summaryText.text = buildString {
            append("风险等级：${report.riskLabel}\n")
            append("命中 ${report.hits.size}/${report.checks.size} 项，风险分 ${report.riskScore}，耗时 ${report.durationMillis} ms")
        }

        val sortedChecks = report.checks.sortedWith(
            compareByDescending<DetectionCheck> { it.hit }
                .thenByDescending { it.severity.score }
                .thenBy { it.area.label }
                .thenBy { it.title }
        )
        sortedChecks.forEach { check ->
            binding.resultContainer.addView(createCheckView(check))
        }
    }

    private fun createCheckView(check: DetectionCheck): LinearLayout {
        val surface = themeColor(MaterialR.attr.colorSurface, Color.WHITE)
        val textColor = themeColor(android.R.attr.textColorPrimary, Color.BLACK)
        val secondaryTextColor = themeColor(android.R.attr.textColorSecondary, Color.DKGRAY)
        val borderColor = severityColor(check.severity, check.hit)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = GradientDrawable().apply {
                cornerRadius = dp(8).toFloat()
                setColor(surface)
                setStroke(dp(if (check.hit) 2 else 1), borderColor)
            }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(10)
            }
        }

        val status = if (check.hit) "命中" else "通过"
        val title = TextView(this).apply {
            text = "$status · ${check.area.label} · ${check.severity.label} · ${check.title}"
            setTextColor(textColor)
            setTypeface(typeface, Typeface.BOLD)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        }
        container.addView(title)

        val detail = TextView(this).apply {
            text = check.detail
            setTextColor(secondaryTextColor)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, dp(6), 0, 0)
        }
        container.addView(detail)

        val evidenceText = when {
            check.evidence.isNotEmpty() -> check.evidence.joinToString(separator = "\n") { "• $it" }
            !check.note.isNullOrBlank() -> check.note
            else -> "未发现命中证据。"
        }
        val evidence = TextView(this).apply {
            text = evidenceText
            setTextColor(if (check.hit) textColor else secondaryTextColor)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, dp(8), 0, 0)
            typeface = Typeface.MONOSPACE
        }
        container.addView(evidence)

        return container
    }

    private fun severityColor(severity: Severity, hit: Boolean): Int {
        if (!hit) return Color.rgb(112, 128, 144)
        return when (severity) {
            Severity.CRITICAL -> Color.rgb(176, 0, 32)
            Severity.HIGH -> Color.rgb(216, 67, 21)
            Severity.MEDIUM -> Color.rgb(245, 127, 23)
            Severity.LOW -> Color.rgb(46, 125, 50)
            Severity.INFO -> Color.rgb(84, 110, 122)
        }
    }

    private fun themeColor(attr: Int, fallback: Int): Int {
        val typedValue = TypedValue()
        if (!theme.resolveAttribute(attr, typedValue, true)) {
            return fallback
        }
        return if (typedValue.resourceId != 0) {
            runCatching { ContextCompat.getColor(this, typedValue.resourceId) }
                .getOrDefault(typedValue.data)
        } else {
            typedValue.data
        }
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density).toInt()
    }

    external fun collectNativeSignals(): Array<String>

    companion object {
        init {
            System.loadLibrary("envscope")
        }
    }
}
