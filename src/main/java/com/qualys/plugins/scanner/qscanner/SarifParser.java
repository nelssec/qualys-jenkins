package com.qualys.plugins.scanner.qscanner;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qualys.plugins.scanner.types.VulnerabilitySummary;
import hudson.FilePath;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Parser for SARIF (Static Analysis Results Interchange Format) reports.
 * Matches the parsing logic from qualys-ado QScannerRunner.parseSarifReport().
 *
 * Severity mapping (Qualys standard):
 * 5 = Critical
 * 4 = High
 * 3 = Medium
 * 2 = Low
 * 1 = Informational
 */
public class SarifParser {

    /**
     * Maps SARIF level to Qualys severity value.
     * Note: 'error' maps to Critical (5) to match qualys-ado behavior.
     */
    private static final Map<String, Integer> LEVEL_TO_SEVERITY = new HashMap<>();

    static {
        LEVEL_TO_SEVERITY.put("error", 5);      // Critical (matches qualys-ado)
        LEVEL_TO_SEVERITY.put("warning", 3);    // Medium
        LEVEL_TO_SEVERITY.put("note", 2);       // Low
        LEVEL_TO_SEVERITY.put("none", 1);       // Info
    }

    /**
     * Parse a SARIF file and extract vulnerability summary.
     */
    public static VulnerabilitySummary parse(FilePath sarifFile) throws IOException, InterruptedException {
        VulnerabilitySummary summary = new VulnerabilitySummary();

        try (InputStreamReader reader = new InputStreamReader(sarifFile.read(), StandardCharsets.UTF_8)) {
            JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();

            JsonArray runs = root.getAsJsonArray("runs");
            if (runs == null || runs.isEmpty()) {
                return summary;
            }

            for (JsonElement runElement : runs) {
                JsonObject run = runElement.getAsJsonObject();

                // Build rule severity map
                Map<String, Integer> ruleSeverityMap = buildRuleSeverityMap(run);

                // Process results
                JsonArray results = run.getAsJsonArray("results");
                if (results != null) {
                    for (JsonElement resultElement : results) {
                        JsonObject result = resultElement.getAsJsonObject();
                        int severity = getSeverityFromResult(result, ruleSeverityMap);
                        summary.increment(severity);
                    }
                }
            }
        }

        return summary;
    }

    /**
     * Parse a SARIF file and extract vulnerability summary from a file path string.
     */
    public static VulnerabilitySummary parse(String sarifFilePath) throws IOException, InterruptedException {
        return parse(new FilePath(new java.io.File(sarifFilePath)));
    }

    private static Map<String, Integer> buildRuleSeverityMap(JsonObject run) {
        Map<String, Integer> map = new HashMap<>();

        JsonObject tool = run.getAsJsonObject("tool");
        if (tool == null) return map;

        JsonObject driver = tool.getAsJsonObject("driver");
        if (driver == null) return map;

        JsonArray rules = driver.getAsJsonArray("rules");
        if (rules == null) return map;

        for (JsonElement ruleElement : rules) {
            JsonObject rule = ruleElement.getAsJsonObject();
            String ruleId = getStringOrNull(rule, "id");
            if (ruleId == null) continue;

            // Try to get severity from properties
            int severity = 1; // Default to info

            JsonObject properties = rule.getAsJsonObject("properties");
            if (properties != null) {
                String severityStr = getStringOrNull(properties, "severity");
                if (severityStr != null) {
                    severity = parseSeverityString(severityStr);
                } else {
                    // Try numeric security-severity
                    JsonElement secSeverity = properties.get("security-severity");
                    if (secSeverity != null && !secSeverity.isJsonNull()) {
                        try {
                            double score = secSeverity.getAsDouble();
                            severity = cvssToSeverity(score);
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // Fallback to defaultConfiguration level
            if (severity == 1) {
                JsonObject defaultConfig = rule.getAsJsonObject("defaultConfiguration");
                if (defaultConfig != null) {
                    String level = getStringOrNull(defaultConfig, "level");
                    if (level != null) {
                        severity = LEVEL_TO_SEVERITY.getOrDefault(level.toLowerCase(), 1);
                    }
                }
            }

            map.put(ruleId, severity);
        }

        return map;
    }

    private static int getSeverityFromResult(JsonObject result, Map<String, Integer> ruleSeverityMap) {
        // First try result.properties.severity
        JsonObject properties = result.getAsJsonObject("properties");
        if (properties != null) {
            String severityStr = getStringOrNull(properties, "severity");
            if (severityStr != null) {
                return parseSeverityString(severityStr);
            }
        }

        // Try rule lookup
        String ruleId = getStringOrNull(result, "ruleId");
        if (ruleId != null && ruleSeverityMap.containsKey(ruleId)) {
            return ruleSeverityMap.get(ruleId);
        }

        // Fallback to result level
        String level = getStringOrNull(result, "level");
        if (level != null) {
            return LEVEL_TO_SEVERITY.getOrDefault(level.toLowerCase(), 1);
        }

        return 1; // Default to info
    }

    private static int parseSeverityString(String severity) {
        if (severity == null) return 1;

        switch (severity.toLowerCase()) {
            case "critical":
                return 5;
            case "high":
                return 4;
            case "medium":
                return 3;
            case "low":
                return 2;
            case "informational":
            case "info":
            default:
                return 1;
        }
    }

    /**
     * Convert CVSS score to severity level.
     * Critical: 9.0-10.0
     * High: 7.0-8.9
     * Medium: 4.0-6.9
     * Low: 0.1-3.9
     */
    private static int cvssToSeverity(double score) {
        if (score >= 9.0) return 5;
        if (score >= 7.0) return 4;
        if (score >= 4.0) return 3;
        if (score >= 0.1) return 2;
        return 1;
    }

    private static String getStringOrNull(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        return element.getAsString();
    }
}
