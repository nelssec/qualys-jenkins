package com.qualys.plugins.scanner.qscanner;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qualys.plugins.scanner.types.PackageInfo;
import com.qualys.plugins.scanner.types.ScanReportDetails;
import com.qualys.plugins.scanner.types.Vulnerability;
import com.qualys.plugins.scanner.types.VulnerabilitySummary;
import hudson.FilePath;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parser for SARIF (Static Analysis Results Interchange Format) reports from Qualys.
 *
 * Qualys SARIF structure:
 * - Rules contain: cve-ids, qds, severity, shortDescription
 * - Results contain: QID, vulnerableSoftware[] with name/installedVersion/fixedVersion
 */
public class SarifParser {

    private static final Map<String, Integer> LEVEL_TO_SEVERITY = new HashMap<>();

    static {
        LEVEL_TO_SEVERITY.put("error", 5);      // Critical
        LEVEL_TO_SEVERITY.put("warning", 3);    // Medium
        LEVEL_TO_SEVERITY.put("note", 2);       // Low
        LEVEL_TO_SEVERITY.put("none", 1);       // Info
    }

    /**
     * Parse a SARIF file and extract vulnerability summary only.
     */
    public static VulnerabilitySummary parse(FilePath sarifFile) throws IOException, InterruptedException {
        return parseDetailed(sarifFile).getVulnerabilitySummary();
    }

    /**
     * Parse a SARIF file and extract full detailed report.
     */
    public static ScanReportDetails parseDetailed(FilePath sarifFile) throws IOException, InterruptedException {
        ScanReportDetails details = new ScanReportDetails();
        VulnerabilitySummary summary = new VulnerabilitySummary();
        Set<String> seenPackages = new HashSet<>();

        try (InputStreamReader reader = new InputStreamReader(sarifFile.read(), StandardCharsets.UTF_8)) {
            JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();

            JsonArray runs = getArrayOrNull(root, "runs");
            if (runs == null || runs.isEmpty()) {
                details.setVulnerabilitySummary(summary);
                return details;
            }

            for (JsonElement runElement : runs) {
                if (!runElement.isJsonObject()) continue;
                JsonObject run = runElement.getAsJsonObject();

                extractTargetInfo(run, details);
                Map<String, RuleInfo> ruleInfoMap = buildRuleInfoMap(run);
                Map<String, String> layerCommandMap = buildLayerCommandMap(run);
                JsonArray results = getArrayOrNull(run, "results");
                if (results != null) {
                    for (JsonElement resultElement : results) {
                        if (!resultElement.isJsonObject()) continue;
                        JsonObject result = resultElement.getAsJsonObject();
                        List<Vulnerability> vulns = parseVulnerabilities(result, ruleInfoMap, layerCommandMap);

                        for (Vulnerability vuln : vulns) {
                            summary.increment(vuln.getSeverityLevel());
                            details.addVulnerability(vuln);

                            if (vuln.getLayerSHA() != null && !vuln.getLayerSHA().isEmpty()) {
                                details.addLayer(vuln.getLayerSHA());
                            }

                            if (vuln.getPackageName() != null && !vuln.getPackageName().isEmpty()) {
                                String pkgKey = vuln.getPackageName() + ":" + vuln.getInstalledVersion();
                                if (!seenPackages.contains(pkgKey)) {
                                    seenPackages.add(pkgKey);
                                    PackageInfo pkg = new PackageInfo();
                                    pkg.setName(vuln.getPackageName());
                                    pkg.setVersion(vuln.getInstalledVersion());
                                    pkg.setLayerSHA(vuln.getLayerSHA());
                                    pkg.setLayerCommand(vuln.getLayerCommand());
                                    details.addPackage(pkg);
                                }
                            }
                        }
                    }
                }
            }
        }

        details.setVulnerabilitySummary(summary);
        details.setTotalPackages(details.getPackages().size());
        return details;
    }

    /**
     * Parse a SARIF file from a file path string.
     */
    public static VulnerabilitySummary parse(String sarifFilePath) throws IOException, InterruptedException {
        return parse(new FilePath(new java.io.File(sarifFilePath)));
    }

    /**
     * Parse detailed report from a file path string.
     */
    public static ScanReportDetails parseDetailed(String sarifFilePath) throws IOException, InterruptedException {
        return parseDetailed(new FilePath(new java.io.File(sarifFilePath)));
    }

    private static void extractTargetInfo(JsonObject run, ScanReportDetails details) {
        JsonObject runProps = getObjectOrNull(run, "properties");
        if (runProps != null) {
            String imageId = getStringOrNull(runProps, "imageID");
            if (imageId == null) {
                imageId = getStringOrNull(runProps, "imageId");
            }
            details.setImageId(imageId);
            details.setImageDigest(getStringOrNull(runProps, "imageDigest"));
            details.setOperatingSystem(getStringOrNull(runProps, "os"));
            if (details.getOperatingSystem() == null) {
                details.setOperatingSystem(getStringOrNull(runProps, "operatingSystem"));
            }
            details.setImageName(getStringOrNull(runProps, "imageName"));

            if (details.getImageName() == null) {
                JsonArray repoTags = getArrayOrNull(runProps, "repoTags");
                if (repoTags != null && !repoTags.isEmpty()) {
                    JsonElement firstTag = repoTags.get(0);
                    if (!firstTag.isJsonNull()) {
                        details.setImageName(firstTag.getAsString());
                    }
                }
            }
        }

        JsonArray artifacts = getArrayOrNull(run, "artifacts");
        if (artifacts != null && !artifacts.isEmpty()) {
            JsonElement firstArtifact = artifacts.get(0);
            if (firstArtifact.isJsonObject()) {
                JsonObject artifact = firstArtifact.getAsJsonObject();
                JsonObject location = getObjectOrNull(artifact, "location");
                if (location != null && details.getImageName() == null) {
                    details.setImageName(getStringOrNull(location, "uri"));
                }
                JsonObject artifactProps = getObjectOrNull(artifact, "properties");
                if (artifactProps != null) {
                    if (details.getImageId() == null) {
                        String imgId = getStringOrNull(artifactProps, "imageID");
                        if (imgId == null) {
                            imgId = getStringOrNull(artifactProps, "imageId");
                        }
                        details.setImageId(imgId);
                    }
                    if (details.getImageDigest() == null) {
                        details.setImageDigest(getStringOrNull(artifactProps, "repoDigest"));
                        if (details.getImageDigest() == null) {
                            details.setImageDigest(getStringOrNull(artifactProps, "imageDigest"));
                        }
                    }
                    if (details.getOperatingSystem() == null) {
                        String osName = getStringOrNull(artifactProps, "osName");
                        String osVersion = getStringOrNull(artifactProps, "osVersion");
                        if (osName != null) {
                            details.setOperatingSystem(osName);
                            details.setOsVersion(osVersion);
                        }
                    }
                }
            }
        }
    }

    /**
     * Parse vulnerabilities from a single result.
     * Qualys can have multiple vulnerable packages per result, so we create one Vulnerability per package.
     */
    private static List<Vulnerability> parseVulnerabilities(JsonObject result, Map<String, RuleInfo> ruleInfoMap, Map<String, String> layerCommandMap) {
        List<Vulnerability> vulns = new ArrayList<>();

        String ruleId = getStringOrNull(result, "ruleId");
        RuleInfo ruleInfo = ruleId != null ? ruleInfoMap.get(ruleId) : null;

        String title = null;
        JsonObject message = getObjectOrNull(result, "message");
        if (message != null) {
            title = getStringOrNull(message, "text");
        }

        JsonObject props = getObjectOrNull(result, "properties");
        String qid = ruleId;
        if (props != null) {
            JsonElement qidElem = props.get("QID");
            if (qidElem != null && !qidElem.isJsonNull()) {
                try {
                    qid = String.valueOf(qidElem.getAsInt());
                } catch (Exception ignored) {}
            }
        }

        JsonArray vulnerableSoftware = props != null ? getArrayOrNull(props, "vulnerableSoftware") : null;

        if (vulnerableSoftware != null && vulnerableSoftware.size() > 0) {
            for (JsonElement swElem : vulnerableSoftware) {
                if (!swElem.isJsonObject()) continue;
                JsonObject sw = swElem.getAsJsonObject();
                Vulnerability vuln = createVulnerability(qid, title, ruleInfo, result);

                vuln.setPackageName(getStringOrNull(sw, "name"));
                vuln.setInstalledVersion(getStringOrNull(sw, "installedVersion"));
                vuln.setFixedVersion(getStringOrNull(sw, "fixedVersion"));
                String layerSHA = getStringOrNull(sw, "layerSHA");
                vuln.setLayerSHA(layerSHA);
                if (layerSHA != null && layerCommandMap.containsKey(layerSHA)) {
                    vuln.setLayerCommand(layerCommandMap.get(layerSHA));
                }

                vulns.add(vuln);
            }
        } else {
            Vulnerability vuln = createVulnerability(qid, title, ruleInfo, result);
            if (props != null) {
                vuln.setPackageName(getStringOrNull(props, "packageName"));
                if (vuln.getPackageName() == null) {
                    vuln.setPackageName(getStringOrNull(props, "affectedPackage"));
                }
                vuln.setInstalledVersion(getStringOrNull(props, "installedVersion"));
                if (vuln.getInstalledVersion() == null) {
                    vuln.setInstalledVersion(getStringOrNull(props, "packageVersion"));
                }
                vuln.setFixedVersion(getStringOrNull(props, "fixedVersion"));
            }

            vulns.add(vuln);
        }

        return vulns;
    }

    private static Vulnerability createVulnerability(String qid, String title, RuleInfo ruleInfo, JsonObject result) {
        Vulnerability vuln = new Vulnerability();
        vuln.setQid(qid);
        vuln.setTitle(title);

        if (ruleInfo != null) {
            vuln.setSeverityLevel(ruleInfo.severityLevel);
            vuln.setSeverity(severityLevelToString(ruleInfo.severityLevel));
            vuln.setCves(ruleInfo.cves != null ? new ArrayList<>(ruleInfo.cves) : new ArrayList<>());
            vuln.setQdsScore(ruleInfo.qdsScore);

            if (title == null || title.isEmpty()) {
                vuln.setTitle(ruleInfo.description);
            }
        }

        if (vuln.getSeverityLevel() == 0) {
            String level = getStringOrNull(result, "level");
            if (level != null) {
                vuln.setSeverityLevel(LEVEL_TO_SEVERITY.getOrDefault(level.toLowerCase(), 1));
                vuln.setSeverity(severityLevelToString(vuln.getSeverityLevel()));
            } else {
                vuln.setSeverityLevel(1);
                vuln.setSeverity("Info");
            }
        }

        return vuln;
    }

    private static class RuleInfo {
        String description;
        int severityLevel;
        List<String> cves = new ArrayList<>();
        double qdsScore;
    }

    private static Map<String, RuleInfo> buildRuleInfoMap(JsonObject run) {
        Map<String, RuleInfo> map = new HashMap<>();

        JsonObject tool = getObjectOrNull(run, "tool");
        if (tool == null) return map;

        JsonObject driver = getObjectOrNull(tool, "driver");
        if (driver == null) return map;

        JsonArray rules = getArrayOrNull(driver, "rules");
        if (rules == null) return map;

        for (JsonElement ruleElement : rules) {
            if (!ruleElement.isJsonObject()) continue;
            JsonObject rule = ruleElement.getAsJsonObject();
            String ruleId = getStringOrNull(rule, "id");
            if (ruleId == null) continue;

            RuleInfo info = new RuleInfo();

            JsonObject shortDesc = getObjectOrNull(rule, "shortDescription");
            if (shortDesc != null) {
                info.description = getStringOrNull(shortDesc, "text");
            }

            JsonObject properties = getObjectOrNull(rule, "properties");
            if (properties != null) {
                JsonElement severityElem = properties.get("severity");
                if (severityElem == null) {
                    severityElem = properties.get("customerSeverity");
                }
                if (severityElem != null && !severityElem.isJsonNull()) {
                    try {
                        int sev = severityElem.getAsInt();
                        if (sev >= 4) {
                            info.severityLevel = 5;
                        } else if (sev == 3) {
                            info.severityLevel = 3;
                        } else if (sev == 2) {
                            info.severityLevel = 2;
                        } else {
                            info.severityLevel = 1;
                        }
                    } catch (Exception ignored) {}
                }

                JsonArray cveIds = getArrayOrNull(properties, "cve-ids");
                if (cveIds != null) {
                    for (JsonElement cve : cveIds) {
                        if (!cve.isJsonNull()) {
                            try {
                                info.cves.add(cve.getAsString());
                            } catch (Exception ignored) {}
                        }
                    }
                }

                JsonElement qdsElem = properties.get("qds");
                if (qdsElem != null && !qdsElem.isJsonNull()) {
                    try {
                        String qdsStr = qdsElem.getAsString();
                        info.qdsScore = Double.parseDouble(qdsStr);
                    } catch (Exception ignored) {}
                }
            }

            if (info.severityLevel == 0) {
                JsonObject defaultConfig = getObjectOrNull(rule, "defaultConfiguration");
                if (defaultConfig != null) {
                    String level = getStringOrNull(defaultConfig, "level");
                    if (level != null) {
                        info.severityLevel = LEVEL_TO_SEVERITY.getOrDefault(level.toLowerCase(), 1);
                    }
                }
            }

            map.put(ruleId, info);
        }

        return map;
    }

    private static Map<String, String> buildLayerCommandMap(JsonObject run) {
        Map<String, String> map = new HashMap<>();

        JsonObject runProps = getObjectOrNull(run, "properties");
        if (runProps == null) return map;

        JsonArray layerInfo = getArrayOrNull(runProps, "layerInfo");
        if (layerInfo == null) return map;

        for (JsonElement layerElement : layerInfo) {
            if (!layerElement.isJsonObject()) continue;
            JsonObject layer = layerElement.getAsJsonObject();

            String hash = getStringOrNull(layer, "LayerContentHash");
            String command = getStringOrNull(layer, "Command");

            if (hash != null && command != null) {
                map.put("sha256:" + hash, command);
                map.put(hash, command);
            }
        }

        return map;
    }

    private static String severityLevelToString(int level) {
        switch (level) {
            case 5: return "Critical";
            case 4: return "High";
            case 3: return "Medium";
            case 2: return "Low";
            default: return "Info";
        }
    }

    private static String getStringOrNull(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        return element.getAsString();
    }

    private static JsonArray getArrayOrNull(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        if (element == null || element.isJsonNull() || !element.isJsonArray()) {
            return null;
        }
        return element.getAsJsonArray();
    }

    private static JsonObject getObjectOrNull(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        if (element == null || element.isJsonNull() || !element.isJsonObject()) {
            return null;
        }
        return element.getAsJsonObject();
    }
}
