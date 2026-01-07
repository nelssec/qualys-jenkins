package com.qualys.plugins.scanner.issues;

import com.google.gson.*;
import hudson.model.TaskListener;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Creates Jira issues for vulnerabilities found during scans.
 * Similar to WorkItemCreator in qualys-ado.
 */
public class JiraIssueCreator {

    private static final String QUALYS_VULN_TAG = "qualys-vuln";

    private final String jiraUrl;
    private final String jiraUsername;
    private final String jiraApiToken;
    private final String projectKey;
    private final TaskListener listener;

    private int issuesCreated = 0;
    private int issuesSkipped = 0;

    public JiraIssueCreator(String jiraUrl, String jiraUsername, String jiraApiToken,
                           String projectKey, TaskListener listener) {
        this.jiraUrl = jiraUrl.endsWith("/") ? jiraUrl.substring(0, jiraUrl.length() - 1) : jiraUrl;
        this.jiraUsername = jiraUsername;
        this.jiraApiToken = jiraApiToken;
        this.projectKey = projectKey;
        this.listener = listener;
    }

    /**
     * Creates Jira issues from SARIF report vulnerabilities.
     *
     * @param sarifPath Path to the SARIF report file
     * @param minSeverity Minimum severity to create issues for (5=Critical, 4=High, etc.)
     * @param labels Additional labels to add to issues
     * @param assignee Optional assignee username
     * @return Number of issues created
     */
    public int createIssuesFromSarif(String sarifPath, int minSeverity,
                                     List<String> labels, String assignee) throws IOException {
        File sarifFile = new File(sarifPath);
        if (!sarifFile.exists()) {
            listener.getLogger().println("SARIF file not found: " + sarifPath);
            return 0;
        }

        JsonObject sarif;
        try (Reader reader = new FileReader(sarifFile, StandardCharsets.UTF_8)) {
            sarif = JsonParser.parseReader(reader).getAsJsonObject();
        }

        JsonArray runs = sarif.getAsJsonArray("runs");
        if (runs == null || runs.isEmpty()) {
            return 0;
        }

        Map<String, VulnerabilityInfo> ruleInfoMap = new HashMap<>();
        for (JsonElement runElement : runs) {
            JsonObject run = runElement.getAsJsonObject();
            JsonObject tool = run.getAsJsonObject("tool");
            if (tool != null) {
                JsonObject driver = tool.getAsJsonObject("driver");
                if (driver != null) {
                    JsonArray rules = driver.getAsJsonArray("rules");
                    if (rules != null) {
                        for (JsonElement ruleElement : rules) {
                            JsonObject rule = ruleElement.getAsJsonObject();
                            String ruleId = getStringOrNull(rule, "id");
                            if (ruleId != null) {
                                VulnerabilityInfo info = new VulnerabilityInfo();
                                info.ruleId = ruleId;

                                JsonObject shortDesc = rule.getAsJsonObject("shortDescription");
                                if (shortDesc != null) {
                                    info.title = getStringOrNull(shortDesc, "text");
                                }

                                JsonObject fullDesc = rule.getAsJsonObject("fullDescription");
                                if (fullDesc != null) {
                                    info.description = getStringOrNull(fullDesc, "text");
                                }

                                JsonObject props = rule.getAsJsonObject("properties");
                                if (props != null) {
                                    JsonElement sev = props.get("severity");
                                    if (sev != null && !sev.isJsonNull()) {
                                        info.severity = sev.getAsInt();
                                    }
                                    JsonArray cves = props.getAsJsonArray("cves");
                                    if (cves != null) {
                                        for (JsonElement cve : cves) {
                                            info.cves.add(cve.getAsString());
                                        }
                                    }
                                }

                                ruleInfoMap.put(ruleId, info);
                            }
                        }
                    }
                }
            }

            JsonArray results = run.getAsJsonArray("results");
            if (results != null) {
                for (JsonElement resultElement : results) {
                    JsonObject result = resultElement.getAsJsonObject();
                    String ruleId = getStringOrNull(result, "ruleId");

                    VulnerabilityInfo info = ruleInfoMap.getOrDefault(ruleId, new VulnerabilityInfo());

                    JsonObject resultProps = result.getAsJsonObject("properties");
                    if (resultProps != null) {
                        JsonElement sev = resultProps.get("severity");
                        if (sev != null && !sev.isJsonNull()) {
                            info.severity = sev.getAsInt();
                        }
                    }

                    if (info.severity < minSeverity) {
                        continue;
                    }

                    JsonObject message = result.getAsJsonObject("message");
                    if (message != null) {
                        info.message = getStringOrNull(message, "text");
                    }

                    try {
                        createIssue(info, labels, assignee);
                    } catch (Exception e) {
                        listener.error("Failed to create Jira issue for " + ruleId + ": " + e.getMessage());
                    }
                }
            }
        }

        listener.getLogger().println(String.format(
            "Jira issues: %d created, %d skipped (duplicates)", issuesCreated, issuesSkipped));

        return issuesCreated;
    }

    private void createIssue(VulnerabilityInfo info, List<String> labels, String assignee) throws IOException {
        String vulnTag = QUALYS_VULN_TAG + ":" + info.ruleId;
        if (issueExists(vulnTag)) {
            issuesSkipped++;
            return;
        }

        String severityName = getSeverityName(info.severity);
        String title = String.format("[%s] %s", severityName,
            truncate(info.title != null ? info.title : info.ruleId, 200));

        StringBuilder description = new StringBuilder();
        description.append("h2. Vulnerability Details\n\n");
        description.append("||Field||Value||\n");
        description.append("|Severity|").append(severityName).append("|\n");
        description.append("|Rule ID|").append(info.ruleId).append("|\n");

        if (!info.cves.isEmpty()) {
            description.append("|CVE(s)|").append(String.join(", ", info.cves)).append("|\n");
        }

        description.append("\nh2. Description\n\n");
        description.append(info.description != null ? info.description : info.message);

        description.append("\n\n----\n");
        description.append("_Created by Qualys Jenkins Plugin_\n");
        description.append("Tag: {{").append(vulnTag).append("}}");

        List<String> allLabels = new ArrayList<>();
        allLabels.add("qualys-vulnerability");
        allLabels.add("severity-" + severityName.toLowerCase());
        if (labels != null) {
            allLabels.addAll(labels);
        }

        JsonObject issueData = new JsonObject();
        JsonObject fields = new JsonObject();

        JsonObject project = new JsonObject();
        project.addProperty("key", projectKey);
        fields.add("project", project);

        fields.addProperty("summary", title);
        fields.addProperty("description", description.toString());

        JsonObject issueType = new JsonObject();
        issueType.addProperty("name", "Bug");
        fields.add("issuetype", issueType);

        // Priority mapping
        JsonObject priority = new JsonObject();
        priority.addProperty("name", mapSeverityToPriority(info.severity));
        fields.add("priority", priority);

        // Labels
        JsonArray labelsArray = new JsonArray();
        for (String label : allLabels) {
            labelsArray.add(label.replaceAll("[^a-zA-Z0-9_-]", "_"));
        }
        fields.add("labels", labelsArray);

        // Assignee
        if (assignee != null && !assignee.isEmpty()) {
            JsonObject assigneeObj = new JsonObject();
            assigneeObj.addProperty("name", assignee);
            fields.add("assignee", assigneeObj);
        }

        issueData.add("fields", fields);

        // Make API call
        HttpURLConnection conn = createConnection("/rest/api/2/issue");
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(issueData.toString().getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == 201) {
            issuesCreated++;
            try (Reader reader = new InputStreamReader(conn.getInputStream())) {
                JsonObject response = JsonParser.parseReader(reader).getAsJsonObject();
                String issueKey = getStringOrNull(response, "key");
                listener.getLogger().println("Created Jira issue: " + issueKey + " - " + title);
            }
        } else {
            String error = readErrorResponse(conn);
            throw new IOException("Failed to create issue: HTTP " + responseCode + " - " + error);
        }
    }

    private boolean issueExists(String vulnTag) throws IOException {
        // Search for existing issue with the vulnerability tag
        String jql = String.format("project = %s AND description ~ \"%s\"", projectKey, vulnTag);

        HttpURLConnection conn = createConnection("/rest/api/2/search?jql=" +
            java.net.URLEncoder.encode(jql, "UTF-8") + "&maxResults=1");
        conn.setRequestMethod("GET");

        int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            try (Reader reader = new InputStreamReader(conn.getInputStream())) {
                JsonObject response = JsonParser.parseReader(reader).getAsJsonObject();
                int total = response.get("total").getAsInt();
                return total > 0;
            }
        }
        return false;
    }

    private HttpURLConnection createConnection(String path) throws IOException {
        URL url = new URL(jiraUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");

        // Basic auth with API token
        String auth = jiraUsername + ":" + jiraApiToken;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

        return conn;
    }

    private String readErrorResponse(HttpURLConnection conn) {
        try (Reader reader = new InputStreamReader(conn.getErrorStream())) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[1024];
            int len;
            while ((len = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, len);
            }
            return sb.toString();
        } catch (Exception e) {
            return "Unknown error";
        }
    }

    private String getSeverityName(int severity) {
        switch (severity) {
            case 5: return "Critical";
            case 4: return "High";
            case 3: return "Medium";
            case 2: return "Low";
            default: return "Info";
        }
    }

    private String mapSeverityToPriority(int severity) {
        switch (severity) {
            case 5: return "Highest";
            case 4: return "High";
            case 3: return "Medium";
            case 2: return "Low";
            default: return "Lowest";
        }
    }

    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength - 3) + "...";
    }

    private String getStringOrNull(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        return element.getAsString();
    }

    public int getIssuesCreated() {
        return issuesCreated;
    }

    public int getIssuesSkipped() {
        return issuesSkipped;
    }

    /**
     * Holds vulnerability information extracted from SARIF.
     */
    private static class VulnerabilityInfo {
        String ruleId;
        String title;
        String description;
        String message;
        int severity = 1;
        List<String> cves = new ArrayList<>();
    }
}
