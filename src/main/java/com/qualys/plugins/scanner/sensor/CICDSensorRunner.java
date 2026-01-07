package com.qualys.plugins.scanner.sensor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.scanner.runner.ScannerRunner;
import com.qualys.plugins.scanner.types.*;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import hudson.util.ArgumentListBuilder;

import java.io.*;

public class CICDSensorRunner implements ScannerRunner {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final CICDSensorConfig config;
    private final FilePath workspace;
    private final Launcher launcher;
    private final TaskListener listener;
    private QualysCSClient client;

    public CICDSensorRunner(CICDSensorConfig config, FilePath workspace,
                            Launcher launcher, TaskListener listener) {
        this.config = config;
        this.workspace = workspace;
        this.launcher = launcher;
        this.listener = listener;
    }

    @Override
    public void setup() throws IOException, InterruptedException {
        log("Setting up CICD Sensor backend");

        client = new QualysCSClient(
            config.getApiServer(),
            config.getUsername(),
            config.getPassword(),
            config.isUseOAuth(),
            config.getClientId(),
            config.getClientSecret(),
            config.getProxyHost(),
            config.getProxyPort(),
            config.getProxyUsername(),
            config.getProxyPassword(),
            listener
        );

        String error = client.testConnection();
        if (error != null) {
            throw new IOException("Failed to connect to Qualys API: " + error);
        }
        log("Successfully connected to Qualys Container Security API");

        if (config.isValidateSensor()) {
            checkSensorRunning();
        }
    }

    @Override
    public QScannerResult scanImage() throws IOException, InterruptedException {
        String imageId = config.getImageId();
        if (imageId == null || imageId.isEmpty()) {
            return QScannerResult.failure(QScannerExitCode.INVALID_ARGUMENTS,
                "Image ID is required for container scan");
        }

        log("Scanning image: " + imageId);

        String imageSha = extractImageSha(imageId);
        if (imageSha == null || imageSha.isEmpty()) {
            return QScannerResult.failure(QScannerExitCode.GENERAL_ERROR,
                "Could not extract SHA for image: " + imageId);
        }
        log("Image SHA: " + imageSha);

        tagImageForQualys(imageId, imageSha);

        long tagTimestamp = System.currentTimeMillis() / 1000;

        log("Waiting for scan results (timeout: " + config.getVulnsTimeout() + "s)...");
        JsonObject scanResult = pollForResults(imageSha, tagTimestamp);

        if (scanResult == null) {
            return QScannerResult.failure(QScannerExitCode.TIMEOUT,
                "Timed out waiting for scan results");
        }

        return processResults(imageId, imageSha, scanResult);
    }

    @Override
    public QScannerResult scanRepo() throws IOException, InterruptedException {
        throw new UnsupportedOperationException(
            "CICD Sensor does not support repository scans. Use QScanner backend instead.");
    }

    @Override
    public QScannerResult scanRootfs() throws IOException, InterruptedException {
        throw new UnsupportedOperationException(
            "CICD Sensor does not support rootfs scans. Use QScanner backend instead.");
    }

    @Override
    public String getBackendName() {
        return "CICD Sensor";
    }

    @Override
    public boolean supportsScanType(String scanType) {
        return "container".equals(scanType);
    }

    private void checkSensorRunning() throws IOException, InterruptedException {
        log("Checking if Qualys sensor is running...");

        ArgumentListBuilder cmd = new ArgumentListBuilder();
        cmd.add("docker", "ps", "--filter", "name=qualys-container-sensor", "--format", "{{.Names}}");

        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        int exitCode = launcher.launch()
            .cmds(cmd)
            .stdout(stdout)
            .pwd(workspace)
            .join();

        String output = stdout.toString().trim();
        if (exitCode != 0 || !output.contains("qualys")) {
            listener.getLogger().println("Warning: Qualys sensor container not detected. " +
                "Ensure the sensor is running for image scanning to work.");
        } else {
            log("Qualys sensor is running");
        }
    }

    private String extractImageSha(String imageId) throws IOException, InterruptedException {
        ArgumentListBuilder cmd = new ArgumentListBuilder();
        cmd.add("docker", "inspect", "--format", "{{.Id}}", imageId);

        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();

        int exitCode = launcher.launch()
            .cmds(cmd)
            .stdout(stdout)
            .stderr(stderr)
            .pwd(workspace)
            .join();

        if (exitCode != 0) {
            String error = stderr.toString().trim();
            throw new IOException("Failed to inspect image " + imageId + ": " + error);
        }

        String sha = stdout.toString().trim();
        if (sha.startsWith("sha256:")) {
            sha = sha.substring(7);
        }
        return sha;
    }

    private void tagImageForQualys(String imageId, String imageSha) throws IOException, InterruptedException {
        log("Tagging image for Qualys scanning...");

        ArgumentListBuilder cmd = new ArgumentListBuilder();
        cmd.add("docker", "tag", imageId, "qualys_scan_target:" + imageSha);

        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int exitCode = launcher.launch()
            .cmds(cmd)
            .stderr(stderr)
            .pwd(workspace)
            .join();

        if (exitCode != 0) {
            String error = stderr.toString().trim();
            throw new IOException("Failed to tag image: " + error);
        }

        log("Image tagged as qualys_scan_target:" + imageSha);
    }

    private JsonObject pollForResults(String imageSha, long tagTimestamp)
            throws IOException, InterruptedException {

        long startTime = System.currentTimeMillis();
        long timeoutMs = config.getVulnsTimeout() * 1000L;
        int pollingIntervalMs = config.getPollingInterval() * 1000;

        while (System.currentTimeMillis() - startTime < timeoutMs) {
            try {
                QualysCSClient.QualysCSResponse response = client.getImages(imageSha, tagTimestamp);

                if (response.isSuccess()) {
                    JsonObject json = response.getBodyAsJson();

                    if (json.has("data") && json.get("data").isJsonArray()) {
                        JsonArray data = json.getAsJsonArray("data");
                        if (data.size() > 0) {
                            JsonObject imageData = data.get(0).getAsJsonObject();
                            if (imageData.has("sha")) {
                                String resultSha = imageData.get("sha").getAsString();
                                QualysCSClient.QualysCSResponse detailResponse =
                                    client.getImageDetails(resultSha);
                                if (detailResponse.isSuccess()) {
                                    return detailResponse.getBodyAsJson();
                                }
                            }
                            return imageData;
                        }
                    }
                } else if (response.getStatusCode() == 404 || response.getStatusCode() == 204) {
                    log("Image not yet indexed, waiting...");
                } else if (response.getStatusCode() >= 500) {
                    log("Server error (" + response.getStatusCode() + "), retrying...");
                } else {
                    log("API error: " + response.getStatusCode() + " - " + response.getBody());
                    return null;
                }
            } catch (IOException e) {
                log("Polling error: " + e.getMessage());
            }

            Thread.sleep(pollingIntervalMs);
        }

        return null;
    }

    private QScannerResult processResults(String imageId, String imageSha, JsonObject scanResult)
            throws IOException, InterruptedException {

        QScannerResult result = new QScannerResult();
        result.setSuccess(true);

        FilePath outputDir = workspace.child("qualys-scan-results");
        outputDir.mkdirs();
        result.setOutputDirectory(outputDir.getRemote());

        FilePath jsonFile = outputDir.child("qualys_" + sanitizeFilename(imageId) + ".json");
        jsonFile.write(GSON.toJson(scanResult), "UTF-8");
        result.setJsonReportPath(jsonFile.getRemote());

        VulnerabilitySummary summary = parseVulnerabilities(scanResult);
        result.setVulnerabilitySummary(summary);

        log("Scan complete: " + summary.getTotal() + " vulnerabilities found");
        log("  Critical: " + summary.getCritical());
        log("  High: " + summary.getHigh());
        log("  Medium: " + summary.getMedium());
        log("  Low: " + summary.getLow());

        if (exceedsThresholds(summary)) {
            result.setPolicyResult(QScannerResult.PolicyResult.DENY);
        } else {
            result.setPolicyResult(QScannerResult.PolicyResult.ALLOW);
        }

        FilePath sarifFile = outputDir.child("qualys_" + sanitizeFilename(imageId) + ".sarif.json");
        generateSarifReport(scanResult, imageId, sarifFile);
        result.setSarifReportPath(sarifFile.getRemote());

        return result;
    }

    private VulnerabilitySummary parseVulnerabilities(JsonObject scanResult) {
        VulnerabilitySummary summary = new VulnerabilitySummary();

        if (!scanResult.has("vulns")) {
            return summary;
        }

        try {
            JsonArray vulns = scanResult.getAsJsonArray("vulns");
            for (JsonElement elem : vulns) {
                JsonObject vuln = elem.getAsJsonObject();
                int severity = vuln.has("severity") ? vuln.get("severity").getAsInt() : 1;

                switch (severity) {
                    case 5:
                        summary.setCritical(summary.getCritical() + 1);
                        break;
                    case 4:
                        summary.setHigh(summary.getHigh() + 1);
                        break;
                    case 3:
                        summary.setMedium(summary.getMedium() + 1);
                        break;
                    default:
                        summary.setLow(summary.getLow() + 1);
                        break;
                }
            }
        } catch (Exception e) {
            log("Warning: Error parsing vulnerabilities: " + e.getMessage());
        }

        summary.setTotal(summary.getCritical() + summary.getHigh() +
                        summary.getMedium() + summary.getLow());
        return summary;
    }

    private boolean exceedsThresholds(VulnerabilitySummary summary) {
        if (config.getMaxCritical() >= 0 && summary.getCritical() > config.getMaxCritical()) {
            return true;
        }
        if (config.getMaxHigh() >= 0 && summary.getHigh() > config.getMaxHigh()) {
            return true;
        }
        if (config.getMaxMedium() >= 0 && summary.getMedium() > config.getMaxMedium()) {
            return true;
        }
        if (config.getMaxLow() >= 0 && summary.getLow() > config.getMaxLow()) {
            return true;
        }
        return false;
    }

    private void generateSarifReport(JsonObject scanResult, String imageId, FilePath outputFile)
            throws IOException, InterruptedException {

        JsonObject sarif = new JsonObject();
        sarif.addProperty("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        sarif.addProperty("version", "2.1.0");

        JsonArray runs = new JsonArray();
        JsonObject run = new JsonObject();

        JsonObject tool = new JsonObject();
        JsonObject driver = new JsonObject();
        driver.addProperty("name", "Qualys Container Security");
        driver.addProperty("version", "1.0");
        tool.add("driver", driver);
        run.add("tool", tool);

        JsonArray results = new JsonArray();
        if (scanResult.has("vulns")) {
            JsonArray vulns = scanResult.getAsJsonArray("vulns");
            for (JsonElement elem : vulns) {
                JsonObject vuln = elem.getAsJsonObject();
                JsonObject result = new JsonObject();

                String qid = vuln.has("qid") ? vuln.get("qid").getAsString() : "unknown";
                result.addProperty("ruleId", "QID-" + qid);

                JsonObject message = new JsonObject();
                String title = vuln.has("title") ? vuln.get("title").getAsString() : "Unknown vulnerability";
                message.addProperty("text", title);
                result.add("message", message);

                int severity = vuln.has("severity") ? vuln.get("severity").getAsInt() : 1;
                String level;
                switch (severity) {
                    case 5:
                    case 4:
                        level = "error";
                        break;
                    case 3:
                        level = "warning";
                        break;
                    default:
                        level = "note";
                        break;
                }
                result.addProperty("level", level);

                JsonArray locations = new JsonArray();
                JsonObject location = new JsonObject();
                JsonObject physicalLocation = new JsonObject();
                JsonObject artifactLocation = new JsonObject();
                artifactLocation.addProperty("uri", imageId);
                physicalLocation.add("artifactLocation", artifactLocation);
                location.add("physicalLocation", physicalLocation);
                locations.add(location);
                result.add("locations", locations);

                results.add(result);
            }
        }
        run.add("results", results);
        runs.add(run);
        sarif.add("runs", runs);

        outputFile.write(GSON.toJson(sarif), "UTF-8");
    }

    private String sanitizeFilename(String name) {
        return name.replaceAll("[^a-zA-Z0-9.-]", "_");
    }

    private void log(String message) {
        listener.getLogger().println("[CICD Sensor] " + message);
    }
}
