package com.qualys.plugins.scanner.qscanner;

import com.qualys.plugins.scanner.types.*;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import hudson.util.ArgumentListBuilder;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages downloading, verifying, and executing the QScanner CLI tool.
 */
public class QScannerRunner {

    private static final String QSCANNER_VERSION = "1.0.0";
    private static final String QSCANNER_DOWNLOAD_URL =
        "https://github.com/nelssec/qualys-lambda/raw/refs/heads/main/scanner-lambda/qscanner.gz";
    // No checksum URL available for this source
    private static final String QSCANNER_CHECKSUM_URL = null;

    private static final int MAX_RETRIES = 5;
    private static final int[] RETRY_DELAYS_SEC = {30, 60, 90, 120, 150};

    private final QScannerConfig config;
    private final FilePath workspace;
    private final Launcher launcher;
    private final TaskListener listener;
    private FilePath qscannerBinary;

    public QScannerRunner(QScannerConfig config, FilePath workspace, Launcher launcher, TaskListener listener) {
        this.config = config;
        this.workspace = workspace;
        this.launcher = launcher;
        this.listener = listener;
    }

    /**
     * Downloads and sets up the QScanner binary.
     */
    public void setup() throws IOException, InterruptedException {
        listener.getLogger().println("Setting up QScanner v" + QSCANNER_VERSION);

        // Validate platform
        validatePlatform();

        // Create temp directory for qscanner
        FilePath tempDir = workspace.child(".qualys-scanner");
        tempDir.mkdirs();

        FilePath gzFile = tempDir.child("qscanner.gz");
        qscannerBinary = tempDir.child("qscanner");

        // Download if not exists or checksum mismatch
        if (!qscannerBinary.exists() || !verifyChecksum(qscannerBinary)) {
            downloadBinary(gzFile);
            extractBinary(gzFile, qscannerBinary);
            gzFile.delete();
        }

        // Make executable
        qscannerBinary.chmod(0755);
        listener.getLogger().println("QScanner ready at: " + qscannerBinary.getRemote());
    }

    private void validatePlatform() throws IOException {
        // QScanner currently only supports linux-amd64
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();

        // Map Java arch names to standard names
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            arch = "amd64";
        }

        if (!os.contains("linux")) {
            throw new IOException("QScanner only supports Linux. Current OS: " + os);
        }
        if (!"amd64".equals(arch)) {
            throw new IOException("QScanner only supports amd64 architecture. Current: " + arch);
        }
    }

    private void downloadBinary(FilePath destination) throws IOException, InterruptedException {
        listener.getLogger().println("Downloading QScanner from: " + QSCANNER_DOWNLOAD_URL);

        URL url = new URL(QSCANNER_DOWNLOAD_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(60000);

        try (InputStream in = conn.getInputStream()) {
            destination.copyFrom(in);
        } finally {
            conn.disconnect();
        }

        listener.getLogger().println("Download complete");
    }

    private void extractBinary(FilePath gzFile, FilePath destination) throws IOException, InterruptedException {
        listener.getLogger().println("Extracting QScanner binary...");

        try (InputStream fis = gzFile.read();
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fis);
             OutputStream out = destination.write()) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = gzis.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }

    private boolean verifyChecksum(FilePath file) {
        // Skip checksum verification if no checksum URL is configured
        if (QSCANNER_CHECKSUM_URL == null) {
            listener.getLogger().println("Checksum verification skipped (no checksum URL configured)");
            return true;
        }

        try {
            // Download expected checksum
            URL checksumUrl = new URL(QSCANNER_CHECKSUM_URL);
            HttpURLConnection conn = (HttpURLConnection) checksumUrl.openConnection();
            conn.setInstanceFollowRedirects(true);

            String expectedChecksum;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                expectedChecksum = reader.readLine();
                if (expectedChecksum != null) {
                    // Format is usually: "checksum  filename" or just "checksum"
                    expectedChecksum = expectedChecksum.split("\\s+")[0].toLowerCase();
                }
            } finally {
                conn.disconnect();
            }

            // Calculate actual checksum
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream fis = file.read()) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, len);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            String actualChecksum = sb.toString();

            boolean matches = actualChecksum.equals(expectedChecksum);
            if (!matches) {
                listener.getLogger().println("Checksum mismatch. Expected: " + expectedChecksum + ", Got: " + actualChecksum);
            }
            return matches;

        } catch (Exception e) {
            listener.getLogger().println("Warning: Could not verify checksum: " + e.getMessage());
            return false;
        }
    }

    /**
     * Executes a container image scan.
     */
    public QScannerResult scanImage() throws IOException, InterruptedException {
        if (config.getImageId() == null || config.getImageId().isEmpty()) {
            return QScannerResult.failure(QScannerExitCode.INVALID_ARGUMENTS, "Image ID is required for container scan");
        }

        List<String> args = buildCommonArgs();
        args.add("image");
        args.add(config.getImageId());

        if (config.getStorageDriver() != null && config.getStorageDriver() != StorageDriver.NONE) {
            args.add("--storage-driver");
            args.add(config.getStorageDriver().getValue());
        }

        if (config.getPlatform() != null && !config.getPlatform().isEmpty()) {
            args.add("--platform");
            args.add(config.getPlatform());
        }

        return executeWithRetry(args);
    }

    /**
     * Executes a code/repository scan.
     */
    public QScannerResult scanRepo() throws IOException, InterruptedException {
        String scanPath = config.getScanPath();
        if (scanPath == null || scanPath.isEmpty()) {
            scanPath = workspace.getRemote();
        }

        List<String> args = buildCommonArgs();
        args.add("repo");
        args.add(scanPath);

        addCodeScanArgs(args);

        return executeWithRetry(args);
    }

    /**
     * Executes a rootfs scan.
     */
    public QScannerResult scanRootfs() throws IOException, InterruptedException {
        String scanPath = config.getScanPath();
        if (scanPath == null || scanPath.isEmpty()) {
            return QScannerResult.failure(QScannerExitCode.INVALID_ARGUMENTS, "Scan path is required for rootfs scan");
        }

        List<String> args = buildCommonArgs();
        args.add("rootfs");
        args.add(scanPath);

        return executeWithRetry(args);
    }

    private List<String> buildCommonArgs() {
        List<String> args = new ArrayList<>();

        // Pod/region
        if (config.getPod() != null && !config.getPod().isEmpty()) {
            args.add("--pod");
            args.add(config.getPod());
        }

        // Mode - use evaluate-policy if policy evaluation is enabled
        args.add("--mode");
        if (config.isUsePolicyEvaluation()) {
            args.add("evaluate-policy");
        } else {
            args.add(config.getMode() != null ? config.getMode() : "get-report");
        }

        // Scan types
        String scanTypes = config.getScanTypes();
        if (config.isScanSecrets() && !scanTypes.contains("secret")) {
            scanTypes = scanTypes + ",secret";
        }
        if (config.isScanMalware() && !scanTypes.contains("malware")) {
            scanTypes = scanTypes + ",malware";
        }
        args.add("--scan-types");
        args.add(scanTypes);

        // Output formats - json is default, add spdx for SBOM if requested
        args.add("--format");
        if (config.isGenerateSbom()) {
            String sbomFormat = config.getSbomFormat();
            if ("cyclonedx".equalsIgnoreCase(sbomFormat)) {
                args.add("json,cyclonedx");
            } else {
                args.add("json,spdx");
            }
        } else {
            args.add("json");
        }

        // Report format (sarif, table, json, gitlab)
        args.add("--report-format");
        args.add(config.getReportFormat() != null ? config.getReportFormat() : "sarif");

        // Output directory
        String outputDir = config.getOutputDir();
        if (outputDir == null || outputDir.isEmpty()) {
            outputDir = workspace.child("qualys-scan-results").getRemote();
        }
        args.add("--output-dir");
        args.add(outputDir);

        // Timeout - QScanner expects duration format like "5m" or "300s"
        args.add("--scan-timeout");
        args.add(config.getScanTimeout() + "s");

        // Log level
        args.add("--log-level");
        args.add(config.getLogLevel() != null ? config.getLogLevel() : "info");

        // Policy tags (only applicable when mode is evaluate-policy)
        if (config.isUsePolicyEvaluation() && config.getPolicyTags() != null && !config.getPolicyTags().isEmpty()) {
            args.add("--policy-tags");
            args.add(config.getPolicyTags());
        }

        // Proxy
        if (config.getProxyUrl() != null && !config.getProxyUrl().isEmpty()) {
            args.add("--proxy");
            args.add(config.getProxyUrl());
        }

        // TLS verification (correct flag name is --skip-verify-tls)
        if (config.isSkipTlsVerify()) {
            args.add("--skip-verify-tls");
        }

        return args;
    }

    private void addCodeScanArgs(List<String> args) {
        if (config.getExcludeDirs() != null && !config.getExcludeDirs().isEmpty()) {
            args.add("--exclude-dirs");
            args.add(config.getExcludeDirs());
        }

        if (config.getExcludeFiles() != null && !config.getExcludeFiles().isEmpty()) {
            args.add("--exclude-files");
            args.add(config.getExcludeFiles());
        }

        // Offline scan disables java-db download for SCA
        if (config.isOfflineScan()) {
            args.add("--offline-scan=true");
        }
    }

    private QScannerResult executeWithRetry(List<String> args) throws IOException, InterruptedException {
        QScannerResult result = null;
        int attempt = 0;

        while (attempt < MAX_RETRIES) {
            result = execute(args);

            // Check if we should retry
            if (result.getExitCode() != null && result.getExitCode().isRetryable()) {
                attempt++;
                if (attempt < MAX_RETRIES) {
                    int delay = RETRY_DELAYS_SEC[Math.min(attempt - 1, RETRY_DELAYS_SEC.length - 1)];
                    listener.getLogger().println(
                        String.format("Scan failed with retryable error (%s). Retrying in %d seconds... (attempt %d/%d)",
                            result.getExitCode().getDescription(), delay, attempt + 1, MAX_RETRIES)
                    );
                    Thread.sleep(delay * 1000L);
                }
            } else {
                break;
            }
        }

        return result;
    }

    private QScannerResult execute(List<String> args) throws IOException, InterruptedException {
        long startTime = System.currentTimeMillis();

        // Build command
        ArgumentListBuilder cmd = new ArgumentListBuilder();
        cmd.add(qscannerBinary.getRemote());
        for (String arg : args) {
            cmd.add(arg);
        }

        // Log command (masking sensitive data)
        listener.getLogger().println("Executing: " + cmd.toString());

        // Set up environment
        EnvVars env = new EnvVars();
        env.put("QUALYS_ACCESS_TOKEN", config.getAccessToken());

        // Create output directory
        String outputDir = config.getOutputDir();
        if (outputDir == null || outputDir.isEmpty()) {
            outputDir = workspace.child("qualys-scan-results").getRemote();
        }
        FilePath outputPath = new FilePath(workspace.getChannel(), outputDir);
        outputPath.mkdirs();

        // Execute with timeout (add 60s buffer to scan timeout for setup/teardown)
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        int timeoutSeconds = config.getScanTimeout() + 60;

        int exitCode;
        try {
            Launcher.ProcStarter procStarter = launcher.launch()
                .cmds(cmd)
                .envs(env)
                .stdout(stdout)
                .stderr(stderr)
                .pwd(workspace);

            hudson.Proc proc = procStarter.start();

            // Wait with timeout
            long deadline = System.currentTimeMillis() + (timeoutSeconds * 1000L);
            while (proc.isAlive()) {
                if (System.currentTimeMillis() > deadline) {
                    proc.kill();
                    return QScannerResult.failure(QScannerExitCode.TIMEOUT,
                        "Scan timed out after " + timeoutSeconds + " seconds");
                }
                Thread.sleep(1000);
            }
            exitCode = proc.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return QScannerResult.failure(QScannerExitCode.GENERAL_ERROR, "Scan interrupted: " + e.getMessage());
        } catch (Exception e) {
            return QScannerResult.failure(QScannerExitCode.GENERAL_ERROR, "Failed to execute QScanner: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;

        // Log output
        String stdoutStr = stdout.toString();
        String stderrStr = stderr.toString();

        if (!stdoutStr.isEmpty()) {
            listener.getLogger().println(stdoutStr);
        }
        if (!stderrStr.isEmpty()) {
            listener.error(stderrStr);
        }

        // Parse result
        QScannerResult result = new QScannerResult();
        result.setExitCode(QScannerExitCode.fromCode(exitCode));
        result.setScanDurationMs(duration);
        result.setOutputDirectory(outputDir);

        if (exitCode == 0) {
            result.setSuccess(true);
            result.setPolicyResult(QScannerResult.PolicyResult.ALLOW);
        } else if (exitCode == 42) {
            result.setSuccess(true); // Scan succeeded, but policy denied
            result.setPolicyResult(QScannerResult.PolicyResult.DENY);
        } else if (exitCode == 43) {
            result.setSuccess(true);
            result.setPolicyResult(QScannerResult.PolicyResult.AUDIT);
        } else {
            result.setSuccess(false);
            result.setErrorMessage(result.getExitCode().getDescription() + ": " + stderrStr);
        }

        // Find report files
        findReportFiles(result, outputPath);

        return result;
    }

    private void findReportFiles(QScannerResult result, FilePath outputDir) {
        try {
            for (FilePath file : outputDir.list()) {
                String name = file.getName();
                if (name.endsWith(".sarif.json") || name.endsWith("-Report.sarif")) {
                    result.setSarifReportPath(file.getRemote());
                } else if (name.endsWith("-ScanResult.json")) {
                    result.setJsonReportPath(file.getRemote());
                } else if (name.endsWith(".spdx.json") || name.endsWith(".cyclonedx.json")) {
                    result.setSbomPath(file.getRemote());
                }
            }
        } catch (Exception e) {
            listener.getLogger().println("Warning: Could not enumerate report files: " + e.getMessage());
        }
    }
}
