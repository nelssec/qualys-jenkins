package com.qualys.plugins.scanner.qscanner;

import com.qualys.plugins.scanner.runner.ScannerRunner;
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
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class QScannerRunner implements ScannerRunner {

    private static final String QSCANNER_VERSION = "4.8.0-2";
    private static final String QSCANNER_DOWNLOAD_URL =
        "https://github.com/nelssec/qualys-lambda/raw/refs/heads/main/scanner-lambda/qscanner.gz";
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

    @Override
    public void setup() throws IOException, InterruptedException {
        listener.getLogger().println("Setting up QScanner v" + QSCANNER_VERSION);

        validatePlatform();

        FilePath tempDir = workspace.child(".qualys-scanner");
        tempDir.mkdirs();

        FilePath gzFile = tempDir.child("qscanner.gz");
        qscannerBinary = tempDir.child("qscanner");

        if (!qscannerBinary.exists() || !verifyChecksum(qscannerBinary)) {
            downloadBinary(gzFile);
            extractBinary(gzFile, qscannerBinary);
            gzFile.delete();
        }

        qscannerBinary.chmod(0755);
        listener.getLogger().println("QScanner ready at: " + qscannerBinary.getRemote());
    }

    private void validatePlatform() throws IOException {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();

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
        if (QSCANNER_CHECKSUM_URL == null) {
            listener.getLogger().println("Checksum verification skipped (no checksum URL configured)");
            return true;
        }

        try {
            URL checksumUrl = new URL(QSCANNER_CHECKSUM_URL);
            HttpURLConnection conn = (HttpURLConnection) checksumUrl.openConnection();
            conn.setInstanceFollowRedirects(true);

            String expectedChecksum;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                expectedChecksum = reader.readLine();
                if (expectedChecksum != null) {
                    expectedChecksum = expectedChecksum.split("\\s+")[0].toLowerCase();
                }
            } finally {
                conn.disconnect();
            }

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

    @Override
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

    @Override
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

    @Override
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

        if (config.getPod() != null && !config.getPod().isEmpty()) {
            args.add("--pod");
            args.add(config.getPod());
        }

        args.add("--mode");
        if (config.isUsePolicyEvaluation()) {
            args.add("evaluate-policy");
        } else {
            args.add(config.getMode() != null ? config.getMode() : "get-report");
        }

        String scanTypes = config.getScanTypes();
        if (config.isScanSecrets() && !scanTypes.contains("secret")) {
            scanTypes = scanTypes + ",secret";
        }
        if (config.isScanMalware() && !scanTypes.contains("malware")) {
            scanTypes = scanTypes + ",malware";
        }
        args.add("--scan-types");
        args.add(scanTypes);

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

        args.add("--report-format");
        args.add(config.getReportFormat() != null ? config.getReportFormat() : "sarif");

        String outputDir = config.getOutputDir();
        if (outputDir == null || outputDir.isEmpty()) {
            outputDir = workspace.child("qualys-scan-results").getRemote();
        }
        args.add("--output-dir");
        args.add(outputDir);

        args.add("--scan-timeout");
        args.add(config.getScanTimeout() + "s");

        args.add("--log-level");
        args.add(config.getLogLevel() != null ? config.getLogLevel() : "info");

        if (config.isUsePolicyEvaluation() && config.getPolicyTags() != null && !config.getPolicyTags().isEmpty()) {
            args.add("--policy-tags");
            args.add(config.getPolicyTags());
        }

        if (config.getProxyUrl() != null && !config.getProxyUrl().isEmpty()) {
            args.add("--proxy");
            args.add(config.getProxyUrl());
        }

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

        if (config.isOfflineScan()) {
            args.add("--offline-scan=true");
        }
    }

    private QScannerResult executeWithRetry(List<String> args) throws IOException, InterruptedException {
        QScannerResult result = null;
        int attempt = 0;

        while (attempt < MAX_RETRIES) {
            result = execute(args);

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

        ArgumentListBuilder cmd = new ArgumentListBuilder();
        cmd.add(qscannerBinary.getRemote());
        for (String arg : args) {
            cmd.add(arg);
        }

        listener.getLogger().println("Executing: " + cmd.toString());

        EnvVars env = new EnvVars();
        env.put("QUALYS_ACCESS_TOKEN", config.getAccessToken());

        String outputDir = config.getOutputDir();
        if (outputDir == null || outputDir.isEmpty()) {
            outputDir = workspace.child("qualys-scan-results").getRemote();
        }
        FilePath outputPath = new FilePath(workspace.getChannel(), outputDir);
        outputPath.mkdirs();

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

        String stdoutStr = stdout.toString();
        String stderrStr = stderr.toString();

        if (!stdoutStr.isEmpty()) {
            listener.getLogger().println(stdoutStr);
        }
        if (!stderrStr.isEmpty()) {
            listener.error(stderrStr);
        }

        QScannerResult result = new QScannerResult();
        result.setExitCode(QScannerExitCode.fromCode(exitCode));
        result.setScanDurationMs(duration);
        result.setOutputDirectory(outputDir);

        if (exitCode == 0) {
            result.setSuccess(true);
            result.setPolicyResult(QScannerResult.PolicyResult.ALLOW);
        } else if (exitCode == 42) {
            result.setSuccess(true);
            result.setPolicyResult(QScannerResult.PolicyResult.DENY);
        } else if (exitCode == 43) {
            result.setSuccess(true);
            result.setPolicyResult(QScannerResult.PolicyResult.AUDIT);
        } else {
            result.setSuccess(false);
            result.setErrorMessage(result.getExitCode().getDescription() + ": " + stderrStr);
        }

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

    @Override
    public String getBackendName() {
        return "QScanner";
    }

    @Override
    public boolean supportsScanType(String scanType) {
        return "container".equals(scanType) || "code".equals(scanType) || "rootfs".equals(scanType);
    }
}
