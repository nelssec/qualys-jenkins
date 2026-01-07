package com.qualys.plugins.scanner.types;

import java.io.Serializable;

/**
 * Result of a QScanner execution.
 */
public class QScannerResult implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum PolicyResult {
        ALLOW,
        DENY,
        AUDIT,
        NOT_EVALUATED
    }

    private QScannerExitCode exitCode;
    private boolean success;
    private String errorMessage;
    private VulnerabilitySummary vulnerabilitySummary;
    private PolicyResult policyResult = PolicyResult.NOT_EVALUATED;

    private String sarifReportPath;
    private String jsonReportPath;
    private String sbomPath;
    private String outputDirectory;

    private String scanId;
    private long scanDurationMs;
    private String imageDigest;

    public QScannerResult() {
        this.vulnerabilitySummary = new VulnerabilitySummary();
    }

    public static QScannerResult success() {
        QScannerResult result = new QScannerResult();
        result.setSuccess(true);
        result.setExitCode(QScannerExitCode.SUCCESS);
        return result;
    }

    public static QScannerResult failure(QScannerExitCode exitCode, String errorMessage) {
        QScannerResult result = new QScannerResult();
        result.setSuccess(false);
        result.setExitCode(exitCode);
        result.setErrorMessage(errorMessage);
        return result;
    }

    public boolean shouldFailBuild() {
        if (!success) {
            return true;
        }
        if (exitCode != null && exitCode.isPolicyDeny()) {
            return true;
        }
        if (exitCode != null && exitCode.isThresholdExceeded()) {
            return true;
        }
        return policyResult == PolicyResult.DENY;
    }

    public QScannerExitCode getExitCode() { return exitCode; }
    public void setExitCode(QScannerExitCode exitCode) { this.exitCode = exitCode; }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public VulnerabilitySummary getVulnerabilitySummary() { return vulnerabilitySummary; }
    public void setVulnerabilitySummary(VulnerabilitySummary vulnerabilitySummary) {
        this.vulnerabilitySummary = vulnerabilitySummary;
    }

    public PolicyResult getPolicyResult() { return policyResult; }
    public void setPolicyResult(PolicyResult policyResult) { this.policyResult = policyResult; }

    public String getSarifReportPath() { return sarifReportPath; }
    public void setSarifReportPath(String sarifReportPath) { this.sarifReportPath = sarifReportPath; }

    public String getJsonReportPath() { return jsonReportPath; }
    public void setJsonReportPath(String jsonReportPath) { this.jsonReportPath = jsonReportPath; }

    public String getSbomPath() { return sbomPath; }
    public void setSbomPath(String sbomPath) { this.sbomPath = sbomPath; }

    public String getOutputDirectory() { return outputDirectory; }
    public void setOutputDirectory(String outputDirectory) { this.outputDirectory = outputDirectory; }

    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }

    public long getScanDurationMs() { return scanDurationMs; }
    public void setScanDurationMs(long scanDurationMs) { this.scanDurationMs = scanDurationMs; }

    public String getImageDigest() { return imageDigest; }
    public void setImageDigest(String imageDigest) { this.imageDigest = imageDigest; }
}
