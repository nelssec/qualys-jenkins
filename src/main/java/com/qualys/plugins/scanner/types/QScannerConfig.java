package com.qualys.plugins.scanner.types;

import java.io.Serializable;

/**
 * Configuration for QScanner execution.
 */
public class QScannerConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    // Connection settings
    private String pod;
    private String accessToken;
    private String proxyUrl;
    private boolean skipTlsVerify;

    // Scan target
    private ScanType scanType;
    private String imageId;
    private String scanPath;
    private String platform;
    private StorageDriver storageDriver;

    // Scan options
    private String scanTypes = "pkg";
    private String mode = "get-report";
    private boolean scanSecrets;
    private boolean scanMalware;
    private int scanTimeout = 300;
    private String logLevel = "info";

    // Code scan options
    private String excludeDirs;
    private String excludeFiles;
    private boolean offlineScan;
    private boolean generateSbom;
    private String sbomFormat = "spdx";

    // Policy options
    private boolean usePolicyEvaluation;
    private String policyTags;

    // Threshold options (when not using policy)
    private int maxCritical = 0;
    private int maxHigh = 0;
    private int maxMedium = -1;  // -1 means unlimited
    private int maxLow = -1;

    // Output options
    private String outputDir;
    private String reportFormat = "sarif";

    public QScannerConfig() {
    }

    // Builder pattern
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final QScannerConfig config = new QScannerConfig();

        public Builder pod(String pod) {
            config.pod = pod;
            return this;
        }

        public Builder accessToken(String accessToken) {
            config.accessToken = accessToken;
            return this;
        }

        public Builder proxyUrl(String proxyUrl) {
            config.proxyUrl = proxyUrl;
            return this;
        }

        public Builder skipTlsVerify(boolean skipTlsVerify) {
            config.skipTlsVerify = skipTlsVerify;
            return this;
        }

        public Builder scanType(ScanType scanType) {
            config.scanType = scanType;
            return this;
        }

        public Builder imageId(String imageId) {
            config.imageId = imageId;
            return this;
        }

        public Builder scanPath(String scanPath) {
            config.scanPath = scanPath;
            return this;
        }

        public Builder platform(String platform) {
            config.platform = platform;
            return this;
        }

        public Builder storageDriver(StorageDriver storageDriver) {
            config.storageDriver = storageDriver;
            return this;
        }

        public Builder scanTypes(String scanTypes) {
            config.scanTypes = scanTypes;
            return this;
        }

        public Builder mode(String mode) {
            config.mode = mode;
            return this;
        }

        public Builder scanSecrets(boolean scanSecrets) {
            config.scanSecrets = scanSecrets;
            return this;
        }

        public Builder scanMalware(boolean scanMalware) {
            config.scanMalware = scanMalware;
            return this;
        }

        public Builder scanTimeout(int scanTimeout) {
            config.scanTimeout = scanTimeout;
            return this;
        }

        public Builder logLevel(String logLevel) {
            config.logLevel = logLevel;
            return this;
        }

        public Builder excludeDirs(String excludeDirs) {
            config.excludeDirs = excludeDirs;
            return this;
        }

        public Builder excludeFiles(String excludeFiles) {
            config.excludeFiles = excludeFiles;
            return this;
        }

        public Builder offlineScan(boolean offlineScan) {
            config.offlineScan = offlineScan;
            return this;
        }

        public Builder generateSbom(boolean generateSbom) {
            config.generateSbom = generateSbom;
            return this;
        }

        public Builder sbomFormat(String sbomFormat) {
            config.sbomFormat = sbomFormat;
            return this;
        }

        public Builder usePolicyEvaluation(boolean usePolicyEvaluation) {
            config.usePolicyEvaluation = usePolicyEvaluation;
            return this;
        }

        public Builder policyTags(String policyTags) {
            config.policyTags = policyTags;
            return this;
        }

        public Builder maxCritical(int maxCritical) {
            config.maxCritical = maxCritical;
            return this;
        }

        public Builder maxHigh(int maxHigh) {
            config.maxHigh = maxHigh;
            return this;
        }

        public Builder maxMedium(int maxMedium) {
            config.maxMedium = maxMedium;
            return this;
        }

        public Builder maxLow(int maxLow) {
            config.maxLow = maxLow;
            return this;
        }

        public Builder outputDir(String outputDir) {
            config.outputDir = outputDir;
            return this;
        }

        public Builder reportFormat(String reportFormat) {
            config.reportFormat = reportFormat;
            return this;
        }

        public QScannerConfig build() {
            return config;
        }
    }

    // Getters
    public String getPod() { return pod; }
    public String getAccessToken() { return accessToken; }
    public String getProxyUrl() { return proxyUrl; }
    public boolean isSkipTlsVerify() { return skipTlsVerify; }
    public ScanType getScanType() { return scanType; }
    public String getImageId() { return imageId; }
    public String getScanPath() { return scanPath; }
    public String getPlatform() { return platform; }
    public StorageDriver getStorageDriver() { return storageDriver; }
    public String getScanTypes() { return scanTypes; }
    public String getMode() { return mode; }
    public boolean isScanSecrets() { return scanSecrets; }
    public boolean isScanMalware() { return scanMalware; }
    public int getScanTimeout() { return scanTimeout; }
    public String getLogLevel() { return logLevel; }
    public String getExcludeDirs() { return excludeDirs; }
    public String getExcludeFiles() { return excludeFiles; }
    public boolean isOfflineScan() { return offlineScan; }
    public boolean isGenerateSbom() { return generateSbom; }
    public String getSbomFormat() { return sbomFormat; }
    public boolean isUsePolicyEvaluation() { return usePolicyEvaluation; }
    public String getPolicyTags() { return policyTags; }
    public int getMaxCritical() { return maxCritical; }
    public int getMaxHigh() { return maxHigh; }
    public int getMaxMedium() { return maxMedium; }
    public int getMaxLow() { return maxLow; }
    public String getOutputDir() { return outputDir; }
    public String getReportFormat() { return reportFormat; }

    // Setters
    public void setPod(String pod) { this.pod = pod; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public void setProxyUrl(String proxyUrl) { this.proxyUrl = proxyUrl; }
    public void setSkipTlsVerify(boolean skipTlsVerify) { this.skipTlsVerify = skipTlsVerify; }
    public void setScanType(ScanType scanType) { this.scanType = scanType; }
    public void setImageId(String imageId) { this.imageId = imageId; }
    public void setScanPath(String scanPath) { this.scanPath = scanPath; }
    public void setPlatform(String platform) { this.platform = platform; }
    public void setStorageDriver(StorageDriver storageDriver) { this.storageDriver = storageDriver; }
    public void setScanTypes(String scanTypes) { this.scanTypes = scanTypes; }
    public void setMode(String mode) { this.mode = mode; }
    public void setScanSecrets(boolean scanSecrets) { this.scanSecrets = scanSecrets; }
    public void setScanMalware(boolean scanMalware) { this.scanMalware = scanMalware; }
    public void setScanTimeout(int scanTimeout) { this.scanTimeout = scanTimeout; }
    public void setLogLevel(String logLevel) { this.logLevel = logLevel; }
    public void setExcludeDirs(String excludeDirs) { this.excludeDirs = excludeDirs; }
    public void setExcludeFiles(String excludeFiles) { this.excludeFiles = excludeFiles; }
    public void setOfflineScan(boolean offlineScan) { this.offlineScan = offlineScan; }
    public void setGenerateSbom(boolean generateSbom) { this.generateSbom = generateSbom; }
    public void setSbomFormat(String sbomFormat) { this.sbomFormat = sbomFormat; }
    public void setUsePolicyEvaluation(boolean usePolicyEvaluation) { this.usePolicyEvaluation = usePolicyEvaluation; }
    public void setPolicyTags(String policyTags) { this.policyTags = policyTags; }
    public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }
    public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }
    public void setMaxMedium(int maxMedium) { this.maxMedium = maxMedium; }
    public void setMaxLow(int maxLow) { this.maxLow = maxLow; }
    public void setOutputDir(String outputDir) { this.outputDir = outputDir; }
    public void setReportFormat(String reportFormat) { this.reportFormat = reportFormat; }
}
