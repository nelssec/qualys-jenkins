package com.qualys.plugins.scanner;

import hudson.model.Action;

/**
 * Build action to store and display Qualys scan results.
 */
public class QualysScanAction implements Action {

    private final int totalVulnerabilities;
    private final int criticalCount;
    private final int highCount;
    private final int mediumCount;
    private final int lowCount;
    private final String policyResult;
    private final boolean scanPassed;
    private final String reportPath;

    public QualysScanAction(int totalVulnerabilities, int criticalCount, int highCount,
                            int mediumCount, int lowCount, String policyResult,
                            boolean scanPassed, String reportPath) {
        this.totalVulnerabilities = totalVulnerabilities;
        this.criticalCount = criticalCount;
        this.highCount = highCount;
        this.mediumCount = mediumCount;
        this.lowCount = lowCount;
        this.policyResult = policyResult;
        this.scanPassed = scanPassed;
        this.reportPath = reportPath;
    }

    @Override
    public String getIconFileName() {
        return "/plugin/qualys-scanner/images/qualys-icon.png";
    }

    @Override
    public String getDisplayName() {
        return "Qualys Scan Results";
    }

    @Override
    public String getUrlName() {
        return "qualys-scan";
    }

    // Getters for Jelly view
    public int getTotalVulnerabilities() { return totalVulnerabilities; }
    public int getCriticalCount() { return criticalCount; }
    public int getHighCount() { return highCount; }
    public int getMediumCount() { return mediumCount; }
    public int getLowCount() { return lowCount; }
    public String getPolicyResult() { return policyResult; }
    public boolean isScanPassed() { return scanPassed; }
    public String getReportPath() { return reportPath; }

    public String getSummary() {
        return String.format("%d vulnerabilities (Critical: %d, High: %d, Medium: %d, Low: %d)",
            totalVulnerabilities, criticalCount, highCount, mediumCount, lowCount);
    }

    public String getStatusClass() {
        if (!scanPassed) {
            return "danger";
        }
        if (criticalCount > 0 || highCount > 0) {
            return "warning";
        }
        return "success";
    }
}
