package com.qualys.plugins.scanner;

import com.qualys.plugins.scanner.types.PackageInfo;
import com.qualys.plugins.scanner.types.ScanReportDetails;
import com.qualys.plugins.scanner.types.Vulnerability;
import hudson.model.Run;
import jenkins.model.RunAction2;

import java.util.ArrayList;
import java.util.List;

/**
 * Build action to store and display Qualys scan results.
 */
public class QualysScanAction implements RunAction2 {

    private final int totalVulnerabilities;
    private final int criticalCount;
    private final int highCount;
    private final int mediumCount;
    private final int lowCount;
    private final String policyResult;
    private final boolean scanPassed;
    private final String reportPath;

    // Detailed report data
    private ScanReportDetails reportDetails;
    private String imageName;

    private transient Run<?, ?> run;

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
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public Run<?, ?> getRun() {
        return run;
    }

    @Override
    public String getIconFileName() {
        // Use Jenkins built-in clipboard icon
        return "clipboard.png";
    }

    @Override
    public String getDisplayName() {
        return "Qualys Scan Results";
    }

    @Override
    public String getUrlName() {
        return "qualys-scan";
    }

    // Basic getters for Jelly view
    public int getTotalVulnerabilities() { return totalVulnerabilities; }
    public int getCriticalCount() { return criticalCount; }
    public int getHighCount() { return highCount; }
    public int getMediumCount() { return mediumCount; }
    public int getLowCount() { return lowCount; }
    public String getPolicyResult() { return policyResult; }
    public boolean isScanPassed() { return scanPassed; }
    public String getReportPath() { return reportPath; }

    // Detailed report getters/setters
    public ScanReportDetails getReportDetails() { return reportDetails; }
    public void setReportDetails(ScanReportDetails reportDetails) {
        this.reportDetails = reportDetails;
    }

    public String getImageName() { return imageName; }
    public void setImageName(String imageName) { this.imageName = imageName; }

    // Convenience methods for Jelly
    public String getImageId() {
        return reportDetails != null ? reportDetails.getImageId() : null;
    }

    public String getImageDigest() {
        return reportDetails != null ? reportDetails.getImageDigest() : null;
    }

    public String getOperatingSystem() {
        return reportDetails != null ? reportDetails.getOsDisplay() : "Unknown";
    }

    public int getTotalPackages() {
        return reportDetails != null ? reportDetails.getTotalPackages() : 0;
    }

    public List<Vulnerability> getVulnerabilities() {
        return reportDetails != null ? reportDetails.getVulnerabilities() : new ArrayList<>();
    }

    public List<Vulnerability> getCriticalVulnerabilities() {
        return reportDetails != null ? reportDetails.getCriticalVulnerabilities() : new ArrayList<>();
    }

    public List<Vulnerability> getHighVulnerabilities() {
        return reportDetails != null ? reportDetails.getHighVulnerabilities() : new ArrayList<>();
    }

    public List<Vulnerability> getMediumVulnerabilities() {
        return reportDetails != null ? reportDetails.getMediumVulnerabilities() : new ArrayList<>();
    }

    public List<Vulnerability> getLowVulnerabilities() {
        return reportDetails != null ? reportDetails.getLowVulnerabilities() : new ArrayList<>();
    }

    public List<PackageInfo> getPackages() {
        return reportDetails != null ? reportDetails.getPackages() : new ArrayList<>();
    }

    public List<String> getLayers() {
        return reportDetails != null ? reportDetails.getLayers() : new ArrayList<>();
    }

    public int getTotalLayers() {
        return reportDetails != null ? reportDetails.getTotalLayers() : 0;
    }

    public boolean hasLayers() {
        return reportDetails != null && reportDetails.hasLayers();
    }

    public boolean hasDetailedReport() {
        return reportDetails != null;
    }

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

    public String getStatusText() {
        return scanPassed ? "PASSED" : "FAILED";
    }

    public String getStatusColor() {
        return scanPassed ? "#28a745" : "#dc3545";
    }
}
