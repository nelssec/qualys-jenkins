package com.qualys.plugins.scanner.types;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Detailed scan report containing full vulnerability and package information.
 */
public class ScanReportDetails implements Serializable {
    private static final long serialVersionUID = 1L;

    // Image metadata
    private String imageId;
    private String imageName;
    private String imageDigest;
    private String operatingSystem;
    private String osVersion;

    // Summary counts
    private VulnerabilitySummary vulnerabilitySummary;
    private int totalPackages;

    // Detailed lists
    private List<Vulnerability> vulnerabilities;
    private List<PackageInfo> packages;

    public ScanReportDetails() {
        this.vulnerabilities = new ArrayList<>();
        this.packages = new ArrayList<>();
        this.vulnerabilitySummary = new VulnerabilitySummary();
    }

    // Getters and Setters
    public String getImageId() { return imageId; }
    public void setImageId(String imageId) { this.imageId = imageId; }

    public String getImageName() { return imageName; }
    public void setImageName(String imageName) { this.imageName = imageName; }

    public String getImageDigest() { return imageDigest; }
    public void setImageDigest(String imageDigest) { this.imageDigest = imageDigest; }

    public String getOperatingSystem() { return operatingSystem; }
    public void setOperatingSystem(String operatingSystem) { this.operatingSystem = operatingSystem; }

    public String getOsVersion() { return osVersion; }
    public void setOsVersion(String osVersion) { this.osVersion = osVersion; }

    public VulnerabilitySummary getVulnerabilitySummary() { return vulnerabilitySummary; }
    public void setVulnerabilitySummary(VulnerabilitySummary vulnerabilitySummary) {
        this.vulnerabilitySummary = vulnerabilitySummary;
    }

    public int getTotalPackages() { return totalPackages; }
    public void setTotalPackages(int totalPackages) { this.totalPackages = totalPackages; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public List<PackageInfo> getPackages() { return packages; }
    public void setPackages(List<PackageInfo> packages) { this.packages = packages; }

    public void addVulnerability(Vulnerability vuln) {
        this.vulnerabilities.add(vuln);
    }

    public void addPackage(PackageInfo pkg) {
        this.packages.add(pkg);
    }

    // Convenience methods for Jelly
    public List<Vulnerability> getCriticalVulnerabilities() {
        return filterBySeverity(5);
    }

    public List<Vulnerability> getHighVulnerabilities() {
        return filterBySeverity(4);
    }

    public List<Vulnerability> getMediumVulnerabilities() {
        return filterBySeverity(3);
    }

    public List<Vulnerability> getLowVulnerabilities() {
        return filterBySeverity(2);
    }

    private List<Vulnerability> filterBySeverity(int level) {
        List<Vulnerability> filtered = new ArrayList<>();
        for (Vulnerability v : vulnerabilities) {
            if (v.getSeverityLevel() == level) {
                filtered.add(v);
            }
        }
        return filtered;
    }

    public String getOsDisplay() {
        if (operatingSystem == null) return "Unknown";
        if (osVersion != null && !osVersion.isEmpty()) {
            return operatingSystem + " " + osVersion;
        }
        return operatingSystem;
    }
}
