package com.qualys.plugins.scanner.types;

import java.io.Serializable;

/**
 * Represents a software package found in the scanned image.
 */
public class PackageInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    private String name;
    private String version;
    private String type; // e.g., "deb", "rpm", "npm", "pip", etc.
    private int vulnerabilityCount;
    private String layerSHA;

    public PackageInfo() {
    }

    public PackageInfo(String name, String version, String type) {
        this.name = name;
        this.version = version;
        this.type = type;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public int getVulnerabilityCount() { return vulnerabilityCount; }
    public void setVulnerabilityCount(int vulnerabilityCount) { this.vulnerabilityCount = vulnerabilityCount; }

    public String getLayerSHA() { return layerSHA; }
    public void setLayerSHA(String layerSHA) { this.layerSHA = layerSHA; }

    public String getLayerShort() {
        if (layerSHA == null || layerSHA.isEmpty()) return null;
        String sha = layerSHA;
        if (sha.startsWith("sha256:")) {
            sha = sha.substring(7);
        }
        return sha.length() > 12 ? sha.substring(0, 12) : sha;
    }

    @Override
    public String toString() {
        return name + ":" + version;
    }
}
