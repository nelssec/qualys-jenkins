package com.qualys.plugins.scanner.types;

/**
 * Types of scans that can be performed by QScanner.
 */
public enum ScanType {
    CONTAINER("container", "Container Image Scan"),
    CODE("code", "Code/Repository Scan"),
    ROOTFS("rootfs", "Root Filesystem Scan");

    private final String value;
    private final String displayName;

    ScanType(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue() {
        return value;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static ScanType fromValue(String value) {
        for (ScanType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown scan type: " + value);
    }
}
