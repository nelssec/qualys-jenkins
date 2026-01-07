package com.qualys.plugins.scanner.types;

/**
 * Container runtime storage drivers supported by QScanner.
 */
public enum StorageDriver {
    NONE("none", "None (default)"),
    DOCKER_OVERLAY2("docker-overlay2", "Docker Overlay2"),
    CONTAINERD_OVERLAYFS("containerd-overlayfs", "Containerd OverlayFS");

    private final String value;
    private final String displayName;

    StorageDriver(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue() {
        return value;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static StorageDriver fromValue(String value) {
        if (value == null || value.isEmpty()) {
            return NONE;
        }
        for (StorageDriver driver : values()) {
            if (driver.value.equalsIgnoreCase(value)) {
                return driver;
            }
        }
        return NONE;
    }
}
