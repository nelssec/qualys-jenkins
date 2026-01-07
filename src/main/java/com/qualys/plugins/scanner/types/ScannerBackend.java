package com.qualys.plugins.scanner.types;

public enum ScannerBackend {

    QSCANNER("qscanner", "QScanner (On-Demand)"),
    CICD_SENSOR("cicd_sensor", "CICD Sensor (Installed)");

    private final String value;
    private final String displayName;

    ScannerBackend(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue() {
        return value;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static ScannerBackend fromValue(String value) {
        if (value == null) {
            return QSCANNER;
        }
        for (ScannerBackend backend : values()) {
            if (backend.value.equalsIgnoreCase(value)) {
                return backend;
            }
        }
        return QSCANNER;
    }
}
