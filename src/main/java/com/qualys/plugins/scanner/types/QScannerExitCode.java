package com.qualys.plugins.scanner.types;

import java.util.HashMap;
import java.util.Map;

/**
 * Exit codes returned by the QScanner CLI tool.
 */
public enum QScannerExitCode {
    SUCCESS(0, "Success"),
    GENERAL_ERROR(1, "General error"),
    INVALID_ARGUMENTS(2, "Invalid arguments"),
    SCAN_FAILED(10, "Scan failed"),
    IMAGE_NOT_FOUND(11, "Image not found"),
    IMAGE_PULL_FAILED(12, "Image pull failed"),
    AUTHENTICATION_FAILED(20, "Authentication failed"),
    AUTHORIZATION_FAILED(21, "Authorization failed"),
    TOKEN_EXPIRED(22, "Token expired"),
    API_ERROR(30, "API error"),
    NETWORK_ERROR(31, "Network error"),
    TIMEOUT(32, "Timeout"),
    FAILED_TO_GET_VULN_REPORT(40, "Failed to get vulnerability report"),
    REPORT_GENERATION_FAILED(41, "Report generation failed"),
    POLICY_EVALUATION_DENY(42, "Policy evaluation: DENY"),
    POLICY_EVALUATION_AUDIT(43, "Policy evaluation: AUDIT"),
    THRESHOLD_EXCEEDED(50, "Vulnerability threshold exceeded"),
    PLATFORM_NOT_SUPPORTED(60, "Platform not supported"),
    BINARY_CORRUPTED(61, "Binary corrupted or invalid checksum");

    private final int code;
    private final String description;

    private static final Map<Integer, QScannerExitCode> CODE_MAP = new HashMap<>();

    static {
        for (QScannerExitCode exitCode : values()) {
            CODE_MAP.put(exitCode.code, exitCode);
        }
    }

    QScannerExitCode(int code, String description) {
        this.code = code;
        this.description = description;
    }

    public int getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSuccess() {
        return this == SUCCESS;
    }

    public boolean isPolicyDeny() {
        return this == POLICY_EVALUATION_DENY;
    }

    public boolean isPolicyAudit() {
        return this == POLICY_EVALUATION_AUDIT;
    }

    public boolean isThresholdExceeded() {
        return this == THRESHOLD_EXCEEDED;
    }

    public boolean isRetryable() {
        return this == FAILED_TO_GET_VULN_REPORT ||
               this == NETWORK_ERROR ||
               this == TIMEOUT;
    }

    public static QScannerExitCode fromCode(int code) {
        return CODE_MAP.getOrDefault(code, GENERAL_ERROR);
    }
}
