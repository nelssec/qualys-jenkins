package com.qualys.plugins.scanner.types;

import java.util.HashMap;
import java.util.Map;

/**
 * Qualys platform pod definitions with gateway URLs.
 * Matches the POD_GATEWAY_URLS from qualys-ado.
 */
public enum QualysPod {
    US1("US1", "https://gateway.qg1.apps.qualys.com"),
    US2("US2", "https://gateway.qg2.apps.qualys.com"),
    US3("US3", "https://gateway.qg3.apps.qualys.com"),
    US4("US4", "https://gateway.qg4.apps.qualys.com"),
    EU1("EU1", "https://gateway.qg1.apps.qualys.eu"),
    EU2("EU2", "https://gateway.qg2.apps.qualys.eu"),
    CA1("CA1", "https://gateway.qg1.apps.qualys.ca"),
    IN1("IN1", "https://gateway.qg1.apps.qualys.in"),
    AU1("AU1", "https://gateway.qg1.apps.qualys.com.au"),
    UK1("UK1", "https://gateway.qg1.apps.qualys.co.uk"),
    AE1("AE1", "https://gateway.qg1.apps.qualys.ae"),
    KSA1("KSA1", "https://gateway.qg1.apps.qualysksa.com");

    private final String name;
    private final String gatewayUrl;

    private static final Map<String, QualysPod> BY_NAME = new HashMap<>();

    static {
        for (QualysPod pod : values()) {
            BY_NAME.put(pod.name.toUpperCase(), pod);
        }
    }

    QualysPod(String name, String gatewayUrl) {
        this.name = name;
        this.gatewayUrl = gatewayUrl;
    }

    public String getName() {
        return name;
    }

    public String getGatewayUrl() {
        return gatewayUrl;
    }

    public static QualysPod fromName(String name) {
        if (name == null) {
            return US1;
        }
        return BY_NAME.getOrDefault(name.toUpperCase(), US1);
    }

    public static boolean isValidPod(String name) {
        return name != null && BY_NAME.containsKey(name.toUpperCase());
    }
}
