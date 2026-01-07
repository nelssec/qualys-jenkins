package com.qualys.plugins.scanner.sensor;

import java.io.Serializable;

public class CICDSensorConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    private String apiServer;
    private String username;
    private String password;
    private boolean useOAuth;
    private String clientId;
    private String clientSecret;

    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;

    private String imageId;
    private String dockerUrl;
    private String dockerCert;

    private int pollingInterval = 10;
    private int vulnsTimeout = 600;

    private int maxCritical = 0;
    private int maxHigh = 0;
    private int maxMedium = -1;
    private int maxLow = -1;

    private String outputDir;
    private boolean validateSensor = true;

    public CICDSensorConfig() {
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final CICDSensorConfig config = new CICDSensorConfig();

        public Builder apiServer(String apiServer) { config.apiServer = apiServer; return this; }
        public Builder username(String username) { config.username = username; return this; }
        public Builder password(String password) { config.password = password; return this; }
        public Builder useOAuth(boolean useOAuth) { config.useOAuth = useOAuth; return this; }
        public Builder clientId(String clientId) { config.clientId = clientId; return this; }
        public Builder clientSecret(String clientSecret) { config.clientSecret = clientSecret; return this; }
        public Builder proxyHost(String proxyHost) { config.proxyHost = proxyHost; return this; }
        public Builder proxyPort(int proxyPort) { config.proxyPort = proxyPort; return this; }
        public Builder proxyUsername(String proxyUsername) { config.proxyUsername = proxyUsername; return this; }
        public Builder proxyPassword(String proxyPassword) { config.proxyPassword = proxyPassword; return this; }
        public Builder imageId(String imageId) { config.imageId = imageId; return this; }
        public Builder dockerUrl(String dockerUrl) { config.dockerUrl = dockerUrl; return this; }
        public Builder dockerCert(String dockerCert) { config.dockerCert = dockerCert; return this; }
        public Builder pollingInterval(int pollingInterval) { config.pollingInterval = pollingInterval; return this; }
        public Builder vulnsTimeout(int vulnsTimeout) { config.vulnsTimeout = vulnsTimeout; return this; }
        public Builder maxCritical(int maxCritical) { config.maxCritical = maxCritical; return this; }
        public Builder maxHigh(int maxHigh) { config.maxHigh = maxHigh; return this; }
        public Builder maxMedium(int maxMedium) { config.maxMedium = maxMedium; return this; }
        public Builder maxLow(int maxLow) { config.maxLow = maxLow; return this; }
        public Builder outputDir(String outputDir) { config.outputDir = outputDir; return this; }
        public Builder validateSensor(boolean validateSensor) { config.validateSensor = validateSensor; return this; }
        public CICDSensorConfig build() { return config; }
    }

    public String getApiServer() { return apiServer; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public boolean isUseOAuth() { return useOAuth; }
    public String getClientId() { return clientId; }
    public String getClientSecret() { return clientSecret; }
    public String getProxyHost() { return proxyHost; }
    public int getProxyPort() { return proxyPort; }
    public String getProxyUsername() { return proxyUsername; }
    public String getProxyPassword() { return proxyPassword; }
    public String getImageId() { return imageId; }
    public String getDockerUrl() { return dockerUrl; }
    public String getDockerCert() { return dockerCert; }
    public int getPollingInterval() { return pollingInterval; }
    public int getVulnsTimeout() { return vulnsTimeout; }
    public int getMaxCritical() { return maxCritical; }
    public int getMaxHigh() { return maxHigh; }
    public int getMaxMedium() { return maxMedium; }
    public int getMaxLow() { return maxLow; }
    public String getOutputDir() { return outputDir; }
    public boolean isValidateSensor() { return validateSensor; }

    public void setApiServer(String apiServer) { this.apiServer = apiServer; }
    public void setUsername(String username) { this.username = username; }
    public void setPassword(String password) { this.password = password; }
    public void setUseOAuth(boolean useOAuth) { this.useOAuth = useOAuth; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public void setProxyHost(String proxyHost) { this.proxyHost = proxyHost; }
    public void setProxyPort(int proxyPort) { this.proxyPort = proxyPort; }
    public void setProxyUsername(String proxyUsername) { this.proxyUsername = proxyUsername; }
    public void setProxyPassword(String proxyPassword) { this.proxyPassword = proxyPassword; }
    public void setImageId(String imageId) { this.imageId = imageId; }
    public void setDockerUrl(String dockerUrl) { this.dockerUrl = dockerUrl; }
    public void setDockerCert(String dockerCert) { this.dockerCert = dockerCert; }
    public void setPollingInterval(int pollingInterval) { this.pollingInterval = pollingInterval; }
    public void setVulnsTimeout(int vulnsTimeout) { this.vulnsTimeout = vulnsTimeout; }
    public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }
    public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }
    public void setMaxMedium(int maxMedium) { this.maxMedium = maxMedium; }
    public void setMaxLow(int maxLow) { this.maxLow = maxLow; }
    public void setOutputDir(String outputDir) { this.outputDir = outputDir; }
    public void setValidateSensor(boolean validateSensor) { this.validateSensor = validateSensor; }
}
