package com.qualys.plugins.scanner.sensor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import hudson.model.TaskListener;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class QualysCSClient {

    private static final int DEFAULT_TIMEOUT = 30000;
    private static final int MAX_AUTH_RETRIES = 5;
    private static final int AUTH_RETRY_DELAY_MS = 5000;

    private final String apiServer;
    private final String username;
    private final String password;
    private final boolean useOAuth;
    private final String clientId;
    private final String clientSecret;
    private final String proxyHost;
    private final int proxyPort;
    private final String proxyUsername;
    private final String proxyPassword;
    private final TaskListener listener;

    private String jwtToken;
    private int timeout = DEFAULT_TIMEOUT;

    public QualysCSClient(String apiServer, String username, String password, TaskListener listener) {
        this(apiServer, username, password, false, null, null, null, 0, null, null, listener);
    }

    public QualysCSClient(String apiServer, String username, String password,
                          boolean useOAuth, String clientId, String clientSecret,
                          String proxyHost, int proxyPort, String proxyUsername, String proxyPassword,
                          TaskListener listener) {
        this.apiServer = apiServer.endsWith("/") ? apiServer.substring(0, apiServer.length() - 1) : apiServer;
        this.username = username;
        this.password = password;
        this.useOAuth = useOAuth;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.listener = listener;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String testConnection() {
        try {
            String token = generateToken();
            if (token == null || token.isEmpty()) {
                return "Failed to generate authentication token";
            }
            if (!validateCSModule(token)) {
                return "Container Security module not enabled for this subscription";
            }
            return null;
        } catch (Exception e) {
            return "Connection test failed: " + e.getMessage();
        }
    }

    public QualysCSResponse getImageDetails(String imageSha) throws IOException {
        ensureAuthenticated();
        String url = apiServer + "/csapi/v1.3/images/" + imageSha;
        return executeGet(url);
    }

    public QualysCSResponse getImages(String imageSha, long scannedAfterEpoch) throws IOException {
        ensureAuthenticated();
        String filter = "sha:" + imageSha;
        if (scannedAfterEpoch > 0) {
            filter += " and updated:[" + scannedAfterEpoch + " ..]";
        }
        String encodedFilter = URLEncoder.encode(filter, StandardCharsets.UTF_8.name());
        String url = apiServer + "/csapi/v1.3/images?filter=" + encodedFilter;
        return executeGet(url);
    }

    private void ensureAuthenticated() throws IOException {
        if (jwtToken == null || jwtToken.isEmpty()) {
            jwtToken = generateToken();
            if (jwtToken == null) {
                throw new IOException("Failed to authenticate with Qualys API");
            }
        }
    }

    private String generateToken() {
        for (int attempt = 0; attempt < MAX_AUTH_RETRIES; attempt++) {
            try {
                String token = doGenerateToken();
                if (token != null && !token.isEmpty()) {
                    return token;
                }
            } catch (Exception e) {
                log("Authentication attempt " + (attempt + 1) + " failed: " + e.getMessage());
            }

            if (attempt < MAX_AUTH_RETRIES - 1) {
                try {
                    Thread.sleep(AUTH_RETRY_DELAY_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        return null;
    }

    private String doGenerateToken() throws IOException {
        String authUrl = apiServer + "/auth";

        try (CloseableHttpClient client = getHttpClient()) {
            HttpPost post = new HttpPost(authUrl);

            if (useOAuth) {
                post.setHeader("Content-Type", "application/x-www-form-urlencoded");
                post.setHeader("client_id", clientId);
                post.setHeader("client_secret", clientSecret);
                post.setEntity(new StringEntity("grant_type=client_credentials"));
            } else {
                post.setHeader("Content-Type", "application/x-www-form-urlencoded");
                String body = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8.name()) +
                             "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8.name()) +
                             "&token=true";
                post.setEntity(new StringEntity(body));
            }

            try (CloseableHttpResponse response = client.execute(post)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity());

                if (statusCode == 200 || statusCode == 201) {
                    if (responseBody != null && !responseBody.isEmpty()) {
                        if (responseBody.startsWith("{")) {
                            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
                            if (json.has("access_token")) {
                                return json.get("access_token").getAsString();
                            }
                        }
                        return responseBody.trim();
                    }
                } else {
                    log("Authentication failed with status " + statusCode + ": " + responseBody);
                }
            }
        }
        return null;
    }

    private boolean validateCSModule(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                JsonObject json = JsonParser.parseString(payload).getAsJsonObject();
                if (json.has("modulesAllowed")) {
                    String modules = json.get("modulesAllowed").getAsString();
                    return modules.contains("CS");
                }
            }
        } catch (Exception e) {
            log("Warning: Could not validate CS module: " + e.getMessage());
        }
        return true;
    }

    private QualysCSResponse executeGet(String url) throws IOException {
        try (CloseableHttpClient client = getHttpClient()) {
            HttpGet get = new HttpGet(url);
            get.setHeader("Authorization", "Bearer " + jwtToken);
            get.setHeader("Accept", "application/json");

            try (CloseableHttpResponse response = client.execute(get)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = response.getEntity() != null ?
                    EntityUtils.toString(response.getEntity()) : "";

                if (statusCode == 401) {
                    jwtToken = generateToken();
                    if (jwtToken != null) {
                        return executeGet(url);
                    }
                }

                return new QualysCSResponse(statusCode, responseBody);
            }
        }
    }

    private CloseableHttpClient getHttpClient() {
        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(timeout)
            .setSocketTimeout(timeout)
            .setConnectionRequestTimeout(timeout)
            .build();

        HttpClientBuilder builder = HttpClients.custom()
            .setDefaultRequestConfig(config);

        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            HttpHost proxy = new HttpHost(proxyHost, proxyPort);
            builder.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));

            if (proxyUsername != null && !proxyUsername.isEmpty()) {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                    new AuthScope(proxyHost, proxyPort),
                    new UsernamePasswordCredentials(proxyUsername, proxyPassword)
                );
                builder.setDefaultCredentialsProvider(credsProvider);
            }
        }

        return builder.build();
    }

    private void log(String message) {
        if (listener != null) {
            listener.getLogger().println("[QualysCS] " + message);
        }
    }

    public static class QualysCSResponse {
        private final int statusCode;
        private final String body;

        public QualysCSResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getBody() {
            return body;
        }

        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }

        public JsonObject getBodyAsJson() {
            if (body == null || body.isEmpty()) {
                return new JsonObject();
            }
            try {
                return JsonParser.parseString(body).getAsJsonObject();
            } catch (Exception e) {
                return new JsonObject();
            }
        }

        public boolean hasVulnerabilities() {
            try {
                JsonObject json = getBodyAsJson();
                return json.has("vulns") && json.get("vulns").isJsonArray();
            } catch (Exception e) {
                return false;
            }
        }
    }
}
