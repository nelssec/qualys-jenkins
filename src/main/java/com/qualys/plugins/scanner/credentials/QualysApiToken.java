package com.qualys.plugins.scanner.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.qualys.plugins.scanner.types.QualysPod;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * Credentials type for storing Qualys API access token.
 *
 * Security notes:
 * - Access token is stored encrypted using Jenkins Secret
 * - Token is never logged or exposed in CLI arguments
 * - Token is passed to QScanner via QUALYS_ACCESS_TOKEN environment variable
 */
public class QualysApiToken extends BaseStandardCredentials {
    private static final long serialVersionUID = 1L;

    private final Secret accessToken;
    private final String pod;

    @DataBoundConstructor
    public QualysApiToken(CredentialsScope scope, String id, String description,
                          @NonNull Secret accessToken, @NonNull String pod) {
        super(scope, id, description);
        this.accessToken = accessToken;
        this.pod = pod != null ? pod : "US1";
    }

    /**
     * Returns the encrypted access token.
     * Use getAccessTokenPlainText() only when needed for API calls.
     */
    @NonNull
    public Secret getAccessToken() {
        return accessToken;
    }

    /**
     * Returns the plaintext access token.
     * WARNING: Only use this when passing to QScanner via environment variable.
     * Never log or display this value.
     */
    @NonNull
    public String getAccessTokenPlainText() {
        return Secret.toString(accessToken);
    }

    /**
     * Returns the Qualys pod/region identifier (e.g., US1, US2, EU1).
     */
    @NonNull
    public String getPod() {
        return pod != null ? pod : "US1";
    }

    /**
     * Returns the gateway URL for the configured pod.
     */
    @NonNull
    public String getGatewayUrl() {
        return QualysPod.fromName(pod).getGatewayUrl();
    }

    /**
     * Returns a masked version of the token for logging (shows first 4 chars only).
     */
    @NonNull
    public String getMaskedToken() {
        String plainText = getAccessTokenPlainText();
        if (plainText.length() <= 4) {
            return "****";
        }
        return plainText.substring(0, 4) + "****...";
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Qualys API Token";
        }

        /**
         * Provides dropdown options for pod selection.
         */
        public ListBoxModel doFillPodItems() {
            ListBoxModel items = new ListBoxModel();
            for (QualysPod pod : QualysPod.values()) {
                items.add(pod.getName() + " (" + pod.getGatewayUrl() + ")", pod.getName());
            }
            return items;
        }

        /**
         * Validates the access token is not empty.
         */
        @POST
        public FormValidation doCheckAccessToken(@QueryParameter Secret accessToken) {
            if (accessToken == null || Secret.toString(accessToken).isEmpty()) {
                return FormValidation.error("Access token is required");
            }
            String token = Secret.toString(accessToken);
            if (token.length() < 10) {
                return FormValidation.warning("Access token seems too short");
            }
            return FormValidation.ok();
        }

        /**
         * Validates the pod selection.
         */
        @POST
        public FormValidation doCheckPod(@QueryParameter String pod) {
            if (pod == null || pod.isEmpty()) {
                return FormValidation.error("Pod is required");
            }
            if (!QualysPod.isValidPod(pod)) {
                return FormValidation.error("Invalid pod: " + pod);
            }
            return FormValidation.ok();
        }
    }
}
