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

public class QualysCredentials extends BaseStandardCredentials {
    private static final long serialVersionUID = 1L;

    private final String username;
    private final Secret password;
    private final String pod;
    private final boolean useOAuth;
    private final String clientId;
    private final Secret clientSecret;

    @DataBoundConstructor
    public QualysCredentials(CredentialsScope scope, String id, String description,
                             @NonNull String username, @NonNull Secret password,
                             @NonNull String pod, boolean useOAuth,
                             String clientId, Secret clientSecret) {
        super(scope, id, description);
        this.username = username;
        this.password = password;
        this.pod = pod != null ? pod : "US1";
        this.useOAuth = useOAuth;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @NonNull
    public String getUsername() {
        return username != null ? username : "";
    }

    @NonNull
    public Secret getPassword() {
        return password;
    }

    @NonNull
    public String getPasswordPlainText() {
        return Secret.toString(password);
    }

    @NonNull
    public String getPod() {
        return pod != null ? pod : "US1";
    }

    public boolean isUseOAuth() {
        return useOAuth;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getClientSecretPlainText() {
        return clientSecret != null ? Secret.toString(clientSecret) : "";
    }

    @NonNull
    public String getApiServer() {
        return QualysPod.fromName(pod).getApiUrl();
    }

    @NonNull
    public String getGatewayUrl() {
        return QualysPod.fromName(pod).getGatewayUrl();
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Qualys Username/Password";
        }

        public ListBoxModel doFillPodItems() {
            ListBoxModel items = new ListBoxModel();
            for (QualysPod pod : QualysPod.values()) {
                items.add(pod.getName() + " (" + pod.getApiUrl() + ")", pod.getName());
            }
            return items;
        }

        @POST
        public FormValidation doCheckUsername(@QueryParameter String username) {
            if (username == null || username.trim().isEmpty()) {
                return FormValidation.error("Username is required");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckPassword(@QueryParameter Secret password) {
            if (password == null || Secret.toString(password).isEmpty()) {
                return FormValidation.error("Password is required");
            }
            return FormValidation.ok();
        }

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
