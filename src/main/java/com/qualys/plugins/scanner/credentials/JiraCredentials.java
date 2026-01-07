package com.qualys.plugins.scanner.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * Credentials type for storing Jira connection details.
 * Used for creating vulnerability issues in Jira.
 */
public class JiraCredentials extends BaseStandardCredentials {
    private static final long serialVersionUID = 1L;

    private final String jiraUrl;
    private final String username;
    private final Secret apiToken;

    @DataBoundConstructor
    public JiraCredentials(CredentialsScope scope, String id, String description,
                           @NonNull String jiraUrl, @NonNull String username,
                           @NonNull Secret apiToken) {
        super(scope, id, description);
        this.jiraUrl = jiraUrl;
        this.username = username;
        this.apiToken = apiToken;
    }

    @NonNull
    public String getJiraUrl() {
        return jiraUrl;
    }

    @NonNull
    public String getUsername() {
        return username;
    }

    @NonNull
    public Secret getApiToken() {
        return apiToken;
    }

    @NonNull
    public String getApiTokenPlainText() {
        return Secret.toString(apiToken);
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Jira API Credentials";
        }

        @POST
        public FormValidation doCheckJiraUrl(@QueryParameter String jiraUrl) {
            if (jiraUrl == null || jiraUrl.isEmpty()) {
                return FormValidation.error("Jira URL is required");
            }
            if (!jiraUrl.startsWith("https://")) {
                return FormValidation.warning("HTTPS is recommended for security");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckUsername(@QueryParameter String username) {
            if (username == null || username.isEmpty()) {
                return FormValidation.error("Username is required");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckApiToken(@QueryParameter Secret apiToken) {
            if (apiToken == null || Secret.toString(apiToken).isEmpty()) {
                return FormValidation.error("API token is required");
            }
            return FormValidation.ok();
        }
    }
}
