package com.qualys.plugins.scanner;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.qualys.plugins.scanner.credentials.JiraCredentials;
import com.qualys.plugins.scanner.credentials.QualysApiToken;
import com.qualys.plugins.scanner.issues.JiraIssueCreator;
import com.qualys.plugins.scanner.qscanner.QScannerRunner;
import com.qualys.plugins.scanner.qscanner.SarifParser;
import com.qualys.plugins.scanner.thresholds.ThresholdEvaluator;
import com.qualys.plugins.scanner.types.*;
import hudson.*;
import hudson.model.*;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Jenkins build step for running Qualys security scans.
 */
public class QualysScannerBuilder extends Builder implements SimpleBuildStep {

    // Required fields
    private final String credentialsId;
    private final String scanType;

    // Container scan options
    private String imageId;
    private String storageDriver;
    private String platform;

    // Code scan options
    private String scanPath;
    private String excludeDirs;
    private String excludeFiles;
    private boolean offlineScan;

    // Scan options
    private String scanTypes = "pkg";
    private boolean scanSecrets;
    private boolean scanMalware;
    private int scanTimeout = 300;
    private boolean generateSbom;
    private String sbomFormat = "spdx";

    // Policy options
    private boolean usePolicyEvaluation;
    private String policyTags;

    // Threshold options
    private int maxCritical = 0;
    private int maxHigh = 0;
    private int maxMedium = -1;
    private int maxLow = -1;

    // Behavior options
    private boolean continueOnError;
    private boolean publishSarif = true;

    // Proxy options
    private String proxyUrl;
    private boolean skipTlsVerify;

    // Jira integration
    private boolean createJiraIssues;
    private String jiraCredentialsId;
    private String jiraProjectKey;
    private int jiraMinSeverity = 4; // Default to High and above
    private String jiraLabels;
    private String jiraAssignee;

    @DataBoundConstructor
    public QualysScannerBuilder(String credentialsId, String scanType) {
        this.credentialsId = credentialsId;
        this.scanType = scanType;
    }

    @Override
    public void perform(@NonNull Run<?, ?> run, @NonNull FilePath workspace,
                        @NonNull EnvVars env, @NonNull Launcher launcher,
                        @NonNull TaskListener listener) throws InterruptedException, IOException {

        listener.getLogger().println("=== Qualys Security Scan ===");

        // Get credentials
        QualysApiToken credentials = CredentialsProvider.findCredentialById(
            credentialsId, QualysApiToken.class, run, Collections.emptyList());

        if (credentials == null) {
            throw new AbortException("Qualys credentials not found: " + credentialsId);
        }

        // Build configuration
        QScannerConfig config = buildConfig(credentials, workspace, env);

        // Run scanner
        QScannerRunner runner = new QScannerRunner(config, workspace, launcher, listener);

        try {
            runner.setup();
        } catch (IOException e) {
            handleError(run, listener, "Failed to setup QScanner: " + e.getMessage());
            return;
        }

        QScannerResult result;
        ScanType type = ScanType.fromValue(scanType);

        switch (type) {
            case CONTAINER:
                listener.getLogger().println("Scanning container image: " + imageId);
                result = runner.scanImage();
                break;
            case CODE:
                listener.getLogger().println("Scanning code repository: " +
                    (scanPath != null ? scanPath : workspace.getRemote()));
                result = runner.scanRepo();
                break;
            case ROOTFS:
                listener.getLogger().println("Scanning rootfs: " + scanPath);
                result = runner.scanRootfs();
                break;
            default:
                throw new AbortException("Unknown scan type: " + scanType);
        }

        // Process results
        processResults(run, workspace, listener, result, config);
    }

    private QScannerConfig buildConfig(QualysApiToken credentials, FilePath workspace, EnvVars env) {
        QScannerConfig.Builder builder = QScannerConfig.builder()
            .accessToken(credentials.getAccessTokenPlainText())
            .pod(credentials.getPod())
            .scanType(ScanType.fromValue(scanType))
            .scanTypes(scanTypes)
            .scanSecrets(scanSecrets)
            .scanMalware(scanMalware)
            .scanTimeout(scanTimeout)
            .usePolicyEvaluation(usePolicyEvaluation)
            .policyTags(policyTags)
            .maxCritical(maxCritical)
            .maxHigh(maxHigh)
            .maxMedium(maxMedium)
            .maxLow(maxLow)
            .generateSbom(generateSbom)
            .sbomFormat(sbomFormat)
            .proxyUrl(proxyUrl)
            .skipTlsVerify(skipTlsVerify)
            .outputDir(workspace.child("qualys-scan-results").getRemote());

        // Expand environment variables
        if (imageId != null) {
            builder.imageId(env.expand(imageId));
        }
        if (scanPath != null) {
            builder.scanPath(env.expand(scanPath));
        }
        if (platform != null) {
            builder.platform(env.expand(platform));
        }
        if (storageDriver != null) {
            builder.storageDriver(StorageDriver.fromValue(storageDriver));
        }
        if (excludeDirs != null) {
            builder.excludeDirs(env.expand(excludeDirs));
        }
        if (excludeFiles != null) {
            builder.excludeFiles(env.expand(excludeFiles));
        }
        builder.offlineScan(offlineScan);

        return builder.build();
    }

    private void processResults(Run<?, ?> run, FilePath workspace, TaskListener listener,
                                QScannerResult result, QScannerConfig config) throws IOException, InterruptedException {

        if (!result.isSuccess()) {
            handleError(run, listener, "Scan failed: " + result.getErrorMessage());
            return;
        }

        // Parse SARIF for vulnerability summary
        if (result.getSarifReportPath() != null) {
            try {
                FilePath sarifFile = new FilePath(workspace.getChannel(),
                    result.getSarifReportPath());
                VulnerabilitySummary summary = SarifParser.parse(sarifFile);
                result.setVulnerabilitySummary(summary);

                listener.getLogger().println("\n" + summary.toString());

                // Archive SARIF report
                if (publishSarif) {
                    FilePath outputDir = workspace.child("qualys-scan-results");
                    outputDir.copyRecursiveTo(
                        new FilePath(new java.io.File(run.getRootDir(), "qualys-reports")));
                }

            } catch (Exception e) {
                listener.getLogger().println("Warning: Could not parse SARIF report: " + e.getMessage());
            }
        }

        // Evaluate thresholds or policy
        boolean shouldFail = false;
        String failureReason = null;

        if (config.isUsePolicyEvaluation()) {
            // Policy-based evaluation
            if (result.getPolicyResult() == QScannerResult.PolicyResult.DENY) {
                shouldFail = true;
                failureReason = "Policy evaluation result: DENY";
            } else if (result.getPolicyResult() == QScannerResult.PolicyResult.AUDIT) {
                listener.getLogger().println("Policy evaluation result: AUDIT (build continues)");
            } else {
                listener.getLogger().println("Policy evaluation result: ALLOW");
            }
        } else {
            // Threshold-based evaluation
            ThresholdEvaluator evaluator = new ThresholdEvaluator(
                maxCritical, maxHigh, maxMedium, maxLow);
            ThresholdEvaluator.ThresholdResult thresholdResult =
                evaluator.evaluate(result.getVulnerabilitySummary());

            listener.getLogger().println("\n" + thresholdResult.toString());

            if (!thresholdResult.isPassed()) {
                shouldFail = true;
                failureReason = thresholdResult.getViolationMessage();
            }
        }

        // Create Jira issues if enabled
        if (createJiraIssues && result.getSarifReportPath() != null) {
            createJiraIssuesFromSarif(run, listener, result.getSarifReportPath());
        }

        // Set build result
        if (shouldFail) {
            listener.error("Security scan failed: " + failureReason);
            if (!continueOnError) {
                run.setResult(Result.FAILURE);
            } else {
                run.setResult(Result.UNSTABLE);
                listener.getLogger().println("Build marked unstable (continueOnError=true)");
            }
        } else {
            listener.getLogger().println("\nSecurity scan passed!");
        }

        // Export environment variables for downstream steps
        exportBuildVariables(run, result);
    }

    private void createJiraIssuesFromSarif(Run<?, ?> run, TaskListener listener, String sarifPath) {
        if (jiraCredentialsId == null || jiraCredentialsId.isEmpty()) {
            listener.getLogger().println("Skipping Jira issue creation: no credentials configured");
            return;
        }

        if (jiraProjectKey == null || jiraProjectKey.isEmpty()) {
            listener.getLogger().println("Skipping Jira issue creation: no project key configured");
            return;
        }

        try {
            JiraCredentials jiraCreds = CredentialsProvider.findCredentialById(
                jiraCredentialsId, JiraCredentials.class, run, Collections.emptyList());

            if (jiraCreds == null) {
                listener.error("Jira credentials not found: " + jiraCredentialsId);
                return;
            }

            listener.getLogger().println("\nCreating Jira issues for vulnerabilities...");

            List<String> labels = null;
            if (jiraLabels != null && !jiraLabels.isEmpty()) {
                labels = Arrays.stream(jiraLabels.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
            }

            JiraIssueCreator creator = new JiraIssueCreator(
                jiraCreds.getJiraUrl(),
                jiraCreds.getUsername(),
                jiraCreds.getApiTokenPlainText(),
                jiraProjectKey,
                listener
            );

            int created = creator.createIssuesFromSarif(sarifPath, jiraMinSeverity, labels, jiraAssignee);
            listener.getLogger().println("Jira integration complete: " + created + " issues created");

        } catch (Exception e) {
            listener.error("Failed to create Jira issues: " + e.getMessage());
        }
    }

    private void exportBuildVariables(Run<?, ?> run, QScannerResult result) {
        VulnerabilitySummary summary = result.getVulnerabilitySummary();

        // Store as build parameters for visibility
        run.addAction(new QualysScanAction(
            summary.getTotal(),
            summary.getCritical(),
            summary.getHigh(),
            summary.getMedium(),
            summary.getLow(),
            result.getPolicyResult().name(),
            !result.shouldFailBuild(),
            result.getSarifReportPath()
        ));
    }

    private void handleError(Run<?, ?> run, TaskListener listener, String message)
            throws AbortException {
        listener.error(message);
        if (!continueOnError) {
            throw new AbortException(message);
        }
        run.setResult(Result.UNSTABLE);
        listener.getLogger().println("Build marked unstable (continueOnError=true)");
    }

    // Getters
    public String getCredentialsId() { return credentialsId; }
    public String getScanType() { return scanType; }
    public String getImageId() { return imageId; }
    public String getStorageDriver() { return storageDriver; }
    public String getPlatform() { return platform; }
    public String getScanPath() { return scanPath; }
    public String getExcludeDirs() { return excludeDirs; }
    public String getExcludeFiles() { return excludeFiles; }
    public boolean isOfflineScan() { return offlineScan; }
    public String getScanTypes() { return scanTypes; }
    public boolean isScanSecrets() { return scanSecrets; }
    public boolean isScanMalware() { return scanMalware; }
    public int getScanTimeout() { return scanTimeout; }
    public boolean isGenerateSbom() { return generateSbom; }
    public String getSbomFormat() { return sbomFormat; }
    public boolean isUsePolicyEvaluation() { return usePolicyEvaluation; }
    public String getPolicyTags() { return policyTags; }
    public int getMaxCritical() { return maxCritical; }
    public int getMaxHigh() { return maxHigh; }
    public int getMaxMedium() { return maxMedium; }
    public int getMaxLow() { return maxLow; }
    public boolean isContinueOnError() { return continueOnError; }
    public boolean isPublishSarif() { return publishSarif; }
    public String getProxyUrl() { return proxyUrl; }
    public boolean isSkipTlsVerify() { return skipTlsVerify; }
    public boolean isCreateJiraIssues() { return createJiraIssues; }
    public String getJiraCredentialsId() { return jiraCredentialsId; }
    public String getJiraProjectKey() { return jiraProjectKey; }
    public int getJiraMinSeverity() { return jiraMinSeverity; }
    public String getJiraLabels() { return jiraLabels; }
    public String getJiraAssignee() { return jiraAssignee; }

    // Setters with @DataBoundSetter
    @DataBoundSetter
    public void setImageId(String imageId) { this.imageId = imageId; }

    @DataBoundSetter
    public void setStorageDriver(String storageDriver) { this.storageDriver = storageDriver; }

    @DataBoundSetter
    public void setPlatform(String platform) { this.platform = platform; }

    @DataBoundSetter
    public void setScanPath(String scanPath) { this.scanPath = scanPath; }

    @DataBoundSetter
    public void setExcludeDirs(String excludeDirs) { this.excludeDirs = excludeDirs; }

    @DataBoundSetter
    public void setExcludeFiles(String excludeFiles) { this.excludeFiles = excludeFiles; }

    @DataBoundSetter
    public void setOfflineScan(boolean offlineScan) { this.offlineScan = offlineScan; }

    @DataBoundSetter
    public void setScanTypes(String scanTypes) { this.scanTypes = scanTypes; }

    @DataBoundSetter
    public void setScanSecrets(boolean scanSecrets) { this.scanSecrets = scanSecrets; }

    @DataBoundSetter
    public void setScanMalware(boolean scanMalware) { this.scanMalware = scanMalware; }

    @DataBoundSetter
    public void setScanTimeout(int scanTimeout) { this.scanTimeout = scanTimeout; }

    @DataBoundSetter
    public void setGenerateSbom(boolean generateSbom) { this.generateSbom = generateSbom; }

    @DataBoundSetter
    public void setSbomFormat(String sbomFormat) { this.sbomFormat = sbomFormat; }

    @DataBoundSetter
    public void setUsePolicyEvaluation(boolean usePolicyEvaluation) {
        this.usePolicyEvaluation = usePolicyEvaluation;
    }

    @DataBoundSetter
    public void setPolicyTags(String policyTags) { this.policyTags = policyTags; }

    @DataBoundSetter
    public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }

    @DataBoundSetter
    public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }

    @DataBoundSetter
    public void setMaxMedium(int maxMedium) { this.maxMedium = maxMedium; }

    @DataBoundSetter
    public void setMaxLow(int maxLow) { this.maxLow = maxLow; }

    @DataBoundSetter
    public void setContinueOnError(boolean continueOnError) { this.continueOnError = continueOnError; }

    @DataBoundSetter
    public void setPublishSarif(boolean publishSarif) { this.publishSarif = publishSarif; }

    @DataBoundSetter
    public void setProxyUrl(String proxyUrl) { this.proxyUrl = proxyUrl; }

    @DataBoundSetter
    public void setSkipTlsVerify(boolean skipTlsVerify) { this.skipTlsVerify = skipTlsVerify; }

    @DataBoundSetter
    public void setCreateJiraIssues(boolean createJiraIssues) { this.createJiraIssues = createJiraIssues; }

    @DataBoundSetter
    public void setJiraCredentialsId(String jiraCredentialsId) { this.jiraCredentialsId = jiraCredentialsId; }

    @DataBoundSetter
    public void setJiraProjectKey(String jiraProjectKey) { this.jiraProjectKey = jiraProjectKey; }

    @DataBoundSetter
    public void setJiraMinSeverity(int jiraMinSeverity) { this.jiraMinSeverity = jiraMinSeverity; }

    @DataBoundSetter
    public void setJiraLabels(String jiraLabels) { this.jiraLabels = jiraLabels; }

    @DataBoundSetter
    public void setJiraAssignee(String jiraAssignee) { this.jiraAssignee = jiraAssignee; }

    @Symbol("qualysScan")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Qualys Security Scan";
        }

        @POST
        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item,
                                                     @QueryParameter String credentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) &&
                    !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                .includeEmptyValue()
                .includeAs(ACL.SYSTEM, item, QualysApiToken.class)
                .includeCurrentValue(credentialsId);
        }

        public ListBoxModel doFillScanTypeItems() {
            ListBoxModel items = new ListBoxModel();
            for (ScanType type : ScanType.values()) {
                items.add(type.getDisplayName(), type.getValue());
            }
            return items;
        }

        public ListBoxModel doFillStorageDriverItems() {
            ListBoxModel items = new ListBoxModel();
            for (StorageDriver driver : StorageDriver.values()) {
                items.add(driver.getDisplayName(), driver.getValue());
            }
            return items;
        }

        public ListBoxModel doFillSbomFormatItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("SPDX", "spdx");
            items.add("CycloneDX", "cyclonedx");
            return items;
        }

        @POST
        public FormValidation doCheckCredentialsId(@QueryParameter String value) {
            if (value == null || value.isEmpty()) {
                return FormValidation.error("Credentials are required");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckImageId(@QueryParameter String value,
                                             @QueryParameter String scanType) {
            if ("container".equals(scanType) && (value == null || value.isEmpty())) {
                return FormValidation.error("Image ID is required for container scans");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckScanTimeout(@QueryParameter int value) {
            if (value < 30) {
                return FormValidation.error("Timeout must be at least 30 seconds");
            }
            if (value > 3600) {
                return FormValidation.warning("Timeout exceeds 1 hour");
            }
            return FormValidation.ok();
        }

        @POST
        public ListBoxModel doFillJiraCredentialsIdItems(@AncestorInPath Item item,
                                                         @QueryParameter String jiraCredentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(jiraCredentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) &&
                    !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(jiraCredentialsId);
                }
            }

            return result
                .includeEmptyValue()
                .includeAs(ACL.SYSTEM, item, JiraCredentials.class)
                .includeCurrentValue(jiraCredentialsId);
        }

        public ListBoxModel doFillJiraMinSeverityItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("Critical (5)", "5");
            items.add("High (4)", "4");
            items.add("Medium (3)", "3");
            items.add("Low (2)", "2");
            items.add("Informational (1)", "1");
            return items;
        }
    }
}
