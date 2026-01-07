package com.qualys.plugins.scanner.pipeline;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.qualys.plugins.scanner.QualysScanAction;
import com.qualys.plugins.scanner.credentials.QualysApiToken;
import com.qualys.plugins.scanner.qscanner.QScannerRunner;
import com.qualys.plugins.scanner.qscanner.SarifParser;
import com.qualys.plugins.scanner.thresholds.ThresholdEvaluator;
import com.qualys.plugins.scanner.types.*;
import hudson.*;
import hudson.model.*;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.workflow.steps.*;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;

/**
 * Pipeline step for Qualys security scanning.
 *
 * Usage in Jenkinsfile:
 *
 * // Container scan
 * def result = qualysScan(
 *     credentialsId: 'qualys-token',
 *     scanType: 'container',
 *     imageId: 'myapp:latest',
 *     maxCritical: 0,
 *     maxHigh: 5
 * )
 *
 * // Code scan
 * qualysScan(
 *     credentialsId: 'qualys-token',
 *     scanType: 'code',
 *     scanPath: '.',
 *     scanSecrets: true
 * )
 */
public class QualysScanStep extends Step implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String credentialsId;
    private final String scanType;

    // Optional parameters
    private String imageId;
    private String storageDriver;
    private String platform;
    private String scanPath;
    private String excludeDirs;
    private String excludeFiles;
    private boolean offlineScan;
    private String scanTypes = "pkg";
    private boolean scanSecrets;
    private boolean scanMalware;
    private int scanTimeout = 300;
    private boolean generateSbom;
    private String sbomFormat = "spdx";
    private boolean usePolicyEvaluation;
    private String policyTags;
    private int maxCritical = 0;
    private int maxHigh = 0;
    private int maxMedium = -1;
    private int maxLow = -1;
    private boolean continueOnError;
    private boolean publishSarif = true;
    private String proxyUrl;
    private boolean skipTlsVerify;

    @DataBoundConstructor
    public QualysScanStep(@NonNull String credentialsId, @NonNull String scanType) {
        this.credentialsId = credentialsId;
        this.scanType = scanType;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new QualysScanStepExecution(this, context);
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

    // Setters
    @DataBoundSetter public void setImageId(String imageId) { this.imageId = imageId; }
    @DataBoundSetter public void setStorageDriver(String storageDriver) { this.storageDriver = storageDriver; }
    @DataBoundSetter public void setPlatform(String platform) { this.platform = platform; }
    @DataBoundSetter public void setScanPath(String scanPath) { this.scanPath = scanPath; }
    @DataBoundSetter public void setExcludeDirs(String excludeDirs) { this.excludeDirs = excludeDirs; }
    @DataBoundSetter public void setExcludeFiles(String excludeFiles) { this.excludeFiles = excludeFiles; }
    @DataBoundSetter public void setOfflineScan(boolean offlineScan) { this.offlineScan = offlineScan; }
    @DataBoundSetter public void setScanTypes(String scanTypes) { this.scanTypes = scanTypes; }
    @DataBoundSetter public void setScanSecrets(boolean scanSecrets) { this.scanSecrets = scanSecrets; }
    @DataBoundSetter public void setScanMalware(boolean scanMalware) { this.scanMalware = scanMalware; }
    @DataBoundSetter public void setScanTimeout(int scanTimeout) { this.scanTimeout = scanTimeout; }
    @DataBoundSetter public void setGenerateSbom(boolean generateSbom) { this.generateSbom = generateSbom; }
    @DataBoundSetter public void setSbomFormat(String sbomFormat) { this.sbomFormat = sbomFormat; }
    @DataBoundSetter public void setUsePolicyEvaluation(boolean usePolicyEvaluation) { this.usePolicyEvaluation = usePolicyEvaluation; }
    @DataBoundSetter public void setPolicyTags(String policyTags) { this.policyTags = policyTags; }
    @DataBoundSetter public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }
    @DataBoundSetter public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }
    @DataBoundSetter public void setMaxMedium(int maxMedium) { this.maxMedium = maxMedium; }
    @DataBoundSetter public void setMaxLow(int maxLow) { this.maxLow = maxLow; }
    @DataBoundSetter public void setContinueOnError(boolean continueOnError) { this.continueOnError = continueOnError; }
    @DataBoundSetter public void setPublishSarif(boolean publishSarif) { this.publishSarif = publishSarif; }
    @DataBoundSetter public void setProxyUrl(String proxyUrl) { this.proxyUrl = proxyUrl; }
    @DataBoundSetter public void setSkipTlsVerify(boolean skipTlsVerify) { this.skipTlsVerify = skipTlsVerify; }

    @Extension
    public static class DescriptorImpl extends StepDescriptor {

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return new HashSet<>(Arrays.asList(
                Run.class,
                FilePath.class,
                Launcher.class,
                TaskListener.class,
                EnvVars.class
            ));
        }

        @Override
        public String getFunctionName() {
            return "qualysScan";
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Qualys Security Scan";
        }
    }

    /**
     * Execution class for the pipeline step.
     */
    private static class QualysScanStepExecution extends SynchronousNonBlockingStepExecution<QualysScanResult> {
        private static final long serialVersionUID = 1L;
        private final transient QualysScanStep step;

        QualysScanStepExecution(QualysScanStep step, StepContext context) {
            super(context);
            this.step = step;
        }

        @Override
        protected QualysScanResult run() throws Exception {
            Run<?, ?> run = getContext().get(Run.class);
            FilePath workspace = getContext().get(FilePath.class);
            Launcher launcher = getContext().get(Launcher.class);
            TaskListener listener = getContext().get(TaskListener.class);
            EnvVars env = getContext().get(EnvVars.class);

            listener.getLogger().println("=== Qualys Security Scan (Pipeline) ===");

            // Get credentials
            QualysApiToken credentials = CredentialsProvider.findCredentialById(
                step.credentialsId, QualysApiToken.class, run, Collections.emptyList());

            if (credentials == null) {
                throw new AbortException("Qualys credentials not found: " + step.credentialsId);
            }

            // Build configuration
            QScannerConfig config = buildConfig(credentials, workspace, env);

            // Run scanner
            QScannerRunner runner = new QScannerRunner(config, workspace, launcher, listener);
            runner.setup();

            QScannerResult result;
            ScanType type = ScanType.fromValue(step.scanType);

            switch (type) {
                case CONTAINER:
                    listener.getLogger().println("Scanning container image: " + step.imageId);
                    result = runner.scanImage();
                    break;
                case CODE:
                    listener.getLogger().println("Scanning code repository");
                    result = runner.scanRepo();
                    break;
                case ROOTFS:
                    listener.getLogger().println("Scanning rootfs: " + step.scanPath);
                    result = runner.scanRootfs();
                    break;
                default:
                    throw new AbortException("Unknown scan type: " + step.scanType);
            }

            // Process and return results
            return processResults(run, workspace, listener, result, config);
        }

        private QScannerConfig buildConfig(QualysApiToken credentials, FilePath workspace, EnvVars env) {
            QScannerConfig.Builder builder = QScannerConfig.builder()
                .accessToken(credentials.getAccessTokenPlainText())
                .pod(credentials.getPod())
                .scanType(ScanType.fromValue(step.scanType))
                .scanTypes(step.scanTypes)
                .scanSecrets(step.scanSecrets)
                .scanMalware(step.scanMalware)
                .scanTimeout(step.scanTimeout)
                .usePolicyEvaluation(step.usePolicyEvaluation)
                .policyTags(step.policyTags)
                .maxCritical(step.maxCritical)
                .maxHigh(step.maxHigh)
                .maxMedium(step.maxMedium)
                .maxLow(step.maxLow)
                .generateSbom(step.generateSbom)
                .sbomFormat(step.sbomFormat)
                .proxyUrl(step.proxyUrl)
                .skipTlsVerify(step.skipTlsVerify)
                .outputDir(workspace.child("qualys-scan-results").getRemote());

            if (step.imageId != null) builder.imageId(env.expand(step.imageId));
            if (step.scanPath != null) builder.scanPath(env.expand(step.scanPath));
            if (step.platform != null) builder.platform(env.expand(step.platform));
            if (step.storageDriver != null) builder.storageDriver(StorageDriver.fromValue(step.storageDriver));
            if (step.excludeDirs != null) builder.excludeDirs(env.expand(step.excludeDirs));
            if (step.excludeFiles != null) builder.excludeFiles(env.expand(step.excludeFiles));
            builder.offlineScan(step.offlineScan);

            return builder.build();
        }

        private QualysScanResult processResults(Run<?, ?> run, FilePath workspace,
                                                 TaskListener listener, QScannerResult result,
                                                 QScannerConfig config) throws IOException, InterruptedException {

            QualysScanResult pipelineResult = new QualysScanResult();

            if (!result.isSuccess()) {
                pipelineResult.setSuccess(false);
                pipelineResult.setErrorMessage(result.getErrorMessage());
                handleFailure(run, listener, result.getErrorMessage());
                return pipelineResult;
            }

            // Parse SARIF
            if (result.getSarifReportPath() != null) {
                try {
                    FilePath sarifFile = new FilePath(workspace.getChannel(), result.getSarifReportPath());
                    VulnerabilitySummary summary = SarifParser.parse(sarifFile);
                    result.setVulnerabilitySummary(summary);

                    pipelineResult.setTotalVulnerabilities(summary.getTotal());
                    pipelineResult.setCriticalCount(summary.getCritical());
                    pipelineResult.setHighCount(summary.getHigh());
                    pipelineResult.setMediumCount(summary.getMedium());
                    pipelineResult.setLowCount(summary.getLow());

                    listener.getLogger().println("\n" + summary.toString());
                } catch (Exception e) {
                    listener.getLogger().println("Warning: Could not parse SARIF: " + e.getMessage());
                }
            }

            // Evaluate
            boolean shouldFail = false;
            String failureReason = null;

            if (config.isUsePolicyEvaluation()) {
                pipelineResult.setPolicyResult(result.getPolicyResult().name());
                if (result.getPolicyResult() == QScannerResult.PolicyResult.DENY) {
                    shouldFail = true;
                    failureReason = "Policy evaluation: DENY";
                }
            } else {
                ThresholdEvaluator evaluator = new ThresholdEvaluator(
                    step.maxCritical, step.maxHigh, step.maxMedium, step.maxLow);
                ThresholdEvaluator.ThresholdResult thresholdResult =
                    evaluator.evaluate(result.getVulnerabilitySummary());

                pipelineResult.setThresholdsPassed(thresholdResult.isPassed());
                listener.getLogger().println("\n" + thresholdResult.toString());

                if (!thresholdResult.isPassed()) {
                    shouldFail = true;
                    failureReason = thresholdResult.getViolationMessage();
                }
            }

            pipelineResult.setSuccess(!shouldFail);
            pipelineResult.setSarifReportPath(result.getSarifReportPath());
            pipelineResult.setJsonReportPath(result.getJsonReportPath());
            pipelineResult.setSbomPath(result.getSbomPath());

            // Add build action
            run.addAction(new QualysScanAction(
                pipelineResult.getTotalVulnerabilities(),
                pipelineResult.getCriticalCount(),
                pipelineResult.getHighCount(),
                pipelineResult.getMediumCount(),
                pipelineResult.getLowCount(),
                pipelineResult.getPolicyResult(),
                pipelineResult.isSuccess(),
                result.getSarifReportPath()
            ));

            if (shouldFail) {
                handleFailure(run, listener, failureReason);
            } else {
                listener.getLogger().println("\nSecurity scan passed!");
            }

            return pipelineResult;
        }

        private void handleFailure(Run<?, ?> run, TaskListener listener, String message)
                throws AbortException {
            listener.error("Security scan failed: " + message);
            if (!step.continueOnError) {
                throw new AbortException(message);
            }
            run.setResult(Result.UNSTABLE);
            listener.getLogger().println("Build marked unstable (continueOnError=true)");
        }
    }

    /**
     * Result object returned by the pipeline step.
     */
    public static class QualysScanResult implements Serializable {
        private static final long serialVersionUID = 1L;

        private boolean success;
        private String errorMessage;
        private int totalVulnerabilities;
        private int criticalCount;
        private int highCount;
        private int mediumCount;
        private int lowCount;
        private String policyResult;
        private boolean thresholdsPassed;
        private String sarifReportPath;
        private String jsonReportPath;
        private String sbomPath;

        // Getters and setters
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }

        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

        public int getTotalVulnerabilities() { return totalVulnerabilities; }
        public void setTotalVulnerabilities(int totalVulnerabilities) { this.totalVulnerabilities = totalVulnerabilities; }

        public int getCriticalCount() { return criticalCount; }
        public void setCriticalCount(int criticalCount) { this.criticalCount = criticalCount; }

        public int getHighCount() { return highCount; }
        public void setHighCount(int highCount) { this.highCount = highCount; }

        public int getMediumCount() { return mediumCount; }
        public void setMediumCount(int mediumCount) { this.mediumCount = mediumCount; }

        public int getLowCount() { return lowCount; }
        public void setLowCount(int lowCount) { this.lowCount = lowCount; }

        public String getPolicyResult() { return policyResult; }
        public void setPolicyResult(String policyResult) { this.policyResult = policyResult; }

        public boolean isThresholdsPassed() { return thresholdsPassed; }
        public void setThresholdsPassed(boolean thresholdsPassed) { this.thresholdsPassed = thresholdsPassed; }

        public String getSarifReportPath() { return sarifReportPath; }
        public void setSarifReportPath(String sarifReportPath) { this.sarifReportPath = sarifReportPath; }

        public String getJsonReportPath() { return jsonReportPath; }
        public void setJsonReportPath(String jsonReportPath) { this.jsonReportPath = jsonReportPath; }

        public String getSbomPath() { return sbomPath; }
        public void setSbomPath(String sbomPath) { this.sbomPath = sbomPath; }
    }
}
