package com.qualys.plugins.scanner.thresholds;

import com.qualys.plugins.scanner.types.VulnerabilitySummary;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates vulnerability counts against configured thresholds.
 */
public class ThresholdEvaluator implements Serializable {
    private static final long serialVersionUID = 1L;

    private int maxCritical = 0;
    private int maxHigh = 0;
    private int maxMedium = -1;  // -1 means unlimited
    private int maxLow = -1;

    public ThresholdEvaluator() {
    }

    public ThresholdEvaluator(int maxCritical, int maxHigh, int maxMedium, int maxLow) {
        this.maxCritical = maxCritical;
        this.maxHigh = maxHigh;
        this.maxMedium = maxMedium;
        this.maxLow = maxLow;
    }

    /**
     * Evaluates the vulnerability summary against the configured thresholds.
     * @return ThresholdResult containing pass/fail status and details
     */
    public ThresholdResult evaluate(VulnerabilitySummary summary) {
        List<String> violations = new ArrayList<>();
        boolean passed = true;

        // Check critical threshold
        if (maxCritical >= 0 && summary.getCritical() > maxCritical) {
            passed = false;
            violations.add(String.format("Critical vulnerabilities (%d) exceed threshold (%d)",
                summary.getCritical(), maxCritical));
        }

        // Check high threshold
        if (maxHigh >= 0 && summary.getHigh() > maxHigh) {
            passed = false;
            violations.add(String.format("High vulnerabilities (%d) exceed threshold (%d)",
                summary.getHigh(), maxHigh));
        }

        // Check medium threshold
        if (maxMedium >= 0 && summary.getMedium() > maxMedium) {
            passed = false;
            violations.add(String.format("Medium vulnerabilities (%d) exceed threshold (%d)",
                summary.getMedium(), maxMedium));
        }

        // Check low threshold
        if (maxLow >= 0 && summary.getLow() > maxLow) {
            passed = false;
            violations.add(String.format("Low vulnerabilities (%d) exceed threshold (%d)",
                summary.getLow(), maxLow));
        }

        return new ThresholdResult(passed, violations, summary);
    }

    // Getters and setters
    public int getMaxCritical() { return maxCritical; }
    public void setMaxCritical(int maxCritical) { this.maxCritical = maxCritical; }

    public int getMaxHigh() { return maxHigh; }
    public void setMaxHigh(int maxHigh) { this.maxHigh = maxHigh; }

    public int getMaxMedium() { return maxMedium; }
    public void setMaxMedium(int maxMedium) { this.maxMedium = maxMedium; }

    public int getMaxLow() { return maxLow; }
    public void setMaxLow(int maxLow) { this.maxLow = maxLow; }

    /**
     * Result of threshold evaluation.
     */
    public static class ThresholdResult implements Serializable {
        private static final long serialVersionUID = 1L;

        private final boolean passed;
        private final List<String> violations;
        private final VulnerabilitySummary summary;

        public ThresholdResult(boolean passed, List<String> violations, VulnerabilitySummary summary) {
            this.passed = passed;
            this.violations = violations;
            this.summary = summary;
        }

        public boolean isPassed() {
            return passed;
        }

        public List<String> getViolations() {
            return violations;
        }

        public VulnerabilitySummary getSummary() {
            return summary;
        }

        public String getViolationMessage() {
            if (passed || violations.isEmpty()) {
                return "All thresholds passed";
            }
            return String.join("; ", violations);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Threshold Evaluation: ").append(passed ? "PASSED" : "FAILED").append("\n");
            sb.append(summary.toString()).append("\n");
            if (!passed) {
                sb.append("Violations:\n");
                for (String v : violations) {
                    sb.append("  - ").append(v).append("\n");
                }
            }
            return sb.toString();
        }
    }
}
