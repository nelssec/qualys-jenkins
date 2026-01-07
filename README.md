# Qualys Scanner Plugin for Jenkins

Integrate Qualys container and code security scanning into your Jenkins CI/CD pipelines.

## Features

- **Two Scanner Backends**:
  - **QScanner (On-Demand)**: Downloads and runs the qscanner binary - no agent installation required
  - **CICD Sensor (Installed)**: Uses the pre-installed Qualys Container Security sensor for faster scans
- **Container Image Scanning**: Scan Docker images for vulnerabilities
- **Code/Repository Scanning**: Scan source code for vulnerabilities (SCA) and secrets
- **Rootfs Scanning**: Scan root filesystem directories
- **Policy Evaluation**: Use Qualys cloud-based policies for pass/fail decisions
- **Threshold-based Gating**: Set maximum allowed vulnerabilities by severity
- **SARIF Report Generation**: Standard format for security findings
- **SBOM Generation**: Generate Software Bill of Materials (SPDX/CycloneDX)
- **Jira Integration**: Automatically create Jira issues for vulnerabilities
- **Pipeline Support**: Full support for declarative and scripted pipelines

## Scanner Backends

This plugin supports two scanning backends:

| Backend | Best For | Requirements |
|---------|----------|--------------|
| **QScanner** | CI/CD pipelines, ephemeral agents | Linux amd64, internet access |
| **CICD Sensor** | Dedicated build servers, faster scans | Pre-installed Qualys sensor |

### QScanner (On-Demand)

QScanner downloads the scanner binary on-demand. No pre-installation required.

- Supports: Container, Code, and Rootfs scans
- Authentication: Qualys API Token
- Best for: Dynamic/ephemeral Jenkins agents

### CICD Sensor (Installed)

Uses the Qualys Container Security sensor that's already deployed on your Jenkins agent.

- Supports: Container scans only
- Authentication: Qualys Username/Password
- Best for: Dedicated build servers with the sensor pre-installed
- Faster: No binary download, sensor runs continuously

## Requirements

- Jenkins 2.426.3 or later
- Java 11 or later
- For QScanner: Linux agent (amd64 architecture)
- For CICD Sensor: Qualys Container Security sensor deployed on agent
- Qualys subscription with API access

## CloudBees CI Compatibility

This plugin is fully compatible with CloudBees CI (formerly CloudBees Jenkins Enterprise).

| Feature | Description |
|---------|-------------|
| Folder-level credentials | Credentials resolve up the folder hierarchy |
| CloudBees Folders | Jobs in nested folders work correctly |
| Operations Center | Shared credentials across managed controllers |
| High Availability | Build actions persist across failover |
| RBAC | Uses standard Jenkins permissions model |

### Folder Credentials

Credentials defined at any folder level are automatically resolved. The plugin searches up the folder hierarchy:

```
Jenkins Root
└── Organization (Folder)      ← Credentials defined here
    └── Team (Folder)
        └── my-pipeline        ← Credentials accessible here
```

### Pipeline in Folders

```groovy
// Works in jobs at any folder depth
qualysScan(
    credentialsId: 'qualys-api-token',  // Resolves from folder or global scope
    scanType: 'container',
    imageId: 'myapp:latest'
)
```

### Dependencies

The plugin includes optional CloudBees Folder support:
- `cloudbees-folder` plugin (optional) - enables folder-scoped credential resolution

No additional configuration required. The plugin detects CloudBees CI automatically.

## Installation

### From Jenkins Update Center

1. Navigate to **Manage Jenkins** > **Manage Plugins**
2. Click the **Available** tab
3. Search for "Qualys Scanner"
4. Check the checkbox and click **Install**

### Manual Installation

1. Download the latest `.hpi` file from releases
2. Navigate to **Manage Jenkins** > **Manage Plugins** > **Advanced**
3. Upload the `.hpi` file under **Deploy Plugin**

## Configuration

### 1. Add Qualys Credentials

#### For QScanner Backend (API Token)

1. Navigate to **Manage Jenkins** > **Manage Credentials**
2. Click **Add Credentials**
3. Select **Qualys API Token** from the Kind dropdown
4. Configure:
   - **Pod**: Select your Qualys platform region (US1, US2, EU1, etc.)
   - **Access Token**: Your Qualys API access token
5. Save the credentials

#### For CICD Sensor Backend (Username/Password)

1. Navigate to **Manage Jenkins** > **Manage Credentials**
2. Click **Add Credentials**
3. Select **Qualys Username/Password** from the Kind dropdown
4. Configure:
   - **Pod**: Select your Qualys platform region
   - **Username**: Your Qualys username
   - **Password**: Your Qualys password
   - (Optional) **Use OAuth**: Enable for OAuth client credentials
5. Save the credentials

### 2. (Optional) Add Jira Credentials

If you want to create Jira issues for vulnerabilities:

1. Add a new credential of type **Jira API Credentials**
2. Configure:
   - **Jira URL**: Your Jira instance URL
   - **Username**: Your Jira email/username
   - **API Token**: Your Jira API token

## Usage

### Freestyle Project

1. Add a build step **Qualys Security Scan**
2. Select your scanner backend (QScanner or CICD Sensor)
3. Select your Qualys credentials
4. Choose scan type (Container, Code, or Rootfs)
5. Configure scan options and thresholds
6. Save and run

### Pipeline with QScanner Backend

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }

        stage('Security Scan') {
            steps {
                qualysScan(
                    credentialsId: 'qualys-api-token',
                    scannerBackend: 'qscanner',
                    scanType: 'container',
                    imageId: "myapp:${BUILD_NUMBER}",
                    maxCritical: 0,
                    maxHigh: 5,
                    scanSecrets: true,
                    publishSarif: true
                )
            }
        }
    }
}
```

### Pipeline with CICD Sensor Backend

```groovy
pipeline {
    agent { label 'qualys-sensor' }

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }

        stage('Security Scan') {
            steps {
                qualysScan(
                    scannerBackend: 'cicd_sensor',
                    cicdCredentialsId: 'qualys-username-password',
                    scanType: 'container',
                    imageId: "myapp:${BUILD_NUMBER}",
                    pollingInterval: 10,
                    vulnsTimeout: 600,
                    maxCritical: 0,
                    maxHigh: 5
                )
            }
        }
    }
}
```

### Code Scan (QScanner only)

```groovy
node {
    stage('Code Scan') {
        def result = qualysScan(
            credentialsId: 'qualys-api-token',
            scannerBackend: 'qscanner',
            scanType: 'code',
            scanPath: '.',
            scanSecrets: true,
            generateSbom: true,
            sbomFormat: 'spdx'
        )

        echo "Vulnerabilities found: ${result.totalVulnerabilities}"
        echo "Critical: ${result.criticalCount}"
        echo "High: ${result.highCount}"
    }
}
```

### Container Scan with Policy Evaluation

```groovy
qualysScan(
    credentialsId: 'qualys-api-token',
    scanType: 'container',
    imageId: 'myapp:latest',
    storageDriver: 'docker-overlay2',
    usePolicyEvaluation: true,
    policyTags: 'production,pci'
)
```

### Code Scan with Jira Integration

```groovy
qualysScan(
    credentialsId: 'qualys-api-token',
    scanType: 'code',
    scanPath: '.',
    scanSecrets: true,
    maxCritical: 0,
    maxHigh: 0,
    createJiraIssues: true,
    jiraCredentialsId: 'jira-credentials',
    jiraProjectKey: 'SEC',
    jiraMinSeverity: 4,
    jiraLabels: 'security,automated'
)
```

## Parameters

### Backend Selection

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scannerBackend` | `qscanner` | Backend to use: `qscanner` or `cicd_sensor` |
| `credentialsId` | - | Qualys API Token credential (for QScanner) |
| `cicdCredentialsId` | - | Qualys Username/Password credential (for CICD Sensor) |

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `scanType` | Type of scan: `container`, `code`, or `rootfs` |

### Container Scan Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `imageId` | - | Container image to scan (required for container scans) |
| `storageDriver` | `none` | Storage driver: `docker-overlay2`, `containerd-overlayfs` |
| `platform` | - | Target platform for multi-arch images (e.g., `linux/amd64`) |

### CICD Sensor Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `pollingInterval` | `10` | How often to check for scan results (seconds) |
| `vulnsTimeout` | `600` | Maximum time to wait for scan results (seconds) |

### Code Scan Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scanPath` | workspace | Path to scan |
| `excludeDirs` | - | Comma-separated directories to exclude |
| `excludeFiles` | - | Comma-separated file patterns to exclude |
| `offlineScan` | `false` | Perform offline scan without network access |

### Scan Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scanTypes` | `pkg` | Comma-separated: `pkg`, `secret`, `malware`, `fileinsight`, `compliance` |
| `scanSecrets` | `false` | Enable secrets scanning |
| `scanMalware` | `false` | Enable malware scanning |
| `scanTimeout` | `300` | Scan timeout in seconds |
| `generateSbom` | `false` | Generate Software Bill of Materials |
| `sbomFormat` | `spdx` | SBOM format: `spdx` or `cyclonedx` |

### Policy Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `usePolicyEvaluation` | `false` | Use Qualys cloud-based policy evaluation |
| `policyTags` | - | Comma-separated policy tags to match |

### Threshold Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `maxCritical` | `0` | Maximum allowed critical vulnerabilities (-1 = unlimited) |
| `maxHigh` | `0` | Maximum allowed high vulnerabilities |
| `maxMedium` | `-1` | Maximum allowed medium vulnerabilities |
| `maxLow` | `-1` | Maximum allowed low vulnerabilities |

### Behavior Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `continueOnError` | `false` | Mark build unstable instead of failed on threshold violation |
| `publishSarif` | `true` | Archive SARIF report as build artifact |

### Jira Integration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `createJiraIssues` | `false` | Create Jira issues for vulnerabilities |
| `jiraCredentialsId` | - | ID of Jira API credentials |
| `jiraProjectKey` | - | Jira project key (e.g., SEC) |
| `jiraMinSeverity` | `4` | Minimum severity for issue creation (5=Critical, 4=High, etc.) |
| `jiraLabels` | - | Comma-separated labels to add to issues |
| `jiraAssignee` | - | Jira username to assign issues |

### Network Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `proxyUrl` | - | HTTP proxy URL |
| `skipTlsVerify` | `false` | Skip TLS certificate verification |

## Pipeline Result Object

The `qualysScan` step returns a result object with the following properties:

```groovy
def result = qualysScan(...)

result.success              // boolean: true if scan passed
result.totalVulnerabilities // int: total vulnerability count
result.criticalCount        // int: critical vulnerabilities
result.highCount           // int: high vulnerabilities
result.mediumCount         // int: medium vulnerabilities
result.lowCount            // int: low vulnerabilities
result.policyResult        // string: ALLOW, DENY, AUDIT, or NOT_EVALUATED
result.thresholdsPassed    // boolean: true if all thresholds passed
result.sarifReportPath     // string: path to SARIF report
result.jsonReportPath      // string: path to JSON scan result
result.sbomPath            // string: path to SBOM file
```

## Security

- Access tokens and passwords are stored encrypted in Jenkins credentials store
- Credentials are passed securely via environment variables
- Credentials are never logged or exposed in command line arguments
- All downloads use HTTPS

## Troubleshooting

### QScanner Binary Download Fails

Ensure your Jenkins agent has internet access to GitHub releases. If behind a proxy, configure the `proxyUrl` parameter.

### CICD Sensor Not Detected

Ensure the Qualys Container Security sensor is running on your Jenkins agent:

```bash
docker ps --filter name=qualys-container-sensor
```

### Scan Times Out

Increase the `scanTimeout` parameter for QScanner or `vulnsTimeout` for CICD Sensor.

### Platform Not Supported (QScanner)

QScanner currently only supports Linux amd64. Ensure your Jenkins agent runs on a compatible platform.

### Policy Evaluation Returns DENY

Check your Qualys policy configuration in the Qualys platform. Review the SARIF report for specific violations.

## Building from Source

```bash
git clone https://github.com/qualys/qualys-jenkins.git
cd qualys-jenkins
mvn clean package -DskipTests
ls target/*.hpi
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- [Issue Tracker](https://github.com/qualys/qualys-jenkins/issues)
- [Qualys Community](https://community.qualys.com/)
