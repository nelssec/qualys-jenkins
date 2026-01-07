# Changelog

## [1.1.0] - 2026-01-07

### Added

- **CICD Sensor Backend**: New scanning backend that uses the pre-installed Qualys Container Security sensor
  - Faster container scans on dedicated build servers
  - No binary download required
  - Uses Qualys Username/Password authentication
  - Configurable polling interval and timeout
- **Qualys Username/Password Credentials**: New credential type for CICD Sensor authentication
  - Supports basic authentication and OAuth client credentials
  - Pod/region selection with API URL mapping
- **Backend Selection**: Choose between QScanner (on-demand) and CICD Sensor (installed) in the UI
- **New Pipeline Parameters**:
  - `scannerBackend`: Select `qscanner` or `cicd_sensor`
  - `cicdCredentialsId`: Credentials for CICD Sensor backend
  - `pollingInterval`: How often to check for CICD Sensor results
  - `vulnsTimeout`: Maximum wait time for CICD Sensor results

### Changed

- Unified plugin architecture with common `ScannerRunner` interface
- QScanner now implements `ScannerRunner` for consistent behavior
- Updated UI to show backend-specific options
- Improved error messages for backend-specific issues

## [1.0.0] - 2026-01-01

### Added

- Initial release
- QScanner backend for on-demand vulnerability scanning
- Container image scanning
- Code/repository scanning with SCA
- Rootfs scanning
- Policy evaluation with Qualys cloud policies
- Threshold-based gating (Critical, High, Medium, Low)
- SARIF report generation
- SBOM generation (SPDX, CycloneDX)
- Jira integration for automatic issue creation
- Pipeline support (declarative and scripted)
- Proxy support
- Qualys API Token credential type
