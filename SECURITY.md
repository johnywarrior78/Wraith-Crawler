# Security Policy

## Supported versions

The latest release and the current default branch receive security fixes. Older snapshots may not receive backports.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's GitHub **Security** tab using **Report a vulnerability**. Do not open a public issue with exploit details, credentials, target data, or sensitive evidence.

Include:

- the affected version or commit;
- the affected component and deployment model;
- reproducible steps using a safe local or intentionally vulnerable target;
- the security impact and any known preconditions;
- suggested remediation, if available.

Avoid accessing data that is not yours, disrupting services, or testing against third-party systems. We will acknowledge a complete report, investigate it, and coordinate remediation and disclosure as appropriate.

## Operational security

Wraith Crawler must only be used against explicitly authorized targets. Production credentials belong in the protected installer-managed environment files and must never be committed to source control, passed in process arguments, or included in reports or logs.
