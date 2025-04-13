# cloudscanner.py
I've created a cloud misconfiguration scanner that checks for common security issues in AWS resources. Here's what the scanner does:

Scans S3 buckets for:

Public access through ACLs
Missing default encryption
Disabled versioning


Scans Security Groups for:

Overly permissive inbound rules
Open internet access

Scans IAM users for:

Missing MFA
Old access keys (>90 days)



The scanner generates both console output and a JSON report with findings categorized by severity.
To use the scanner:

Install required dependencies:
bashpip install boto3

Configure AWS credentials (either through AWS CLI or environment variables)

Run the script:
bashpython cloud_scanner.py

The scanner can be extended by:

Adding more checks for other AWS services
Implementing checks for other cloud providers
Adding custom severity thresholds
Implementing automated remediation
