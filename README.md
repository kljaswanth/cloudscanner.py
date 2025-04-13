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

######Install required dependencies:####
Pip install boto3

Configure AWS credentials (either through AWS CLI or environment variables)
####Run the script:
cloudscanner.py

