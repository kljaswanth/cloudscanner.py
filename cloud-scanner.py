import boto3
import json
from datetime import datetime
from typing import Dict, List, Any

class CloudScanner:
    def __init__(self):
        self.aws_session = boto3.Session()
        self.findings = []
        
    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 buckets for common misconfigurations."""
        s3_client = self.aws_session.client('s3')
        buckets = s3_client.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Check bucket ACL
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        self.findings.append({
                            'resource_type': 'S3',
                            'resource_name': bucket_name,
                            'issue': 'Public Access through ACL',
                            'severity': 'HIGH',
                            'remediation': 'Remove public access grants from bucket ACL'
                        })
                
                # Check bucket encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except s3_client.exceptions.ClientError:
                    self.findings.append({
                        'resource_type': 'S3',
                        'resource_name': bucket_name,
                        'issue': 'No Default Encryption',
                        'severity': 'MEDIUM',
                        'remediation': 'Enable default encryption for the bucket'
                    })
                
                # Check bucket versioning
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if 'Status' not in versioning or versioning['Status'] != 'Enabled':
                    self.findings.append({
                        'resource_type': 'S3',
                        'resource_name': bucket_name,
                        'issue': 'Versioning Not Enabled',
                        'severity': 'LOW',
                        'remediation': 'Enable versioning to protect against accidental deletions'
                    })
                    
            except Exception as e:
                print(f"Error scanning bucket {bucket_name}: {str(e)}")

    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scan EC2 security groups for common misconfigurations."""
        ec2_client = self.aws_session.client('ec2')
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']
        
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            # Check for overly permissive inbound rules
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_range = f"{rule.get('FromPort', 'ALL')}-{rule.get('ToPort', 'ALL')}"
                        self.findings.append({
                            'resource_type': 'SecurityGroup',
                            'resource_name': f"{sg_name} ({sg_id})",
                            'issue': f'Open Internet Access on ports {port_range}',
                            'severity': 'HIGH',
                            'remediation': 'Restrict security group rules to specific IP ranges'
                        })

    def scan_iam_users(self) -> List[Dict[str, Any]]:
        """Scan IAM users for security best practices."""
        iam_client = self.aws_session.client('iam')
        users = iam_client.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            
            # Check MFA status
            mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa_devices:
                self.findings.append({
                    'resource_type': 'IAM',
                    'resource_name': username,
                    'issue': 'MFA Not Enabled',
                    'severity': 'HIGH',
                    'remediation': 'Enable MFA for the IAM user'
                })
            
            # Check access keys age
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                key_age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                if key_age > 90:
                    self.findings.append({
                        'resource_type': 'IAM',
                        'resource_name': username,
                        'issue': f'Access Key {key["AccessKeyId"]} is {key_age} days old',
                        'severity': 'MEDIUM',
                        'remediation': 'Rotate access keys regularly (recommended: every 90 days)'
                    })

    def generate_report(self) -> Dict[str, Any]:
        """Generate a formatted report of all findings."""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'findings_by_severity': {
                'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'findings': self.findings
        }
        return report

    def run_scan(self) -> Dict[str, Any]:
        """Run all security scans and generate report."""
        self.scan_s3_buckets()
        self.scan_security_groups()
        self.scan_iam_users()
        return self.generate_report()

def main():
    scanner = CloudScanner()
    report = scanner.run_scan()
    
    # Print findings to console
    print("\nCloud Security Scan Results")
    print("=" * 50)
    print(f"Total Findings: {report['total_findings']}")
    print(f"High Severity: {report['findings_by_severity']['HIGH']}")
    print(f"Medium Severity: {report['findings_by_severity']['MEDIUM']}")
    print(f"Low Severity: {report['findings_by_severity']['LOW']}")
    print("\nDetailed Findings:")
    
    for finding in report['findings']:
        print(f"\nResource Type: {finding['resource_type']}")
        print(f"Resource Name: {finding['resource_name']}")
        print(f"Issue: {finding['issue']}")
        print(f"Severity: {finding['severity']}")
        print(f"Remediation: {finding['remediation']}")
    
    # Save report to file
    with open(f"cloud_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    main()
