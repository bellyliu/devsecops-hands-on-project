#!/usr/bin/env python3
"""
AWS Security Baseline Verification Script

This script verifies that the essential AWS security services are properly
enabled and configured in your AWS account.

Requirements:
- boto3 library
- Configured AWS credentials (AWS CLI, environment variables, or IAM role)

Services checked:
- Amazon GuardDuty
- AWS Security Hub
- IAM Access Analyzer
- AWS CloudTrail
- AWS Config
"""

import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, Any
import json


class AWSSecurityBaselineVerifier:
    """Class to verify AWS security baseline services are enabled."""

    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize the verifier with AWS clients.

        Args:
            region (str): AWS region to check services in
        """
        self.region = region
        self.results = {}

        try:
            # Initialize AWS clients
            self.guardduty = boto3.client('guardduty', region_name=region)
            self.securityhub = boto3.client('securityhub', region_name=region)
            self.accessanalyzer = boto3.client(
                'accessanalyzer', region_name=region)
            self.cloudtrail = boto3.client('cloudtrail', region_name=region)
            self.config = boto3.client('config', region_name=region)
            self.sts = boto3.client('sts')

            # Get account information
            self.account_id = self.sts.get_caller_identity()['Account']

        except NoCredentialsError:
            print("❌ Error: AWS credentials not found!")
            print(
                "Please configure your AWS credentials using one of the following methods:")
            print("1. AWS CLI: aws configure")
            print("2. Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("3. IAM role (if running on EC2)")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error initializing AWS clients: {str(e)}")
            sys.exit(1)

    def check_guardduty(self) -> Dict[str, Any]:
        """Check if GuardDuty is enabled."""
        try:
            response = self.guardduty.list_detectors()

            if not response['DetectorIds']:
                return {
                    'enabled': False,
                    'status': 'No GuardDuty detectors found',
                    'details': {}
                }

            detector_id = response['DetectorIds'][0]
            detector_details = self.guardduty.get_detector(
                DetectorId=detector_id)

            return {
                'enabled': detector_details['Status'] == 'ENABLED',
                'status': detector_details['Status'],
                'details': {
                    'detector_id': detector_id,
                    'service_role': detector_details.get('ServiceRole', 'N/A'),
                    'finding_publishing_frequency': detector_details.get('FindingPublishingFrequency', 'N/A')
                }
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'BadRequestException':
                return {
                    'enabled': False,
                    'status': 'GuardDuty not enabled in this region',
                    'details': {}
                }
            else:
                return {
                    'enabled': False,
                    'status': f'Error checking GuardDuty: {e.response["Error"]["Message"]}',
                    'details': {}
                }

    def check_security_hub(self) -> Dict[str, Any]:
        """Check if Security Hub is enabled."""
        try:
            hub_details = self.securityhub.describe_hub()

            # Get enabled standards
            standards_response = self.securityhub.get_enabled_standards()
            enabled_standards = [
                standard['StandardsArn'].split('/')[-1]
                for standard in standards_response['StandardsSubscriptions']
                if standard['StandardsStatus'] == 'READY'
            ]

            return {
                'enabled': True,
                'status': 'ACTIVE',
                'details': {
                    'hub_arn': hub_details['HubArn'],
                    'subscribed_at': hub_details['SubscribedAt'].isoformat(),
                    'enabled_standards': enabled_standards,
                    'auto_enable_controls': hub_details.get('AutoEnableControls', False)
                }
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                return {
                    'enabled': False,
                    'status': 'Security Hub not enabled',
                    'details': {}
                }
            else:
                return {
                    'enabled': False,
                    'status': f'Error checking Security Hub: {e.response["Error"]["Message"]}',
                    'details': {}
                }

    def check_access_analyzer(self) -> Dict[str, Any]:
        """Check if IAM Access Analyzer is enabled."""
        try:
            response = self.accessanalyzer.list_analyzers()

            if not response['analyzers']:
                return {
                    'enabled': False,
                    'status': 'No Access Analyzers found',
                    'details': {}
                }

            analyzers = []
            for analyzer in response['analyzers']:
                analyzers.append({
                    'name': analyzer['name'],
                    'status': analyzer['status'],
                    'type': analyzer['type'],
                    'created_at': analyzer['createdAt'].isoformat()
                })

            active_analyzers = [
                a for a in analyzers if a['status'] == 'ACTIVE']

            return {
                'enabled': len(active_analyzers) > 0,
                'status': f'{len(active_analyzers)} active analyzer(s) found',
                'details': {
                    'analyzers': analyzers,
                    'active_count': len(active_analyzers)
                }
            }

        except ClientError as e:
            return {
                'enabled': False,
                'status': f'Error checking Access Analyzer: {e.response["Error"]["Message"]}',
                'details': {}
            }

    def check_cloudtrail(self) -> Dict[str, Any]:
        """Check if CloudTrail is enabled with multi-region trail."""
        try:
            response = self.cloudtrail.describe_trails()

            if not response['trailList']:
                return {
                    'enabled': False,
                    'status': 'No CloudTrail trails found',
                    'details': {}
                }

            trails = []
            multi_region_trails = 0

            for trail in response['trailList']:
                trail_status = self.cloudtrail.get_trail_status(
                    Name=trail['TrailARN'])

                trail_info = {
                    'name': trail['Name'],
                    'is_logging': trail_status['IsLogging'],
                    'is_multi_region': trail.get('IsMultiRegionTrail', False),
                    'include_global_events': trail.get('IncludeGlobalServiceEvents', False),
                    's3_bucket': trail.get('S3BucketName', 'N/A')
                }

                trails.append(trail_info)

                if trail_info['is_multi_region'] and trail_info['is_logging']:
                    multi_region_trails += 1

            return {
                'enabled': multi_region_trails > 0,
                'status': f'{multi_region_trails} active multi-region trail(s) found',
                'details': {
                    'trails': trails,
                    'multi_region_count': multi_region_trails
                }
            }

        except ClientError as e:
            return {
                'enabled': False,
                'status': f'Error checking CloudTrail: {e.response["Error"]["Message"]}',
                'details': {}
            }

    def check_config(self) -> Dict[str, Any]:
        """Check if AWS Config is enabled."""
        try:
            # Check configuration recorders
            recorders_response = self.config.describe_configuration_recorders()

            if not recorders_response['ConfigurationRecorders']:
                return {
                    'enabled': False,
                    'status': 'No Config recorders found',
                    'details': {}
                }

            # Check delivery channels
            channels_response = self.config.describe_delivery_channels()

            # Check recorder status
            recorder_status = self.config.describe_configuration_recorder_status()

            active_recorders = [
                recorder for recorder in recorder_status['ConfigurationRecordersStatus']
                if recorder['recording']
            ]

            # Get Config rules count
            rules_response = self.config.describe_config_rules()
            rules_count = len(rules_response['ConfigRules'])

            return {
                'enabled': len(active_recorders) > 0,
                'status': f'{len(active_recorders)} active recorder(s) found',
                'details': {
                    'recorders': len(recorders_response['ConfigurationRecorders']),
                    'active_recorders': len(active_recorders),
                    'delivery_channels': len(channels_response['DeliveryChannels']),
                    'config_rules': rules_count
                }
            }

        except ClientError as e:
            return {
                'enabled': False,
                'status': f'Error checking Config: {e.response["Error"]["Message"]}',
                'details': {}
            }

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all security baseline checks."""
        print(f"🔍 AWS Security Baseline Verification")
        print(f"Account ID: {self.account_id}")
        print(f"Region: {self.region}")
        print("=" * 60)

        checks = {
            'GuardDuty': self.check_guardduty,
            'Security Hub': self.check_security_hub,
            'IAM Access Analyzer': self.check_access_analyzer,
            'CloudTrail': self.check_cloudtrail,
            'AWS Config': self.check_config
        }

        all_results = {}
        passed_checks = 0
        total_checks = len(checks)

        for service_name, check_function in checks.items():
            print(f"\n📋 Checking {service_name}...")
            result = check_function()
            all_results[service_name] = result

            if result['enabled']:
                print(f"✅ {service_name}: {result['status']}")
                passed_checks += 1
            else:
                print(f"❌ {service_name}: {result['status']}")

            # Print additional details if available
            if result['details']:
                for key, value in result['details'].items():
                    if key != 'analyzers' and key != 'trails':  # Skip complex objects
                        print(f"   {key}: {value}")

        print("\n" + "=" * 60)
        print(f"📊 Summary: {passed_checks}/{total_checks} services enabled")

        if passed_checks == total_checks:
            print("🎉 All security baseline services are enabled!")
            return_code = 0
        else:
            print("⚠️  Some security services need attention.")
            return_code = 1

        print("\n💡 Next steps:")
        if passed_checks < total_checks:
            print("   - Run 'terraform apply' to enable missing services")
        print("   - Monitor Security Hub for security findings")
        print("   - Review GuardDuty findings regularly")
        print("   - Check Access Analyzer findings for unintended access")

        return {
            'results': all_results,
            'summary': {
                'passed': passed_checks,
                'total': total_checks,
                'success_rate': passed_checks / total_checks * 100
            },
            'return_code': return_code
        }


def main():
    """Main function to run the verification script."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Verify AWS Security Baseline Services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_baseline.py                    # Check us-east-1 (default)
  python verify_baseline.py --region us-west-2 # Check specific region
  python verify_baseline.py --json             # Output in JSON format
        """
    )

    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region to check (default: us-east-1)'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )

    args = parser.parse_args()

    # Run verification
    verifier = AWSSecurityBaselineVerifier(region=args.region)
    results = verifier.run_all_checks()

    if args.json:
        print("\n" + "=" * 60)
        print("JSON Output:")
        print(json.dumps(results, indent=2, default=str))

    sys.exit(results['return_code'])


if __name__ == '__main__':
    main()
