import json
import boto3
import os
from botocore.vendored import requests
import datetime as dt
from botocore.exceptions import ClientError

def lambda_handler(event, context):

    checks = Checkclass()
    checks.mfa_check()
    checks.cloudtrail_allregion_check()
    checks.s3_access_logs_check()
    checks.s3_public_check_results()
    checks.send_report()


class Checkclass():
    def __init__(self):
        self.report = ''

    def mfa_check(self):
        iamclient = boto3.client('iam')
        sns = boto3.client('sns')

        response = iamclient.list_users()
        userVirtualMfa = iamclient.list_virtual_mfa_devices()
        virtualEnabled = []
        physicalString = ''

        mfa_users = {}
        notmfa_users = []

        for user in response['Users']:

            userMfa = iamclient.list_mfa_devices(UserName=user['UserName'])

            if len(userMfa['MFADevices']) > 0:
                mfa_users[(user['UserName'])] = 'PhysicalMFAEnabled'
            else:
                notmfa_users.append(user['UserName'])

        for virtual_mfauser in userVirtualMfa['VirtualMFADevices']:
            user = virtual_mfauser['User']['Arn'].split(':')[-1]
            mfa_users[user] = 'VirtualMFAEnabled'
        
        self.report += f'Users with MFA : {mfa_users} \n'
        return mfa_users

    def cloudtrail_allregion_check(self):

        IsMultiRegionTrail = False
        S3BucketEnabled = False
        trail_list = []
        ctclient = boto3.client('cloudtrail')
        trails = ctclient.list_trails()
        trail_info = {}

        if len(trails['Trails']) > 0:

            for trail in trails['Trails']:
                trail_list.append(trail['TrailARN'])
                # get_trail = ctclient.get_trail(Name='string')

            trail_response = ctclient.describe_trails(
                trailNameList=trail_list, includeShadowTrails=True)

            for trail_detail in trail_response['trailList']:
                if trail_detail['IsMultiRegionTrail'] and trail_detail['S3BucketName']:
                    IsMultiRegionTrail = True
                    S3BucketEnabled = True

            self.report += f'Cloudtrail is enabled , CloudTrail is MultiRegion = {IsMultiRegionTrail}, Cloudtrail Logs to Bucket = {S3BucketEnabled}\n'
            return IsMultiRegionTrail, S3BucketEnabled


    def s3_access_logs_check(self):
        logging_buckets = []
        client = boto3.client('s3')
        response = client.list_buckets()
        for bucket in response['Buckets']:
            check = client.get_bucket_logging(Bucket=bucket['Name'])
            try:
                if check['LoggingEnabled']:
                    logging_buckets.append(bucket['Name'])
            except KeyError as e:
                continue

        print(logging_buckets)
        self.report += f'These are the buckets where server access logs are enabled {logging_buckets}\n'
        return logging_buckets

    def s3_public_check_results(self):
        support_client = boto3.client('support', region_name='us-east-1')
        ta_checks = support_client.describe_trusted_advisor_checks(
            language='en')
        flagged = {}
        buckets_to_review = []

        ta_results = support_client.describe_trusted_advisor_check_result(
            checkId='Pfx0RwqBli', language='en')

        for result in ta_results['result']['flaggedResources']:
            if result['metadata'] == 'Yellow' or result['metadata'] == 'Red':
                flagged[result['metadata'][2]] = result['metadata']

                if result['metadata'][3] == 'Yes' or result['metadata'][4] == 'Yes' or result['metadata'][6] == 'Yes':
                    buckets_to_review.append(result['metadata'][2])

        self.report += f'These are the flagged buckets {flagged}\n and Please Review the Bucket POLICY or ACL of these buckets {buckets_to_review} \n'
        return flagged, buckets_to_review

    def send_report(self):
        snsClient = boto3.client('sns')
        snsClient.publish(
            TopicArn=os.environ['TopicTarget'],
            Subject='Security Essentials',
            Message=self.report
        )


