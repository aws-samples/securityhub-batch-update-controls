#!/usr/bin/env python3
"""
Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import boto3
import sys
import time
import argparse
import re
import string
import time

from botocore.exceptions import ClientError

def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a SecurityHub client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: SecurityHub client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='SecurityHubcontrols'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for {}.".format(
        aws_account_number
    ))

    return session


def control_state(securityhub_client):
    #client = boto3.client('securityhub', region_name="us-east-1")
    if len(control_id_list) > 0:
        for cont in control_id_list:
            control_id = cont
            print("Disabling control for ID: {}".format(control_id))
            resp = securityhub_client.batch_update_standards_control_associations(
                StandardsControlAssociationUpdates=[
                    {
                        'StandardsArn': SECURITY_STANDARD,
                        'SecurityControlId': control_id,
                        'AssociationStatus': 'DISABLED',
                        'UpdatedReason': 'multiaccountscript'
                    },
                ]
            )
    else:
        responcontrol = securityhub_client.list_security_control_definitions()
        for control in responcontrol['SecurityControlDefinitions']:
            control_id = control['SecurityControlId']
            print("disabling control {}".format(control_id))
            resp = securityhub_client.batch_update_standards_control_associations(
            StandardsControlAssociationUpdates=[
                {
                    'StandardsArn': SECURITY_STANDARD,
                    'SecurityControlId': control_id,
                    'AssociationStatus': 'DISABLED',
                    'UpdatedReason': 'multiaccountscript'
                },
            ]
        )
        while responcontrol.get("NextToken"):
        # time.sleep(3)

            responcontrol = securityhub_client.list_security_control_definitions(
            NextToken=responcontrol['NextToken']
        )
        
            for control in responcontrol['SecurityControlDefinitions']:
                control_id = control['SecurityControlId']
                print("disabling control {}".format(control_id))
                resbatch = securityhub_client.batch_update_standards_control_associations(
                StandardsControlAssociationUpdates=[
                    {
                        'StandardsArn': SECURITY_STANDARD,
                        'SecurityControlId': control_id,
                        'AssociationStatus': 'DISABLED',
                        'UpdatedReason': 'multiaccountscript'
                    },
                ]
            )
if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Disable control in all security standards in Security Hub accounts')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account.")
    parser.add_argument('--disable_regions', type=str, required=True, help="Comma separated list of regions to disable all controls. If not specified, all available regions disabled.")
    parser.add_argument('--input_file', type=argparse.FileType('r'), help='Path to txt file containing the list of account IDs.')
    parser.add_argument('--controls_input_file', type=argparse.FileType('r'), required=False, help='Path to txt file containing the list of Control IDs to disable across Security Standard.')
    parser.add_argument('--control_standards', type=str, required=False,help="comma separated list of standards ARN resources to disable controls for ( i.e. arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0)")

    args = parser.parse_args()

    # Generate account list
    aws_account_list = []
    control_id_list = []

    for acct in args.input_file.readlines():
        if not re.match(r'[0-9]{12}', str(acct)):
            print("Invalid account number {}, skipping".format(acct))
            continue

        aws_account_list.append(acct.rstrip())
    if args.controls_input_file:
        for controlid in args.controls_input_file.readlines():
            print(controlid)
            if len(controlid) < 3:
                print("Unable to process line: {}".format(controlid))
                continue

            control_id_list.append(controlid.rstrip())

    # Getting SecurityHub regions
    session = boto3.session.Session()

    securityhub_regions = []
    if args.disable_regions:
        securityhub_regions = [str(item) for item in args.disable_regions.split(',')]
        print("Disabling members in these regions: {}".format(securityhub_regions))
    else:
        securityhub_regions = session.get_available_regions('securityhub')
        print("Disabling control in all standards for all available SecurityHub regions {}".format(securityhub_regions))


    # Processing accounts have Control standard disabled
    failed_accounts = []
    # Check optinal flag  Standards file input
    list_standards_arns = []
    if args.control_standards:
        list_standards_arns = [str(item) for item in args.control_standards.split(',')]
        print("Enabling the following Security Hub Standards for enabled account(s) and region(s): {}".format(list_standards_arns))

    for account in aws_account_list:
        try:

            print('***********Account Loop***************')
            session = assume_role(account, args.assume_role)
            
            for aws_region in securityhub_regions:
                print('-----------Region Loop--------------')
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))

                securityhub_client = session.client('securityhub', region_name=aws_region)
                try:
                    if len(list_standards_arns) > 0:
                        for item in list_standards_arns:
                            if aws_region in item or 'ruleset':
                                SECURITY_STANDARD = str(item)
                                print("Disabling controls for the Security Hub Standards for enabled account {} and region {}: {}".format(account, aws_region, SECURITY_STANDARD))
                                control_state(securityhub_client)
                            else:
                                continue
                    else:

                        describe_response = securityhub_client.describe_standards()
                        for standards_arn in describe_response["Standards"]:
                            SECURITY_STANDARD = standards_arn["StandardsArn"]
                            print("Disabling controls for the Security Hub Standards for enabled account {} and region {}: {}".format(account, aws_region, SECURITY_STANDARD))
                            control_state(securityhub_client)
                        print("Finished disabling control on account {} for region {}".format(account, aws_region))
                except ClientError as e:
                    print("Error disabling controls for  {} in  account {}".format(SECURITY_STANDARD, account))
                    failed_accounts.append({ account : repr(e)})

    
        except ClientError as e:
            print("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })

    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            for account_id, message in account.items():
                print("{}: \n\t{}".format(account_id, message))
        print("---------------------------------------------------------------")
