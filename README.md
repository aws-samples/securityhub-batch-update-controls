## AWS Security Hub multi-account controls security standard change script

These scripts automate the process of Enabling controls in all standards across a group of AWS accounts that are in your control. (Note, that you can have one administrator account and up to a 5000 member accounts).

The **enablecontrols.py** script will do the following for each account and region provided to the script:
* Enable all controls for enabled security standard.



## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Prerequisites

* To view information about security controls and enable and disable security controls in standards, the AWS Identity and Access Management (IAM) role that you use to access AWS Security Hub needs permissions to call the following API actions. Without adding permissions for these actions, you won't be able to call these APIs. To get the necessary permissions, you can use Security Hub managed policies. Alternatively, you can update custom IAM policies to include permissions for these actions. Custom policies should also include permissions for the DescribeStandardsControls and UpdateStandardsControl APIs.

    BatchGetSecurityControls – Returns information about a batch of security controls for the current account and AWS Region.

    ListSecurityControlDefinitions – Returns information about security controls that apply to a specified standard.

    ListStandardsControlAssociations – Identifies whether a security control is currently enabled in or disabled from each enabled standard in the account.

    BatchGetStandardsControlAssociations – For a batch of security controls, identifies whether each control is currently enabled in or disabled from a specified standard.

    BatchUpdateStandardsControlAssociations – Used to enable a security control in standards that include the control, or to disable a control in standards. This is a batch substitute for the existing UpdateStandardsControl API if an administrator doesn’t want to allow member accounts to enable or disable controls.

In addition to the preceding APIs, you should also add permission to call BatchGetControlEvaluations to your IAM role. This permission is necessary to view the enablement and compliance status of a control, the findings count for a control, and the overall security score for controls on the Security Hub console. Because only the console calls BatchGetControlEvaluations, this IAM permission doesn't directly correspond to publicly documented Security Hub APIs or AWS CLI commands.

* The script depends on a pre-existing role in the admin account and all of the member accounts that will be accessed.  The role name must be the same in all accounts and the role trust relationship needs to allow your instance or local credentials to assume the role.  The policy document below contains the required permissions for the script to succeed:

``` 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "securityhub:ListStandardsControlAssociations",
                "securityhub:BatchUpdateStandardsControlAssociations",
                "securityhub:DescribeStandards",
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
```

If you do not have a common role that includes at least the above permissions you will need to create a role in each member account as well as the administrative account with at least the above permissions.  When creating the role ensure you use the same role name in every account.  You can use the **change-control-state.yaml** CloudFormation template to automate this process.  This template creates a role named: **ManageSecurityHubcontrols**.  The template creates only global resources so it can be created in any region.    

* A text file that includes the list of accounts where the controls needs to be enabled.  Each account should be listed on its own line in the file.

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* Launch ec2 instance in your master account https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to an instance that has permissions to allow the instance to call AssumeRole within the master account, if you used the **change-control-state.yaml** template an instance role with a profile name of **ManageSecurityHubcontrols** has been created, otherwise see the documentation on creating an instance role here:  https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/ on creating an instance role.
* Install required software
    * APT: sudo apt-get -y install python3-pip python3 git
    * RPM: sudo yum -y install python3-pip python3 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
    * cd aws-securityhub-multiaccount-scripts/securityhub-change-control
* Copy the text file containing the account numbers to the instance using one of the methods below
    * S3 `s3 cp s3://bucket/key_name enable.txt .`
    * pscp.exe `pscp local_file_path username@hostname:.`
    * scp `scp local_file_path username@hostname:.`

#### Option 2: Locally:
* Ensure you have credentials setup on your local machine for your master account that have permission to call AssumeRole.
* Install Required Software:
    * Windows:
        * Install Python https://www.python.org/downloads/windows/
        * Open command prompt:
            * pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/securityhub-change-control
    * Mac:
        * Install Python https://www.python.org/downloads/mac-osx/
        * Open command prompt:
            * pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/securityhub-change-control
    * Linux:
        * sudo apt-get -y install install python2-pip python2 git
        * sudo pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/securityhub-change-control
        
        Or
        
        * sudo yum install git python
        * sudo pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/securityhub-change-control

### 2. Execute Scripts
#### 2a. Enable controls
* Copy the required txt file to this directory
    * Should be a format where each account number is listed on a line.

```
usage: enablecontrols.py [-h] --assume_role ASSUME_ROLE 
                                --enabled_regions ENABLED_REGIONS
                                --input_file PATH_TO_ACCOUNTS_FILE

Enables control in all standards in Security Hub accounts

                        
required arguments:
  -h, --help            show this help message and exit
  
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account.
  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to enable the control security standard in.
                        If not specified, all available regions are enabled.

  --input_file INPUT_FILE
                        Path to the txt file containing the list of account IDs.
  
  
```

```
Example usage:
$ python3 enablecontrols.py --assume_role ManageSecurityHubcontrols --enabled_regions us-west-2,us-east-1 --input_file /home/ec2-user/accounts.txt

$ python3 enablecontrols.py --assume_role ManageSecurityHubcontrols --enable_regions us-west-2,us-east-1 --input_file accounts.txt --controls_input_file controls.txt --control_standards arn:aws:securityhub:us-west-2::standards/aws-foundational-security-best-practices/v/1.0.0,arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0
```

#### 2b. Disable controls
* Copy the required txt file to this directory
    * Should be a format where each account number is listed on a line.

```
usage: disablecontrols.py [-h] --assume_role ASSUME_ROLE 
                                 --disabled_regions ENABLED_REGIONS
                                 --input_file PATH_TO_ACCOUNTS_FILE

Disables control in all standards in Security Hub accounts

                        
required arguments:
  -h, --help            show this help message and exit
  
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account.
  --disabled_regions ENABLED_REGIONS
                        comma separated list of regions to disable the control security standard in.
                        If not specified, all available regions are enabled.

  --input_file INPUT_FILE
                        Path to the txt file containing the list of account IDs.
  
  
```

```
Example usage:
$ python3 disablecontrols.py --assume_role ManageSecurityHubcontrols --disable_regions us-west-2,us-east-1 --input_file /home/ec2-user/accounts.txt

$ python3 disablecontrols.py --assume_role ManageSecurityHubcontrols --disable_regions us-west-2,us-east-1 --input_file accounts.txt --controls_input_file controls.txt --control_standards arn:aws:securityhub:us-west-2::standards/aws-foundational-security-best-practices/v/1.0.0,arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0

'''

