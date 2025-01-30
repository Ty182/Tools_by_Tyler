# Tools_by_Tyler
A collection of custom tooling I've built. These are for educational purposes and I do not take responsibility for their misuse. 

## AWS 

### [Unauthenticated IAM Enumeration](./aws_unauthenticated_iam_enumeration/)
- IAM identities can be enumerated in a target AWS account without authentication. This takes advantage of native AWS functionality and will likely always be an issue unless AWS makes significant changes which would cause customer impact (inconvenience). 

- There are multiple methods for this to work. See some [examples on my blog](https://www.techwithtyler.dev/cloud-security/aws-attacks-and-techniques/enumerate-unauthenticated-iam-users-and-roles).

- This script will require:
    - a target AWS Account ID ([some ways to discover this discussed here](https://www.techwithtyler.dev/cloud-security/aws-attacks-and-techniques/enumerate-aws-account-ids))
    - valid credentials in your AWS account
    - an IAM Role in your account that you have access to run [iam:UpdateAssumeRolePolicy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/update-assume-role-policy.html) on

- This script was tested on Python version `3.13.1`

```
python3 ./enumerate_aws_iam.py --help                                               
usage: enumerate_aws_iam.py [-h] -p PROFILE -r ROLE_NAME -a ACCOUNT [-nf NAMES_FILE] [-rf ROLES_FILE] [-o OUTPUT_FILE]

Enumerate IAM Users and Roles in AWS Accounts without authentication.

options:
  -h, --help            show this help message and exit
  -p, --profile PROFILE
                        Provide the AWS Profile to use for authentication.
  -r, --role-name ROLE_NAME
                        Provide the IAM Role Name to test with. This must be a valid role in your account.
  -a, --account ACCOUNT
                        Provide the target AWS Account ID to enumerate.
  -nf, --names_file NAMES_FILE
                        Provide the file name containing user names to try.
  -rf, --roles_file ROLES_FILE
                        Provide the file name containing role names to try.
  -o, --output_file OUTPUT_FILE
                        Name of the file to output valid identities.
```