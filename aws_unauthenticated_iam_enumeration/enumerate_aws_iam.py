from boto3 import Session
from argparse import ArgumentParser, ArgumentTypeError
from botocore.exceptions import NoCredentialsError, ClientError
from os.path import exists
from sys import exit


def text_color(text, color):
    """
    Description: Outputs provided text in color.
    """

    colors = {
        "white": "\033[97m",
        "green": "\033[92m",
        "red": "\033[91m"
    }

    return f"{colors.get(color, '')}{text}\033[0m"


def get_arguments():
    """
    Description: Collects command line arguments.
    """

    parser = ArgumentParser(
        description="Enumerate IAM Users and Roles in AWS Accounts without authentication.")

    parser.add_argument(
        "-p",
        "--profile",
        type=str,
        help="Provide the AWS Profile to use for authentication.",
        required=True
    )

    parser.add_argument(
        "-r",
        "--role-name",
        type=str,
        help="Provide the IAM Role Name to test with. This must be a valid role in your account.",
        required=True
    )

    parser.add_argument(
        "-a",
        "--account",
        type=int,
        help="Provide the target AWS Account ID to enumerate.",
        required=True
    )

    parser.add_argument(
        "-nf",
        "--names_file",
        help="Provide the file name containing user names to try.",
        required=False
    )

    parser.add_argument(
        "-rf",
        "--roles_file",
        help="Provide the file name containing role names to try.",
        required=False
    )

    parser.add_argument(
        "-o",
        "--output_file",
        help="Name of the file to output valid identities.",
        default="valid_aws_identities.txt",
        required=False
    )

    # save all the arguments
    args = parser.parse_args()

    return args


def validate_profile_creds(profile):
    """
    Description: Accepts provided profile name, checks if profile is found in ~/.aws/credentials file, and validates credentials if found.
    """
    try:
        # Create an empty session to first check if the profile exists in ~/.aws/credentials file
        session = Session()

        # Check if the profile is found in the ~/.aws/credentials file
        available_profiles = session.available_profiles

        # Profile found, test credentials
        if profile in available_profiles:
            session = Session(profile_name=profile)
            sts = session.client("sts")
            response = sts.get_caller_identity()

            return {
                "current_session": session,
                "identity": response
            }

        # Profile not found in credentials file
        else:
            exit(text_color(f"Profile '{
                 profile}' was not found in ~/.aws/credentials file.", "red"))

    # Exceptions: https://github.com/boto/botocore/blob/develop/botocore/exceptions.py
    except NoCredentialsError as e:
        exit(text_color("Error: {e}", "red"))

    # Catch other errors
    except Exception as e:
        exit(text_color(f"Error: {e}", "red"))


def enumerate_identities(current_session, role_to_update, aws_acct_id, names_file, roles_file, output_file):
    """
    Description: Validates file(s) provided i.e., list of users and/or list of roles. Then it attempts to check if the identity exists in the target AWS account.
    """

    def test_identity(current_session, role_to_update, aws_acct_id, principal_type, identity_file):
        """
        Description: Attempts to check if the identity exists in the target AWS account. Valid identities are output to a file.
        """
        with open(identity_file, 'r') as file:
            for name in file:
                name = name.strip()
                try:
                    # update the provided IAM role's Trust Policy, this provides no output if it works
                    iam = current_session.client("iam")
                    iam.update_assume_role_policy(
                        RoleName=role_to_update,
                        PolicyDocument=f"""{{
                            "Version": "2012-10-17",
                            "Statement": [
                                {{
                                    "Effect": "Deny",
                                    "Principal": {{
                                        "AWS": "arn:aws:iam::{aws_acct_id}:{principal_type}/{name}"
                                    }},
                                    "Action": "sts:AssumeRole"
                                }}
                            ]
                        }}"""
                    )

                    # principal is valid
                    print(text_color(f"The identity: arn:aws:iam::{aws_acct_id}:{
                          principal_type}/{name} is valid!", "green"))

                    # write principal to file
                    with open(output_file, 'a') as outfile:
                        outfile.write(f"\narn:aws:iam::{aws_acct_id}:{
                            principal_type}/{name}")
                        outfile.close()

                # principal is not valid, trust policy won't be updated
                except ClientError as e:
                    print(text_color(
                        f"{e.response['Error']['Message']}", "red"))

                # catch other error
                except Exception as e:
                    exit(text_color(f"Error: {e}", "red"))

    # file names not provided
    if not names_file and not roles_file:
        exit(text_color(f"Error: You must specify at least one file.", "red"))

    # a file name was provided but does not exist
    if names_file and not exists(names_file):
        exit(text_color(f"Error: The file name provided '{
             names_file}' was not found.", "red"))

    elif names_file:
        print(text_color(f"Using the '{names_file}' file.", "white"))

        # check if users in the file are valid aws identities
        test_identity(current_session, role_to_update, aws_acct_id,
                      principal_type="user", identity_file=(names_file))

    # a file name was provided but does not exist
    if roles_file and not exists(roles_file):
        exit(text_color(f"Error: The file name provided '{
             roles_file}' was not found.", "red"))

    elif roles_file:
        print(text_color(f"Using the '{roles_file}' file.", "white"))

        # check if roles in the file are valid aws identities
        test_identity(current_session, role_to_update, aws_acct_id,
                      principal_type="role", identity_file=(roles_file))


def main():
    """
    Description: Main function, executes script.
    """

    # collect command line arguments
    args = get_arguments()

    print(text_color(f"\nValidating profile and credentials for profile '{
          args.profile}'", "white"))

    # validates profile and credentials are valid
    whoami = validate_profile_creds(args.profile)

    print(text_color(f"Running enumeration as {
          whoami['identity']['Arn']}", "white"))

    # validate aws identities
    enumerate_identities(
        current_session=whoami['current_session'], role_to_update=(args.role_name), aws_acct_id=(args.account), names_file=(args.names_file), roles_file=(args.roles_file), output_file=(args.output_file))


# Good practice to use this so if we ever import this script into another script, this script won't automatically execute unless it's called within that script by specifying `script.main()`
if __name__ == "__main__":
    main()
