"""AWS IAM collector: builds the escalation-analysis prompt.

Modified from EscalateGPT (Tenable, GPL-3.0), 2026-10-21:
- imports updated for the main/cloud package split
- policies are now keyed by USER ARN with full policy documents inline
  (the original keyed customer-managed policies by policy ARN, which lost
  the user-policy association the prompt asks the model to reason about);
- AWS-managed policy documents are now fetched and inlined as well.
"""

import os
import sys
import json
from collections import defaultdict

import boto3

from botocore.exceptions import ClientError

from cloud.base import Cloud
from main.prompts import PROMPTS


class AWS(Cloud):
    def __init__(self, args):
        super().__init__()
        if args.profile:
            self.client = self._connect(profile=args.profile)
        elif args.aws_key and args.aws_secret:
            self.client = self._connect(aws_key=args.aws_key, aws_secret=args.aws_secret)
        # Fallback to environment variables
        elif os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
            self.client = self._connect(aws_key=os.environ.get('AWS_ACCESS_KEY_ID'),
                                        aws_secret=os.environ.get('AWS_SECRET_ACCESS_KEY'))
        else:
            self.logger.error("There is no credentials to connect AWS")
            sys.exit(0)

    def _connect(self, **kwargs):
        """
            Establishes a connection to AWS Identity and Access Management (IAM) service.
            This function supports two modes of authentication:
            1. Using an AWS CLI profile: Provide the 'profile' parameter with the desired AWS CLI profile name.
            2. Using AWS access key and secret key: Provide 'aws_key' and 'aws_secret' parameters.

            Note: Only one mode of authentication should be used at a time.

            @param kwargs: Keyword arguments for specifying authentication parameters.
                - If using a profile: {'profile': 'profile_name'}
                - If using access key and secret key: {'aws_key': 'access_key', 'aws_secret': 'secret_key'}

            @return: IAM client object for making API requests.
            @rtype: boto3.client.IAM or None if connection fails.
            """
        try:
            # Check if a profile is provided
            if kwargs.get('profile'):
                self.logger.debug(
                    f"Try to establishing connection to AWS' using the profile {kwargs.get('profile')}")
                session = boto3.Session(profile_name=kwargs.get('profile'))
                return session.client("iam")
            # Check if access key and secret key are provided
            if kwargs.get('aws_key') and kwargs.get('aws_secret'):
                self.logger.debug(
                    f"Try to establishing connection to AWS' using AWS key and AWS secret")
                return boto3.client("iam", aws_access_key_id=kwargs.get('aws_key'),
                                    aws_secret_access_key=kwargs.get('aws_secret'))
        except Exception as e:
            self.logger.error(f"Error while try to connect AWS {e}")
            return None

    def start(self) -> str:
        """
        Collects the Attached Managed Policies for every user in the AWS account and
        generates the prompt for the LLM.

        @return: Prompt we want to send to the LLM
        @rtype: str
        """
        users_policies: dict = defaultdict(lambda: {"Policy": []})
        try:
            aws_data = self.client.get_account_authorization_details()
            account_id = self._get_account_id()
            self.logger.debug(f"Get all policies in account {account_id}")
            for user in aws_data.get('UserDetailList', []):
                user_arn = user.get("Arn", "unknown-user")
                for policy in user.get('AttachedManagedPolicies', []):
                    policy_arn = policy.get("PolicyArn")
                    if not policy_arn:
                        continue
                    try:
                        policy_document = self._extract_policy_document(policy_arn)
                        users_policies[user_arn]["Policy"].append({policy_arn: policy_document})
                    except ClientError as e:
                        self.logger.error(f"Error while processing policy {policy_arn}: {e}")
                    except Exception as e:
                        self.logger.error(f"Unexpected error while processing policy {policy_arn}: {e}")
        except ClientError as e:
            self.logger.error(f"Error while connecting to AWS: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error while connecting to AWS: {e}")

        if not users_policies:
            self.logger.error("No attached managed policies were collected; nothing to analyze.")
        return PROMPTS['AWS'].format(json.dumps(users_policies, default=str, indent=2))

    def _get_account_id(self):
        """
            Retrieves the AWS account ID associated with the IAM user used for authentication.
            This method makes a request to the IAM client to get details of the authenticated user and extracts
            the account ID from the user's ARN (Amazon Resource Name). If successful, it returns the account ID;
            otherwise, it returns an empty string.
            """
        try:
            account_id = self.client.get_user()["User"]["Arn"].split("::")[1].split(":")[0]
        except Exception as e:
            self.logger.error(f"Error while try get account_id {e}")
            account_id = ""
        return account_id

    def _extract_policy_document(self, policy_arn):
        """
        Extracts the policy document statements associated with the specified IAM policy.
        This method retrieves the policy version information using the provided policy ARN, and then
        fetches the corresponding policy document. It returns the list of policy statements included
        in the policy document.

        @param policy_arn: ARN of the IAM policy.
        @type policy_arn: str

        @return: List of policy statements extracted from the policy document.
        @rtype: List[Dict[str, Any]]
        """
        policy_version = self.client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = \
            self.client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]
        return policy_document["Statement"]
