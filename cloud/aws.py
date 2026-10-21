"""AWS IAM collector: builds the escalation-analysis prompt.

Gathers users, groups and roles together with every attached policy type
(managed, inline, permission boundaries) plus role trust policies, and formats
them into the analysis prompt. Policies are keyed by principal ARN with full
policy documents inline.
"""

import os
import sys
import json

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
            Supports two modes: an AWS CLI profile, or access key + secret key.
            """
        try:
            if kwargs.get('profile'):
                self.logger.debug(
                    f"Try to establishing connection to AWS using the profile {kwargs.get('profile')}")
                session = boto3.Session(profile_name=kwargs.get('profile'))
                return session.client("iam")
            if kwargs.get('aws_key') and kwargs.get('aws_secret'):
                self.logger.debug(
                    "Try to establishing connection to AWS using AWS key and AWS secret")
                return boto3.client("iam", aws_access_key_id=kwargs.get('aws_key'),
                                    aws_secret_access_key=kwargs.get('aws_secret'))
        except Exception as e:
            self.logger.error(f"Error while try to connect AWS {e}")
            return None

    def start(self) -> str:
        """
        Collects users, groups and roles with all their policy types and builds
        the analysis prompt.
        """
        account_id = ""
        result = {
            "account_id": account_id,
            "users": {},
            "groups": {},
            "roles": {},
        }

        try:
            account_id = self._get_account_id()
            result["account_id"] = account_id
            self.logger.debug(f"Collecting authorization details for account {account_id}")

            details = self._get_all_authorization_details()

            for user in details.get("UserDetailList", []):
                arn = user.get("Arn", "unknown-user")
                result["users"][arn] = {
                    "user_name": user.get("UserName"),
                    "groups": user.get("GroupList", []),
                    "attached_managed_policies": self._managed_policy_docs(
                        user.get("AttachedManagedPolicies", [])
                    ),
                    "inline_policies": self._inline_policy_docs(user.get("UserPolicyList", [])),
                    "permission_boundary": self._boundary_doc(user.get("PermissionsBoundary")),
                }

            for group in details.get("GroupDetailList", []):
                arn = group.get("Arn", "unknown-group")
                result["groups"][arn] = {
                    "group_name": group.get("GroupName"),
                    "attached_managed_policies": self._managed_policy_docs(
                        group.get("AttachedManagedPolicies", [])
                    ),
                    "inline_policies": self._inline_policy_docs(group.get("GroupPolicyList", [])),
                    "permission_boundary": self._boundary_doc(group.get("PermissionsBoundary")),
                }

            for role in details.get("RoleDetailList", []):
                arn = role.get("Arn", "unknown-role")
                result["roles"][arn] = {
                    "role_name": role.get("RoleName"),
                    "trust_policy": role.get("AssumeRolePolicyDocument"),
                    "attached_managed_policies": self._managed_policy_docs(
                        role.get("AttachedManagedPolicies", [])
                    ),
                    "inline_policies": self._inline_policy_docs(role.get("RolePolicyList", [])),
                    "permission_boundary": self._boundary_doc(role.get("PermissionsBoundary")),
                }

        except ClientError as e:
            self.logger.error(f"Error while connecting to AWS: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error while connecting to AWS: {e}")

        if not (result["users"] or result["groups"] or result["roles"]):
            self.logger.error("No IAM principals were collected; nothing to analyze.")

        return PROMPTS['AWS'].format(json.dumps(result, default=str, indent=2))

    def _get_all_authorization_details(self) -> dict:
        """Fetch all pages of GetAccountAuthorizationDetails."""
        merged = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        marker = None
        while True:
            kwargs = {}
            if marker:
                kwargs["Marker"] = marker
            response = self.client.get_account_authorization_details(**kwargs)
            for key in merged:
                merged[key].extend(response.get(key, []))
            marker = response.get("Marker")
            if not marker:
                break
        return merged

    def _managed_policy_docs(self, attached: list) -> list:
        """Fetch full documents for attached managed policies."""
        out = []
        for policy in attached or []:
            arn = policy.get("PolicyArn")
            if not arn:
                continue
            try:
                document = self._extract_policy_document(arn)
                out.append({"arn": arn, "name": policy.get("PolicyName"), "document": document})
            except ClientError as e:
                self.logger.error(f"Error while processing policy {arn}: {e}")
                out.append({"arn": arn, "name": policy.get("PolicyName"), "error": str(e)})
            except Exception as e:
                self.logger.error(f"Unexpected error while processing policy {arn}: {e}")
                out.append({"arn": arn, "name": policy.get("PolicyName"), "error": str(e)})
        return out

    def _inline_policy_docs(self, policy_list: list) -> list:
        """Inline policies already carry their document in the detail response."""
        out = []
        for policy in policy_list or []:
            out.append({"name": policy.get("PolicyName"), "document": policy.get("PolicyDocument")})
        return out

    def _boundary_doc(self, boundary) -> dict | None:
        if not boundary:
            return None
        arn = boundary.get("PermissionsBoundaryArn")
        if not arn:
            return boundary
        try:
            document = self._extract_policy_document(arn)
            return {"arn": arn, "type": boundary.get("PermissionsBoundaryType"), "document": document}
        except Exception as e:
            self.logger.error(f"Error while processing permission boundary {arn}: {e}")
            return {"arn": arn, "type": boundary.get("PermissionsBoundaryType"), "error": str(e)}

    def _get_account_id(self):
        try:
            account_id = self.client.get_user()["User"]["Arn"].split("::")[1].split(":")[0]
        except Exception as e:
            self.logger.error(f"Error while try get account_id {e}")
            account_id = ""
        return account_id

    def _extract_policy_document(self, policy_arn):
        policy_version = self.client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = \
            self.client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]
        return policy_document
