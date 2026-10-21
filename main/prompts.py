"""Prompt templates sent to the LLM.

Each template instructs the model to return only valid JSON so responses can be
parsed and persisted. The AWS template covers users, groups, roles and all
attached policy types (managed, inline, permission boundaries).
"""

PROMPTS = {
    "AZURE": """Identify potential privilege escalation paths in an Azure environment based on the given 2 JSON data one for users and one for groups.
In the user JSON the key is User SPN and the value is where the user is a member of (groups and directory roles)
In the group JSON the key is the group name and the value is the owners of the group
Generate output in the specified JSON format:
"paths":
{{
[
        "path": "[SourceUserName]-[ACTION (The action the source can do to get to the target)]->[TargetUserName]",
        "description": "Explanation of why this escalation is possible",
        "mitigation": "Suggestions for preventing this escalation",
        "all_users": "If we have others users with the same permission write here there SPN"
    ...
]
}}
When analyzing privilege escalation paths:
- Consider both direct escalations and potential indirect multi-step attacks
- Aggregate users with identical escalation capabilities
- Offer technically accurate and detailed explanations
- Propose practical mitigation measures
Return only valid JSON, with no commentary or markdown.
Your output should be only the JSON
User data JSON: {}
Group owner data JSON: {}
""",
    "AWS": """Identify potential privilege escalation paths in the following AWS IAM configuration.

The data contains, per account:
- users: each with attached managed policies, inline policies, permission boundary, and group memberships
- groups: attached managed policies, inline policies, permission boundary
- roles: trust policy (who may assume the role), attached managed policies, inline policies, permission boundary

Consider ALL policy types: AWS-managed, customer-managed, inline, permission boundaries, and trust policies. Identify paths by which a principal can gain permissions it should not have, including indirect multi-step attacks such as:
- iam:PassRole combined with a service action (ec2:RunInstances, lambda:CreateFunction, ...)
- iam:CreateAccessKey on another user
- iam:AttachUserPolicy / iam:PutUserPolicy / iam:AttachRolePolicy on self or others
- sts:AssumeRole into a privileged role (cross-reference the role's trust policy and its own permissions)
- permission-boundary bypass or removal
- group/role membership abuse
- trust-policy misconfiguration allowing cross-account or wildcard principals

Aggregate principals with identical escalation capabilities. Propose practical mitigations.

Return only valid JSON, with no commentary or markdown, in this format:
{{"paths": [
    {{"path": "[Source]-[Action]->[Target]", "source_type": "user|group|role", "target": "principal or resource", "policy_type": "managed|inline|boundary|trust", "policy": "Action", "risk": "Explain the risk", "mitigation": "Mitigation steps", "all_principals": "Other principals with the same capability"}}
], "summary": "One-paragraph overview of the account's escalation posture"}}

Configuration:
{}""",
}
