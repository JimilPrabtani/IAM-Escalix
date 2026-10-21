"""Prompt templates sent to the LLM.

Modified from EscalateGPT (Tenable, GPL-3.0), 2026-10-21: added an explicit
"return only JSON" instruction to the AWS prompt so responses parse reliably.
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
    "AWS": """Identify potential privilege escalation paths based on the provided IAM policies.
The data maps each IAM user ARN to the managed policies attached to that user, with full policy documents inline.
List users who can gain unauthorized access or elevated permissions, considering actions beyond direct access.

Present the findings as JSON, following this format:
{{"paths": [
    {{"path": "[SourceUserName]-[PolicyAction]->[Target]", "policy": "PolicyAction", "risk": "Explain the risk associated with the path", "mitigation": "Provide mitigation steps to address the risk", "all_users": "List other users with similar permissions"}}
]}}

When analyzing:
- Consider direct escalations and indirect multi-step attacks (for example PassRole combined with service actions such as ec2:RunInstances, or AttachUserPolicy used on the identity itself)
- Aggregate users with identical escalation capabilities
- Offer technically accurate and detailed explanations
- Propose practical mitigation measures
Return only valid JSON, with no commentary or markdown.
Your output should be only the JSON

Policies:
{}""",
}
