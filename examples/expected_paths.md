# Ground truth for `examples/sample_policies.json`

Scenario: AWS account `123456789012` contains an administrator user
(`admin`) and a privileged role (`SandboxAdmin` whose trust policy allows
`dave` to assume it). Four users hold customer-managed policies with
deliberate escalation primitives.

## Expected paths

| # | User | Mechanism | Expected path (what a good answer says) |
|---|---|---|---|
| 1 | alice | `iam:CreateAccessKey` on `*` | alice can create a long-term access key **for any other IAM user** (e.g. `admin`), then operates with that user's permissions |
| 2 | bob | `ec2:RunInstances` + `iam:PassRole` on `role/*` | bob can launch an EC2 instance **passing a privileged role** (e.g. `SandboxAdmin`) and harvest that role's credentials from instance metadata |
| 3 | carol | `iam:AttachUserPolicy` / `iam:PutUserPolicy` on `*` | carol can attach `AdministratorAccess` (or an inline admin policy) **to herself**, self-escalating immediately |
| 4 | dave | `sts:AssumeRole` on `role/SandboxAdmin` | dave can directly assume `SandboxAdmin`; if that role is privileged, this is admin access (needs cross-referencing the role's own permission set, which this snapshot does not include) |

## Scoring rubric

Run the tool with several models over the same snapshot, then judge each
model's answer per expected path:

- **found**: the mechanism and its consequence are stated correctly
- **partial**: the primitive is noticed but the consequence is wrong or incomplete
- **missed**: the path is not reported
- **hallucinated**: a reported path does not follow from the given policy data
  (e.g. inventing actions the policies do not grant)

## Known limits of this fixture

- It only contains attached managed policies; inline user policies, permission
  boundaries, SCPs and role definitions are absent, so exactly reproducible
  findings are limited to what the model can infer.
- Path 4 depends on out-of-band knowledge (`SandboxAdmin` being privileged),
  so "partial" with a reasonable caveat is an acceptable full score for it.
