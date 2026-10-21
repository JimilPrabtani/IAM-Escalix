# Ground truth for `examples/sample_policies*.json`

Scenario: AWS account `123456789012` (and `999999999999` for the alt
snapshot) contain an administrator user (`admin`) and a privileged role
(`SandboxAdmin` whose trust policy allows `dave` to assume it). Several
users hold customer-managed policies with deliberate escalation primitives,
plus a group, a role and a permission boundary to exercise all policy types.

## Expected paths (sample_policies.json)

| # | Principal | Mechanism | Expected path |
|---|---|---|---|
| 1 | alice (user) | `iam:CreateAccessKey` on `*` | alice can create a long-term access key for any other IAM user (e.g. `admin`) and operate with that user's permissions |
| 2 | bob (user) | `ec2:RunInstances` + `iam:PassRole` on `role/*` | bob can launch an EC2 instance passing a privileged role and harvest that role's credentials from instance metadata |
| 3 | carol (user) | `iam:AttachUserPolicy` / `iam:PutUserPolicy` on `*` | carol can attach `AdministratorAccess` (or an inline admin policy) to herself and self-escalate immediately |
| 4 | dave (user) | `sts:AssumeRole` on `role/SandboxAdmin` | dave can directly assume `SandboxAdmin`; if that role is privileged this is admin access (role's own permissions are in the snapshot) |
| 5 | group Developers / eve | group membership + inline policy | eve inherits the group's inline policy; check whether the boundary on eve actually restricts it |
| 6 | role SandboxAdmin | trust policy allows only dave | verify the trust policy is not wildcarded and the role is not overly broad |

## Scoring rubric

Run the tool with several models over the same snapshot, then judge each
model's answer per expected path:

- **found**: the mechanism and its consequence are stated correctly
- **partial**: the primitive is noticed but the consequence is wrong or incomplete
- **missed**: the path is not reported
- **hallucinated**: a reported path does not follow from the given policy data
  (e.g. inventing actions the policies do not grant)

## Known limits of these fixtures

- They only contain attached managed policies, inline policies, one boundary
  and role trust policies; SCPs and permission boundaries on every principal
  are absent, so findings are limited to what the model can infer.
- Path 4 depends on the role's own permission set, which IS included here
  (SandboxAdmin has AdministratorAccess), so a full "found" is expected.
- Multiple snapshots can be audited in one invocation via
  `--policies-dir examples/` (writes one report per file).
