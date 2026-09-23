# AWS Sandbox Security Suite (`aws-sandbox-security`)

> 🟡 **Status**: Currently in Design & Architectural Specification.

An upcoming **Agentic Security Engineering Suite for AWS & Amazon Bedrock**, mirroring the deterministic MCP + self-learning knowledge base architecture of [`gcp-sandbox-security`](../gcp-sandbox-security/).

---

## 🎯 Target Threat Models & Capabilities

1. **Least-Privilege AWS IAM Role Solver**:
   - Deterministic AST analysis across Terraform (`aws_iam_policy`, `aws_iam_role_policy_attachment`) and CloudFormation templates.
   - Eliminating `AdministratorAccess`, `PowerUserAccess`, and unscoped `iam:PassRole` privilege escalation vectors.

2. **Amazon Bedrock & GenAI Sandbox Lockdown**:
   - Preventing exportable long-lived IAM user access keys (`aws_iam_access_key`) on roles holding `bedrock:InvokeModel` or `bedrock:InvokeModelWithResponseStream`.
   - Applying Service Control Policies (SCPs) and Permission Boundaries to prevent Denial-of-Wallet abuse on foundation models.

3. **IMDSv2 Enforcement & STS Token Exfiltration Prevention**:
   - Enforcing `http_tokens = "required"` and `http_put_response_hop_limit = 1` on EC2 launch templates and instances.
   - Restricting outbound VPC security groups and routing traffic strictly through AWS PrivateLink / VPC Endpoints.

4. **Red/Blue Teaming Skills & MCP Tools**:
   - `/pentest-aws-sandbox`: Scans AWS IaC for permissive wildcards (`Action: "*"`, `Resource: "*"`), credential leakage, and insecure metadata endpoints.
   - `/harden-aws-sandbox`: Automatically calculates minimal IAM policies, deploys baseline security groups, and enforces pre-merge compliance gates.

---

## 🏗️ Architecture

Will follow the identical zero-dependency Python stdio MCP server standard defined in `plugins/gcp-sandbox-security`:
* `mcp/server.py`: AWS JSON-RPC 2.0 MCP server.
* `kb/`: YAML knowledge base of AWS service archetypes, least-privilege policies, and known IAM traps.
* `skills/`: Red/Blue adversarial workflows.
* `examples/sandboxes/`: Vulnerable AWS & Bedrock sandbox environments for testing.
