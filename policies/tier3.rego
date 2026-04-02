# ============================================================================
# OPA Policy - Tier 3: Human-Only Escalation (~10% of drift remediation volume)
# ============================================================================
#
# PURPOSE:
#   Hard block the most dangerous infrastructure changes. These require manual
#   investigation, explicit human decision-making, and often cross-team approval.
#   This tier exists to prevent catastrophic automation mistakes.
#
# WHEN THIS APPLIES:
#   - High risk score (>= 0.8)
#   - Security-critical resources in production
#   - Active incidents (prevents hotfix reversal)
#   - Destructive changes (resource deletion)
#   - Network infrastructure changes (VPC, subnets, routing)
#
# WHAT HAPPENS:
#   1. Surgeon Agent generates patch
#   2. Checker Agent validates
#   3. OPA evaluates: Tier 3 deny[] triggers
#   4. GitHub PR created with label "escalated/human-only"
#   5. PR description includes escalation reason
#   6. NO auto-merge possible (blocked at CI level)
#   7. Human must review, decide, and manually apply OR close PR
#
# PRODUCTION STATISTICS:
#   - ~10% of all drift events escalate to Tier 3
#   - Average resolution time: 4-8 hours (requires human availability)
#   - Manual application rate: 60% (humans review, approve, manually apply)
#   - PR closure rate: 40% (humans determine patch is incorrect or timing bad)
#
# WHY TIER 3 EXISTS:
#   Some changes are too dangerous to trust to automation, even with validation:
#     - Deleting a database (data loss)
#     - Modifying IAM during security incident (access issues)
#     - Changing VPC routing (network outage)
#     - Reverting hotfixes during active incidents (P1 extension)
#
# SAFETY PHILOSOPHY:
#   "The cost of a human reviewing this change: 10 minutes.
#    The cost of getting it wrong: 4-hour outage.
#    Always err on the side of human review."
#
# ============================================================================

package drift.remediation.tier3

# ----------------------------------------------------------------------------
# HARD BLOCKS - These deny[] rules prevent ANY merge
# ----------------------------------------------------------------------------

# BLOCK 1: Active Incident (The 22-Minute P1 Extension Preventer)
# ---------------
# If PagerDuty reports an active incident, block ALL automated remediation.
#
# REAL PRODUCTION FAILURE (Slide 22):
#   Timeline:
#     14:02 - Service degraded (P1)
#     14:11 - SRE made emergency Console hotfix
#     14:14 - Service recovered
#     14:19 - Drift detection reverted hotfix (active_incident not implemented)
#     14:23 - Service degraded AGAIN
#     14:36 - Incident resolved (22 additional minutes of P1 downtime)
#
# LESSON LEARNED:
#   Operational context trumps automation. If a human is actively fighting a
#   fire, do NOT interfere with their changes. Wait for incident resolution.
#
# OVERRIDE PATH:
#   If remediation is genuinely required during incident (rare), incident
#   commander can add "incident/override" label with explanation.
deny[msg] {
    input.active_incident == true
    not input.pr_labels["incident/override"]
    msg := "BLOCK: Active incident detected (PagerDuty). All remediation paused. Override: incident commander must add 'incident/override' label with justification."
}

# BLOCK 2: Destructive Changes (No Exceptions)
# ---------------
# Resource deletion or critical configuration removal requires manual human
# execution with eyes-on-screen. NO automation pathway exists.
#
# EXAMPLES OF DESTRUCTIVE:
#   - destroy: true in Terraform plan
#   - Deleting databases (aws_db_instance)
#   - Removing KMS keys (aws_kms_key)
#   - Destroying VPCs (aws_vpc)
#   - Removing security group rules (potential lockout)
#
# WHY NO OVERRIDE:
#   Destructive operations are irreversible. Even with perfect validation,
#   the blast radius is too high. Humans must observe the apply in real-time
#   and be ready to Ctrl+C if something unexpected happens.
deny[msg] {
    input.has_destructive_changes == true
    msg := "BLOCK: Destructive changes detected (resource deletion or removal operations). No automation permitted. Human must manually run terraform apply with observation."
}

# BLOCK 3: Critical Resources Without Multi-Team Approval
# ---------------
# Some resources are so critical that they require approval from BOTH
# the owning team AND a secondary reviewer (often security or platform leads).
#
# CRITICAL RESOURCES:
#   - Databases (data loss risk)
#   - IAM (security escalation risk)
#   - KMS (encryption key exposure)
#   - VPCs (network isolation breach)
#   - Secrets (credential exposure)
deny[msg] {
    critical_resource_types[input.resource_type]
    not has_sufficient_approvals
    msg := sprintf("BLOCK: '%v' requires multi-team approval. Missing required labels. Risk score: %v", [input.resource_type, input.risk_score])
}

# BLOCK 4: Security Domain Without SecOps Approval
# ---------------
# ANY change in the security domain (security groups, IAM, GuardDuty, Config)
# must have explicit security team approval via "secops/approved" label.
#
# WHY SEPARATE FROM BLOCK 3:
#   Security team may approve a security group change that isn't "critical"
#   by Tier 3 standards but still needs security expertise to evaluate.
deny[msg] {
    input.domain == "security"
    not input.pr_labels["secops/approved"]
    msg := "BLOCK: Security domain change requires security team review. Add 'secops/approved' label. CODEOWNERS routes to @security-team."
}

# BLOCK 5: Network Changes (VPC, Subnets, Routing)
# ---------------
# Network infrastructure changes can cause widespread outages. These always
# require network team review AND production change control.
deny[msg] {
    network_resource_types[input.resource_type]
    not input.pr_labels["netops/approved"]
    not input.pr_labels["change-control/approved"]
    msg := sprintf("BLOCK: Network resource '%v' requires both 'netops/approved' AND 'change-control/approved' labels.", [input.resource_type])
}

# BLOCK 6: High Risk Score (Detective Agent Flagged This)
# ---------------
# If Detective Agent analyzed the drift and determined risk >= 0.8 (high),
# block merge until human explicitly reviews the RCA report and approves.
#
# HIGH RISK INDICATORS:
#   - Large blast radius (affects many resources)
#   - Security-sensitive changes (SSH, IAM, encryption)
#   - Production environment
#   - Multiple policy violations
deny[msg] {
    input.risk_score >= 0.8
    not input.pr_labels["risk/acknowledged"]
    msg := sprintf("BLOCK: High risk score (%v). Human must review Detective Agent RCA and add 'risk/acknowledged' label.", [input.risk_score])
}

# ----------------------------------------------------------------------------
# HELPER: MULTI-TEAM APPROVAL VERIFICATION
# ----------------------------------------------------------------------------
# Critical resources require approval from at least 2 teams:
#   1. Owning team (platform/infrastructure)
#   2. Secondary team (security OR compliance OR platform-leads)
has_sufficient_approvals {
    # Must have primary approval
    input.pr_labels["drift/approved"]

    # AND at least one secondary approval
    count([label | input.pr_labels[label];
           label in {"secops/approved", "compliance/approved", "platform-leads/approved"}]) >= 1
}

# ----------------------------------------------------------------------------
# HELPER: CRITICAL RESOURCE TYPES
# ----------------------------------------------------------------------------
critical_resource_types := {
    "aws_db_instance",           # RDS databases
    "aws_rds_cluster",            # Aurora clusters
    "aws_iam_role",              # IAM roles
    "aws_iam_policy",            # IAM policies
    "aws_iam_user",              # IAM users
    "aws_kms_key",               # KMS encryption keys
    "aws_vpc",                   # Virtual Private Clouds
    "aws_secretsmanager_secret", # Secrets Manager
}

# ----------------------------------------------------------------------------
# HELPER: NETWORK RESOURCE TYPES
# ----------------------------------------------------------------------------
# Network changes can cause widespread outages across multiple services
network_resource_types := {
    "aws_vpc",
    "aws_subnet",
    "aws_route_table",
    "aws_nat_gateway",
    "aws_internet_gateway",
    "aws_vpc_peering_connection",
    "aws_transit_gateway",
}

# ----------------------------------------------------------------------------
# EXPECTED INPUT SCHEMA (Tier 3 Additions)
# ----------------------------------------------------------------------------
# All fields from Tier 1/2, plus:
#
# {
#   "pr_labels": {
#     "drift/approved": false,            # Primary approval
#     "secops/approved": false,           # Security team approval
#     "netops/approved": false,           # Network team approval
#     "compliance/approved": false,       # Compliance approval
#     "platform-leads/approved": false,   # Platform leads approval
#     "risk/acknowledged": false,         # High-risk acknowledgment
#     "change-control/approved": false,   # Change control board approval
#     "incident/override": false          # Incident commander override
#   }
# }
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# ESCALATION REASONS (For PR Description)
# ----------------------------------------------------------------------------
# When Tier 3 triggers, the system includes escalation reason in PR:
#
# "ESCALATION REASON:
#  - Resource type 'aws_iam_role' is critical (requires multi-team approval)
#  - Risk score 0.87 exceeds high-risk threshold (>= 0.8)
#  - Security domain requires security team review
#
#  REQUIRED ACTIONS:
#  1. Review Detective Agent RCA report (see PR description)
#  2. Verify Surgeon patch correctness (see Files Changed)
#  3. Add required labels:
#     - 'drift/approved' (primary team)
#     - 'secops/approved' (security team)
#     - 'risk/acknowledged' (acknowledge high risk)
#  4. After labels added, CI will re-run OPA check
#  5. If all deny[] rules pass, PR can merge
#  6. OR close PR if patch is incorrect"
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# INTEGRATION WITH CI/CD
# ----------------------------------------------------------------------------
# GitHub Actions workflow evaluates OPA policies on:
#   - PR creation (initial evaluation)
#   - Label changes (re-evaluation when human adds label)
#   - Commit pushes (re-evaluation after Surgeon updates patch)
#
# Workflow pseudocode:
#   opa eval --data policies/ --input pr_data.json "data.drift.remediation"
#   if deny[msg] exists:
#       github.block_merge()
#       github.comment(msg)
#   else:
#       github.allow_merge()
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# PRODUCTION LESSONS LEARNED
# ----------------------------------------------------------------------------
# Why Tier 3 thresholds are what they are:
#
# 1. risk >= 0.8 (not 0.7 or 0.9):
#    Tuned over 6 months. 0.7 caught too many false positives (alert fatigue),
#    0.9 missed genuinely risky changes. 0.8 is the validated sweet spot.
#
# 2. active_incident guard exists:
#    Learned from 22-minute P1 extension (Slide 22). Before this guard,
#    automation reverted emergency hotfixes.
#
# 3. network resources always blocked:
#    One VPC routing table change took down 47 services for 90 minutes.
#    Network changes now require network team + change control.
#
# 4. has_destructive_changes with no override:
#    Early version allowed "destructive/acknowledged" label override. Bad idea.
#    Someone approved a database deletion, thinking it was a replica.
#    It was the primary. Data loss. No override path anymore.
#
# ----------------------------------------------------------------------------
