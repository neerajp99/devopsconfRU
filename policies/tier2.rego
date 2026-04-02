# ============================================================================
# OPA Policy - Tier 2: Require Human Review (~50% of drift remediation volume)
# ============================================================================
#
# PURPOSE:
#   Handle medium-risk infrastructure changes that don't qualify for auto-merge
#   but aren't dangerous enough to hard-block. These require human review and
#   approval via GitHub PR labels before merge is allowed.
#
# WHEN THIS APPLIES:
#   - Doesn't qualify for Tier 1 (risk >= 0.5 OR critical resource)
#   - Doesn't trigger Tier 3 hard blocks (not destructive, no active incident)
#   - Medium risk or production changes
#
# WHAT HAPPENS:
#   1. Surgeon Agent generates patch
#   2. Checker Agent validates (syntax, semantic, policy)
#   3. OPA evaluates: Tier 1 fails, Tier 2 requires review
#   4. GitHub PR created with label "requires-review"
#   5. CODEOWNERS auto-assigns team based on domain
#   6. Human reviewer adds "drift/approved" label
#   7. CI re-runs OPA check (now passes)
#   8. PR merges
#
# PRODUCTION STATISTICS:
#   - ~50% of all drift events route through Tier 2
#   - Average review time: 2-4 hours (human availability dependent)
#   - Rejection rate: ~5% (humans reject PR, provide feedback)
#   - Most common: Security groups, IAM policies, production resources
#
# LABEL-BASED APPROVAL:
#   GitHub PR labels act as approval gates:
#     - "drift/approved": Generic approval for critical resources
#     - "secops/approved": Security team approval for security domain
#     - "netops/approved": Network team approval for network changes
#
# SAFETY GUARANTEES:
#   - All Tier 3 blocks still apply (active_incident, destructive, etc.)
#   - Requires explicit human decision via PR label
#   - CODEOWNERS ensures correct team reviews
#   - Full audit trail in PR comments and labels
#   - Can be rejected and refined
#
# ============================================================================

package drift.remediation.tier2

# ----------------------------------------------------------------------------
# DENY RULES (Hard blocks that prevent merge even with approval)
# ----------------------------------------------------------------------------
# These rules create hard stops that NO amount of human approval can override.
# They exist to prevent catastrophic mistakes during sensitive operations.

# BLOCK 1: Active Incident Guard (The Hotfix Reversal Prevention)
# ---------------
# During an active incident (P1/P0), block ALL automated remediation unless
# explicitly overridden with "incident/override" label.
#
# WHY THIS EXISTS:
#   Real production incident (Slide 20): SRE made emergency hotfix via Console
#   to resolve P1. 5 minutes later, drift detection fired and reverted the fix,
#   causing 22 additional minutes of downtime. The SRE thought they misdiagnosed
#   the problem and re-investigated from scratch.
#
# LESSON LEARNED:
#   Operational context matters. If a human is actively fighting a fire, do NOT
#   auto-remediate their changes. PagerDuty integration sets active_incident=true.
deny[msg] {
    input.active_incident == true
    not input.pr_labels["incident/override"]
    msg := "BLOCK: Active incident detected. Remediation paused to prevent hotfix reversal. Override: add 'incident/override' label."
}

# BLOCK 2: Destructive Changes
# ---------------
# Changes that delete resources or remove critical configuration are NEVER
# auto-approved, even with human review. They require manual terraform apply
# with eyes-on-screen observation.
#
# EXAMPLES:
#   - Deleting aws_db_instance (data loss risk)
#   - Removing security group rules (access loss risk)
#   - Destroying aws_kms_key (encryption key loss)
#
# WHY NO OVERRIDE:
#   Terraform's destroy operations are irreversible. Even with approval, the
#   risk of accidental data loss is too high. Humans must run these manually.
deny[msg] {
    input.has_destructive_changes == true
    msg := "BLOCK: Destructive changes detected (resource deletion or critical config removal). Manual terraform apply required."
}

# BLOCK 3: Critical Resources Without Approval
# ---------------
# Critical infrastructure (databases, IAM, KMS, VPCs) must have explicit
# "drift/approved" label before merge is allowed.
#
# This prevents accidental auto-merge if someone removes the "requires-review"
# label prematurely.
deny[msg] {
    critical_resource_types[input.resource_type]
    not input.pr_labels["drift/approved"]
    msg := sprintf("BLOCK: '%v' is a critical resource. Add 'drift/approved' label after review. Current risk: %v", [input.resource_type, input.risk_score])
}

# BLOCK 4: Security Domain Without SecOps Approval
# ---------------
# Any change classified as "security" domain (security groups, IAM, GuardDuty)
# must have explicit approval from the security team via "secops/approved" label.
#
# WHY SEPARATE LABEL:
#   Security team has different SLAs and review criteria. Generic "drift/approved"
#   is insufficient for security-sensitive changes.
deny[msg] {
    input.domain == "security"
    not input.pr_labels["secops/approved"]
    msg := "BLOCK: Security domain changes require 'secops/approved' label. Route to security team via CODEOWNERS."
}

# ----------------------------------------------------------------------------
# CRITICAL RESOURCE CLASSIFICATION
# ----------------------------------------------------------------------------
# Same as Tier 1, but used for Tier 2's approval requirements
critical_resource_types := {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_kms_key",
    "aws_vpc",
    "aws_secretsmanager_secret",
}

# ----------------------------------------------------------------------------
# EXPECTED INPUT SCHEMA
# ----------------------------------------------------------------------------
# Same schema as Tier 1, with additional fields used by Tier 2:
#
# {
#   "resource_type": "aws_security_group",
#   "risk_score": 0.65,                         # Medium risk
#   "active_incident": false,
#   "has_destructive_changes": false,
#   "domain": "security",                       # Routes to security team
#   "pr_labels": {
#     "drift/approved": true,                   # Human approved
#     "secops/approved": true,                  # Security team approved
#     "incident/override": false
#   }
# }
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# EXAMPLES
# ----------------------------------------------------------------------------
#
# EXAMPLE 1: Medium-risk change, approved by human
# Input:
#   resource_type: "aws_security_group"
#   risk_score: 0.65
#   active_incident: false
#   has_destructive_changes: false
#   domain: "security"
#   pr_labels: {"secops/approved": true}
# Result: All deny[] rules evaluate to false → merge allowed
#
# EXAMPLE 2: Active incident, no override
# Input:
#   resource_type: "aws_s3_bucket"
#   risk_score: 0.4
#   active_incident: true  # PagerDuty incident active
#   pr_labels: {}
# Result: deny[] = ["BLOCK: Active incident..."] → merge blocked
#
# EXAMPLE 3: Critical resource, missing approval
# Input:
#   resource_type: "aws_iam_role"
#   risk_score: 0.55
#   pr_labels: {"requires-review": true}  # Reviewer forgot to add drift/approved
# Result: deny[] = ["BLOCK: 'aws_iam_role' is critical..."] → merge blocked
#
# EXAMPLE 4: Destructive change (always blocked)
# Input:
#   resource_type: "aws_db_instance"
#   has_destructive_changes: true
#   pr_labels: {"drift/approved": true}  # Approval doesn't help
# Result: deny[] = ["BLOCK: Destructive changes..."] → merge blocked
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# CODEOWNERS INTEGRATION
# ----------------------------------------------------------------------------
# GitHub CODEOWNERS file routes PRs to correct teams:
#
# .github/CODEOWNERS:
#   code/terraform/security/ @security-team
#   code/terraform/network/  @network-team
#   code/terraform/compute/  @platform-team
#
# When a PR is created:
#   1. GitHub auto-assigns reviewers based on file paths
#   2. Assigned team reviews change
#   3. Team adds required label ("drift/approved", "secops/approved")
#   4. OPA re-evaluates on label change
#   5. If deny[] is empty, PR can merge
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# REJECTION AND FEEDBACK LOOP
# ----------------------------------------------------------------------------
# If a human reviewer rejects the PR:
#   1. Reviewer closes PR with comment explaining why
#   2. Closure event triggers feedback collection
#   3. Feedback stored for future Surgeon Agent improvements
#   4. Drift event remains in "unresolved" state
#   5. Detective Agent re-analyzes on next detection cycle
#
# Common rejection reasons:
#   - "Patch doesn't address root cause"
#   - "Change conflicts with planned migration"
#   - "Timing is inappropriate (freeze period)"
#   - "Requires additional testing first"
#
# This feedback loop improves Surgeon Agent accuracy over time (75% → 95%).
# ----------------------------------------------------------------------------
