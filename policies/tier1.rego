# ============================================================================
# OPA Policy - Tier 1: Auto-Merge (~40% of drift remediation volume)
# ============================================================================
#
# PURPOSE:
#   Automatically approve and merge low-risk infrastructure changes without
#   human intervention. This tier handles safe, routine drift corrections
#   like tag updates and minor configuration normalization.
#
# WHEN THIS APPLIES:
#   - Risk score < 0.5 (low to medium risk)
#   - Non-critical resource types
#   - No active incident in progress
#   - Change is tag-only OR minor configuration drift
#
# WHAT HAPPENS:
#   1. Surgeon Agent generates patch
#   2. Checker Agent validates (syntax, semantic, policy)
#   3. OPA evaluates: auto_approve = true
#   4. GitHub PR created with label "auto-merge/approved"
#   5. CI runs terraform validate + plan
#   6. PR auto-merges (no human review)
#   7. Change appears in daily audit digest
#
# PRODUCTION STATISTICS:
#   - ~40% of all drift events qualify for Tier 1
#   - Average time to remediation: 8 minutes
#   - False positive rate: <2% (caught by Checker Agent before OPA)
#   - Human time saved: ~15 hours/week at 50 events/day
#
# SAFETY GUARANTEES:
#   - Never runs during active incidents (active_incident guard)
#   - Never touches critical resources (databases, IAM, KMS, VPCs)
#   - Always validated by 3-stage Checker Agent first
#   - All changes create PR with full audit trail
#   - Zero AWS access - only GitHub PR creation permission
#
# ============================================================================

package drift.remediation.tier1

# ----------------------------------------------------------------------------
# AUTO-APPROVE DECISION
# ----------------------------------------------------------------------------
# Default to false - changes must explicitly qualify for auto-merge
default auto_approve = false

# Auto-approve when ALL conditions are met:
#   1. Low risk score (< 0.5)
#   2. Not a critical resource type
#   3. No active incident
#   4. Change is tag-only (safest possible change)
auto_approve {
    input.risk_score < 0.5                           # Risk threshold
    not critical_resource_types[input.resource_type] # Not critical
    not input.active_incident                        # No incident (THE HOTFIX GUARD)
    tag_only_change                                  # Only tags modified
}

# ----------------------------------------------------------------------------
# HELPER: TAG-ONLY CHANGE DETECTION
# ----------------------------------------------------------------------------
# A tag-only change is the safest possible infrastructure modification:
#   - No functional impact
#   - No security implications
#   - Fully reversible
#   - Cannot cause outages
#
# This uses set comprehension to verify that ONLY the "tags" key was modified
# in the Terraform diff. If any other attribute changed, this fails.
tag_only_change {
    changed_keys := {k | _ = input.diff[k]}  # Extract all changed keys
    changed_keys == {"tags"}                 # Verify ONLY "tags" changed
}

# ----------------------------------------------------------------------------
# HELPER: CRITICAL RESOURCE CLASSIFICATION
# ----------------------------------------------------------------------------
# Resources that should NEVER auto-merge, even at low risk:
#   - Databases: Data loss risk
#   - IAM: Security escalation risk
#   - KMS: Encryption key exposure risk
#   - VPC: Network isolation breach risk
#   - Secrets: Credential exposure risk
#
# These ALWAYS require human review (Tier 2) or hard block (Tier 3)
critical_resource_types := {
    "aws_db_instance",           # RDS databases
    "aws_rds_cluster",            # Aurora clusters
    "aws_iam_role",              # IAM roles
    "aws_iam_policy",            # IAM policies
    "aws_iam_user",              # IAM users
    "aws_kms_key",               # KMS encryption keys
    "aws_vpc",                   # VPCs
    "aws_secretsmanager_secret", # Secrets Manager
}

# ----------------------------------------------------------------------------
# EXPECTED INPUT SCHEMA
# ----------------------------------------------------------------------------
# This policy expects the following input structure from the Checker Agent:
#
# {
#   "resource_type": "aws_s3_bucket",           # Terraform resource type
#   "risk_score": 0.42,                         # 0.0-1.0 from Detective Agent
#   "active_incident": false,                   # PagerDuty integration status
#   "has_destructive_changes": false,           # Checker Agent analysis
#   "domain": "infrastructure",                 # infrastructure|security|network
#   "diff": {                                   # Terraform plan diff
#     "tags": {
#       "before": {"Environment": "dev"},
#       "after": {"Environment": "dev", "ManagedBy": "Terraform"}
#     }
#   },
#   "pr_labels": {                              # GitHub PR labels
#     "drift/approved": false,
#     "secops/approved": false,
#     "incident/override": false
#   }
# }
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# EXAMPLES
# ----------------------------------------------------------------------------
#
# EXAMPLE 1: Auto-approved (tag-only change on non-critical resource)
# Input:
#   resource_type: "aws_s3_bucket"
#   risk_score: 0.25
#   active_incident: false
#   diff: {"tags": {...}}
# Result: auto_approve = true
#
# EXAMPLE 2: Rejected (critical resource)
# Input:
#   resource_type: "aws_iam_role"
#   risk_score: 0.25
#   active_incident: false
#   diff: {"tags": {...}}
# Result: auto_approve = false (routes to Tier 2 for human review)
#
# EXAMPLE 3: Rejected (active incident)
# Input:
#   resource_type: "aws_s3_bucket"
#   risk_score: 0.25
#   active_incident: true  # PagerDuty incident active
#   diff: {"tags": {...}}
# Result: auto_approve = false (blocks all remediation during incidents)
#
# EXAMPLE 4: Rejected (not tag-only)
# Input:
#   resource_type: "aws_s3_bucket"
#   risk_score: 0.25
#   active_incident: false
#   diff: {"tags": {...}, "versioning": {...}}  # Multiple keys changed
# Result: auto_approve = false (routes to Tier 2 for human review)
#
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# INTEGRATION WITH OTHER TIERS
# ----------------------------------------------------------------------------
# If auto_approve = false, the decision cascades to:
#   - Tier 2 (tier2.rego): Requires human review but allows merge with approval
#   - Tier 3 (tier3.rego): Hard blocks that prevent ANY merge
#
# This policy ONLY grants permission. Denials are handled by tier2/tier3.
# ----------------------------------------------------------------------------
