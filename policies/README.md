# OPA Policies for IaC Drift Remediation

## Overview

This directory contains the 3-tier Open Policy Agent (OPA) policy system for governing AI-driven infrastructure drift remediation. These policies determine whether a remediation PR should auto-merge, require human review, or be hard-blocked.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Drift Detection → Correlation → Detective Agent        │
│  → Surgeon Agent → Checker Agent → OPA Evaluation       │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │   OPA Policy Engine     │
              │   (3-Tier Evaluation)   │
              └─────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  ┌──────────┐        ┌──────────┐       ┌──────────┐
  │ TIER 1   │        │ TIER 2   │       │ TIER 3   │
  │ Auto-    │        │ Requires │       │ Human-   │
  │ Merge    │        │ Review   │       │ Only     │
  │ (~40%)   │        │ (~50%)   │       │ (~10%)   │
  └──────────┘        └──────────┘       └──────────┘
       │                    │                   │
       ▼                    ▼                   ▼
  Auto-merge         PR + Labels         PR + Escalation
  in 8 min           Human approval      Manual apply
```

## The Three Tiers

### Tier 1: Auto-Merge (tier1.rego)

**Volume**: ~40% of drift events
**Purpose**: Automatically approve and merge low-risk changes
**Average Time**: 8 minutes from detection to merge

**Conditions (ALL must be true)**:
- `risk_score < 0.5` (low to medium risk)
- Not a critical resource (not databases, IAM, KMS, VPCs)
- No active incident (`active_incident == false`)
- Change is tag-only (safest possible modification)

**What Happens**:
1. Surgeon generates patch
2. Checker validates (3-stage pipeline)
3. OPA: `auto_approve = true`
4. PR created with label `auto-merge/approved`
5. CI runs terraform validate + plan
6. PR auto-merges (no human intervention)
7. Change appears in daily audit digest

**Examples**:
- Tag updates on S3 buckets
- CloudWatch log group tag drift
- Non-critical resource tag normalization

**Safety**: All Tier 2/3 blocks still apply. Never touches critical resources. Never runs during incidents.

---

### Tier 2: Requires Review (tier2.rego)

**Volume**: ~50% of drift events
**Purpose**: Medium-risk changes requiring human approval via PR labels
**Average Time**: 2-4 hours (human availability dependent)

**Conditions**:
- Doesn't qualify for Tier 1 (risk >= 0.5 OR critical resource)
- Doesn't trigger Tier 3 hard blocks
- Medium risk or production changes

**What Happens**:
1. Surgeon generates patch
2. Checker validates
3. OPA: Tier 1 fails, Tier 2 requires review
4. PR created with label `requires-review`
5. CODEOWNERS auto-assigns team based on file path
6. Human reviews, adds approval label:
   - `drift/approved` (generic approval)
   - `secops/approved` (security team approval)
   - `netops/approved` (network team approval)
7. CI re-runs OPA check (now passes)
8. PR merges

**Examples**:
- Security group rule changes
- IAM policy modifications
- Production resource configuration drift
- Medium-risk infrastructure changes (0.5-0.8)

**Hard Blocks (Even with Approval)**:
- Active incidents (unless `incident/override` label)
- Destructive changes (resource deletion)
- Critical resources without proper labels
- Security domain without `secops/approved`

**Rejection Rate**: ~5% (humans close PR, provide feedback for learning)

---

### Tier 3: Human-Only Escalation (tier3.rego)

**Volume**: ~10% of drift events
**Purpose**: Hard block the most dangerous changes
**Average Time**: 4-8 hours (requires manual investigation and apply)

**Triggers (ANY triggers Tier 3)**:
- High risk score (`>= 0.8`)
- Active incident (`active_incident == true`)
- Destructive changes (`has_destructive_changes == true`)
- Network infrastructure (VPC, subnets, routing)
- Critical resources without multi-team approval

**What Happens**:
1. Surgeon generates patch
2. Checker validates
3. OPA: Multiple `deny[]` rules trigger
4. PR created with label `escalated/human-only`
5. PR description includes escalation reason
6. NO auto-merge possible (blocked at CI level)
7. Human reviews Detective RCA report
8. Human decides:
   - **Option A**: Add all required labels, manually run `terraform apply`
   - **Option B**: Close PR (patch incorrect or timing inappropriate)

**Examples**:
- Database modifications (aws_db_instance)
- VPC routing changes (aws_route_table)
- IAM role/policy changes in production
- KMS key modifications
- Any change during active P1 incident

**Required Labels for Merge**:
- `drift/approved` (primary team)
- `secops/approved` OR `compliance/approved` OR `platform-leads/approved` (secondary)
- `risk/acknowledged` (if risk >= 0.8)
- `change-control/approved` (for network resources)
- `incident/override` (if active_incident == true)

**Manual Apply Rate**: 60% (humans approve and manually apply)
**Closure Rate**: 40% (humans determine patch is wrong or timing bad)

---

## Policy Files

```
policies/
├── tier1.rego        # Auto-merge logic (170 lines)
├── tier2.rego        # Review + hard blocks (229 lines)
├── tier3.rego        # Escalation + multi-approval (283 lines)
└── README.md         # This file
```

## Input Schema

All policies expect this input structure from the Checker Agent:

```json
{
  "resource_type": "aws_security_group",
  "risk_score": 0.65,
  "active_incident": false,
  "has_destructive_changes": false,
  "domain": "security",
  "environment": "prod",
  "diff": {
    "ingress": {
      "before": [{"cidr": "10.0.0.0/8", "port": 22}],
      "after": [{"cidr": "0.0.0.0/0", "port": 22}]
    }
  },
  "pr_labels": {
    "drift/approved": false,
    "secops/approved": false,
    "netops/approved": false,
    "compliance/approved": false,
    "platform-leads/approved": false,
    "risk/acknowledged": false,
    "change-control/approved": false,
    "incident/override": false
  }
}
```

## Evaluation Order

1. **Tier 1**: Check if `auto_approve` conditions met
   - If `true`: Allow auto-merge, skip Tier 2/3
   - If `false`: Continue to Tier 2

2. **Tier 2**: Check if any `deny[]` rules trigger
   - If `deny[]` exists: Block merge, show message
   - If no `deny[]`: Allow merge with human approval

3. **Tier 3**: Check if high-risk conditions met
   - If triggers: Require manual investigation + apply
   - If not: Allow standard PR flow

## Integration with CI/CD

GitHub Actions workflow evaluates OPA on every PR event:

```yaml
- name: Evaluate OPA Policy
  run: |
    opa eval \
      --data policies/ \
      --input pr_data.json \
      --format pretty \
      "data.drift.remediation"

    # If deny[] exists: block merge, comment on PR
    # If auto_approve: allow merge, add label
    # Else: require review, assign via CODEOWNERS
```

## Testing Policies

```bash
# Test Tier 1 auto-approve
opa eval --data tier1.rego --input test_tier1_pass.json \
  "data.drift.remediation.tier1.auto_approve"

# Test Tier 2 deny rules
opa eval --data tier2.rego --input test_tier2_block.json \
  "data.drift.remediation.tier2.deny"

# Test Tier 3 escalation
opa eval --data tier3.rego --input test_tier3_escalate.json \
  "data.drift.remediation.tier3.deny"
```

## Production Statistics

- **Tier 1 auto-merge**: 40% of volume, 8 min avg time, <2% false positive
- **Tier 2 review**: 50% of volume, 2-4 hr avg time, 5% rejection rate
- **Tier 3 escalation**: 10% of volume, 4-8 hr avg time, 40% closure rate

**Overall**:
- Total drift events: ~50/day
- Auto-merged: 20/day (40%)
- Human-reviewed: 25/day (50%)
- Escalated: 5/day (10%)
- Human time saved: ~15 hours/week

## Real Production Failures

### The 22-Minute P1 Extension (Why active_incident Exists)

**Timeline**:
- 14:02 - Service degraded (P1)
- 14:11 - SRE made emergency Console hotfix
- 14:14 - Service recovered
- 14:19 - Drift detection reverted hotfix (`active_incident` not implemented yet)
- 14:23 - Service degraded AGAIN
- 14:36 - Incident resolved (22 additional minutes of P1)

**Lesson**: Operational context matters. If a human is fighting a fire, do NOT interfere.

**Fix**: `active_incident` guard in all three tiers (Tier 2 line 51, Tier 3 line 30)

### The VPC Routing Outage (Why Network Resources Always Escalate)

**Impact**: One VPC routing table change took down 47 services for 90 minutes

**Cause**: Automated remediation modified production VPC route without network team review

**Lesson**: Network changes have massive blast radius. Always require network team + change control.

**Fix**: Tier 3 network_resource_types block (Tier 3 line 137)

## Key Principles

1. **Fail Safe**: Default to `false` (deny), explicitly allow
2. **Defense in Depth**: Multiple validation layers (Checker → OPA → Human)
3. **Operational Context**: `active_incident` prevents hotfix reversal
4. **Explainability**: Every `deny[]` includes actionable message
5. **Auditability**: All decisions logged with reasoning
6. **Learning**: Rejections feed back to improve Surgeon Agent

## Common Questions

**Q: Why not use fine-tuning instead of rules?**
A: Rules are explainable, testable, and auditable. LLMs can generate the patch, but governance requires deterministic logic.

**Q: What if OPA is too strict?**
A: Tier 3 allows label-based overrides (`incident/override`, `risk/acknowledged`). But destructive changes have NO override for safety.

**Q: How do you prevent alert fatigue?**
A: Tier 1 handles 40% silently. Tier 2 routes to correct team via CODEOWNERS. Tier 3 only triggers for genuinely dangerous changes (10%).

**Q: Can someone bypass OPA?**
A: No. GitHub branch protection enforces OPA check as required status. Merge is blocked if OPA fails. Only repo admins can override (audit logged).

## Further Reading

- **Slide 19**: OPA Guardrails (presentation)
- **Slide 20**: Hotfix Reversal Story (why active_incident exists)
- **Slide 23**: Cross-Team Workflow (CODEOWNERS integration)
- **Code**: `code/agents/checker_agent.py` (OPA integration)
