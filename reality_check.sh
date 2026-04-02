#!/bin/bash
# ================================================================
# Reality Check: 24 Hours After Perfect Deployment (Drift Happens)
# ================================================================
# This script demonstrates why drift is INEVITABLE, not preventable.
# Three root causes shown: Manual hotfixes, OOB automation, incidents
# ================================================================

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ================================================================
# [STARTING STATE] 24 Hours After Perfect Deployment
# ================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[STARTING STATE]${NC} 24 Hours After Perfect Deployment"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Infrastructure deployed via modern_pipeline.sh"
echo "All resources match Terraform state perfectly"
echo ""

cat << 'EOF'
$ terraform plan
No changes. Your infrastructure matches the configuration.
EOF

echo ""
echo -e "${GREEN}✓${NC} Code and cloud are in perfect sync"
echo ""
sleep 2

# ================================================================
# [ROOT CAUSE 1] MANUAL HOTFIX - "I'll revert it later"
# ================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[ROOT CAUSE 1]${NC} Manual Hotfix"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "SCENARIO:"
echo "  Production debugging session. Engineer needs temporary access."
echo "  Opens AWS Console instead of submitting PR."
echo ""
sleep 1

cat << 'EOF'
$ aws ec2 authorize-security-group-ingress \
    --group-id sg-0abc123 \
    --protocol tcp \
    --port 22 \
    --cidr 203.0.113.42/32

{
  "Return": true,
  "SecurityGroupRules": [{
    "CidrIpv4": "203.0.113.42/32",
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22
  }]
}
EOF

echo ""
echo -e "${YELLOW}→${NC} Engineer's thought: \"I'll revert this later...\""
echo ""
sleep 1

echo "3 hours later..."
sleep 1
echo "  (They never reverted it)"
echo ""
echo -e "${RED}✗${NC} Terraform state now diverged: +1 manual change"
echo -e "${RED}✗${NC} No PR. No review. No audit trail."
echo ""
sleep 2

# ================================================================
# [ROOT CAUSE 2] OUT-OF-BAND AUTOMATION
# ================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[ROOT CAUSE 2]${NC} Out-of-Band Automation"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "SCENARIO:"
echo "  AWS Lambda auto-rotates RDS credentials (security best practice)."
echo "  Updates security group to allow new monitoring endpoint."
echo "  Runs outside of IaC pipeline."
echo ""
sleep 1

cat << 'EOF'
$ aws lambda invoke --function-name credential-rotator response.json

{
  "StatusCode": 200,
  "ExecutedVersion": "$LATEST"
}

$ cat response.json | jq .
{
  "message": "Credentials rotated successfully",
  "modified_resources": [
    "aws_security_group.db_sg",
    "aws_secretsmanager_secret.db_password"
  ],
  "changes": [
    "Added ingress rule: 10.50.0.0/16 port 3306 (monitoring)"
  ]
}
EOF

echo ""
echo -e "${YELLOW}→${NC} Lambda function modified infrastructure directly"
echo -e "${YELLOW}→${NC} No Terraform involvement. Separate automation system."
echo ""
echo -e "${RED}✗${NC} Terraform state now diverged: +2 changes (manual + Lambda)"
echo ""
sleep 2

# ================================================================
# [ROOT CAUSE 3] INCIDENT RESPONSE
# ================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[ROOT CAUSE 3]${NC} Incident Response"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "SCENARIO:"
echo "  2:17am - PagerDuty alert: API service degraded (P1)"
echo "  2:23am - SRE investigates: RDS connection timeout"
echo "  2:31am - Emergency fix via Console: security group rule added"
echo ""
sleep 1

cat << 'EOF'
[02:31] $ aws ec2 authorize-security-group-ingress \
            --group-id sg-db-prod \
            --protocol tcp \
            --port 3306 \
            --source-group sg-api-prod \
            --description "Emergency P1 fix - API to DB timeout"

[02:33] Service recovered. P1 resolved.

[02:34] SRE thought: "I'll create PR tomorrow morning..."

[09:00] Morning standup.
        Incident postmortem scheduled for next week.
        PR forgotten.

[2 WEEKS LATER]
        PR still not created.
        The hotfix is now "production reality."
EOF

echo ""
echo -e "${YELLOW}→${NC} Emergency situation = Console changes"
echo -e "${YELLOW}→${NC} Good intentions, but PR deferred forever"
echo ""
echo -e "${RED}✗${NC} Terraform state now diverged: +3 changes"
echo ""
sleep 2

# ================================================================
# [THE INEVITABLE TRUTH] State Comparison
# ================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[THE INEVITABLE TRUTH]${NC} 24 Hours Later"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cat << 'EOF'
$ terraform plan

Terraform will perform the following actions:

  # aws_security_group.api_sg will be updated in-place
  ~ resource "aws_security_group" "api_sg" {
      ~ ingress {
          ~ cidr_blocks = [
              - "203.0.113.42/32"  # Manual hotfix
            ]
          ~ description = "" -> "Internal SSH only"
        }
    }

  # aws_security_group.db_sg will be updated in-place
  ~ resource "aws_security_group" "db_sg" {
      ~ ingress {
          + source_security_group_id = "sg-0abc123"  # Lambda rotation
          + source_security_group_id = "sg-api-prod" # Incident hotfix
        }
    }

Plan: 0 to add, 2 to change, 0 to destroy.

EOF

echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}DECLARED STATE ≠ ACTUAL STATE${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Changes: 3 undocumented modifications"
echo "Source:  1 manual, 1 automated, 1 incident"
echo "Age:     < 24 hours"
echo ""
sleep 1

# ================================================================
# [KEY INSIGHT]
# ================================================================
cat << 'EOF'

╔════════════════════════════════════════════════════════════════╗
║                    KEY INSIGHT                                 ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  Drift is NOT a failure of infrastructure-as-code.            ║
║                                                                ║
║  Drift is a PROPERTY of humans operating dynamic systems      ║
║  under pressure, with legitimate constraints:                 ║
║                                                                ║
║    • Incidents require immediate action (no time for PRs)     ║
║    • Debugging requires temporary access (Console is faster)  ║
║    • Automation lives outside GitOps (Lambda, SaaS, ASGs)     ║
║                                                                ║
║  You cannot prevent drift.                                    ║
║  You can only detect it, understand it, and remediate it.     ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

EOF

echo ""
echo -e "${YELLOW}Next question:${NC}"
echo "  How do you detect drift across multiple domains?"
echo "  How do you understand which changes are legitimate?"
echo "  How do you automatically fix the dangerous ones?"
echo ""
echo -e "${CYAN}That's what the rest of this talk is about.${NC}"
echo ""

# ================================================================
# COMPARISON WITH DAY 1
# ================================================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}DAY 1 vs DAY 2+${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "DAY 1 (modern_pipeline.sh):"
echo "  - AI generates code"
echo "  - Security scan validates"
echo "  - PR review approves"
echo "  - terraform apply deploys"
echo -e "  ${GREEN}Status: SOLVED ✓${NC}"
echo ""
echo "DAY 2+ (reality_check.sh):"
echo "  - Manual changes bypass Git"
echo "  - Automation bypasses IaC"
echo "  - Incidents bypass process"
echo "  - State diverges silently"
echo -e "  ${RED}Status: UNSOLVED ✗${NC}"
echo ""
echo "The generation problem is solved."
echo "The operations problem has not even started."
echo ""

# ================================================================
# DEMO OUTPUT
# ================================================================
if [ "$1" == "--show-diff" ]; then
    echo ""
    echo -e "${CYAN}Full state comparison:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    cat << 'EOF'
DECLARED (Terraform)              ACTUAL (AWS Cloud)
────────────────────              ──────────────────
sg-0abc123:                       sg-0abc123:
  ingress:                          ingress:
    cidr: 10.0.0.0/8                  cidr: 10.0.0.0/8
    desc: "Internal SSH"              cidr: 203.0.113.42/32  [DRIFT]
                                      desc: ""               [DRIFT]

sg-db-prod:                       sg-db-prod:
  ingress:                          ingress:
    source: sg-app-prod               source: sg-app-prod
                                      source: 10.50.0.0/16   [DRIFT]
                                      source: sg-api-prod    [DRIFT]

Changes: 3 drift events in < 24 hours
All changes: legitimate reasons, zero malice
Result: Code no longer represents reality
EOF
    echo "─────────────────────────────────────────────────────────────"
fi

echo ""
echo "This is Slide 4: Drift Happens - The Inevitable Truth"
echo "Next: Slide 5 shows how one drift creates multi-domain chaos"
echo ""
