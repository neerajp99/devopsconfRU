"""
GitHub integration for creating PRs with remediation patches
Surgeon agent's output goes here
"""
import os
from typing import Optional
from github import Github, GithubException
from core.schemas import RemediationPlan, CheckerReport, PRMetadata


class GitHubIntegration:
    """Creates and manages remediation PRs"""

    def __init__(self, repo_name: str, token: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.client = Github(self.token) if self.token else None
        self.repo_name = repo_name
        self.repo = None

        if self.client:
            try:
                self.repo = self.client.get_repo(repo_name)
            except GithubException:
                pass

    def create_remediation_pr(
        self,
        plan: RemediationPlan,
        checker_report: CheckerReport,
        base_branch: str = "main"
    ) -> PRMetadata:
        """
        Create GitHub PR with Terraform patch

        In demo mode (no token), returns mock PR
        """
        # Generate unique branch name
        import time
        timestamp = int(time.time() * 1000) % 100000  # Last 5 digits of milliseconds
        branch_name = f"drift-fix/{plan.drift_event_id[:8]}-{timestamp}"

        # PR title and body
        severity = plan.risk_assessment.get('severity', 'MEDIUM').upper()
        resource_name = plan.affected_files[0].split('/')[-1].replace('.tf', '') if plan.affected_files else 'resource'
        title = f"[DRIFT:{severity}] Fix drift in {resource_name}"
        body = self._generate_pr_body(plan, checker_report)

        # Mock PR for demo (no actual GitHub API call)
        if not self.repo:
            return PRMetadata(
                pr_number=42,
                pr_url=f"https://github.com/{self.repo_name}/pull/42",
                title=title,
                body=body,
                status="open",
                auto_merge_enabled=checker_report.approved
            )

        # Real GitHub PR creation
        try:
            # Create branch
            base_ref = self.repo.get_git_ref(f"heads/{base_branch}")
            self.repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=base_ref.object.sha
            )

            # Commit patch
            file_path = plan.affected_files[0]
            try:
                contents = self.repo.get_contents(file_path, ref=branch_name)
                self.repo.update_file(
                    path=file_path,
                    message=f"Fix drift: {plan.drift_event_id}",
                    content=plan.terraform_patch,
                    sha=contents.sha,
                    branch=branch_name
                )
            except GithubException:
                # File doesn't exist, create it
                self.repo.create_file(
                    path=file_path,
                    message=f"Fix drift: {plan.drift_event_id}",
                    content=plan.terraform_patch,
                    branch=branch_name
                )

            # Create PR
            pr = self.repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=base_branch
            )

            # Add labels
            pr.add_to_labels("drift-remediation", "automated")
            if checker_report.approved:
                pr.add_to_labels("auto-merge-candidate")

            return PRMetadata(
                pr_number=pr.number,
                pr_url=pr.html_url,
                title=title,
                body=body,
                status="open",
                auto_merge_enabled=checker_report.approved
            )

        except Exception as e:
            raise Exception(f"Failed to create PR: {str(e)}")

    def _generate_pr_body(self, plan: RemediationPlan, checker_report: CheckerReport) -> str:
        """Generate PR description matching Slide 19 format"""
        severity = plan.risk_assessment.get('severity', 'MEDIUM').upper()
        risk_score = plan.risk_assessment.get('estimated_risk', 0.5)
        environment = plan.risk_assessment.get('environment', 'unknown')

        # Determine tier based on risk score
        if risk_score < 0.3:
            tier = "Tier 1 (auto-approve eligible)"
        elif risk_score < 0.7:
            tier = "Tier 2 (requires review)"
        else:
            tier = "Tier 3 (requires security approval)"

        # Validation status
        validate_status = "[OK]" if checker_report.terraform_validate_passed else "[FAIL]"
        plan_status = "[OK]" if checker_report.terraform_plan_passed else "[FAIL]"
        checker_status = "[OK]" if checker_report.approved else "[FAIL]"
        opa_status = "[OK]" if checker_report.opa_policy_passed else "[WAIT]"

        body = f"""[RISK ASSESSMENT]
  Severity:   {severity}
  Risk Score: {risk_score:.2f} / 1.0
  Tier:       {tier}
  Environment: {environment}

[ROOT CAUSE ANALYSIS]
  Drift Event: {plan.drift_event_id}
  Resource:    {plan.affected_files[0] if plan.affected_files else 'unknown'}
  Detection:   Automated drift scanner
  Reasoning:   {checker_report.reasoning}

[PROPOSED FIX]
  Files Changed: {len(plan.affected_files)} file(s)
  Change Type:   {plan.change_type}

{chr(10).join(f'  - {f}' for f in plan.affected_files)}

[VALIDATION RESULTS]
  {validate_status}   terraform validate   {'PASSED' if checker_report.terraform_validate_passed else 'FAILED'}
  {plan_status}   terraform plan       {'PASSED' if checker_report.terraform_plan_passed else 'FAILED'}
  {checker_status}   Checker Agent        {checker_report.recommendation.upper()}
  {opa_status}   OPA policy gate      {'PASSED' if checker_report.opa_policy_passed else 'BLOCKED'}

[CHECKER AGENT REPORT]
  Recommendation: {checker_report.recommendation.upper()}
  Destructive:    {'Yes - BLOCKED' if checker_report.destructive_changes_detected else 'No'}
  Issues:         {len(checker_report.issues_found) if checker_report.issues_found else 0}
{chr(10).join(f'  - {issue}' for issue in checker_report.issues_found) if checker_report.issues_found else '  No issues detected'}

[METADATA]
  Generated By:   drift-agent v1.2.0
  Auto-merge:     {'ENABLED' if checker_report.approved and risk_score < 0.3 else 'DISABLED'}
"""
        return body
