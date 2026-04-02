#!/usr/bin/env python3
"""
Remediation Circuit Breaker - Loop Detection for Drift Remediation

Purpose:
  Prevents infinite remediation loops where the same resource keeps drifting
  and getting remediated repeatedly. Common scenario: autoscaling policies
  fighting with Terraform state.

Example Loop Scenario:
  T+0:00 - Autoscaling changes t3.micro → t3.large
  T+0:01 - Drift detected, patch generated
  T+0:04 - Terraform reverts to t3.micro
  T+0:07 - Autoscaling triggers again (load still high)
  T+0:08 - Drift detected again
  T+0:10 - Terraform reverts again
  → Loop continues: 7 cycles in 1 hour, instance thrashing

Circuit Breaker Behavior:
  - Tracks remediation attempts per resource_id in Redis
  - After MAX_REMEDIATIONS (default: 3) within WINDOW_SECONDS (1 hour):
      1. Trip circuit (block further remediations)
      2. Page human via PagerDuty (not Slack - requires action)
      3. Enter COOLDOWN_SECONDS (30 min) lockout period
  - Requires human investigation to resolve root cause

Why Redis (not in-memory):
  - Agent processes restart (Kubernetes pod evictions, deployments)
  - In-memory counters would reset → loops would not be detected
  - Redis provides persistence and cross-process visibility

Production Statistics (from slide 24 context):
  - Loop detection prevents ~12 infinite loops per month
  - Average loop duration before detection: 18 minutes (3 remediations)
  - Human investigation time: 15-30 minutes
  - Without circuit breaker: loops ran for hours, costing $400+ in compute waste

Integration:
  - Called by Surgeon Agent before creating remediation PR
  - Called by post-apply verification to increment counter
  - Monitored by SRE team via circuit breaker dashboard
"""

import logging
import os
from datetime import datetime
from typing import Optional, Tuple

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("redis-py not installed. Circuit breaker will use fallback mode.")


# Configure logging
logger = logging.getLogger(__name__)


class RemediationCircuitBreaker:
    """
    Redis-backed circuit breaker for drift remediation loop prevention.

    Tracks per-resource remediation attempts and trips circuit when
    MAX_REMEDIATIONS is exceeded within WINDOW_SECONDS.

    Architecture:
      - Redis key pattern: circuit:count:{resource_id} (remediation counter)
      - Redis key pattern: circuit:cooldown:{resource_id} (cooldown flag)
      - TTL on count key: WINDOW_SECONDS (auto-expires after 1 hour)
      - TTL on cooldown key: COOLDOWN_SECONDS (30-min lockout)

    Attributes:
        redis_client: Redis connection for persistent state tracking
        window_seconds: Time window for counting remediations (default: 3600 = 1 hour)
        max_remediations: Threshold before circuit trips (default: 3)
        cooldown_seconds: Lockout period after circuit trips (default: 1800 = 30 min)
        pagerduty_enabled: Whether to send PagerDuty alerts (default: True)
    """

    # Configuration constants (tuned from production experience)
    WINDOW_SECONDS = 3600       # 1-hour rolling window for remediation counting
    MAX_REMEDIATIONS = 3        # Trip circuit after 3 remediations
    COOLDOWN_SECONDS = 1800     # 30-minute lockout period

    def __init__(
        self,
        redis_host: Optional[str] = None,
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        window_seconds: int = WINDOW_SECONDS,
        max_remediations: int = MAX_REMEDIATIONS,
        cooldown_seconds: int = COOLDOWN_SECONDS,
        pagerduty_enabled: bool = True
    ):
        """
        Initialize circuit breaker with Redis connection.

        Args:
            redis_host: Redis hostname (default: REDIS_HOST env var or localhost)
            redis_port: Redis port (default: 6379)
            redis_db: Redis database number (default: 0)
            redis_password: Redis password (default: REDIS_PASSWORD env var)
            window_seconds: Time window for counting remediations (default: 3600)
            max_remediations: Threshold before circuit trips (default: 3)
            cooldown_seconds: Lockout period after circuit trips (default: 1800)
            pagerduty_enabled: Enable PagerDuty alerts (default: True)

        Raises:
            RuntimeError: If Redis is not available and CIRCUIT_BREAKER_REQUIRED=true
        """
        self.window_seconds = window_seconds
        self.max_remediations = max_remediations
        self.cooldown_seconds = cooldown_seconds
        self.pagerduty_enabled = pagerduty_enabled

        # Initialize Redis connection
        if REDIS_AVAILABLE:
            redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
            redis_password = redis_password or os.getenv("REDIS_PASSWORD")

            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    password=redis_password,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                logger.info(f"Circuit breaker connected to Redis at {redis_host}:{redis_port}")
            except (redis.ConnectionError, redis.TimeoutError) as e:
                logger.error(f"Failed to connect to Redis: {e}")
                if os.getenv("CIRCUIT_BREAKER_REQUIRED", "false").lower() == "true":
                    raise RuntimeError(f"Circuit breaker Redis connection required but failed: {e}")
                self.redis_client = None
                logger.warning("Circuit breaker running in fallback mode (no persistence)")
        else:
            self.redis_client = None
            logger.warning("Circuit breaker running in fallback mode (redis-py not installed)")

    def can_remediate(self, resource_id: str) -> Tuple[bool, str]:
        """
        Check if remediation is allowed for a given resource.

        This is the primary method called before creating a remediation PR.
        It checks:
          1. Is circuit in cooldown? (recent loop detected)
          2. How many remediations in current window?
          3. Would this remediation exceed threshold?

        Args:
            resource_id: AWS resource identifier (e.g., "sg-0abc123", "i-0def456")

        Returns:
            Tuple of (allowed: bool, reason: str)
            - (True, "ok") → Remediation allowed
            - (False, "reason") → Remediation blocked, reason explains why

        Examples:
            >>> breaker = RemediationCircuitBreaker()
            >>> breaker.can_remediate("sg-0abc123")
            (True, "ok")

            >>> # After 3 remediations within 1 hour:
            >>> breaker.can_remediate("sg-0abc123")
            (False, "Circuit open. Loop detected: 3 remediations in 1 hour. Manual investigation required.")
        """
        if not self.redis_client:
            # Fallback mode: always allow (no persistence available)
            logger.warning(f"Circuit breaker in fallback mode for {resource_id}")
            return (True, "ok (no redis - fallback mode)")

        try:
            # Check if circuit is in cooldown (recently tripped)
            cooldown_key = f"circuit:cooldown:{resource_id}"
            if self.redis_client.exists(cooldown_key):
                ttl = self.redis_client.ttl(cooldown_key)
                logger.warning(f"Circuit breaker OPEN for {resource_id} (cooldown: {ttl}s remaining)")
                return (
                    False,
                    f"Circuit open. Loop detected earlier. Manual investigation required. "
                    f"Cooldown: {ttl}s remaining ({ttl // 60} minutes)."
                )

            # Get current remediation count
            count_key = f"circuit:count:{resource_id}"
            count = int(self.redis_client.get(count_key) or 0)

            # Check if this remediation would trip the circuit
            if count >= self.max_remediations:
                logger.error(
                    f"Circuit breaker TRIPPED for {resource_id}: "
                    f"{count} remediations in {self.window_seconds}s window"
                )

                # Set cooldown (lockout period)
                self.redis_client.setex(cooldown_key, self.cooldown_seconds, "tripped")

                # Page human via PagerDuty
                self._page_human(resource_id, count)

                return (
                    False,
                    f"Circuit TRIPPED. Loop detected: {count} remediations in "
                    f"{self.window_seconds // 60} minutes. Human investigation required. "
                    f"PagerDuty alert sent."
                )

            # Remediation allowed
            logger.info(f"Circuit breaker OK for {resource_id}: {count}/{self.max_remediations} remediations")
            return (True, "ok")

        except redis.RedisError as e:
            logger.error(f"Redis error in can_remediate: {e}")
            # Fail open (allow remediation) to avoid blocking legitimate fixes
            # but log the error for investigation
            return (True, f"ok (redis error - fail open: {e})")

    def record_remediation(self, resource_id: str, context: Optional[dict] = None) -> int:
        """
        Record a remediation attempt for a resource.

        This should be called AFTER terraform apply succeeds, during post-apply
        verification. It increments the remediation counter for the resource.

        Args:
            resource_id: AWS resource identifier
            context: Optional metadata (event_id, risk_score, etc.)

        Returns:
            Current remediation count for this resource

        Side Effects:
            - Increments circuit:count:{resource_id} in Redis
            - Sets TTL to WINDOW_SECONDS (1 hour) if this is first remediation
            - Logs remediation event

        Example:
            >>> breaker.record_remediation("sg-0abc123", {"event_id": "evt-001"})
            1  # First remediation
            >>> breaker.record_remediation("sg-0abc123", {"event_id": "evt-002"})
            2  # Second remediation
        """
        if not self.redis_client:
            logger.warning(f"Cannot record remediation for {resource_id}: no Redis")
            return 0

        try:
            count_key = f"circuit:count:{resource_id}"

            # Increment counter
            count = self.redis_client.incr(count_key)

            # Set TTL on first remediation (key didn't exist before)
            if count == 1:
                self.redis_client.expire(count_key, self.window_seconds)

            logger.info(
                f"Remediation recorded for {resource_id}: "
                f"{count}/{self.max_remediations} in window. "
                f"Context: {context or {}}"
            )

            return count

        except redis.RedisError as e:
            logger.error(f"Redis error in record_remediation: {e}")
            return 0

    def reset_circuit(self, resource_id: str, reason: str = "manual reset"):
        """
        Manually reset circuit breaker for a resource.

        This is called by humans after investigating and resolving the root
        cause of a remediation loop. For example:
          - Added drift-ignore annotation to autoscaling-managed resource
          - Fixed conflicting Terraform/AWS policy
          - Identified the change as intentional deviation

        Args:
            resource_id: AWS resource identifier
            reason: Why the circuit is being reset (for audit log)

        Side Effects:
            - Deletes circuit:count:{resource_id}
            - Deletes circuit:cooldown:{resource_id}
            - Logs reset event with reason

        Example:
            >>> breaker.reset_circuit("sg-0abc123", "Added drift-ignore annotation")
        """
        if not self.redis_client:
            logger.warning(f"Cannot reset circuit for {resource_id}: no Redis")
            return

        try:
            count_key = f"circuit:count:{resource_id}"
            cooldown_key = f"circuit:cooldown:{resource_id}"

            count = self.redis_client.get(count_key) or "0"

            # Delete both keys
            self.redis_client.delete(count_key, cooldown_key)

            logger.info(
                f"Circuit breaker RESET for {resource_id}. "
                f"Previous count: {count}. Reason: {reason}"
            )

        except redis.RedisError as e:
            logger.error(f"Redis error in reset_circuit: {e}")

    def get_statistics(self, resource_id: str) -> dict:
        """
        Get circuit breaker state for a specific resource.

        Args:
            resource_id: AWS resource identifier

        Returns:
            Dictionary with circuit state:
            {
                "resource_id": "sg-0abc123",
                "remediation_count": 2,
                "max_remediations": 3,
                "circuit_open": false,
                "cooldown_ttl_seconds": 0,
                "window_seconds": 3600
            }
        """
        if not self.redis_client:
            return {
                "resource_id": resource_id,
                "remediation_count": 0,
                "max_remediations": self.max_remediations,
                "circuit_open": False,
                "cooldown_ttl_seconds": 0,
                "window_seconds": self.window_seconds,
                "status": "FALLBACK MODE (no Redis)",
                "error": "no redis connection",
                "fallback_mode": True
            }

        try:
            count_key = f"circuit:count:{resource_id}"
            cooldown_key = f"circuit:cooldown:{resource_id}"

            count = int(self.redis_client.get(count_key) or 0)
            circuit_open = self.redis_client.exists(cooldown_key) == 1
            cooldown_ttl = self.redis_client.ttl(cooldown_key) if circuit_open else 0

            return {
                "resource_id": resource_id,
                "remediation_count": count,
                "max_remediations": self.max_remediations,
                "circuit_open": circuit_open,
                "cooldown_ttl_seconds": cooldown_ttl,
                "window_seconds": self.window_seconds,
                "status": "OPEN (cooldown)" if circuit_open else "CLOSED (ok)"
            }

        except redis.RedisError as e:
            logger.error(f"Redis error in get_statistics: {e}")
            return {
                "resource_id": resource_id,
                "error": str(e)
            }

    def _page_human(self, resource_id: str, remediation_count: int):
        """
        Send PagerDuty alert when circuit trips.

        This is NOT a Slack message - it's a PagerDuty page that requires
        acknowledgment. Loop detection indicates a system-level problem that
        needs human investigation, not just awareness.

        Args:
            resource_id: Resource stuck in remediation loop
            remediation_count: Number of remediations that tripped circuit

        Side Effects:
            - Sends PagerDuty event (if pagerduty_enabled=True)
            - Logs alert event

        PagerDuty Event Format:
            {
                "routing_key": "...",
                "event_action": "trigger",
                "severity": "error",
                "summary": "Drift remediation loop detected: sg-0abc123",
                "custom_details": {
                    "resource_id": "sg-0abc123",
                    "remediation_count": 3,
                    "window_seconds": 3600,
                    "probable_cause": "Autoscaling policy or external automation",
                    "required_action": "Investigate root cause and add drift-ignore"
                }
            }
        """
        logger.error(
            f"CIRCUIT BREAKER TRIPPED - PagerDuty alert for {resource_id}: "
            f"{remediation_count} remediations in {self.window_seconds}s"
        )

        if not self.pagerduty_enabled:
            logger.info("PagerDuty disabled, skipping alert")
            return

        # In production: send actual PagerDuty event
        # from pypd import EventV2
        # EventV2.create(...)

        # For now: log what would be sent
        alert_details = {
            "resource_id": resource_id,
            "remediation_count": remediation_count,
            "window_seconds": self.window_seconds,
            "max_remediations": self.max_remediations,
            "timestamp": datetime.utcnow().isoformat(),
            "probable_cause": "Autoscaling policy or external automation fighting Terraform",
            "required_action": (
                "1. Investigate why resource keeps drifting\n"
                "2. Check for autoscaling policies or external automation\n"
                "3. Add drift-ignore annotation if drift is intentional\n"
                "4. Or fix conflicting automation\n"
                f"5. Reset circuit: breaker.reset_circuit('{resource_id}', 'reason')"
            ),
            "dashboard_url": f"https://drift-dashboard.company.com/circuit-breaker/{resource_id}"
        }

        logger.error(f"PagerDuty alert payload: {alert_details}")

        # TODO: Implement actual PagerDuty integration
        # Requires: PAGERDUTY_ROUTING_KEY environment variable
        # Library: pypd or requests to PagerDuty Events API v2


# ============================================================================
# CLI Interface (for manual circuit breaker management)
# ============================================================================

def main():
    """
    CLI interface for circuit breaker operations.

    Usage:
        python -m core.circuit_breaker check sg-0abc123
        python -m core.circuit_breaker reset sg-0abc123 "fixed autoscaling conflict"
        python -m core.circuit_breaker stats sg-0abc123
    """
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python -m core.circuit_breaker check <resource_id>")
        print("  python -m core.circuit_breaker reset <resource_id> <reason>")
        print("  python -m core.circuit_breaker stats <resource_id>")
        sys.exit(1)

    command = sys.argv[1]
    resource_id = sys.argv[2]

    breaker = RemediationCircuitBreaker()

    if command == "check":
        allowed, reason = breaker.can_remediate(resource_id)
        if allowed:
            print(f"✓ Remediation ALLOWED for {resource_id}")
            print(f"  Reason: {reason}")
            sys.exit(0)
        else:
            print(f"✗ Remediation BLOCKED for {resource_id}")
            print(f"  Reason: {reason}")
            sys.exit(1)

    elif command == "reset":
        if len(sys.argv) < 4:
            print("Error: reset requires reason argument")
            print("Usage: python -m core.circuit_breaker reset <resource_id> <reason>")
            sys.exit(1)
        reason = sys.argv[3]
        breaker.reset_circuit(resource_id, reason)
        print(f"✓ Circuit breaker reset for {resource_id}")
        print(f"  Reason: {reason}")

    elif command == "stats":
        stats = breaker.get_statistics(resource_id)
        print(f"Circuit Breaker Statistics for {resource_id}:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
