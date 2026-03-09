"""
VantaOps — Vanta API Client (shared module)

Used by both the poller and the Slack bot for Vanta API access.
"""

import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

VANTA_API_BASE = "https://api.vanta.com"
VANTA_AUTH_URL = f"{VANTA_API_BASE}/oauth/token"

log = logging.getLogger("vantaops-vanta")


class VantaClient:
    """Minimal Vanta REST API client using OAuth2 client credentials."""

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: float = 0

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def _authenticate(self) -> str:
        """Obtain or refresh an OAuth2 access token."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        log.info("Authenticating with Vanta API...")
        resp = requests.post(
            VANTA_AUTH_URL,
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "vanta-api.all:read",
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600) - 300
        log.info("Authenticated successfully.")
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._authenticate()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get_paginated(self, endpoint: str, params: dict = None) -> list:
        """Fetch all pages from a paginated Vanta endpoint."""
        results = []
        params = params or {}
        params.setdefault("pageSize", 100)
        cursor = None

        while True:
            if cursor:
                params["pageCursor"] = cursor
            resp = requests.get(
                f"{VANTA_API_BASE}{endpoint}",
                headers=self._headers(),
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            body = resp.json()

            data = body.get("results", {}).get("data", [])
            results.extend(data)

            page_info = body.get("results", {}).get("pageInfo", {})
            if page_info.get("hasNextPage") and page_info.get("endCursor"):
                cursor = page_info["endCursor"]
            else:
                break

        return results

    def get_failing_tests(self) -> list:
        """Fetch tests that are currently failing."""
        log.info("Fetching failing tests from Vanta...")
        tests = self._get_paginated(
            "/v1/tests",
            params={"filter[status]": "FAILING"},
        )
        log.info(f"Found {len(tests)} failing tests.")
        return tests

    def get_vulnerabilities(self, sla_days: int = 5) -> list:
        """Fetch vulnerabilities with SLA approaching within N days."""
        log.info(f"Fetching vulnerabilities with SLA within {sla_days} days...")
        cutoff = (datetime.now(timezone.utc) + timedelta(days=sla_days)).isoformat()
        vulns = self._get_paginated(
            "/v1/vulnerabilities",
            params={"filter[slaDeadlineBefore]": cutoff},
        )
        log.info(f"Found {len(vulns)} vulnerabilities approaching SLA.")
        return vulns

    def get_resources(self, resource_type: str = None) -> list:
        """Fetch monitored resources, optionally filtered by type."""
        log.info(f"Fetching resources (type={resource_type})...")
        params = {}
        if resource_type:
            params["filter[resourceType]"] = resource_type
        return self._get_paginated("/v1/resources", params=params)
