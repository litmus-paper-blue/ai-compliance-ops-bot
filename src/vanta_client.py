"""
VantaOps — Vanta API Client (shared module)

Used by both the poller and the Slack bot for Vanta API access.
"""

import time
import os
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

    def get_person_security_tasks(self) -> list:
        """Fetch personnel/security tasks if account scopes expose them."""
        configured_endpoint = os.environ.get("VANTAOPS_PERSON_SECURITY_ENDPOINT", "").strip()
        candidates = [configured_endpoint] if configured_endpoint else [
            "/v1/people",
            "/v1/personnel",
            "/v1/security-tasks",
        ]

        for endpoint in [c for c in candidates if c]:
            try:
                rows = self._get_paginated(endpoint, params={"pageSize": 100})
            except requests.exceptions.HTTPError as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                # Scoped tokens commonly cannot access personnel endpoints.
                if status in (403, 404):
                    log.info(f"Skipping unavailable personnel endpoint {endpoint} (status={status}).")
                    continue
                raise

            normalized = self._normalize_person_security_rows(rows)
            if normalized:
                log.info(f"Fetched {len(normalized)} personnel/security task rows from {endpoint}.")
                return normalized

        log.info("No accessible personnel/security endpoint returned task rows.")
        return []

    def _normalize_person_security_rows(self, rows: list) -> list:
        """Normalize varying personnel payload shapes into task rows."""
        results = []
        for row in rows:
            if not isinstance(row, dict):
                continue

            # Shape A: endpoint directly returns task-like rows.
            if any(k in row for k in ("taskName", "taskType", "completedAt", "assignedAt")):
                owner_name = (
                    row.get("ownerName")
                    or row.get("personName")
                    or row.get("userName")
                    or row.get("owner")
                    or ""
                )
                owner_email = row.get("ownerEmail") or row.get("personEmail") or row.get("email") or ""
                task_title = row.get("taskName") or row.get("title") or row.get("name") or "Unnamed security task"
                task_id = row.get("id") or row.get("taskId") or f"{owner_email}:{task_title}"
                status = "completed" if row.get("completedAt") else (row.get("status") or "open")
                results.append({
                    "person_task_id": str(task_id),
                    "owner_name": str(owner_name),
                    "owner_email": str(owner_email),
                    "task_title": str(task_title),
                    "task_category": str(row.get("taskType") or row.get("category") or "security"),
                    "status": str(status).lower(),
                    "due_date": str(row.get("dueDate") or row.get("dueAt") or ""),
                    "completed_at": str(row.get("completedAt") or ""),
                    "raw_json": row,
                })
                continue

            # Shape B: person row with nested security tasks.
            person_name = row.get("name") or row.get("displayName") or ""
            person_email = row.get("email") or row.get("workEmail") or ""
            nested_tasks = (
                row.get("securityTasks")
                or row.get("tasks")
                or row.get("overdueSecurityTasks")
                or []
            )
            if not isinstance(nested_tasks, list):
                continue

            for task in nested_tasks:
                if not isinstance(task, dict):
                    continue
                task_title = task.get("name") or task.get("title") or task.get("taskName") or "Unnamed security task"
                task_id = task.get("id") or f"{person_email}:{task_title}"
                status = "completed" if task.get("completedAt") else (task.get("status") or "open")
                results.append({
                    "person_task_id": str(task_id),
                    "owner_name": str(person_name),
                    "owner_email": str(person_email),
                    "task_title": str(task_title),
                    "task_category": str(task.get("type") or task.get("category") or "security"),
                    "status": str(status).lower(),
                    "due_date": str(task.get("dueDate") or ""),
                    "completed_at": str(task.get("completedAt") or ""),
                    "raw_json": task,
                })

        return results
