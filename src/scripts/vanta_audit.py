"""
VantaOps — Audit all Vanta tests and vulnerabilities to determine IAM scope.
Dumps categorized findings to stdout for review.
"""

import os
import json
import sys
from collections import Counter

# Reuse the VantaClient from the poller
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scripts.vanta_poller import VantaClient

VANTA_CLIENT_ID = os.environ.get("VANTA_CLIENT_ID", "")
VANTA_CLIENT_SECRET = os.environ.get("VANTA_CLIENT_SECRET", "")


def main():
    if not VANTA_CLIENT_ID or not VANTA_CLIENT_SECRET:
        print("ERROR: VANTA_CLIENT_ID and VANTA_CLIENT_SECRET required")
        sys.exit(1)

    client = VantaClient(VANTA_CLIENT_ID, VANTA_CLIENT_SECRET)

    # Fetch all failing tests
    print("=" * 80)
    print("FAILING TESTS")
    print("=" * 80)
    tests = client.get_failing_tests()
    print(f"Total: {len(tests)}\n")

    # Categorize tests by keywords to identify AWS services
    aws_services = Counter()
    test_categories = {}

    for t in tests:
        name = t.get("name", "")
        desc = t.get("description", "")
        category = t.get("category", "")
        text = f"{name} {desc}".lower()

        # Detect AWS services mentioned
        services = set()
        service_keywords = {
            "EC2": ["ec2", "instance", "ami"],
            "S3": ["s3", "bucket"],
            "RDS": ["rds", "database", "aurora"],
            "EKS": ["eks", "kubernetes", "cluster"],
            "ECS": ["ecs", "fargate", "container"],
            "Lambda": ["lambda", "function"],
            "CloudWatch": ["cloudwatch", "alarm", "metric", "monitoring"],
            "CloudTrail": ["cloudtrail", "trail", "audit log"],
            "AWS Config": ["aws config", "config rule", "configuration recorder"],
            "IAM": ["iam", "role", "policy", "mfa", "access key", "credential"],
            "VPC": ["vpc", "subnet", "security group", "network acl", "flow log"],
            "DynamoDB": ["dynamodb", "dynamo"],
            "ELB/ALB": ["load balancer", "alb", "elb", "nlb", "target group"],
            "SNS": ["sns", "notification", "topic"],
            "SQS": ["sqs", "queue"],
            "KMS": ["kms", "encryption key", "cmk"],
            "WAF": ["waf", "firewall", "bot management"],
            "GuardDuty": ["guardduty", "intrusion detection", "threat"],
            "SSM": ["ssm", "systems manager", "patch", "parameter store"],
            "ACM": ["certificate", "ssl", "tls", "acm"],
            "Route53": ["route53", "dns", "domain"],
            "CloudFront": ["cloudfront", "cdn", "distribution"],
            "Secrets Manager": ["secrets manager", "secret"],
            "ECR": ["ecr", "container registry", "image"],
            "STS": ["sts", "assume role"],
            "Inspector": ["inspector", "vulnerability scan"],
            "Cloudflare": ["cloudflare"],
            "Non-AWS (Policy)": ["policy", "approved", "company has"],
            "Non-AWS (Personnel)": ["personnel", "employee", "workstation", "screenlock", "mdr"],
        }

        for svc, keywords in service_keywords.items():
            if any(kw in text for kw in keywords):
                services.add(svc)

        if not services:
            services.add("Uncategorized")

        for svc in services:
            aws_services[svc] += 1

        cat_key = category or "uncategorized"
        if cat_key not in test_categories:
            test_categories[cat_key] = []
        test_categories[cat_key].append({
            "name": name,
            "services": sorted(services),
        })

    print("--- Tests by AWS Service ---")
    for svc, count in aws_services.most_common():
        print(f"  {svc}: {count}")

    print(f"\n--- Tests by Category ---")
    for cat, items in sorted(test_categories.items()):
        print(f"\n  [{cat}] ({len(items)} tests):")
        for item in items:
            print(f"    - {item['name'][:90]} → {', '.join(item['services'])}")

    # Fetch vulnerabilities
    print("\n" + "=" * 80)
    print("VULNERABILITIES (approaching SLA)")
    print("=" * 80)
    vulns = client.get_vulnerabilities(sla_days=30)
    print(f"Total: {len(vulns)}\n")

    vuln_types = Counter()
    vuln_sources = Counter()
    vuln_severities = Counter()

    for v in vulns:
        vtype = v.get("vulnerabilityType", "unknown")
        source = v.get("scanSource", v.get("integrationId", "unknown"))
        severity = v.get("severity", "unknown")
        vuln_types[vtype] += 1
        vuln_sources[source] += 1
        vuln_severities[severity] += 1

    print("--- By Type ---")
    for vtype, count in vuln_types.most_common():
        print(f"  {vtype}: {count}")

    print("\n--- By Source/Integration ---")
    for source, count in vuln_sources.most_common():
        print(f"  {source}: {count}")

    print("\n--- By Severity ---")
    for sev, count in vuln_severities.most_common():
        print(f"  {sev}: {count}")

    # Sample 5 vulns for context
    print("\n--- Sample Vulnerabilities ---")
    for v in vulns[:5]:
        print(f"  - {v.get('name', '?')}: {v.get('description', '')[:120]}")
        print(f"    type={v.get('vulnerabilityType')}, severity={v.get('severity')}, "
              f"source={v.get('scanSource', v.get('integrationId'))}, "
              f"fixable={v.get('isFixable')}")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY — AWS SERVICES THAT NEED IAM PERMISSIONS")
    print("=" * 80)
    aws_only = {k: v for k, v in aws_services.items()
                if not k.startswith("Non-AWS") and k != "Uncategorized" and k != "Cloudflare"}
    for svc, count in sorted(aws_only.items(), key=lambda x: -x[1]):
        print(f"  {svc}: {count} failing tests")

    non_aws = {k: v for k, v in aws_services.items()
               if k.startswith("Non-AWS") or k == "Cloudflare"}
    if non_aws:
        print("\n  Non-AWS (no IAM needed):")
        for svc, count in sorted(non_aws.items(), key=lambda x: -x[1]):
            print(f"    {svc}: {count}")


if __name__ == "__main__":
    main()
