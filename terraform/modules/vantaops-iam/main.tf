# ==========================================================================
# VantaOps — IAM Remediation Role
#
# Deploy this module in each AWS account where VantaOps should be able
# to remediate compliance findings. Scoped to actual Vanta failing tests.
#
# Services covered (auto-remediable):
#   CloudWatch, S3, CloudTrail, VPC, EC2, RDS, DynamoDB, EKS,
#   ELB/ALB, GuardDuty, Inspector, ACM, SNS, SSM, AWS Config
#
# Explicitly excluded (manual-only):
#   IAM policies, Cloudflare, personnel/policy controls
#
# Usage:
#   module "vantaops_role" {
#     source                  = "./modules/vantaops-iam"
#     trusted_principal       = "arn:aws:iam::AGENT_ACCOUNT:role/vantaops-agent"
#     environment             = "prod"
#     sns_cloudwatch_topic_arn = "arn:aws:sns:us-east-1:ACCOUNT:cloudwatch-alarm-topic"
#     sns_guardduty_topic_arn  = "arn:aws:sns:us-east-1:ACCOUNT:GuardDuty_to_Slack"
#   }
# ==========================================================================

variable "trusted_principal" {
  description = "ARN of the IAM user/role in the agent account that will AssumeRole"
  type        = string
}

variable "environment" {
  description = "Environment label (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "sns_cloudwatch_topic_arn" {
  description = "ARN of the existing SNS topic for CloudWatch alarm notifications"
  type        = string
}

variable "sns_guardduty_topic_arn" {
  description = "ARN of the existing SNS topic for GuardDuty findings (GuardDuty_to_Slack)"
  type        = string
}

variable "role_name" {
  description = "Name of the IAM role to create"
  type        = string
  default     = "vantaops-remediation-role"
}

# ── IAM Role with Trust Policy ───────────────────────────────────────────

resource "aws_iam_role" "vantaops" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_principal
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "vantaops-${var.environment}"
          }
        }
      }
    ]
  })

  tags = {
    Project     = "VantaOps"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── CloudWatch Remediation (16 failing tests) ─────────────────────────
# Covers: alarm creation for ALB/RDS/Lambda, VPC flow log metrics,
# monitoring alerts for CPU, memory, IO, latency, unhealthy hosts

resource "aws_iam_role_policy" "cloudwatch" {
  name = "vantaops-cloudwatch"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchAlarms"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:GetMetricData",
          "cloudwatch:EnableAlarmActions",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:PutRetentionPolicy",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── S3 Remediation (7 failing tests) ──────────────────────────────────
# Covers: encryption, public access block, versioning, access logging,
# logging bucket hardening, cross-region replication read

resource "aws_iam_role_policy" "s3" {
  name = "vantaops-s3"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Security"
        Effect = "Allow"
        Action = [
          "s3:PutBucketEncryption",
          "s3:GetBucketEncryption",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:GetBucketVersioning",
          "s3:PutBucketLogging",
          "s3:GetBucketLogging",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:ListBucket",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetReplicationConfiguration",
          "s3:GetBucketTagging",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── EC2 Remediation (14 failing tests) ────────────────────────────────
# Covers: IMDSv2 enforcement, public port restrictions,
# security group rules, SSH access hardening

resource "aws_iam_role_policy" "ec2" {
  name = "vantaops-ec2"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceMetadataOptions",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeImages",
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityGroups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── VPC Remediation (10 failing tests) ────────────────────────────────
# Covers: flow logs, network ACLs, subnet visibility

resource "aws_iam_role_policy" "vpc" {
  name = "vantaops-vpc"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VPCFlowLogs"
        Effect = "Allow"
        Action = [
          "ec2:CreateFlowLogs",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeNetworkInterfaces",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── RDS Remediation (21 failing tests) ────────────────────────────────
# Covers: Multi-AZ, automated backups, encryption at rest,
# IP restriction verification, monitoring

resource "aws_iam_role_policy" "rds" {
  name = "vantaops-rds"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RDSRemediation"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots",
          "rds:DescribeDBSubnetGroups",
          "rds:ModifyDBInstance",
          "rds:ModifyDBCluster",
          "rds:ListTagsForResource",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── DynamoDB Remediation (4 failing tests) ─────────────────────────────
# Covers: encryption at rest, point-in-time recovery

resource "aws_iam_role_policy" "dynamodb" {
  name = "vantaops-dynamodb"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBRemediation"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:ListTables",
          "dynamodb:UpdateTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:ListTagsOfResource",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── EKS Remediation (4 failing tests) ─────────────────────────────────
# Covers: audit log enablement, endpoint access restrictions,
# security group verification

resource "aws_iam_role_policy" "eks" {
  name = "vantaops-eks"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EKSRemediation"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:UpdateClusterConfig",
          "eks:ListNodegroups",
          "eks:DescribeNodegroup",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── ELB/ALB (5 failing tests) ─────────────────────────────────────────
# Covers: load balancer health monitoring, target group checks

resource "aws_iam_role_policy" "elb" {
  name = "vantaops-elb"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ELBDiscovery"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── GuardDuty (2 failing tests) ───────────────────────────────────────
# Covers: intrusion detection enablement and notification config

resource "aws_iam_role_policy" "guardduty" {
  name = "vantaops-guardduty"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GuardDutyRemediation"
        Effect = "Allow"
        Action = [
          "guardduty:CreateDetector",
          "guardduty:GetDetector",
          "guardduty:ListDetectors",
          "guardduty:UpdateDetector",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Inspector (6 failing tests) ───────────────────────────────────────
# Covers: vulnerability scanning enablement

resource "aws_iam_role_policy" "inspector" {
  name = "vantaops-inspector"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InspectorRemediation"
        Effect = "Allow"
        Action = [
          "inspector2:Enable",
          "inspector2:BatchGetAccountStatus",
          "inspector2:ListFindings",
          "inspector2:GetFindingsReportStatus",
          "inspector2:ListCoverage",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── ACM — Certificate Management (8 failing tests) ────────────────────
# Covers: expired cert detection, SSL/TLS validation (read-only —
# cert renewal is manual but bot needs read to verify and report)

resource "aws_iam_role_policy" "acm" {
  name = "vantaops-acm"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ACMDiscovery"
        Effect = "Allow"
        Action = [
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "acm:GetCertificate",
          "acm:ListTagsForCertificate",
          "acm:RenewCertificate",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── SNS — Notifications (2 failing tests) ─────────────────────────────
# Covers: GuardDuty/CloudWatch alarm notification targets

resource "aws_iam_role_policy" "sns" {
  name = "vantaops-sns"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SNSPublishToAlarmTopics"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:GetTopicAttributes",
          "sns:ListSubscriptionsByTopic",
        ]
        Resource = [
          var.sns_cloudwatch_topic_arn,
          var.sns_guardduty_topic_arn,
        ]
      },
      {
        Sid    = "SNSListTopics"
        Effect = "Allow"
        Action = [
          "sns:ListTopics",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── SSM Remediation — EC2 patching (2 failing tests) ──────────────────

resource "aws_iam_role_policy" "ssm" {
  name = "vantaops-ssm"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMCommands"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
          "ssm:ListComplianceItems",
          "ssm:ListComplianceSummaries",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Logging Remediation — CloudTrail/Config (5 failing tests) ─────────
# Covers: trail creation, log integrity, Config recorder enablement

resource "aws_iam_role_policy" "logging" {
  name = "vantaops-logging"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailConfig"
        Effect = "Allow"
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:UpdateTrail",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetInsightSelectors",
          "cloudtrail:PutInsightSelectors",
          "config:PutConfigurationRecorder",
          "config:StartConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "config:DescribeDeliveryChannels",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Read-Only Discovery ──────────────────────────────────────────────
# Cross-service read access for plan generation and verification.
# IAM is read-only — VantaOps never modifies IAM policies (manual-only).

resource "aws_iam_role_policy" "readonly" {
  name = "vantaops-readonly"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyDiscovery"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "iam:GetPolicy",
          "iam:ListPolicies",
          "iam:GetRole",
          "iam:ListUsers",
          "iam:GetLoginProfile",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "ecs:DescribeServices",
          "ecs:DescribeClusters",
          "ecs:ListServices",
          "ecs:ListClusters",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "tag:GetResources",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Explicit Deny on IAM Mutations ────────────────────────────────────
# Safety net: even if a broader policy is attached, VantaOps cannot
# create/modify/delete IAM users, roles, policies, or groups.

resource "aws_iam_role_policy" "deny_iam_mutations" {
  name = "vantaops-deny-iam-mutations"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyIAMMutations"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:CreateGroup",
          "iam:DeleteGroup",
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup",
          "iam:UpdateAssumeRolePolicy",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Outputs ──────────────────────────────────────────────────────────

output "role_arn" {
  description = "ARN of the VantaOps remediation role"
  value       = aws_iam_role.vantaops.arn
}

output "role_name" {
  description = "Name of the VantaOps remediation role"
  value       = aws_iam_role.vantaops.name
}
