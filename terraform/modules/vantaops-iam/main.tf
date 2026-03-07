# ==========================================================================
# VantaOps — IAM Remediation Role
#
# Deploy this module in each AWS account where VantaOps should be able
# to remediate compliance findings. Adjust the policy to match your
# comfort level per environment.
#
# Usage:
#   module "vantaops_role" {
#     source              = "./modules/vantaops-iam"
#     trusted_principal   = "arn:aws:iam::AGENT_ACCOUNT:role/vantaops-agent"
#     environment         = "prod"
#     sns_alert_topic_arn = "arn:aws:sns:us-east-1:333333333333:ops-alerts"
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

variable "sns_alert_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm actions (optional)"
  type        = string
  default     = ""
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

# ── CloudWatch Remediation ───────────────────────────────────────────────

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
          "cloudwatch:DeleteAlarms",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricStatistics",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── S3 Remediation ───────────────────────────────────────────────────────

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
          "s3:ListBucket",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── SSM Remediation (EC2 patching) ───────────────────────────────────────

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
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Security Group Remediation ───────────────────────────────────────────

resource "aws_iam_role_policy" "security_groups" {
  name = "vantaops-security-groups"
  role = aws_iam_role.vantaops.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityGroups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Read-Only Discovery ──────────────────────────────────────────────────

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
          "ec2:Describe*",
          "elasticloadbalancing:Describe*",
          "rds:Describe*",
          "ecs:Describe*",
          "ecs:List*",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "iam:GetPolicy",
          "iam:ListPolicies",
          "iam:GetRole",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Logging Remediation (CloudTrail/Config) ──────────────────────────────

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
          "config:PutConfigurationRecorder",
          "config:StartConfigurationRecorder",
          "config:PutDeliveryChannel",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Outputs ──────────────────────────────────────────────────────────────

output "role_arn" {
  description = "ARN of the VantaOps remediation role"
  value       = aws_iam_role.vantaops.arn
}

output "role_name" {
  description = "Name of the VantaOps remediation role"
  value       = aws_iam_role.vantaops.name
}
