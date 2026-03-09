provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile (local dev). Leave empty in CI — uses env vars instead."
  type        = string
  default     = "openbb_awsbot1"
}

variable "environment" {
  description = "Environment label (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "sns_cloudwatch_topic_arn" {
  description = "ARN of the SNS topic for CloudWatch alarm notifications (cloudwatch-alarm-topic)"
  type        = string
}

variable "sns_guardduty_topic_arn" {
  description = "ARN of the SNS topic for GuardDuty findings (GuardDuty_to_Slack)"
  type        = string
}

# ── Remediation Role ───────────────────────────────────────────────────
# The same AWS credentials (openbb_awsbot1 / AWS_ACCESS_KEY_ID) are used
# for both Terraform and the bot. The trusted_principal is the caller
# identity that will AssumeRole into the remediation role.

variable "trusted_principal" {
  description = "ARN of the IAM user/role that runs the bot and Terraform"
  type        = string
}

module "vantaops_iam" {
  source                   = "./modules/vantaops-iam"
  trusted_principal        = var.trusted_principal
  environment              = var.environment
  sns_cloudwatch_topic_arn = var.sns_cloudwatch_topic_arn
  sns_guardduty_topic_arn  = var.sns_guardduty_topic_arn
}

# ── Outputs ────────────────────────────────────────────────────────────

output "role_arn" {
  value = module.vantaops_iam.role_arn
}

output "role_name" {
  value = module.vantaops_iam.role_name
}
