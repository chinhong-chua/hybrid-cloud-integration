variable "project_name" {
  description = "Project identifier used in queue names, IAM policy names and tags."
  type        = string
  default     = "hybrid-cloud-integration"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.project_name))
    error_message = "Use 3-40 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "aws_region" {
  description = "AWS region containing both the bucket and queues."
  type        = string
  default     = "ap-southeast-1"
}

variable "environment" {
  description = "Environment label used in resource names and tags."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging or prod."
  }
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name; use lowercase letters, digits and hyphens."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Use 3–63 lowercase letters, digits or hyphens, starting and ending with a letter or digit."
  }
}
