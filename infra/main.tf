provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

module "file_ingestion" {
  source      = "./modules/file-ingestion"
  name_prefix = "${var.project_name}-${var.environment}"
  bucket_name = var.bucket_name
}
