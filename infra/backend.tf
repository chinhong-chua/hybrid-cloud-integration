terraform {
  backend "s3" {
    key          = "dev/ingestion.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
