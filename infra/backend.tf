terraform {
  backend "s3" {
    bucket       = "hce-dev-446709109300-terraform-state"
    key          = "dev/ingestion.tfstate"
    region       = "ap-southeast-1"
    encrypt      = true
    use_lockfile = true
  }
}
