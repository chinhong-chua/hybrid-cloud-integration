output "bucket_name" {
  description = "Upload CSV files under incoming/ in this bucket."
  value       = module.file_ingestion.bucket_name
}

output "queue_url" {
  description = "Queue polled by the future ingestion worker."
  value       = module.file_ingestion.queue_url
}

output "dead_letter_queue_url" {
  description = "Queue holding messages that exhausted processing retries."
  value       = module.file_ingestion.dead_letter_queue_url
}

output "uploader_policy_arn" {
  description = "Attach to the API workload role that generates presigned uploads."
  value       = module.file_ingestion.uploader_policy_arn
}

output "worker_policy_arn" {
  description = "Attach to the ingestion worker workload role."
  value       = module.file_ingestion.worker_policy_arn
}

