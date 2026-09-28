output "bucket_name" {
  description = "Input bucket name."
  value       = aws_s3_bucket.input.id
}

output "queue_url" {
  description = "Ingestion queue URL."
  value       = aws_sqs_queue.ingestion.id
}

output "dead_letter_queue_url" {
  description = "Dead-letter queue URL."
  value       = aws_sqs_queue.dead_letter.id
}

output "uploader_policy_arn" {
  description = "API uploader IAM policy ARN."
  value       = aws_iam_policy.uploader.arn
}

output "worker_policy_arn" {
  description = "Worker IAM policy ARN."
  value       = aws_iam_policy.worker.arn
}
