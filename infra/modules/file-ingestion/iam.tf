# Policies only: role trust belongs to the EKS setup, outside this slice.
resource "aws_iam_policy" "uploader" {
  name        = "${var.name_prefix}-csv-uploader"
  description = "API may issue presigned uploads only under incoming/."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.input.arn}/incoming/*"
    }]
  })
}

resource "aws_iam_policy" "worker" {
  name        = "${var.name_prefix}-csv-worker"
  description = "Worker may read input versions and consume its queue."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.input.arn}/incoming/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage", "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.ingestion.arn
      }
    ]
  })
}

