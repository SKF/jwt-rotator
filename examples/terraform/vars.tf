variable "name" {
  description = "Specifies the friendly name of the secret."
  type        = string
}

variable "value" {
  description = "Specifies text data that you want to encrypt and store in this version of the secret"
  type        = string
}

variable "recovery_window_in_days" {
  description = "Specifies the number of days that AWS Secrets Manager waits before it can delete the secret. This value can be 0 to force deletion without recovery or range from 7 to 30 days"
  type        = number
  default     = 7
}

variable "automatically_after_days" {
  description = "specifies the number of days to rotate the secret, only used when rotation lambda is set"
  default     = 0
}

variable "rotation_lambda_arn" {
  description = "Specifies the ARN of the Lambda function that can rotate the secret."
  type        = string
  default     = null
}