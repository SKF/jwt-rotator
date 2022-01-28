resource "aws_secretsmanager_secret" "secret" {
  name                    = var.name
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_rotation" "rotation" {
  count = var.rotation_lambda_arn == null ? 0 : 1

  secret_id           = aws_secretsmanager_secret.secret.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.automatically_after_days
  }
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = var.value
}

