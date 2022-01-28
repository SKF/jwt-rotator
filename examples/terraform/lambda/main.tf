module "function-jwt-rotator" {
  source      = "git::https://dev.azure.com/skfdc/REP-SW/_git/terraform-modules//modules/lambda/function?ref=19.2.0"
  name_prefix = "jwt-rotator"
  description = "Rotates a jwt token, storing it in a secret"
  filename    = "${var.build_folder}/function-jwt-rotator.zip"
  bucket      = module.storage.bucket
  policy_arns = [
    aws_iam_policy.jwt-rotator.arn,
    "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess"
  ]

  concurrent_executions = 1
  timeout               = 900

  environment = {
    USERS_CREDENTIALS_SECRETS_MANAGER_ARN = var.users_credentials_secrets_manager_arn
  }
}

resource "aws_iam_policy" "jwt-rotator" {
  name   = "jwt-rotator-policy"
  policy = data.aws_iam_policy_document.jwt-rotator.json
}

data "aws_iam_policy_document" "jwt-rotator" {
  statement {
    actions = ["lambda:InvokeFunction"]

    resources = [
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
    ]
  }

  statement {
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]

    resources = [
      "arn:aws:secretsmanager:eu-west-1:${var.users_account_id}:secret:authorize/${var.stage}/grpc/client/reporting*",
      var.users_credentials_secrets_manager_arn
    ]
  }

  statement {
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]

    resources = [
      "arn:aws:kms:eu-west-1:${var.users_account_id}:*"
    ]
  }
}
