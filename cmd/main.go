package main

import (
	ddlambda "github.com/DataDog/datadog-lambda-go"
	"github.com/SKF/go-rest-utility/client/auth"
	"github.com/SKF/go-utility/v2/env"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/SKF/jwt-rotator/internal/rotator"
)

var (
	UsersCredentialsSecretID = env.MustGetAsString("USERS_CREDENTIALS_SECRETS_MANAGER_ARN")
)

func main() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	credentialsTokenProvider := auth.SecretCredentialsTokenProvider{
		SecretID:      UsersCredentialsSecretID,
		SecretsClient: auth.SecretsManagerV1Client{},
	}

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsmanager.New(sess),
		TokenProvider:  &credentialsTokenProvider,
	}

	lambda.Start(ddlambda.WrapFunction(jwtRotator.Rotate, &ddlambda.Config{
		DDTraceEnabled: true,
		// ShouldUseLogForwarder flushes traces and metrics to CloudWatch
		ShouldUseLogForwarder: true,
	}))
}
