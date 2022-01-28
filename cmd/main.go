package main

import (
	ddlambda "github.com/DataDog/datadog-lambda-go"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/SKF/jwt-rotator/internal/rotator"
)

func main() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsmanager.New(sess),
	}

	lambda.Start(ddlambda.WrapFunction(jwtRotator.Rotate, &ddlambda.Config{
		DDTraceEnabled: true,
		// ShouldUseLogForwarder flushes traces and metrics to CloudWatch
		ShouldUseLogForwarder: true,
	}))
}
