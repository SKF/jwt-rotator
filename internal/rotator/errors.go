package rotator

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

var (
	ErrResourceNotFound = fmt.Errorf("resource not found")
)

func parseAWSError(err error) error {
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case secretsmanager.ErrCodeResourceNotFoundException:
			return fmt.Errorf("%w: %s", ErrResourceNotFound, err.Error())
		}
	}

	return err
}
