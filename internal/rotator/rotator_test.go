package rotator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/SKF/go-rest-utility/client/auth"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SKF/jwt-rotator/internal/rotator"
	"github.com/SKF/jwt-rotator/internal/rotator/step"
	"github.com/SKF/jwt-rotator/internal/rotator/testutils/inmemorysecretsmanager"
	"github.com/SKF/jwt-rotator/internal/rotator/versionstage"
)

const (
	secretToRotate = "secret/to/rotate"
)

func TestRotate_CreateSecret_Uninitialized(t *testing.T) {
	// Given
	secretsManager := inmemorysecretsmanager.New()
	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(context.Background(), rotator.SecretManagerEvent{
		Step:               step.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})

	// Then
	require.Error(t, err)
	assert.ErrorIs(t, err, rotator.ErrResourceNotFound)
}

func TestRotate_CreateSecret(t *testing.T) {
	// Given
	ctx := context.Background()
	secretsManager := inmemorysecretsmanager.New()
	initialToken := rotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
		Step:               step.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})

	// Then
	require.NoError(t, err)
	currentToken := getCurrentToken(t, secretsManager)
	assert.Equal(t, initialToken, currentToken)

	pendingToken := getPendingToken(t, secretsManager)
	assert.Equal(t, "token-0", string(pendingToken.RawToken))
}

func TestRotate_CreateSecret_Twice(t *testing.T) {
	// Given
	ctx := context.Background()
	secretsManager := inmemorysecretsmanager.New()
	initialToken := rotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	for i := 0; i < 2; i++ {
		// When
		err := jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
			Step:               step.CreateSecret,
			SecretID:           secretToRotate,
			ClientRequestToken: "version-0",
		})

		// Then
		require.NoError(t, err)
		currentToken := getCurrentToken(t, secretsManager)
		assert.Equal(t, initialToken, currentToken)

		pendingToken := getPendingToken(t, secretsManager)
		assert.Equal(t, "token-0", string(pendingToken.RawToken))
	}
}

func TestRotate_TestSecret(t *testing.T) {
	// Given
	ctx := context.Background()
	secretsManager := inmemorysecretsmanager.New()
	initialToken := rotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
		Step:               step.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})
	require.NoError(t, err)
	err = jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
		Step:               step.TestSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})

	// Then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestRotate_FinishSecret(t *testing.T) {
	// Given
	ctx := context.Background()
	secretsManager := inmemorysecretsmanager.New()
	initialToken := rotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := rotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
		Step:               step.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})
	require.NoError(t, err)
	err = jwtRotator.Rotate(ctx, rotator.SecretManagerEvent{
		Step:               step.FinishSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})

	// Then
	require.NoError(t, err)
	currentToken := getCurrentToken(t, secretsManager)
	assert.Equal(t, "token-0", string(currentToken.RawToken))

	pendingToken := getPendingToken(t, secretsManager)
	assert.Equal(t, "token-0", string(pendingToken.RawToken))
}

func initializeSecretsManager(t *testing.T, manager *inmemorysecretsmanager.InMemorySecretsManager, token rotator.StoredToken) {
	bytes, err := json.Marshal(token)
	require.NoError(t, err)

	_, err = manager.PutSecretValueWithContext(context.Background(), &secretsmanager.PutSecretValueInput{
		ClientRequestToken: aws.String("initial-version"),
		SecretBinary:       bytes,
		SecretId:           aws.String(secretToRotate),
		VersionStages:      []*string{versionstage.AwsCurrent.StringPtr()},
	})

	require.NoError(t, err)
}

func getCurrentToken(t *testing.T, secretsManager *inmemorysecretsmanager.InMemorySecretsManager) rotator.StoredToken {
	t.Helper()

	result, err := secretsManager.GetSecretValueWithContext(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretToRotate),
		VersionStage: versionstage.AwsCurrent.StringPtr(),
	})
	require.NoError(t, err)

	var token rotator.StoredToken
	err = json.Unmarshal(result.SecretBinary, &token)
	require.NoError(t, err)

	return token
}

func getPendingToken(t *testing.T, secretsManager *inmemorysecretsmanager.InMemorySecretsManager) rotator.StoredToken {
	t.Helper()

	result, err := secretsManager.GetSecretValueWithContext(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretToRotate),
		VersionStage: versionstage.AWSPending.StringPtr(),
	})
	require.NoError(t, err)

	var token rotator.StoredToken
	err = json.Unmarshal(result.SecretBinary, &token)
	require.NoError(t, err)

	return token
}

type TokenProviderStub struct {
	count int
}

func (t *TokenProviderStub) GetRawToken(context.Context) (auth.RawToken, error) {
	token := fmt.Sprintf("token-%d", t.count)
	t.count++

	return auth.RawToken(token), nil
}

var _ auth.TokenProvider = &TokenProviderStub{}
