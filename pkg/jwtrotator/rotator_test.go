package jwtrotator_test

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

	"github.com/SKF/jwt-rotator/pkg/jwtrotator"
	step2 "github.com/SKF/jwt-rotator/pkg/jwtrotator/step"
	inmemorysecretsmanager2 "github.com/SKF/jwt-rotator/pkg/jwtrotator/testutils/inmemorysecretsmanager"
	versionstage2 "github.com/SKF/jwt-rotator/pkg/jwtrotator/versionstage"
)

const (
	secretToRotate = "secret/to/rotate"
)

func TestRotate_CreateSecret_Uninitialized(t *testing.T) {
	// Given
	secretsManager := inmemorysecretsmanager2.New()
	jwtRotator := jwtrotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(context.Background(), jwtrotator.SecretManagerEvent{
		Step:               step2.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})

	// Then
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtrotator.ErrResourceNotFound)
}

func TestRotate_CreateSecret(t *testing.T) {
	// Given
	ctx := context.Background()
	secretsManager := inmemorysecretsmanager2.New()
	initialToken := jwtrotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := jwtrotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
		Step:               step2.CreateSecret,
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
	secretsManager := inmemorysecretsmanager2.New()
	initialToken := jwtrotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := jwtrotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	for i := 0; i < 2; i++ {
		// When
		err := jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
			Step:               step2.CreateSecret,
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
	secretsManager := inmemorysecretsmanager2.New()
	initialToken := jwtrotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := jwtrotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
		Step:               step2.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})
	require.NoError(t, err)
	err = jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
		Step:               step2.TestSecret,
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
	secretsManager := inmemorysecretsmanager2.New()
	initialToken := jwtrotator.StoredToken{
		RawToken: "first-token",
	}
	initializeSecretsManager(t, secretsManager, initialToken)

	jwtRotator := jwtrotator.JWTRotator{
		SecretsManager: secretsManager,
		TokenProvider:  &TokenProviderStub{},
	}

	// When
	err := jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
		Step:               step2.CreateSecret,
		SecretID:           secretToRotate,
		ClientRequestToken: "version-0",
	})
	require.NoError(t, err)
	err = jwtRotator.Rotate(ctx, jwtrotator.SecretManagerEvent{
		Step:               step2.FinishSecret,
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

func initializeSecretsManager(t *testing.T, manager *inmemorysecretsmanager2.InMemorySecretsManager, token jwtrotator.StoredToken) {
	bytes, err := json.Marshal(token)
	require.NoError(t, err)

	_, err = manager.PutSecretValueWithContext(context.Background(), &secretsmanager.PutSecretValueInput{
		ClientRequestToken: aws.String("initial-version"),
		SecretBinary:       bytes,
		SecretId:           aws.String(secretToRotate),
		VersionStages:      []*string{versionstage2.AwsCurrent.StringPtr()},
	})

	require.NoError(t, err)
}

func getCurrentToken(t *testing.T, secretsManager *inmemorysecretsmanager2.InMemorySecretsManager) jwtrotator.StoredToken {
	t.Helper()

	result, err := secretsManager.GetSecretValueWithContext(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretToRotate),
		VersionStage: versionstage2.AwsCurrent.StringPtr(),
	})
	require.NoError(t, err)

	var token jwtrotator.StoredToken
	err = json.Unmarshal(result.SecretBinary, &token)
	require.NoError(t, err)

	return token
}

func getPendingToken(t *testing.T, secretsManager *inmemorysecretsmanager2.InMemorySecretsManager) jwtrotator.StoredToken {
	t.Helper()

	result, err := secretsManager.GetSecretValueWithContext(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretToRotate),
		VersionStage: versionstage2.AWSPending.StringPtr(),
	})
	require.NoError(t, err)

	var token jwtrotator.StoredToken
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
