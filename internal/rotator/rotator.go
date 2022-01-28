package rotator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SKF/go-rest-utility/client/auth"
	"github.com/SKF/go-utility/v2/log"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/SKF/jwt-rotator/internal/rotator/step"
	"github.com/SKF/jwt-rotator/internal/rotator/versionstage"
)

type JWTRotator struct {
	SecretsManager *secretsmanager.SecretsManager
	TokenProvider  auth.SecretCredentialsTokenProvider
}

type SecretManagerEvent struct {
	Step               step.Step `json:"Step"`
	SecretID           string    `json:"SecretId"`
	ClientRequestToken string    `json:"ClientRequestToken"`
}

type secretVersion struct {
	SecretID           string
	ClientRequestToken string
}

func (h JWTRotator) Rotate(ctx context.Context, event SecretManagerEvent) error {
	version := secretVersion{
		SecretID:           event.SecretID,
		ClientRequestToken: event.ClientRequestToken,
	}

	switch event.Step {
	case step.CreateSecret:
		return h.CreateSecret(ctx, version)
	case step.SetSecret:
		return nil
	case step.TestSecret:
		return h.TestSecret(ctx, version)
	case step.FinishSecret:
		return h.FinishSecret(ctx, version)
	}

	return nil
}

func (h JWTRotator) CreateSecret(ctx context.Context, version secretVersion) error {
	log.WithTracing(ctx).Infof("Creating secret with versionID: %s", version.ClientRequestToken)

	if _, err := h.getCurrentSecret(ctx, version.SecretID); err != nil {
		return fmt.Errorf("failed to create secret: no secret with stage %s found: %w", versionstage.AwsCurrent, err)
	}

	_, err := h.getPendingSecret(ctx, version)
	if errors.Is(parseAWSError(err), ErrResourceNotFound) {
		if err = h.provisionNewToken(ctx, version); err != nil {
			return fmt.Errorf("failed to provision new token: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get pending secret: %w", err)
	}

	return nil
}

func (h JWTRotator) TestSecret(ctx context.Context, version secretVersion) error {
	log.WithTracing(ctx).Infof("Testing secret with versionID: %s", version.ClientRequestToken)

	storedToken, err := h.getPendingSecret(ctx, version)
	if err != nil {
		return fmt.Errorf("failed to get pending secret: %w", err)
	}

	expiry, err := storedToken.RawToken.ParseExpires()
	if err != nil {
		return fmt.Errorf("failed to parse JWT expiry: %w", err)
	}

	if time.Now().After(expiry) {
		return fmt.Errorf("JWT token test failed: PENDING token already expired")
	}

	return nil
}

func (h JWTRotator) FinishSecret(ctx context.Context, version secretVersion) error {
	log.WithTracing(ctx).Infof("Finishing secret with versionID: %s", version.ClientRequestToken)

	metadata, err := h.SecretsManager.DescribeSecretWithContext(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: &version.SecretID,
	})
	if err != nil {
		return fmt.Errorf("failed to describe secret with id '%s': %w", version.SecretID, err)
	}

	currentVersion, err := h.findCurrentVersion(metadata)
	if err != nil {
		return fmt.Errorf("could not find current version: %w", err)
	}

	if currentVersion == version.ClientRequestToken {
		return nil
	}

	if _, err = h.SecretsManager.UpdateSecretVersionStageWithContext(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		MoveToVersionId:     &version.ClientRequestToken,
		RemoveFromVersionId: &currentVersion,
		SecretId:            &version.SecretID,
		VersionStage:        versionstage.AwsCurrent.StringPtr(),
	}); err != nil {
		return fmt.Errorf("failed to update secret from PENDING to CURRENT: %w", err)
	}

	return nil
}

func (h JWTRotator) findCurrentVersion(metadata *secretsmanager.DescribeSecretOutput) (string, error) {
	for versionID, stages := range metadata.VersionIdsToStages {
		for _, stage := range stages {
			if stageEquals(stage, versionstage.AwsCurrent) {
				return versionID, nil
			}
		}
	}

	return "", fmt.Errorf("could not find secret with stage %s in metadata", versionstage.AwsCurrent)
}

func stageEquals(stage *string, versionStage versionstage.VersionStage) bool {
	return stage != nil && *stage == string(versionStage)
}

func (h JWTRotator) provisionNewToken(ctx context.Context, version secretVersion) error {
	rawToken, err := h.TokenProvider.GetRawToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to provision new token: %w", err)
	}

	secretBytes, err := json.Marshal(StoredToken{RawToken: rawToken})
	if err != nil {
		return fmt.Errorf("failed to marshal secretmodel: %w", err)
	}

	if _, err = h.SecretsManager.PutSecretValueWithContext(ctx, &secretsmanager.PutSecretValueInput{
		ClientRequestToken: &version.ClientRequestToken,
		SecretBinary:       secretBytes,
		SecretId:           &version.SecretID,
		VersionStages:      []*string{versionstage.AWSPending.StringPtr()},
	}); err != nil {
		return fmt.Errorf("failed to put secret value: %w", err)
	}

	return nil
}

func (h JWTRotator) getPendingSecret(ctx context.Context, version secretVersion) (StoredToken, error) {
	return h.getSecret(ctx, secretsmanager.GetSecretValueInput{
		SecretId:     &version.SecretID,
		VersionId:    &version.ClientRequestToken,
		VersionStage: versionstage.AWSPending.StringPtr(),
	})
}

func (h JWTRotator) getCurrentSecret(ctx context.Context, secretID string) (StoredToken, error) {
	return h.getSecretByStage(ctx, secretID, versionstage.AwsCurrent)
}

func (h JWTRotator) getSecretByStage(ctx context.Context, secretID string, stage versionstage.VersionStage) (StoredToken, error) {
	secretBinary, err := h.SecretsManager.GetSecretValueWithContext(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     &secretID,
		VersionStage: stage.StringPtr(),
	})
	if err != nil {
		return StoredToken{}, fmt.Errorf("failed to get secret value: %w", err)
	}

	var storedToken StoredToken
	if err = json.Unmarshal(secretBinary.SecretBinary, &storedToken); err != nil {
		return StoredToken{}, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return storedToken, nil
}

func (h JWTRotator) getSecret(ctx context.Context, input secretsmanager.GetSecretValueInput) (StoredToken, error) {
	secretBinary, err := h.SecretsManager.GetSecretValueWithContext(ctx, &input)
	if err != nil {
		return StoredToken{}, fmt.Errorf("failed to get secret value: %w", err)
	}

	var storedToken StoredToken
	if err = json.Unmarshal(secretBinary.SecretBinary, &storedToken); err != nil {
		return StoredToken{}, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return storedToken, nil
}
