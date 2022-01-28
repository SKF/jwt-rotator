package inmemorysecretsmanager

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/SKF/jwt-rotator/internal/rotator"
)

type InMemorySecretsManager struct {
	content map[string]versions
}

func New() *InMemorySecretsManager {
	return &InMemorySecretsManager{
		content: make(map[string]versions),
	}
}

func (s InMemorySecretsManager) DescribeSecretWithContext(_ aws.Context, input *secretsmanager.DescribeSecretInput, _ ...request.Option) (*secretsmanager.DescribeSecretOutput, error) {
	contentVersions := s.content[*input.SecretId]

	result := make(map[string][]*string)

	for _, v := range contentVersions {
		result[v.VersionID] = v.Stages.ToStrings()
	}

	return &secretsmanager.DescribeSecretOutput{
		VersionIdsToStages: result,
	}, nil
}

func (s *InMemorySecretsManager) UpdateSecretVersionStageWithContext(_ aws.Context, input *secretsmanager.UpdateSecretVersionStageInput, _ ...request.Option) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
	contentVersions := s.content[*input.SecretId]

	for i := range contentVersions {
		if contentVersions[i].VersionID == *input.RemoveFromVersionId {
			contentVersions[i].Stages.RemoveStage(input.VersionStage)
		}

		if contentVersions[i].VersionID == *input.MoveToVersionId {
			contentVersions[i].Stages.AddStage(input.VersionStage)
		}
	}

	return nil, nil
}

func (s *InMemorySecretsManager) PutSecretValueWithContext(_ aws.Context, input *secretsmanager.PutSecretValueInput, _ ...request.Option) (*secretsmanager.PutSecretValueOutput, error) {
	newVersion := version{
		VersionID:    *input.ClientRequestToken,
		Stages:       StagesFromStrings(input.VersionStages),
		SecretBinary: input.SecretBinary,
	}

	existingVersions, ok := s.content[*input.SecretId]
	if !ok {
		s.content[*input.SecretId] = versions{newVersion}
		return nil, nil
	}

	s.content[*input.SecretId] = append(existingVersions, newVersion)

	return nil, nil
}

func (s InMemorySecretsManager) GetSecretValueWithContext(_ aws.Context, input *secretsmanager.GetSecretValueInput, _ ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {
	versionSlice, ok := s.content[*input.SecretId]
	if !ok {
		return nil, &secretsmanager.ResourceNotFoundException{}
	}

	if matchedVersion := versionSlice.Get(input.VersionId, input.VersionStage); matchedVersion != nil {
		return &secretsmanager.GetSecretValueOutput{
			SecretBinary:  matchedVersion.SecretBinary,
			VersionId:     &matchedVersion.VersionID,
			VersionStages: matchedVersion.Stages.ToStrings(),
		}, nil
	}

	return nil, &secretsmanager.ResourceNotFoundException{}
}

var _ rotator.SecretsManagerClient = &InMemorySecretsManager{}
