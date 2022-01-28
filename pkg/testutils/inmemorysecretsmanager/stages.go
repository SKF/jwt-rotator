package inmemorysecretsmanager

import (
	"github.com/SKF/jwt-rotator/pkg/versionstage"
)

type Stages []versionstage.VersionStage

func StagesFromStrings(input []*string) Stages {
	result := make(Stages, len(input))

	for i := range input {
		result[i] = versionstage.VersionStage(*input[i])
	}

	return result
}

func (stageSlice Stages) ToStrings() []*string {
	strings := make([]*string, len(stageSlice))

	for i := range stageSlice {
		strings[i] = stageSlice[i].StringPtr()
	}

	return strings
}

func (stageSlice Stages) IncludesStage(stage *string) bool {
	for _, stageInSlice := range stageSlice {
		if *stage == string(stageInSlice) {
			return true
		}
	}

	return false
}

func (stageSlice *Stages) RemoveStage(stage *string) {
	result := make(Stages, 0, len(*stageSlice))

	for _, stageInSlice := range *stageSlice {
		if string(stageInSlice) != *stage {
			result = append(result, stageInSlice)
		}
	}

	*stageSlice = result
}

func (stageSlice *Stages) AddStage(stage *string) {
	*stageSlice = append(*stageSlice, versionstage.VersionStage(*stage))
}
