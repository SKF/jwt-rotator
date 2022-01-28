package versionstage

// VersionStage is a Secret Manager Version ID.
type VersionStage string

const (
	AwsCurrent  VersionStage = "AWSCURRENT"
	AWSPending  VersionStage = "AWSPENDING"
	AWSPrevious VersionStage = "AWSPREVIOUS"
)

func (vs VersionStage) StringPtr() *string {
	stringValue := string(vs)
	return &stringValue
}
