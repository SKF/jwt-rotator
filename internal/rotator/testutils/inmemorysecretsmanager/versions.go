package inmemorysecretsmanager

type version struct {
	VersionID    string
	Stages       Stages
	SecretBinary []byte
}

func (v version) Get(versionID *string, versionStage *string) *version {
	if versionID != nil && versionStage == nil { //nolint:nestif
		if *versionID == v.VersionID {
			return &v
		}
	} else if versionID == nil && versionStage != nil {
		if v.Stages.IncludesStage(versionStage) {
			return &v
		}
	} else if versionID != nil && versionStage != nil {
		if *versionID == v.VersionID && v.Stages.IncludesStage(versionStage) {
			return &v
		}
	}

	return nil
}

type versions []version

func (v versions) Get(versionID *string, versionStage *string) *version {
	for _, version := range v {
		if matchedVersion := version.Get(versionID, versionStage); matchedVersion != nil {
			return matchedVersion
		}
	}

	return nil
}

func (v version) GetByInput() {}
