package step

type Step string

const (
	CreateSecret Step = "createSecret"
	SetSecret    Step = "setSecret"
	TestSecret   Step = "testSecret"
	FinishSecret Step = "finishSecret"
)
