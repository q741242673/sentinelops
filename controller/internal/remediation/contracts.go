package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	opsv1alpha1 "github.com/q741242673/sentinelops/controller/api/v1alpha1"
)

const (
	ActionRestart  = "restart_deployment"
	ActionRollback = "rollback_deployment"
	ActionScale    = "scale_deployment"
)

type actionContract struct {
	Name                  string   `json:"name"`
	Risk                  string   `json:"risk"`
	Parameters            []string `json:"parameters"`
	RequiredPreconditions []string `json:"requiredPreconditions"`
	Reversible            bool     `json:"reversible"`
	VerificationProfile   string   `json:"verificationProfile"`
	Version               string   `json:"version"`
}

var contracts = map[string]actionContract{
	ActionRestart: {
		Name:                  ActionRestart,
		Risk:                  "medium",
		Parameters:            []string{"name"},
		RequiredPreconditions: workloadPreconditions(),
		Reversible:            false,
		VerificationProfile:   "workload_strict",
		Version:               "v1",
	},
	ActionRollback: {
		Name:                  ActionRollback,
		Risk:                  "high",
		Parameters:            []string{"name", "revision"},
		RequiredPreconditions: append(workloadPreconditions(), "rollbackTarget"),
		Reversible:            true,
		VerificationProfile:   "workload_strict",
		Version:               "v1",
	},
	ActionScale: {
		Name:                  ActionScale,
		Risk:                  "high",
		Parameters:            []string{"name", "replicas"},
		RequiredPreconditions: workloadPreconditions(),
		Reversible:            true,
		VerificationProfile:   "workload_strict",
		Version:               "v1",
	},
}

func workloadPreconditions() []string {
	return []string{
		"resourceVersion",
		"generation",
		"desiredReplicas",
		"paused",
		"currentRevision",
		"currentReplicaSetUid",
		"currentTemplateHash",
		"capturedAt",
	}
}

func CatalogDigest(name string) (string, bool) {
	contract, ok := contracts[name]
	if !ok {
		return "", false
	}
	return digestJSON(contract), true
}

func SnapshotDigest(precondition opsv1alpha1.ExecutionPrecondition) string {
	payload := map[string]any{
		"capturedAt":           precondition.CapturedAt,
		"currentReplicaSetUid": precondition.CurrentReplicaSetUID,
		"currentRevision":      precondition.CurrentRevision,
		"currentTemplateHash":  precondition.CurrentTemplateHash,
		"desiredReplicas":      precondition.DesiredReplicas,
		"generation":           precondition.Generation,
		"paused":               precondition.Paused,
		"resourceVersion":      precondition.ResourceVersion,
	}
	if precondition.RollbackTarget != nil {
		payload["rollbackTarget"] = precondition.RollbackTarget
	}
	return digestJSON(payload)
}

func digestJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("canonical contract value is not serializable: %v", err))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
