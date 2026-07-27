package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type SentinelRemediationSpec struct {
	ActionID      string                 `json:"actionId"`
	IncidentID    string                 `json:"incidentId"`
	Action        RemediationAction      `json:"action"`
	Target        RemediationTarget      `json:"target"`
	Precondition  ExecutionPrecondition  `json:"precondition"`
	Authorization ExecutionAuthorization `json:"authorization"`
	Fence         ExecutionFence         `json:"fence"`
}

type RemediationAction struct {
	Plugin        string           `json:"plugin"`
	CatalogDigest string           `json:"catalogDigest"`
	Parameters    ActionParameters `json:"parameters"`
}

type ActionParameters struct {
	Name     string `json:"name"`
	Revision *int64 `json:"revision,omitempty"`
	Replicas *int32 `json:"replicas,omitempty"`
}

type RemediationTarget struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	ClusterID  string    `json:"clusterId"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
}

type ExecutionPrecondition struct {
	SnapshotDigest       string          `json:"snapshotDigest"`
	ClusterID            string          `json:"clusterId"`
	ResourceVersion      string          `json:"resourceVersion"`
	Generation           int64           `json:"generation"`
	DesiredReplicas      int32           `json:"desiredReplicas"`
	Paused               bool            `json:"paused"`
	CurrentRevision      int64           `json:"currentRevision"`
	CurrentReplicaSetUID types.UID       `json:"currentReplicaSetUid"`
	CurrentTemplateHash  string          `json:"currentTemplateHash"`
	CapturedAt           metav1.Time     `json:"capturedAt"`
	RollbackTarget       *RollbackTarget `json:"rollbackTarget,omitempty"`
}

type RollbackTarget struct {
	Revision          int64     `json:"revision"`
	ReplicaSetUID     types.UID `json:"replicaSetUid"`
	HealthProofDigest string    `json:"healthProofDigest"`
}

type ExecutionAuthorization struct {
	Decision        string `json:"decision"`
	PolicyDigest    string `json:"policyDigest"`
	ApprovalID      string `json:"approvalId,omitempty"`
	ApprovalVersion *int64 `json:"approvalVersion,omitempty"`
	ApprovalDigest  string `json:"approvalDigest,omitempty"`
}

type ExecutionFence struct {
	Generation int64       `json:"generation"`
	ExpiresAt  metav1.Time `json:"expiresAt"`
}

type SentinelRemediationStatus struct {
	Phase              string             `json:"phase,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	ControllerID       string             `json:"controllerId,omitempty"`
	Attempt            int64              `json:"attempt,omitempty"`
	StartedAt          *metav1.Time       `json:"startedAt,omitempty"`
	FinishedAt         *metav1.Time       `json:"finishedAt,omitempty"`
	Reason             string             `json:"reason,omitempty"`
	Result             *RemediationResult `json:"result,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type RemediationResult struct {
	BeforeResourceVersion string `json:"beforeResourceVersion,omitempty"`
	AfterResourceVersion  string `json:"afterResourceVersion,omitempty"`
	ObservedActionID      string `json:"observedActionId,omitempty"`
	OutcomeDigest         string `json:"outcomeDigest,omitempty"`
	Message               string `json:"message,omitempty"`
}

type SentinelRemediation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SentinelRemediationSpec   `json:"spec"`
	Status SentinelRemediationStatus `json:"status,omitempty"`
}

type SentinelRemediationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SentinelRemediation `json:"items"`
}

func (in *SentinelRemediation) DeepCopyInto(out *SentinelRemediation) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = *in.Spec.DeepCopy()
	out.Status = *in.Status.DeepCopy()
}

func (in *SentinelRemediation) DeepCopy() *SentinelRemediation {
	if in == nil {
		return nil
	}
	out := new(SentinelRemediation)
	in.DeepCopyInto(out)
	return out
}

func (in *SentinelRemediation) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *SentinelRemediationList) DeepCopyInto(out *SentinelRemediationList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SentinelRemediation, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *SentinelRemediationList) DeepCopy() *SentinelRemediationList {
	if in == nil {
		return nil
	}
	out := new(SentinelRemediationList)
	in.DeepCopyInto(out)
	return out
}

func (in *SentinelRemediationList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *SentinelRemediationSpec) DeepCopy() *SentinelRemediationSpec {
	if in == nil {
		return nil
	}
	out := new(SentinelRemediationSpec)
	*out = *in
	out.Action = *in.Action.DeepCopy()
	out.Precondition = *in.Precondition.DeepCopy()
	out.Authorization = *in.Authorization.DeepCopy()
	return out
}

func (in *RemediationAction) DeepCopy() *RemediationAction {
	if in == nil {
		return nil
	}
	out := new(RemediationAction)
	*out = *in
	out.Parameters = in.Parameters
	if in.Parameters.Revision != nil {
		value := *in.Parameters.Revision
		out.Parameters.Revision = &value
	}
	if in.Parameters.Replicas != nil {
		value := *in.Parameters.Replicas
		out.Parameters.Replicas = &value
	}
	return out
}

func (in *ExecutionPrecondition) DeepCopy() *ExecutionPrecondition {
	if in == nil {
		return nil
	}
	out := new(ExecutionPrecondition)
	*out = *in
	if in.RollbackTarget != nil {
		value := *in.RollbackTarget
		out.RollbackTarget = &value
	}
	return out
}

func (in *ExecutionAuthorization) DeepCopy() *ExecutionAuthorization {
	if in == nil {
		return nil
	}
	out := new(ExecutionAuthorization)
	*out = *in
	if in.ApprovalVersion != nil {
		value := *in.ApprovalVersion
		out.ApprovalVersion = &value
	}
	return out
}

func (in *SentinelRemediationStatus) DeepCopy() *SentinelRemediationStatus {
	if in == nil {
		return nil
	}
	out := new(SentinelRemediationStatus)
	*out = *in
	if in.StartedAt != nil {
		value := in.StartedAt.DeepCopy()
		out.StartedAt = value
	}
	if in.FinishedAt != nil {
		value := in.FinishedAt.DeepCopy()
		out.FinishedAt = value
	}
	if in.Result != nil {
		value := *in.Result
		out.Result = &value
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	return out
}
