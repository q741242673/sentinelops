package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	opsv1alpha1 "github.com/q741242673/sentinelops/controller/api/v1alpha1"
	"github.com/q741242673/sentinelops/controller/internal/admissionintegrity"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const (
	PhasePending   = "Pending"
	PhaseExecuting = "Executing"
	PhaseSucceeded = "Succeeded"
	PhaseFailed    = "Failed"
	PhaseRejected  = "Rejected"
	PhaseStale     = "Stale"

	actionIDAnnotation        = "ops.sentinelops.io/action-id"
	actionPluginAnnotation    = "ops.sentinelops.io/action-plugin"
	fenceGenerationAnnotation = "ops.sentinelops.io/fence-generation"
)

type Reconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	ControllerID       string
	Clock              func() time.Time
	AfterWrite         func(*opsv1alpha1.SentinelRemediation, *appsv1.Deployment) error
	AdmissionIntegrity interface {
		Check(context.Context) admissionintegrity.Result
	}
}

type validationFailure struct {
	phase  string
	reason string
	err    error
}

type validatedContext struct {
	deployment     *appsv1.Deployment
	replicaSets    []appsv1.ReplicaSet
	rollbackTarget *appsv1.ReplicaSet
	beforeVersion  string
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager, maxConcurrent int) error {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&opsv1alpha1.SentinelRemediation{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).
		Complete(r)
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	request ctrl.Request,
) (ctrl.Result, error) {
	remediation := &opsv1alpha1.SentinelRemediation{}
	if err := r.Get(ctx, request.NamespacedName, remediation); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if isTerminal(remediation.Status.Phase) {
		return ctrl.Result{}, nil
	}

	if failure := r.validateStatic(remediation); failure != nil {
		return ctrl.Result{}, r.finishFailure(ctx, remediation, failure)
	}

	execution, failure := r.validateClusterState(ctx, remediation)
	if failure != nil {
		if failure.phase == "" {
			return ctrl.Result{}, failure.err
		}
		return ctrl.Result{}, r.finishFailure(ctx, remediation, failure)
	}

	if recovered, failure := alreadyApplied(remediation, execution.deployment); recovered {
		if failure != nil {
			return ctrl.Result{}, r.finishFailure(ctx, remediation, failure)
		}
		return ctrl.Result{}, r.finishSuccess(
			ctx,
			remediation,
			execution.beforeVersion,
			execution.deployment.ResourceVersion,
			"recovered the result from the Deployment action marker",
		)
	}
	if failure != nil {
		return ctrl.Result{}, r.finishFailure(ctx, remediation, failure)
	}

	if r.AdmissionIntegrity != nil {
		integrity := r.AdmissionIntegrity.Check(ctx)
		if !integrity.Healthy {
			reason := "AdmissionIntegrityDrift"
			if integrity.Unknown {
				reason = "AdmissionIntegrityUnknown"
			} else if integrity.Mode != admissionintegrity.ModeEnforced {
				reason = "AdmissionFenceNotEnforced"
			}
			return ctrl.Result{}, r.finishFailure(
				ctx,
				remediation,
				rejected(
					reason,
					"cluster admission integrity does not authorize automatic writes",
				),
			)
		}
	}

	if err := r.markExecuting(ctx, remediation); err != nil {
		return ctrl.Result{}, err
	}

	updated, err := r.execute(ctx, remediation, execution)
	if err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	if r.AfterWrite != nil {
		if err := r.AfterWrite(remediation, updated); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.finishSuccess(
		ctx,
		remediation,
		execution.beforeVersion,
		updated.ResourceVersion,
		"registered action was applied exactly once",
	)
}

func (r *Reconciler) validateStatic(
	remediation *opsv1alpha1.SentinelRemediation,
) *validationFailure {
	now := time.Now().UTC()
	if r.Clock != nil {
		now = r.Clock().UTC()
	}
	spec := remediation.Spec
	if remediation.Name != spec.ActionID {
		return rejected("ActionIdentityMismatch", "metadata.name does not match actionId")
	}
	if remediation.Namespace != spec.Target.Namespace {
		return rejected("TargetNamespaceMismatch", "resource and target namespaces differ")
	}
	if spec.Target.APIVersion != "apps/v1" || spec.Target.Kind != "Deployment" {
		return rejected("UnsupportedTarget", "only apps/v1 Deployment targets are supported")
	}
	if !spec.Fence.ExpiresAt.Time.After(now) {
		return stale("FenceExpired", "execution fence has expired")
	}
	if spec.Fence.Generation != spec.Precondition.Generation {
		return rejected(
			"FenceGenerationMismatch",
			"execution fence must bind the captured Deployment generation",
		)
	}
	expectedCatalogDigest, ok := CatalogDigest(spec.Action.Plugin)
	if !ok {
		return rejected("ActionNotRegistered", "action is not in the controller catalog")
	}
	if spec.Action.CatalogDigest != expectedCatalogDigest {
		return rejected("CatalogDigestMismatch", "action catalog digest does not match")
	}
	if spec.Precondition.SnapshotDigest != SnapshotDigest(spec.Precondition) {
		return rejected("SnapshotDigestMismatch", "execution snapshot digest does not match")
	}
	if spec.Action.Parameters.Name != spec.Target.Name {
		return rejected("ActionTargetMismatch", "action parameter target does not match")
	}
	if failure := validateParameters(spec.Action); failure != nil {
		return failure
	}
	if failure := validateAuthorization(spec); failure != nil {
		return failure
	}
	return nil
}

func (r *Reconciler) validateClusterState(
	ctx context.Context,
	remediation *opsv1alpha1.SentinelRemediation,
) (*validatedContext, *validationFailure) {
	target := remediation.Spec.Target
	deployment := &appsv1.Deployment{}
	key := types.NamespacedName{Namespace: target.Namespace, Name: target.Name}
	if err := r.Get(ctx, key, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, stale("TargetMissing", "target Deployment no longer exists")
		}
		return nil, &validationFailure{reason: "TargetReadFailed", err: err}
	}
	if deployment.UID != target.UID {
		return nil, stale("TargetUIDChanged", "target Deployment UID changed")
	}

	if recovered, failure := alreadyApplied(remediation, deployment); recovered || failure != nil {
		return &validatedContext{
			deployment:    deployment,
			beforeVersion: remediation.Spec.Precondition.ResourceVersion,
		}, failure
	}

	precondition := remediation.Spec.Precondition
	if deployment.ResourceVersion != precondition.ResourceVersion {
		return nil, stale("ResourceVersionChanged", "target resourceVersion changed")
	}
	if deployment.Generation != precondition.Generation {
		return nil, stale("GenerationChanged", "target generation changed")
	}
	replicas := int32(0)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	if replicas != precondition.DesiredReplicas {
		return nil, stale("ReplicaCountChanged", "target desired replicas changed")
	}
	if deployment.Spec.Paused != precondition.Paused {
		return nil, stale("PauseStateChanged", "target pause state changed")
	}

	replicaSetList := &appsv1.ReplicaSetList{}
	if err := r.List(ctx, replicaSetList, client.InNamespace(target.Namespace)); err != nil {
		return nil, &validationFailure{reason: "ReplicaSetReadFailed", err: err}
	}
	owned := ownedReplicaSets(deployment, replicaSetList.Items)
	if deployment.Annotations["deployment.kubernetes.io/revision"] !=
		strconv.FormatInt(precondition.CurrentRevision, 10) {
		return nil, stale("CurrentRevisionChanged", "Deployment revision changed")
	}
	current := replicaSetForRevision(owned, precondition.CurrentRevision)
	if current == nil {
		return nil, stale("CurrentRevisionMissing", "captured current ReplicaSet is missing")
	}
	if current.UID != precondition.CurrentReplicaSetUID {
		return nil, stale("CurrentReplicaSetChanged", "current ReplicaSet UID changed")
	}
	if templateHash(current) != precondition.CurrentTemplateHash {
		return nil, stale("CurrentTemplateChanged", "current template hash changed")
	}

	var rollbackTarget *appsv1.ReplicaSet
	if remediation.Spec.Action.Plugin == ActionRollback {
		rollback := precondition.RollbackTarget
		if rollback == nil {
			return nil, rejected("RollbackProofMissing", "rollback target proof is missing")
		}
		rollbackTarget = replicaSetForRevision(owned, rollback.Revision)
		if rollbackTarget == nil || rollbackTarget.UID != rollback.ReplicaSetUID {
			return nil, stale("RollbackTargetChanged", "rollback target no longer matches")
		}
		if failure := validateRollbackProof(
			deployment,
			rollbackTarget,
			rollback.HealthProofDigest,
			r.now(),
		); failure != nil {
			return nil, failure
		}
	}

	return &validatedContext{
		deployment:     deployment,
		replicaSets:    owned,
		rollbackTarget: rollbackTarget,
		beforeVersion:  deployment.ResourceVersion,
	}, nil
}

func (r *Reconciler) execute(
	ctx context.Context,
	remediation *opsv1alpha1.SentinelRemediation,
	execution *validatedContext,
) (*appsv1.Deployment, error) {
	deployment := execution.deployment.DeepCopy()
	ensureAnnotations(&deployment.ObjectMeta)
	deployment.Annotations[actionIDAnnotation] = remediation.Spec.ActionID
	deployment.Annotations[actionPluginAnnotation] = remediation.Spec.Action.Plugin
	deployment.Annotations[fenceGenerationAnnotation] = strconv.FormatInt(
		remediation.Spec.Fence.Generation,
		10,
	)

	switch remediation.Spec.Action.Plugin {
	case ActionRestart:
		ensureAnnotations(&deployment.Spec.Template.ObjectMeta)
		deployment.Spec.Template.Annotations[actionIDAnnotation] = remediation.Spec.ActionID
		deployment.Spec.Template.Annotations[fenceGenerationAnnotation] = strconv.FormatInt(
			remediation.Spec.Fence.Generation,
			10,
		)
	case ActionScale:
		replicas := *remediation.Spec.Action.Parameters.Replicas
		deployment.Spec.Replicas = &replicas
	case ActionRollback:
		if execution.rollbackTarget == nil {
			return nil, errors.New("validated rollback target is missing")
		}
		deployment.Spec.Template = *execution.rollbackTarget.Spec.Template.DeepCopy()
		if deployment.Spec.Template.Labels != nil {
			delete(deployment.Spec.Template.Labels, appsv1.DefaultDeploymentUniqueLabelKey)
		}
		ensureAnnotations(&deployment.Spec.Template.ObjectMeta)
		delete(deployment.Spec.Template.Annotations, "sentinelops.io/health-status")
		deployment.Spec.Template.Annotations[actionIDAnnotation] = remediation.Spec.ActionID
		deployment.Spec.Template.Annotations[fenceGenerationAnnotation] = strconv.FormatInt(
			remediation.Spec.Fence.Generation,
			10,
		)
	default:
		return nil, fmt.Errorf("unsupported registered action %q", remediation.Spec.Action.Plugin)
	}

	if err := r.Update(ctx, deployment); err != nil {
		return nil, err
	}
	return deployment, nil
}

func alreadyApplied(
	remediation *opsv1alpha1.SentinelRemediation,
	deployment *appsv1.Deployment,
) (bool, *validationFailure) {
	annotations := deployment.Annotations
	if annotations == nil {
		return false, nil
	}
	existingActionID := annotations[actionIDAnnotation]
	existingPlugin := annotations[actionPluginAnnotation]
	existingGeneration, err := strconv.ParseInt(annotations[fenceGenerationAnnotation], 10, 64)
	if err != nil && annotations[fenceGenerationAnnotation] != "" {
		return false, stale("FenceMarkerInvalid", "Deployment fence marker is invalid")
	}
	requestedGeneration := remediation.Spec.Fence.Generation
	if existingActionID == remediation.Spec.ActionID {
		if existingGeneration != requestedGeneration {
			return true, stale("FenceMarkerMismatch", "action marker has a different fence")
		}
		if existingPlugin != remediation.Spec.Action.Plugin {
			return true, stale("ActionMarkerMismatch", "action marker has a different plugin")
		}
		switch remediation.Spec.Action.Plugin {
		case ActionRestart, ActionRollback:
			if deployment.Spec.Template.Annotations[actionIDAnnotation] != existingActionID {
				return true, stale("ActionOutcomeUnknown", "template action marker is missing")
			}
		case ActionScale:
			expected := *remediation.Spec.Action.Parameters.Replicas
			if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != expected {
				return true, stale("ActionOutcomeUnknown", "replica count does not match marker")
			}
		}
		return true, nil
	}
	if existingGeneration >= requestedGeneration && existingActionID != "" {
		return false, stale("FenceSuperseded", "a newer or equal target fence already exists")
	}
	return false, nil
}

func (r *Reconciler) markExecuting(
	ctx context.Context,
	remediation *opsv1alpha1.SentinelRemediation,
) error {
	base := remediation.DeepCopy()
	now := metav1.NewTime(r.now())
	remediation.Status.Phase = PhaseExecuting
	remediation.Status.ObservedGeneration = remediation.Generation
	remediation.Status.ControllerID = r.controllerID()
	remediation.Status.Attempt++
	if remediation.Status.StartedAt == nil {
		remediation.Status.StartedAt = &now
	}
	remediation.Status.Reason = "ExecutionStarted"
	apimeta.SetStatusCondition(&remediation.Status.Conditions, metav1.Condition{
		Type:               "Executed",
		Status:             metav1.ConditionUnknown,
		ObservedGeneration: remediation.Generation,
		Reason:             "ExecutionStarted",
		Message:            "registered action is crossing the Kubernetes write boundary",
	})
	return r.Status().Patch(ctx, remediation, client.MergeFrom(base))
}

func (r *Reconciler) finishSuccess(
	ctx context.Context,
	remediation *opsv1alpha1.SentinelRemediation,
	beforeVersion string,
	afterVersion string,
	message string,
) error {
	base := remediation.DeepCopy()
	now := metav1.NewTime(r.now())
	result := &opsv1alpha1.RemediationResult{
		BeforeResourceVersion: beforeVersion,
		AfterResourceVersion:  afterVersion,
		ObservedActionID:      remediation.Spec.ActionID,
		Message:               message,
	}
	result.OutcomeDigest = digestJSON(result)
	remediation.Status.Phase = PhaseSucceeded
	remediation.Status.ObservedGeneration = remediation.Generation
	remediation.Status.ControllerID = r.controllerID()
	remediation.Status.FinishedAt = &now
	remediation.Status.Reason = "ActionApplied"
	remediation.Status.Result = result
	apimeta.SetStatusCondition(&remediation.Status.Conditions, metav1.Condition{
		Type:               "Executed",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: remediation.Generation,
		Reason:             "ActionApplied",
		Message:            message,
	})
	return r.Status().Patch(ctx, remediation, client.MergeFrom(base))
}

func (r *Reconciler) finishFailure(
	ctx context.Context,
	remediation *opsv1alpha1.SentinelRemediation,
	failure *validationFailure,
) error {
	base := remediation.DeepCopy()
	now := metav1.NewTime(r.now())
	remediation.Status.Phase = failure.phase
	remediation.Status.ObservedGeneration = remediation.Generation
	remediation.Status.ControllerID = r.controllerID()
	remediation.Status.FinishedAt = &now
	remediation.Status.Reason = failure.reason
	apimeta.SetStatusCondition(&remediation.Status.Conditions, metav1.Condition{
		Type:               "Executed",
		Status:             metav1.ConditionFalse,
		ObservedGeneration: remediation.Generation,
		Reason:             failure.reason,
		Message:            failure.err.Error(),
	})
	return r.Status().Patch(ctx, remediation, client.MergeFrom(base))
}

func (r *Reconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock().UTC()
	}
	return time.Now().UTC()
}

func (r *Reconciler) controllerID() string {
	if r.ControllerID != "" {
		return r.ControllerID
	}
	return "sentinelops-remediation-controller"
}

func rejected(reason string, message string) *validationFailure {
	return &validationFailure{
		phase: PhaseRejected, reason: reason, err: errors.New(message),
	}
}

func stale(reason string, message string) *validationFailure {
	return &validationFailure{
		phase: PhaseStale, reason: reason, err: errors.New(message),
	}
}

func isTerminal(phase string) bool {
	switch phase {
	case PhaseSucceeded, PhaseFailed, PhaseRejected, PhaseStale, "Cancelled":
		return true
	default:
		return false
	}
}

func ensureAnnotations(metadata *metav1.ObjectMeta) {
	if metadata.Annotations == nil {
		metadata.Annotations = map[string]string{}
	}
}

func validateParameters(action opsv1alpha1.RemediationAction) *validationFailure {
	switch action.Plugin {
	case ActionRestart:
		if action.Parameters.Revision != nil || action.Parameters.Replicas != nil {
			return rejected("InvalidActionParameters", "restart accepts only a target name")
		}
	case ActionRollback:
		if action.Parameters.Revision == nil || action.Parameters.Replicas != nil {
			return rejected("InvalidActionParameters", "rollback requires one revision")
		}
	case ActionScale:
		if action.Parameters.Replicas == nil || action.Parameters.Revision != nil {
			return rejected("InvalidActionParameters", "scale requires one replica count")
		}
	default:
		return rejected("ActionNotRegistered", "action is not registered")
	}
	return nil
}

func validateAuthorization(
	spec opsv1alpha1.SentinelRemediationSpec,
) *validationFailure {
	authorization := spec.Authorization
	expectedPolicyDigest := AuthorizationPolicyDigest(
		spec.Action.Plugin,
		authorization.Decision,
		spec.Action.CatalogDigest,
	)
	if authorization.PolicyDigest != expectedPolicyDigest {
		return rejected(
			"AuthorizationPolicyDigestMismatch",
			"authorization policy digest does not match the action contract",
		)
	}
	switch authorization.Decision {
	case "human_approval":
		if authorization.ApprovalID == "" ||
			authorization.ApprovalVersion == nil ||
			authorization.ApprovalDigest == "" {
			return rejected("ApprovalBindingMissing", "human approval binding is incomplete")
		}
		expectedApprovalDigest := HumanApprovalDigest(
			spec.ActionID,
			authorization.ApprovalID,
			*authorization.ApprovalVersion,
			authorization.PolicyDigest,
		)
		if authorization.ApprovalDigest != expectedApprovalDigest {
			return rejected(
				"ApprovalDigestMismatch",
				"human approval digest does not match the immutable action",
			)
		}
	case "risk_policy":
		if authorization.ApprovalID != "" ||
			authorization.ApprovalVersion != nil ||
			authorization.ApprovalDigest != "" {
			return rejected("AutomaticAuthorizationInvalid", "automatic decision carries approval data")
		}
	default:
		return rejected("AuthorizationInvalid", "authorization decision is unsupported")
	}
	return nil
}

func ownedReplicaSets(
	deployment *appsv1.Deployment,
	items []appsv1.ReplicaSet,
) []appsv1.ReplicaSet {
	owned := make([]appsv1.ReplicaSet, 0, len(items))
	for i := range items {
		for _, owner := range items[i].OwnerReferences {
			if owner.Controller != nil && *owner.Controller && owner.UID == deployment.UID {
				owned = append(owned, items[i])
				break
			}
		}
	}
	return owned
}

func replicaSetForRevision(items []appsv1.ReplicaSet, revision int64) *appsv1.ReplicaSet {
	expected := strconv.FormatInt(revision, 10)
	for i := range items {
		if items[i].Annotations["deployment.kubernetes.io/revision"] == expected {
			return &items[i]
		}
	}
	return nil
}

func templateHash(replicaSet *appsv1.ReplicaSet) string {
	if replicaSet.Labels[appsv1.DefaultDeploymentUniqueLabelKey] != "" {
		return replicaSet.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
	}
	return replicaSet.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
}

func validateRollbackProof(
	deployment *appsv1.Deployment,
	replicaSet *appsv1.ReplicaSet,
	expectedDigest string,
	now time.Time,
) *validationFailure {
	annotations := replicaSet.Annotations
	revision := annotations["deployment.kubernetes.io/revision"]
	gitCommit := replicaSet.Spec.Template.Annotations["sentinelops.io/git-commit"]
	proofGitCommit := gitCommit
	if proofGitCommit == "" {
		proofGitCommit = "none"
	}
	imageItems := make([]map[string]string, 0, len(replicaSet.Spec.Template.Spec.Containers))
	for _, container := range replicaSet.Spec.Template.Spec.Containers {
		imageItems = append(imageItems, map[string]string{
			"image": container.Image,
			"name":  container.Name,
		})
	}
	sort.Slice(imageItems, func(i int, j int) bool {
		return imageItems[i]["name"] < imageItems[j]["name"]
	})
	images := prefixedDigestJSON(imageItems)
	runtimeImages := annotations["sentinelops.io/health-proof-runtime-images"]
	subject := prefixedDigestJSON(map[string]string{
		"deployment_uid":  string(deployment.UID),
		"git_commit":      gitCommit,
		"images":          images,
		"replica_set_uid": string(replicaSet.UID),
		"revision":        revision,
		"runtime_images":  runtimeImages,
		"template_hash":   templateHash(replicaSet),
	})
	expectedAnnotations := map[string]string{
		"sentinelops.io/health-proof-deployment-uid": string(deployment.UID),
		"sentinelops.io/health-proof-git-commit":     proofGitCommit,
		"sentinelops.io/health-proof-images":         images,
		"sentinelops.io/health-proof-replicaset-uid": string(replicaSet.UID),
		"sentinelops.io/health-proof-revision":       revision,
		"sentinelops.io/health-proof-status":         "healthy",
		"sentinelops.io/health-proof-subject":        subject,
		"sentinelops.io/health-proof-template-hash":  templateHash(replicaSet),
		"sentinelops.io/health-proof-version":        "v1",
	}
	for key, value := range expectedAnnotations {
		if value == "" || annotations[key] != value {
			return stale("RollbackHealthProofChanged", "rollback health proof is invalid")
		}
	}
	if !strings.HasPrefix(runtimeImages, "sha256:") {
		return stale("RollbackHealthProofChanged", "runtime image proof is invalid")
	}
	verifiedAt := annotations["sentinelops.io/health-proof-verified-at"]
	verifiedTime, err := time.Parse(time.RFC3339, verifiedAt)
	if err != nil || verifiedTime.After(now.Add(5*time.Minute)) {
		return stale("RollbackHealthProofChanged", "rollback verification time is invalid")
	}
	verifier := annotations["sentinelops.io/health-proof-verifier"]
	if strings.TrimSpace(verifier) == "" {
		return stale("RollbackHealthProofChanged", "rollback verifier is missing")
	}
	if RollbackHealthProofDigest(
		subject,
		"v1",
		verifiedAt,
		verifier,
	) != expectedDigest {
		return stale("RollbackHealthProofDigestChanged", "rollback health proof digest changed")
	}
	return nil
}
