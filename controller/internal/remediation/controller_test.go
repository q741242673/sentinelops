package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	opsv1alpha1 "github.com/q741242673/sentinelops/controller/api/v1alpha1"
	"github.com/q741242673/sentinelops/controller/internal/admissionintegrity"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace  = "sentinelops-workloads"
	testDeployment = "order-service"
	testClusterID  = "prod-cluster-a"
	testNowText    = "2026-07-26T06:00:00Z"
)

func TestCrossLanguageContractDigests(t *testing.T) {
	expected := map[string]string{
		ActionRestart:  "c417d3f9952779f103b2a80c8b1271cd15468357e1b4aa3faa7fe5c5d56a1569",
		ActionRollback: "59708f23f4b777687ff488d96caae1676a9b6e04fda417e7a0d95656667e3524",
		ActionScale:    "323e8de7071a289afbdbe2fbb1cfa3c84949ae5dd2155f0cde19b6ee011af591",
	}
	for action, want := range expected {
		got, ok := CatalogDigest(action)
		if !ok || got != want {
			t.Fatalf("CatalogDigest(%q) = %q/%t, want %q/true", action, got, ok, want)
		}
	}
	catalogDigest, _ := CatalogDigest(ActionRollback)
	policyDigest := AuthorizationPolicyDigest(
		ActionRollback,
		"human_approval",
		catalogDigest,
	)
	if policyDigest != "052150405c4500c3df974ebbc2afdbfc581e379401b32db2f42df49efefc6a2f" {
		t.Fatalf("human policy digest = %q", policyDigest)
	}
	if got := HumanApprovalDigest(
		strings.Repeat("a", 64),
		"approval-01",
		3,
		policyDigest,
	); got != "53f3af3433c04424eb546ced8767e954c0bccec9d881643d14716d96e2028388" {
		t.Fatalf("human approval digest = %q", got)
	}
	capturedAt, err := time.Parse(time.RFC3339Nano, "2026-07-26T10:06:19.316941Z")
	if err != nil {
		t.Fatalf("parse snapshot time: %v", err)
	}
	snapshot := opsv1alpha1.ExecutionPrecondition{
		ClusterID:            testClusterID,
		ResourceVersion:      "919",
		Generation:           1,
		DesiredReplicas:      1,
		Paused:               false,
		CurrentRevision:      1,
		CurrentReplicaSetUID: types.UID("b3ff8fd0-5bb3-4a4d-87ef-14dd72d2c637"),
		CurrentTemplateHash:  "6894bfdf4f",
		CapturedAt:           metav1.NewTime(capturedAt),
	}
	if got := SnapshotDigest(snapshot); got !=
		"57fd6030506849b9626899ec3e1a8e8258b30c95c75d954e2ca88ba0b777fa31" {
		t.Fatalf("snapshot digest = %q", got)
	}
}

func TestRestartAppliesRegisteredAction(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)

	reconcileOnce(t, reconciler, remediation)

	deployment := getDeployment(t, kubeClient)
	if got := deployment.Spec.Template.Annotations[actionIDAnnotation]; got != remediation.Name {
		t.Fatalf("restart action marker = %q, want %q", got, remediation.Name)
	}
	if got := deployment.Annotations[actionPluginAnnotation]; got != ActionRestart {
		t.Fatalf("action plugin marker = %q, want %q", got, ActionRestart)
	}
	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestTargetClusterMismatchRejectsBeforeWriteBoundary(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		func(remediation *opsv1alpha1.SentinelRemediation) {
			remediation.Spec.Target.ClusterID = "prod-cluster-b"
		},
	)

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "ClusterIdentityMismatch")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestPreconditionClusterMismatchRejectsBeforeWriteBoundary(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		func(remediation *opsv1alpha1.SentinelRemediation) {
			remediation.Spec.Precondition.ClusterID = "prod-cluster-b"
		},
	)

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "ClusterIdentityMismatch")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestControllerWithoutExpectedClusterRejectsBeforeWriteBoundary(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	reconciler.ExpectedClusterID = ""

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "ClusterIdentityMismatch")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestAdmissionDriftRejectsBeforeDeploymentWrite(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	checker := &fixedIntegrityChecker{result: admissionintegrity.Result{
		Healthy: false,
		Mode:    admissionintegrity.ModeEnforced,
		Object:  "enforce_binding",
		Reason:  "read_failed",
	}}
	reconciler.AdmissionIntegrity = checker.Check

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "AdmissionIntegrityDrift")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
	if checker.calls != 1 {
		t.Fatalf("integrity checks = %d, want 1", checker.calls)
	}
}

func TestAdmissionReadFailureRejectsAsUnknown(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	checker := &fixedIntegrityChecker{
		result: admissionintegrity.Result{
			Healthy: false,
			Unknown: true,
			Mode:    admissionintegrity.ModeUnknown,
			Object:  "workload_policy",
			Reason:  "read_failed",
		},
	}
	reconciler.AdmissionIntegrity = checker.Check

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "AdmissionIntegrityUnknown")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestAdmissionAuditModeRejectsAutomaticWrite(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	checker := &fixedIntegrityChecker{
		result: admissionintegrity.Result{
			Healthy: false,
			Mode:    admissionintegrity.ModeAudit,
			Object:  "namespace",
			Reason:  "enforcement_not_enabled",
		},
	}
	reconciler.AdmissionIntegrity = checker.Check

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "AdmissionFenceNotEnforced")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestHealthyAdmissionIntegrityAllowsRegisteredWrite(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	checker := &fixedIntegrityChecker{
		result: admissionintegrity.Result{
			Healthy: true,
			Mode:    admissionintegrity.ModeEnforced,
		},
	}
	reconciler.AdmissionIntegrity = checker.Check

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestAdmissionIntegrityPermitIsExplicitlyFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		result     admissionintegrity.Result
		wantReason string
	}{
		{
			name: "healthy audit mode",
			result: admissionintegrity.Result{
				Healthy: true,
				Mode:    admissionintegrity.ModeAudit,
			},
			wantReason: "AdmissionFenceNotEnforced",
		},
		{
			name: "healthy unknown result",
			result: admissionintegrity.Result{
				Healthy: true,
				Unknown: true,
				Mode:    admissionintegrity.ModeEnforced,
			},
			wantReason: "AdmissionIntegrityUnknown",
		},
		{
			name:       "zero value result",
			result:     admissionintegrity.Result{},
			wantReason: "AdmissionFenceNotEnforced",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler, kubeClient, remediation := newTestReconciler(
				t,
				ActionRestart,
				nil,
			)
			checker := &fixedIntegrityChecker{result: test.result}
			reconciler.AdmissionIntegrity = checker.Check

			reconcileOnce(t, reconciler, remediation)

			assertPhase(
				t,
				kubeClient,
				remediation,
				PhaseRejected,
				test.wantReason,
			)
			assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
		})
	}
}

func TestFenceExpiringDuringAdmissionPreflightCannotWrite(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	now := mustTime(t)
	reconciler.Clock = func() time.Time { return now }
	reconciler.AdmissionIntegrity = func(context.Context) admissionintegrity.Result {
		now = remediation.Spec.Fence.ExpiresAt.Time.Add(time.Second)
		return admissionintegrity.Result{
			Healthy: true,
			Mode:    admissionintegrity.ModeEnforced,
		}
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "FenceExpired")
	assertNoWriteBoundaryCrossed(t, kubeClient, remediation)
}

func TestDisabledAdmissionIntegrityLeavesRegisteredWriteEnabled(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	if reconciler.AdmissionIntegrity != nil {
		t.Fatal("test setup unexpectedly enabled admission integrity")
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestScaleAppliesRequestedReplicaCount(t *testing.T) {
	replicas := int32(5)
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionScale,
		func(remediation *opsv1alpha1.SentinelRemediation) {
			remediation.Spec.Action.Parameters.Replicas = &replicas
		},
	)

	reconcileOnce(t, reconciler, remediation)

	deployment := getDeployment(t, kubeClient)
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != replicas {
		t.Fatalf("replicas = %v, want %d", deployment.Spec.Replicas, replicas)
	}
	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestRollbackUsesHealthProvedReplicaSet(t *testing.T) {
	revision := int64(1)
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRollback,
		func(remediation *opsv1alpha1.SentinelRemediation) {
			remediation.Spec.Action.Parameters.Revision = &revision
		},
	)
	rollbackTarget := rollbackReplicaSet()
	proof := rollbackProof(getDeployment(t, kubeClient), rollbackTarget)
	remediation.Spec.Precondition.RollbackTarget = &opsv1alpha1.RollbackTarget{
		Revision:      revision,
		ReplicaSetUID: rollbackTarget.UID,
		HealthProofDigest: RollbackHealthProofDigest(
			proof["subject"],
			proof["version"],
			proof["verifiedAt"],
			proof["verifier"],
		),
	}
	remediation.Spec.Precondition.SnapshotDigest = SnapshotDigest(
		remediation.Spec.Precondition,
	)
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("update rollback remediation: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	deployment := getDeployment(t, kubeClient)
	if got := deployment.Spec.Template.Spec.Containers[0].Image; got != "example/order:v1" {
		t.Fatalf("rollback image = %q, want example/order:v1", got)
	}
	if got := deployment.Spec.Template.Annotations[actionIDAnnotation]; got != remediation.Name {
		t.Fatalf("rollback action marker = %q, want %q", got, remediation.Name)
	}
	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestChangedResourceVersionMakesRequestStale(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	remediation.Spec.Precondition.ResourceVersion = "9"
	remediation.Spec.Precondition.SnapshotDigest = SnapshotDigest(
		remediation.Spec.Precondition,
	)
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("make captured resourceVersion stale: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "ResourceVersionChanged")
	deployment := getDeployment(t, kubeClient)
	if deployment.Spec.Template.Annotations[actionIDAnnotation] != "" {
		t.Fatal("stale request mutated the Deployment")
	}
}

func TestExpiredFenceMakesRequestStale(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	expired := metav1.NewTime(mustTime(t).Add(-time.Second))
	remediation.Spec.Fence.ExpiresAt = expired
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("expire remediation: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "FenceExpired")
	deployment := getDeployment(t, kubeClient)
	if deployment.Spec.Template.Annotations[actionIDAnnotation] != "" {
		t.Fatal("expired request mutated the Deployment")
	}
}

func TestCatalogDigestMismatchRejectsRequest(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	remediation.Spec.Action.CatalogDigest = "untrusted-catalog"
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("change catalog digest: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "CatalogDigestMismatch")
}

func TestFenceMustBindCapturedDeploymentGeneration(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	remediation.Spec.Fence.Generation++
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("change fence generation: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "FenceGenerationMismatch")
}

func TestAuthorizationPolicyDigestMismatchRejectsRequest(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	remediation.Spec.Authorization.PolicyDigest = "untrusted-policy"
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("change policy digest: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(
		t,
		kubeClient,
		remediation,
		PhaseRejected,
		"AuthorizationPolicyDigestMismatch",
	)
}

func TestHumanApprovalDigestBindsActionAndVersion(t *testing.T) {
	approvalVersion := int64(3)
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		func(remediation *opsv1alpha1.SentinelRemediation) {
			remediation.Spec.Authorization.Decision = "human_approval"
			remediation.Spec.Authorization.ApprovalID = "approval-01"
			remediation.Spec.Authorization.ApprovalVersion = &approvalVersion
		},
	)
	remediation.Spec.Authorization.ApprovalDigest = "wrong-approval-digest"
	if err := kubeClient.Update(context.Background(), remediation); err != nil {
		t.Fatalf("change approval digest: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseRejected, "ApprovalDigestMismatch")
}

func TestCrashAfterWriteRecoversWithoutRepeatingAction(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	crash := errors.New("simulated controller crash after Kubernetes accepted the write")
	reconciler.AfterWrite = func(
		_ *opsv1alpha1.SentinelRemediation,
		_ *appsv1.Deployment,
	) error {
		return crash
	}

	_, err := reconciler.Reconcile(context.Background(), requestFor(remediation))
	if !errors.Is(err, crash) {
		t.Fatalf("first reconcile error = %v, want simulated crash", err)
	}
	afterCrash := getDeployment(t, kubeClient)
	if got := afterCrash.Spec.Template.Annotations[actionIDAnnotation]; got != remediation.Name {
		t.Fatalf("write was not persisted before crash: marker = %q", got)
	}

	restarted := &Reconciler{
		Client:            kubeClient,
		ControllerID:      "controller-after-restart",
		ExpectedClusterID: testClusterID,
		Clock:             func() time.Time { return mustTime(t) },
	}
	reconcileOnce(t, restarted, remediation)

	afterRecovery := getDeployment(t, kubeClient)
	if got := afterRecovery.Spec.Template.Annotations[actionIDAnnotation]; got != remediation.Name {
		t.Fatalf("recovered marker = %q, want %q", got, remediation.Name)
	}
	assertPhase(t, kubeClient, remediation, PhaseSucceeded, "ActionApplied")
}

func TestNewerFencePreventsOldRequest(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	deployment := getDeployment(t, kubeClient)
	if deployment.Annotations == nil {
		deployment.Annotations = map[string]string{}
	}
	deployment.Annotations[actionIDAnnotation] = "newer-action"
	deployment.Annotations[fenceGenerationAnnotation] = "8"
	if err := kubeClient.Update(context.Background(), deployment); err != nil {
		t.Fatalf("write newer fence: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "FenceSuperseded")
	deployment = getDeployment(t, kubeClient)
	if got := deployment.Annotations[actionIDAnnotation]; got != "newer-action" {
		t.Fatalf("old request replaced newer action marker with %q", got)
	}
}

func TestCopiedActionMarkerOnReplacementDeploymentIsNotTrusted(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	deployment := getDeployment(t, kubeClient)
	deployment.UID = types.UID("replacement-deployment-uid")
	deployment.Annotations[actionIDAnnotation] = remediation.Name
	deployment.Annotations[actionPluginAnnotation] = ActionRestart
	deployment.Annotations[fenceGenerationAnnotation] = "4"
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[actionIDAnnotation] = remediation.Name
	if err := kubeClient.Update(context.Background(), deployment); err != nil {
		t.Fatalf("replace Deployment identity: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "TargetUIDChanged")
}

func TestActionMarkerMustBindRegisteredPlugin(t *testing.T) {
	reconciler, kubeClient, remediation := newTestReconciler(
		t,
		ActionRestart,
		nil,
	)
	deployment := getDeployment(t, kubeClient)
	deployment.Annotations[actionIDAnnotation] = remediation.Name
	deployment.Annotations[actionPluginAnnotation] = ActionScale
	deployment.Annotations[fenceGenerationAnnotation] = "4"
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[actionIDAnnotation] = remediation.Name
	if err := kubeClient.Update(context.Background(), deployment); err != nil {
		t.Fatalf("write mismatched action marker: %v", err)
	}

	reconcileOnce(t, reconciler, remediation)

	assertPhase(t, kubeClient, remediation, PhaseStale, "ActionMarkerMismatch")
}

func newTestReconciler(
	t *testing.T,
	action string,
	mutate func(*opsv1alpha1.SentinelRemediation),
) (*Reconciler, client.Client, *opsv1alpha1.SentinelRemediation) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add apps scheme: %v", err)
	}
	if err := opsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add remediation scheme: %v", err)
	}
	deployment := baseDeployment()
	current := currentReplicaSet()
	rollback := rollbackReplicaSet()
	remediation := baseRemediation(action)
	if mutate != nil {
		mutate(remediation)
	}
	remediation.Spec.Action.CatalogDigest = mustCatalogDigest(t, action)
	remediation.Spec.Authorization.PolicyDigest = AuthorizationPolicyDigest(
		action,
		remediation.Spec.Authorization.Decision,
		remediation.Spec.Action.CatalogDigest,
	)
	if remediation.Spec.Authorization.Decision == "human_approval" {
		remediation.Spec.Authorization.ApprovalDigest = HumanApprovalDigest(
			remediation.Spec.ActionID,
			remediation.Spec.Authorization.ApprovalID,
			*remediation.Spec.Authorization.ApprovalVersion,
			remediation.Spec.Authorization.PolicyDigest,
		)
	}
	remediation.Spec.Precondition.SnapshotDigest = SnapshotDigest(
		remediation.Spec.Precondition,
	)
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&opsv1alpha1.SentinelRemediation{}).
		WithObjects(deployment, current, rollback, remediation).
		Build()
	reconciler := &Reconciler{
		Client:            kubeClient,
		Scheme:            scheme,
		ControllerID:      "controller-test",
		ExpectedClusterID: testClusterID,
		Clock:             func() time.Time { return mustTime(t) },
	}
	return reconciler, kubeClient, remediation
}

type fixedIntegrityChecker struct {
	result admissionintegrity.Result
	calls  int
}

func (f *fixedIntegrityChecker) Check(context.Context) admissionintegrity.Result {
	f.calls++
	return f.result
}

func assertNoWriteBoundaryCrossed(
	t *testing.T,
	kubeClient client.Client,
	remediation *opsv1alpha1.SentinelRemediation,
) {
	t.Helper()
	deployment := getDeployment(t, kubeClient)
	if deployment.Annotations[actionIDAnnotation] != "" ||
		deployment.Spec.Template.Annotations[actionIDAnnotation] != "" {
		t.Fatal("admission integrity failure mutated the Deployment")
	}
	actual := &opsv1alpha1.SentinelRemediation{}
	if err := kubeClient.Get(
		context.Background(),
		client.ObjectKeyFromObject(remediation),
		actual,
	); err != nil {
		t.Fatalf("get remediation: %v", err)
	}
	if actual.Status.Attempt != 0 || actual.Status.StartedAt != nil {
		t.Fatalf(
			"write boundary was marked before rejection: attempt=%d startedAt=%v",
			actual.Status.Attempt,
			actual.Status.StartedAt,
		)
	}
}

func baseDeployment() *appsv1.Deployment {
	replicas := int32(3)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            testDeployment,
			Namespace:       testNamespace,
			UID:             types.UID("deployment-uid"),
			ResourceVersion: "10",
			Generation:      4,
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": "2",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": testDeployment},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": testDeployment},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "example/order:v2"},
					},
				},
			},
		},
	}
}

func currentReplicaSet() *appsv1.ReplicaSet {
	return replicaSet("order-service-current", "replicaset-current-uid", "2", "hash-v2", "v2")
}

func rollbackReplicaSet() *appsv1.ReplicaSet {
	replicaSet := replicaSet(
		"order-service-rollback",
		"replicaset-rollback-uid",
		"1",
		"hash-v1",
		"v1",
	)
	proof := rollbackProof(baseDeployment(), replicaSet)
	replicaSet.Annotations["sentinelops.io/health-proof-version"] = proof["version"]
	replicaSet.Annotations["sentinelops.io/health-proof-status"] = proof["status"]
	replicaSet.Annotations["sentinelops.io/health-proof-subject"] = proof["subject"]
	replicaSet.Annotations["sentinelops.io/health-proof-deployment-uid"] = proof["deploymentUid"]
	replicaSet.Annotations["sentinelops.io/health-proof-replicaset-uid"] = proof["replicaSetUid"]
	replicaSet.Annotations["sentinelops.io/health-proof-revision"] = proof["revision"]
	replicaSet.Annotations["sentinelops.io/health-proof-template-hash"] = proof["templateHash"]
	replicaSet.Annotations["sentinelops.io/health-proof-images"] = proof["images"]
	replicaSet.Annotations["sentinelops.io/health-proof-runtime-images"] = proof["runtimeImages"]
	replicaSet.Annotations["sentinelops.io/health-proof-git-commit"] = proof["gitCommit"]
	replicaSet.Annotations["sentinelops.io/health-proof-verified-at"] = proof["verifiedAt"]
	replicaSet.Annotations["sentinelops.io/health-proof-verifier"] = proof["verifier"]
	return replicaSet
}

func replicaSet(
	name string,
	uid string,
	revision string,
	hash string,
	imageTag string,
) *appsv1.ReplicaSet {
	controller := true
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			UID:       types.UID(uid),
			Labels: map[string]string{
				appsv1.DefaultDeploymentUniqueLabelKey: hash,
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": revision,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       testDeployment,
					UID:        types.UID("deployment-uid"),
					Controller: &controller,
				},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                                  testDeployment,
						appsv1.DefaultDeploymentUniqueLabelKey: hash,
					},
					Annotations: map[string]string{
						"sentinelops.io/health-status": "healthy",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "example/order:" + imageTag},
					},
				},
			},
		},
	}
}

func rollbackProof(
	deployment *appsv1.Deployment,
	replicaSet *appsv1.ReplicaSet,
) map[string]string {
	runtimeImages := "sha256:runtime-v1"
	images := prefixedDigestJSON([]map[string]string{
		{"image": "example/order:v1", "name": "app"},
	})
	subject := prefixedDigestJSON(map[string]string{
		"deployment_uid":  string(deployment.UID),
		"git_commit":      "",
		"images":          images,
		"replica_set_uid": string(replicaSet.UID),
		"revision":        replicaSet.Annotations["deployment.kubernetes.io/revision"],
		"runtime_images":  runtimeImages,
		"template_hash":   templateHash(replicaSet),
	})
	return map[string]string{
		"deploymentUid": string(deployment.UID),
		"gitCommit":     "none",
		"images":        images,
		"replicaSetUid": string(replicaSet.UID),
		"revision":      replicaSet.Annotations["deployment.kubernetes.io/revision"],
		"runtimeImages": runtimeImages,
		"status":        "healthy",
		"subject":       subject,
		"templateHash":  templateHash(replicaSet),
		"verifiedAt":    "2026-07-26T05:30:00Z",
		"verifier":      "sentinelops-health-proof/v1",
		"version":       "v1",
	}
}

func baseRemediation(action string) *opsv1alpha1.SentinelRemediation {
	now, err := time.Parse(time.RFC3339, testNowText)
	if err != nil {
		panic(err)
	}
	captured := metav1.NewTime(now.Add(-time.Minute))
	expires := metav1.NewTime(now.Add(5 * time.Minute))
	return &opsv1alpha1.SentinelRemediation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: opsv1alpha1.GroupVersion.String(),
			Kind:       "SentinelRemediation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "action-01",
			Namespace:  testNamespace,
			Generation: 1,
		},
		Spec: opsv1alpha1.SentinelRemediationSpec{
			ActionID:   "action-01",
			IncidentID: "incident-01",
			Action: opsv1alpha1.RemediationAction{
				Plugin: action,
				Parameters: opsv1alpha1.ActionParameters{
					Name: testDeployment,
				},
			},
			Target: opsv1alpha1.RemediationTarget{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				ClusterID:  testClusterID,
				Namespace:  testNamespace,
				Name:       testDeployment,
				UID:        types.UID("deployment-uid"),
			},
			Precondition: opsv1alpha1.ExecutionPrecondition{
				ClusterID:            testClusterID,
				ResourceVersion:      "10",
				Generation:           4,
				DesiredReplicas:      3,
				Paused:               false,
				CurrentRevision:      2,
				CurrentReplicaSetUID: types.UID("replicaset-current-uid"),
				CurrentTemplateHash:  "hash-v2",
				CapturedAt:           captured,
			},
			Authorization: opsv1alpha1.ExecutionAuthorization{
				Decision:     "risk_policy",
				PolicyDigest: "policy-digest",
			},
			Fence: opsv1alpha1.ExecutionFence{
				Generation: 4,
				ExpiresAt:  expires,
			},
		},
	}
}

func reconcileOnce(
	t *testing.T,
	reconciler *Reconciler,
	remediation *opsv1alpha1.SentinelRemediation,
) {
	t.Helper()
	if _, err := reconciler.Reconcile(
		context.Background(),
		requestFor(remediation),
	); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func requestFor(remediation *opsv1alpha1.SentinelRemediation) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: remediation.Namespace,
			Name:      remediation.Name,
		},
	}
}

func getDeployment(t *testing.T, kubeClient client.Client) *appsv1.Deployment {
	t.Helper()
	deployment := &appsv1.Deployment{}
	if err := kubeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: testNamespace, Name: testDeployment},
		deployment,
	); err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	return deployment
}

func assertPhase(
	t *testing.T,
	kubeClient client.Client,
	remediation *opsv1alpha1.SentinelRemediation,
	phase string,
	reason string,
) {
	t.Helper()
	actual := &opsv1alpha1.SentinelRemediation{}
	if err := kubeClient.Get(
		context.Background(),
		client.ObjectKeyFromObject(remediation),
		actual,
	); err != nil {
		t.Fatalf("get remediation: %v", err)
	}
	if actual.Status.Phase != phase || actual.Status.Reason != reason {
		t.Fatalf(
			"status = %s/%s, want %s/%s",
			actual.Status.Phase,
			actual.Status.Reason,
			phase,
			reason,
		)
	}
}

func mustCatalogDigest(t *testing.T, action string) string {
	t.Helper()
	digest, ok := CatalogDigest(action)
	if !ok {
		t.Fatalf("missing catalog digest for %q", action)
	}
	return digest
}

func mustTime(t *testing.T) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339, testNowText)
	if err != nil {
		t.Fatalf("parse fixed time: %v", err)
	}
	return value
}
