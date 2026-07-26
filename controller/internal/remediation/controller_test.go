package remediation

import (
	"context"
	"errors"
	"testing"
	"time"

	opsv1alpha1 "github.com/q741242673/sentinelops/controller/api/v1alpha1"
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
	testNowText    = "2026-07-26T06:00:00Z"
)

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
		Revision:          revision,
		ReplicaSetUID:     rollbackTarget.UID,
		HealthProofDigest: digestJSON(proof),
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
		Client:       kubeClient,
		ControllerID: "controller-after-restart",
		Clock:        func() time.Time { return mustTime(t) },
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
	remediation.Spec.Precondition.SnapshotDigest = SnapshotDigest(
		remediation.Spec.Precondition,
	)
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&opsv1alpha1.SentinelRemediation{}).
		WithObjects(deployment, current, rollback, remediation).
		Build()
	reconciler := &Reconciler{
		Client:       kubeClient,
		Scheme:       scheme,
		ControllerID: "controller-test",
		Clock:        func() time.Time { return mustTime(t) },
	}
	return reconciler, kubeClient, remediation
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
	return map[string]string{
		"deploymentUid": string(deployment.UID),
		"gitCommit":     "commit-v1",
		"images":        "example/order:v1",
		"replicaSetUid": string(replicaSet.UID),
		"revision":      replicaSet.Annotations["deployment.kubernetes.io/revision"],
		"runtimeImages": "example/order@sha256:v1",
		"status":        "healthy",
		"subject":       testNamespace + "/" + testDeployment,
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
				Namespace:  testNamespace,
				Name:       testDeployment,
				UID:        types.UID("deployment-uid"),
			},
			Precondition: opsv1alpha1.ExecutionPrecondition{
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
