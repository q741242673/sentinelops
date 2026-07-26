package admissionintegrity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const testNamespace = "sentinelops-workloads"

func TestHealthyEnforcedBundlePasses(t *testing.T) {
	checker := newTestChecker(t, healthyObjects())

	result := checker.Check(context.Background())

	if !result.Healthy || result.Mode != ModeEnforced {
		t.Fatalf("result = %#v, want healthy enforced", result)
	}
}

func TestAuditOnlyBundleBlocksAutomaticRemediation(t *testing.T) {
	objects := healthyObjects()
	namespace := objects[keyFor(
		schema.GroupVersionKind{Version: "v1", Kind: "Namespace"},
		"",
		testNamespace,
	)]
	namespace.SetLabels(map[string]string{
		"sentinelops.io/admission-audit": "true",
	})
	checker := newTestChecker(t, objects)

	result := checker.Check(context.Background())

	if result.Healthy || result.Mode != ModeAudit ||
		result.Reason != "enforcement_not_enabled" {
		t.Fatalf("result = %#v, want blocked audit mode", result)
	}
}

func TestMissingBindingFailsClosedAsUnknown(t *testing.T) {
	objects := healthyObjects()
	delete(objects, keyFor(
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicyBinding",
		},
		"",
		"sentinelops-workload-write-fence",
	))
	checker := newTestChecker(t, objects)

	result := checker.Check(context.Background())

	if result.Healthy || !result.Unknown ||
		result.Object != "enforce_binding" ||
		result.Reason != "read_failed" {
		t.Fatalf("result = %#v, want unknown enforce binding", result)
	}
}

func TestUnexpectedGuardWriterIsDetected(t *testing.T) {
	objects := healthyObjects()
	guard := objects[keyFor(
		schema.GroupVersionKind{
			Group: "ops.sentinelops.io", Version: "v1alpha1",
			Kind: "SentinelAdmissionGuard",
		},
		testNamespace,
		"sentinelops-workload-write-fence",
	)]
	writers, _, _ := unstructured.NestedSlice(
		guard.Object,
		"spec",
		"allowedDeploymentWriters",
	)
	writers = append(writers, "system:serviceaccount:default:intruder")
	if err := unstructured.SetNestedSlice(
		guard.Object,
		writers,
		"spec",
		"allowedDeploymentWriters",
	); err != nil {
		t.Fatalf("mutate guard: %v", err)
	}
	checker := newTestChecker(t, objects)

	result := checker.Check(context.Background())

	if result.Healthy || result.Object != "guard" ||
		result.Reason != "spec_mismatch" {
		t.Fatalf("result = %#v, want guard drift", result)
	}
}

func TestAuthorizationExpressionWeakeningIsDetected(t *testing.T) {
	objects := healthyObjects()
	policy := objects[keyFor(
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicy",
		},
		"",
		"sentinelops-workload-write-fence",
	)]
	validations, _, _ := unstructured.NestedSlice(
		policy.Object,
		"spec",
		"validations",
	)
	first := validations[0].(map[string]any)
	first["expression"] = first["expression"].(string) + " || true"
	if err := unstructured.SetNestedSlice(
		policy.Object,
		validations,
		"spec",
		"validations",
	); err != nil {
		t.Fatalf("mutate policy: %v", err)
	}
	checker := newTestChecker(t, objects)

	result := checker.Check(context.Background())

	if result.Healthy || result.Object != "workload_policy" ||
		result.Reason != "authorization_expression_changed" {
		t.Fatalf("result = %#v, want policy drift", result)
	}
}

func TestUnobservedPolicyGenerationIsDetected(t *testing.T) {
	objects := healthyObjects()
	policy := objects[keyFor(
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicy",
		},
		"",
		"sentinelops-workload-write-fence",
	)]
	policy.SetGeneration(2)
	checker := newTestChecker(t, objects)

	result := checker.Check(context.Background())

	if result.Healthy || result.Reason != "generation_not_observed" {
		t.Fatalf("result = %#v, want unobserved generation", result)
	}
}

func TestCRDContractWeakeningIsDetected(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*unstructured.Unstructured)
		reason string
	}{
		{
			name: "identity",
			mutate: func(object *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(
					object.Object,
					"OtherGuard",
					"spec",
					"names",
					"kind",
				)
			},
			reason: "identity_changed",
		},
		{
			name: "stored version",
			mutate: func(object *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(
					object.Object,
					[]any{"v1beta1"},
					"status",
					"storedVersions",
				)
			},
			reason: "stored_version_changed",
		},
		{
			name: "required field",
			mutate: func(object *unstructured.Unstructured) {
				versions, _, _ := unstructured.NestedSlice(
					object.Object,
					"spec",
					"versions",
				)
				spec := versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)["properties"].(map[string]any)["spec"].(map[string]any)
				spec["required"] = []any{"allowedDeploymentWriters"}
				_ = unstructured.SetNestedSlice(
					object.Object,
					versions,
					"spec",
					"versions",
				)
			},
			reason: "schema_weakened",
		},
		{
			name: "set semantics",
			mutate: func(object *unstructured.Unstructured) {
				versions, _, _ := unstructured.NestedSlice(
					object.Object,
					"spec",
					"versions",
				)
				spec := versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)["properties"].(map[string]any)["spec"].(map[string]any)
				properties := spec["properties"].(map[string]any)
				properties["allowedPolicyManagers"].(map[string]any)["x-kubernetes-list-type"] = "atomic"
				_ = unstructured.SetNestedSlice(
					object.Object,
					versions,
					"spec",
					"versions",
				)
			},
			reason: "schema_weakened",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := crd(
				"sentineladmissionguards.ops.sentinelops.io",
				"SentinelAdmissionGuard",
				false,
			)
			test.mutate(object)
			if reason := validateCRD(object, "SentinelAdmissionGuard"); reason != test.reason {
				t.Fatalf("reason = %q, want %q", reason, test.reason)
			}
		})
	}
}

func TestGuardSpecParserRejectsUnknownFields(t *testing.T) {
	_, err := ParseGuardSpec(`{"allowedPolicyManagers":[],"extra":[]}`)
	if err == nil {
		t.Fatal("invalid guard baseline was accepted")
	}
}

type mapReader struct {
	objects map[string]*unstructured.Unstructured
	err     error
}

func (m *mapReader) Get(
	_ context.Context,
	key client.ObjectKey,
	object client.Object,
	_ ...client.GetOption,
) error {
	if m.err != nil {
		return m.err
	}
	target := object.(*unstructured.Unstructured)
	source := m.objects[keyFor(
		target.GroupVersionKind(),
		key.Namespace,
		key.Name,
	)]
	if source == nil {
		return errors.New("not found")
	}
	target.Object = runtime.DeepCopyJSON(source.Object)
	return nil
}

func newTestChecker(
	t *testing.T,
	objects map[string]*unstructured.Unstructured,
) *Checker {
	t.Helper()
	spec := guardSpec()
	checker, err := NewChecker(&mapReader{objects: objects}, Config{
		Namespace:            testNamespace,
		PolicyName:           "sentinelops-workload-write-fence",
		GovernancePolicyName: "sentinelops-admission-governance",
		GuardName:            "sentinelops-workload-write-fence",
		ExpectedGuardSpec:    spec,
		RequestTimeout:       time.Second,
	})
	if err != nil {
		t.Fatalf("create checker: %v", err)
	}
	checker.now = func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}
	return checker
}

func healthyObjects() map[string]*unstructured.Unstructured {
	objects := map[string]*unstructured.Unstructured{}
	add := func(object *unstructured.Unstructured) {
		objects[keyFor(
			object.GroupVersionKind(),
			object.GetNamespace(),
			object.GetName(),
		)] = object
	}
	namespace := resource(
		schema.GroupVersionKind{Version: "v1", Kind: "Namespace"},
		"",
		testNamespace,
		nil,
	)
	namespace.SetLabels(map[string]string{
		"sentinelops.io/admission-protected": "true",
	})
	add(namespace)
	add(crd(
		"sentineladmissionguards.ops.sentinelops.io",
		"SentinelAdmissionGuard",
		false,
	))
	add(crd(
		"sentinelremediations.ops.sentinelops.io",
		"SentinelRemediation",
		true,
	))
	add(workloadPolicy())
	add(governancePolicy())
	add(binding(
		"sentinelops-workload-write-fence-audit",
		"sentinelops-workload-write-fence",
		[]any{"Warn", "Audit"},
		map[string]any{"sentinelops.io/admission-audit": "true"},
	))
	add(binding(
		"sentinelops-workload-write-fence",
		"sentinelops-workload-write-fence",
		[]any{"Deny", "Audit"},
		map[string]any{"sentinelops.io/admission-protected": "true"},
	))
	add(binding(
		"sentinelops-admission-governance",
		"sentinelops-admission-governance",
		[]any{"Deny", "Audit"},
		nil,
	))
	add(resource(
		schema.GroupVersionKind{
			Group: "ops.sentinelops.io", Version: "v1alpha1",
			Kind: "SentinelAdmissionGuard",
		},
		testNamespace,
		"sentinelops-workload-write-fence",
		guardSpec(),
	))
	return objects
}

func resource(
	gvk schema.GroupVersionKind,
	namespace string,
	name string,
	spec map[string]any,
) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
		"metadata": map[string]any{
			"name":       name,
			"namespace":  namespace,
			"generation": int64(1),
		},
	}}
	if spec != nil {
		object.Object["spec"] = spec
	}
	object.SetGroupVersionKind(gvk)
	return object
}

func crd(name string, kind string, statusSubresource bool) *unstructured.Unstructured {
	required := []any{
		"allowedDeploymentWriters",
		"allowedPolicyManagers",
		"allowedRemediationCreators",
		"allowedRemediationDeleters",
		"allowedRemediationStatusWriters",
	}
	if kind == "SentinelRemediation" {
		required = []any{"action", "actionId", "authorization", "fence", "incidentId", "precondition", "target"}
	}
	properties := map[string]any{}
	if kind == "SentinelAdmissionGuard" {
		for _, item := range required {
			properties[item.(string)] = map[string]any{
				"type":                   "array",
				"x-kubernetes-list-type": "set",
			}
		}
	}
	version := map[string]any{
		"name":    "v1alpha1",
		"served":  true,
		"storage": true,
		"schema": map[string]any{
			"openAPIV3Schema": map[string]any{
				"properties": map[string]any{
					"spec": map[string]any{
						"required":   required,
						"properties": properties,
					},
				},
			},
		},
	}
	if statusSubresource {
		version["subresources"] = map[string]any{"status": map[string]any{}}
	}
	object := resource(
		schema.GroupVersionKind{
			Group: "apiextensions.k8s.io", Version: "v1",
			Kind: "CustomResourceDefinition",
		},
		"",
		name,
		map[string]any{
			"group": "ops.sentinelops.io",
			"scope": "Namespaced",
			"names": map[string]any{
				"kind":   kind,
				"plural": strings.ToLower(kind) + "s",
			},
			"versions": []any{version},
		},
	)
	object.Object["status"] = map[string]any{
		"storedVersions": []any{"v1alpha1"},
		"conditions": []any{
			map[string]any{"type": "Established", "status": "True"},
			map[string]any{"type": "NamesAccepted", "status": "True"},
		},
	}
	return object
}

func workloadPolicy() *unstructured.Unstructured {
	spec := policySpec(
		[]any{
			variable("isDeployment", "request.resource.group == 'apps' && request.resource.resource == 'deployments'"),
			variable("isRemediation", "request.resource.group == 'ops.sentinelops.io' && request.resource.resource == 'sentinelremediations'"),
		},
		[]any{
			validation("!variables.isDeployment || request.userInfo.username in params.spec.allowedDeploymentWriters"),
			validation("!variables.isRemediation || request.operation != 'CREATE' || request.userInfo.username in params.spec.allowedRemediationCreators"),
			validation("!variables.isRemediation || request.operation != 'UPDATE' || request.subResource == 'status'"),
			validation("!variables.isRemediation || request.operation != 'UPDATE' || request.subResource != 'status' || request.userInfo.username in params.spec.allowedRemediationStatusWriters"),
			validation("!variables.isRemediation || request.operation != 'DELETE' || request.userInfo.username in params.spec.allowedRemediationDeleters"),
		},
		[]any{
			rule([]any{"apps"}, []any{"v1"}, []any{"CREATE", "UPDATE", "DELETE"}, []any{"deployments"}, "Namespaced"),
			rule([]any{"ops.sentinelops.io"}, []any{"v1alpha1"}, []any{"CREATE", "UPDATE", "DELETE"}, []any{"sentinelremediations", "sentinelremediations/status"}, "Namespaced"),
		},
	)
	return policy("sentinelops-workload-write-fence", spec)
}

func governancePolicy() *unstructured.Unstructured {
	spec := policySpec(
		[]any{
			variable("isGuard", "request.resource.group == 'ops.sentinelops.io' && request.resource.resource == 'sentineladmissionguards'"),
			variable("isNamespace", "request.resource.group == '' && request.resource.resource == 'namespaces'"),
			variable("oldProtection", "variables.isNamespace && has(oldObject.metadata.labels) && 'sentinelops.io/admission-protected' in oldObject.metadata.labels ? oldObject.metadata.labels['sentinelops.io/admission-protected'] : ''"),
			variable("newProtection", "variables.isNamespace && has(object.metadata.labels) && 'sentinelops.io/admission-protected' in object.metadata.labels ? object.metadata.labels['sentinelops.io/admission-protected'] : ''"),
		},
		[]any{
			validation("!variables.isGuard || request.name != params.metadata.name || request.namespace != params.metadata.namespace || request.userInfo.username in params.spec.allowedPolicyManagers"),
			validation("!variables.isNamespace || request.name != params.metadata.namespace || variables.oldProtection == variables.newProtection || request.userInfo.username in params.spec.allowedPolicyManagers"),
		},
		[]any{
			rule([]any{"ops.sentinelops.io"}, []any{"v1alpha1"}, []any{"UPDATE", "DELETE"}, []any{"sentineladmissionguards"}, "*"),
			rule([]any{""}, []any{"v1"}, []any{"UPDATE"}, []any{"namespaces"}, "Cluster"),
		},
	)
	return policy("sentinelops-admission-governance", spec)
}

func policy(name string, spec map[string]any) *unstructured.Unstructured {
	object := resource(
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicy",
		},
		"",
		name,
		spec,
	)
	object.Object["status"] = map[string]any{
		"observedGeneration": int64(1),
		"typeChecking":       map[string]any{},
	}
	return object
}

func policySpec(
	variables []any,
	validations []any,
	rules []any,
) map[string]any {
	return map[string]any{
		"failurePolicy": "Fail",
		"paramKind": map[string]any{
			"apiVersion": "ops.sentinelops.io/v1alpha1",
			"kind":       "SentinelAdmissionGuard",
		},
		"matchConstraints": map[string]any{
			"matchPolicy":   "Equivalent",
			"resourceRules": rules,
		},
		"variables":   variables,
		"validations": validations,
	}
}

func variable(name string, expression string) map[string]any {
	return map[string]any{"name": name, "expression": expression}
}

func validation(expression string) map[string]any {
	return map[string]any{"expression": expression, "reason": "Forbidden"}
}

func rule(
	groups []any,
	versions []any,
	operations []any,
	resources []any,
	scope string,
) map[string]any {
	value := map[string]any{
		"apiGroups":   groups,
		"apiVersions": versions,
		"operations":  operations,
		"resources":   resources,
	}
	if scope != "" {
		value["scope"] = scope
	}
	return value
}

func binding(
	name string,
	policyName string,
	actions []any,
	selector map[string]any,
) *unstructured.Unstructured {
	spec := map[string]any{
		"policyName":        policyName,
		"validationActions": actions,
		"paramRef": map[string]any{
			"name":                    "sentinelops-workload-write-fence",
			"namespace":               testNamespace,
			"parameterNotFoundAction": "Deny",
		},
	}
	if selector != nil {
		spec["matchResources"] = map[string]any{
			"namespaceSelector": map[string]any{
				"matchLabels": selector,
			},
		}
	}
	return resource(
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicyBinding",
		},
		"",
		name,
		spec,
	)
}

func guardSpec() map[string]any {
	return map[string]any{
		"allowedPolicyManagers": []any{
			"system:serviceaccount:sentinelops-system:sentinelops-admission-admin",
		},
		"allowedDeploymentWriters": []any{
			"system:serviceaccount:sentinelops-system:sentinelops-remediation-controller",
		},
		"allowedRemediationCreators": []any{
			"system:serviceaccount:sentinelops-system:sentinelops-executor",
		},
		"allowedRemediationStatusWriters": []any{
			"system:serviceaccount:sentinelops-system:sentinelops-remediation-controller",
		},
		"allowedRemediationDeleters": []any{},
	}
}

func keyFor(
	gvk schema.GroupVersionKind,
	namespace string,
	name string,
) string {
	return gvk.String() + "|" + namespace + "|" + name
}
