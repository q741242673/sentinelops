package admissionintegrity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	ModeEnforced = "enforced"
	ModeAudit    = "audit"
	ModeDisabled = "disabled"
	ModeUnknown  = "unknown"
)

var (
	integrityHealthy = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sentinelops_admission_integrity_healthy",
		Help: "Whether the live admission bundle permits automatic remediation.",
	})
	integrityMode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sentinelops_admission_integrity_mode",
		Help: "One-hot live admission enforcement mode.",
	}, []string{"mode"})
	lastCheck = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sentinelops_admission_integrity_last_check_timestamp_seconds",
		Help: "Unix timestamp of the latest admission integrity check.",
	})
	drift = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sentinelops_admission_integrity_drift",
		Help: "Current bounded admission drift reason.",
	}, []string{"object", "reason"})
)

func init() {
	metrics.Registry.MustRegister(integrityHealthy, integrityMode, lastCheck, drift)
}

type Reader interface {
	Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error
}

type Config struct {
	Namespace            string
	PolicyName           string
	GovernancePolicyName string
	GuardName            string
	ExpectedGuardSpec    map[string]any
	RequestTimeout       time.Duration
}

type Result struct {
	Healthy bool
	Unknown bool
	Mode    string
	Object  string
	Reason  string
}

type Checker struct {
	reader Reader
	config Config
	now    func() time.Time
}

func NewChecker(reader Reader, config Config) (*Checker, error) {
	if reader == nil {
		return nil, errors.New("admission integrity reader is required")
	}
	if config.Namespace == "" || config.PolicyName == "" ||
		config.GovernancePolicyName == "" || config.GuardName == "" {
		return nil, errors.New("admission integrity object names are required")
	}
	if len(config.ExpectedGuardSpec) == 0 {
		return nil, errors.New("expected SentinelAdmissionGuard spec is required")
	}
	if config.RequestTimeout <= 0 {
		return nil, errors.New("admission integrity request timeout must be positive")
	}
	config.ExpectedGuardSpec = normalizeGuardSpec(config.ExpectedGuardSpec)
	return &Checker{
		reader: reader,
		config: config,
		now:    time.Now,
	}, nil
}

func ParseGuardSpec(payload string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode expected SentinelAdmissionGuard spec: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("expected SentinelAdmissionGuard spec has trailing data")
	}
	expectedKeys := []string{
		"allowedDeploymentWriters",
		"allowedPolicyManagers",
		"allowedRemediationCreators",
		"allowedRemediationDeleters",
		"allowedRemediationStatusWriters",
	}
	actualKeys := make([]string, 0, len(value))
	for key := range value {
		actualKeys = append(actualKeys, key)
	}
	sort.Strings(actualKeys)
	if strings.Join(actualKeys, "\x00") != strings.Join(expectedKeys, "\x00") {
		return nil, errors.New("expected SentinelAdmissionGuard spec has unexpected fields")
	}
	for _, key := range expectedKeys {
		items, ok := value[key].([]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an identity array", key)
		}
		if key != "allowedRemediationDeleters" && len(items) == 0 {
			return nil, fmt.Errorf("%s must not be empty", key)
		}
		seen := map[string]struct{}{}
		for _, item := range items {
			identity, ok := item.(string)
			if !ok || strings.TrimSpace(identity) == "" {
				return nil, fmt.Errorf("%s contains an invalid identity", key)
			}
			if _, duplicate := seen[identity]; duplicate {
				return nil, fmt.Errorf("%s contains a duplicate identity", key)
			}
			seen[identity] = struct{}{}
		}
	}
	return normalizeGuardSpec(value), nil
}

func (c *Checker) Check(ctx context.Context) Result {
	result := c.check(ctx)
	c.record(result)
	return result
}

func (c *Checker) check(ctx context.Context) Result {
	namespace, failure := c.get(
		ctx,
		schema.GroupVersionKind{Version: "v1", Kind: "Namespace"},
		client.ObjectKey{Name: c.config.Namespace},
		"namespace",
	)
	if failure != nil {
		return *failure
	}
	labels := namespace.GetLabels()
	auditEnabled := labels["sentinelops.io/admission-audit"] == "true"
	enforced := labels["sentinelops.io/admission-protected"] == "true"
	mode := ModeDisabled
	if enforced {
		mode = ModeEnforced
	} else if auditEnabled {
		mode = ModeAudit
	}

	for _, crd := range []struct {
		name string
		kind string
	}{
		{"sentineladmissionguards.ops.sentinelops.io", "SentinelAdmissionGuard"},
		{"sentinelremediations.ops.sentinelops.io", "SentinelRemediation"},
	} {
		resource, readFailure := c.get(
			ctx,
			schema.GroupVersionKind{
				Group:   "apiextensions.k8s.io",
				Version: "v1",
				Kind:    "CustomResourceDefinition",
			},
			client.ObjectKey{Name: crd.name},
			"crd",
		)
		if readFailure != nil {
			readFailure.Mode = mode
			return *readFailure
		}
		if reason := validateCRD(resource, crd.kind); reason != "" {
			return unhealthy(mode, "crd", reason)
		}
	}

	workloadPolicy, failure := c.get(
		ctx,
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicy",
		},
		client.ObjectKey{Name: c.config.PolicyName},
		"workload_policy",
	)
	if failure != nil {
		failure.Mode = mode
		return *failure
	}
	if reason := validateWorkloadPolicy(workloadPolicy); reason != "" {
		return unhealthy(mode, "workload_policy", reason)
	}

	governancePolicy, failure := c.get(
		ctx,
		schema.GroupVersionKind{
			Group: "admissionregistration.k8s.io", Version: "v1",
			Kind: "ValidatingAdmissionPolicy",
		},
		client.ObjectKey{Name: c.config.GovernancePolicyName},
		"governance_policy",
	)
	if failure != nil {
		failure.Mode = mode
		return *failure
	}
	if reason := validateGovernancePolicy(governancePolicy); reason != "" {
		return unhealthy(mode, "governance_policy", reason)
	}

	for _, binding := range []struct {
		name     string
		policy   string
		actions  []string
		selector map[string]string
		object   string
	}{
		{
			c.config.PolicyName + "-audit",
			c.config.PolicyName,
			[]string{"Audit", "Warn"},
			map[string]string{"sentinelops.io/admission-audit": "true"},
			"audit_binding",
		},
		{
			c.config.PolicyName,
			c.config.PolicyName,
			[]string{"Audit", "Deny"},
			map[string]string{"sentinelops.io/admission-protected": "true"},
			"enforce_binding",
		},
		{
			c.config.GovernancePolicyName,
			c.config.GovernancePolicyName,
			[]string{"Audit", "Deny"},
			nil,
			"governance_binding",
		},
	} {
		resource, readFailure := c.get(
			ctx,
			schema.GroupVersionKind{
				Group: "admissionregistration.k8s.io", Version: "v1",
				Kind: "ValidatingAdmissionPolicyBinding",
			},
			client.ObjectKey{Name: binding.name},
			binding.object,
		)
		if readFailure != nil {
			readFailure.Mode = mode
			return *readFailure
		}
		if reason := validateBinding(
			resource,
			binding.policy,
			binding.actions,
			c.config.GuardName,
			c.config.Namespace,
			binding.selector,
		); reason != "" {
			return unhealthy(mode, binding.object, reason)
		}
	}

	guard, failure := c.get(
		ctx,
		schema.GroupVersionKind{
			Group: "ops.sentinelops.io", Version: "v1alpha1",
			Kind: "SentinelAdmissionGuard",
		},
		client.ObjectKey{
			Name: c.config.GuardName, Namespace: c.config.Namespace,
		},
		"guard",
	)
	if failure != nil {
		failure.Mode = mode
		return *failure
	}
	spec, ok, err := unstructured.NestedMap(guard.Object, "spec")
	if err != nil || !ok || !equalJSON(
		normalizeGuardSpec(spec),
		c.config.ExpectedGuardSpec,
	) {
		return unhealthy(mode, "guard", "spec_mismatch")
	}

	if mode == ModeAudit {
		return unhealthy(mode, "namespace", "enforcement_not_enabled")
	}
	if mode == ModeDisabled {
		return unhealthy(mode, "namespace", "enforcement_not_enabled")
	}
	return Result{Healthy: true, Mode: ModeEnforced}
}

func (c *Checker) get(
	ctx context.Context,
	gvk schema.GroupVersionKind,
	key client.ObjectKey,
	object string,
) (*unstructured.Unstructured, *Result) {
	value := &unstructured.Unstructured{}
	value.SetGroupVersionKind(gvk)
	readContext, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()
	if err := c.reader.Get(readContext, key, value); err != nil {
		result := Result{
			Healthy: false,
			Unknown: true,
			Mode:    ModeUnknown,
			Object:  object,
			Reason:  "read_failed",
		}
		return nil, &result
	}
	return value, nil
}

func (c *Checker) record(result Result) {
	integrityHealthy.Set(boolFloat(result.Healthy))
	for _, mode := range []string{
		ModeEnforced, ModeAudit, ModeDisabled, ModeUnknown,
	} {
		integrityMode.WithLabelValues(mode).Set(boolFloat(result.Mode == mode))
	}
	drift.Reset()
	if !result.Healthy {
		drift.WithLabelValues(result.Object, result.Reason).Set(1)
	}
	lastCheck.Set(float64(c.now().UTC().Unix()))
}

func unhealthy(mode string, object string, reason string) Result {
	return Result{
		Healthy: false,
		Mode:    mode,
		Object:  object,
		Reason:  reason,
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func normalizeGuardSpec(value map[string]any) map[string]any {
	normalized := make(map[string]any, len(value))
	for key, raw := range value {
		items, ok := raw.([]any)
		if !ok {
			normalized[key] = raw
			continue
		}
		stringsOnly := make([]string, 0, len(items))
		for _, item := range items {
			if text, ok := item.(string); ok {
				stringsOnly = append(stringsOnly, text)
			}
		}
		sort.Strings(stringsOnly)
		converted := make([]any, 0, len(stringsOnly))
		for _, item := range stringsOnly {
			converted = append(converted, item)
		}
		normalized[key] = converted
	}
	return normalized
}

func equalJSON(left any, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func validateCRD(resource *unstructured.Unstructured, kind string) string {
	expectedPlural := "sentineladmissionguards"
	if kind == "SentinelRemediation" {
		expectedPlural = "sentinelremediations"
	}
	group, _, _ := unstructured.NestedString(resource.Object, "spec", "group")
	scope, _, _ := unstructured.NestedString(resource.Object, "spec", "scope")
	actualKind, _, _ := unstructured.NestedString(resource.Object, "spec", "names", "kind")
	plural, _, _ := unstructured.NestedString(resource.Object, "spec", "names", "plural")
	if group != "ops.sentinelops.io" || scope != "Namespaced" ||
		actualKind != kind || plural != expectedPlural {
		return "identity_changed"
	}
	conditions, ok, err := unstructured.NestedSlice(
		resource.Object,
		"status",
		"conditions",
	)
	if err != nil || !ok {
		return "status_not_observed"
	}
	required := map[string]bool{"Established": false, "NamesAccepted": false}
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, tracked := required[fmt.Sprint(condition["type"])]; tracked &&
			fmt.Sprint(condition["status"]) == "True" {
			required[fmt.Sprint(condition["type"])] = true
		}
	}
	if !required["Established"] || !required["NamesAccepted"] {
		return "not_established"
	}
	storedVersions, ok, err := unstructured.NestedFieldNoCopy(
		resource.Object,
		"status",
		"storedVersions",
	)
	if err != nil || !ok || !sameStringSlice(storedVersions, []string{"v1alpha1"}) {
		return "stored_version_changed"
	}
	versions, ok, err := unstructured.NestedSlice(resource.Object, "spec", "versions")
	if err != nil || !ok {
		return "version_missing"
	}
	for _, item := range versions {
		version, ok := item.(map[string]any)
		if !ok || version["name"] != "v1alpha1" ||
			version["served"] != true || version["storage"] != true {
			continue
		}
		schemaValue, schemaOK := version["schema"].(map[string]any)
		openAPI, openAPIOK := schemaValue["openAPIV3Schema"].(map[string]any)
		properties, propertiesOK := openAPI["properties"].(map[string]any)
		spec, specOK := properties["spec"].(map[string]any)
		if !schemaOK || !openAPIOK || !propertiesOK || !specOK {
			return "schema_missing"
		}
		if kind == "SentinelRemediation" {
			subresources, ok := version["subresources"].(map[string]any)
			if !ok {
				return "status_subresource_missing"
			}
			if _, ok := subresources["status"]; !ok {
				return "status_subresource_missing"
			}
		}
		requiredFields := stringSet(spec["required"])
		expected := map[string]struct{}{
			"action":        {},
			"actionId":      {},
			"authorization": {},
			"fence":         {},
			"incidentId":    {},
			"precondition":  {},
			"target":        {},
		}
		if kind == "SentinelAdmissionGuard" {
			expected = map[string]struct{}{
				"allowedDeploymentWriters":        {},
				"allowedPolicyManagers":           {},
				"allowedRemediationCreators":      {},
				"allowedRemediationDeleters":      {},
				"allowedRemediationStatusWriters": {},
			}
		}
		if !sameStringSet(requiredFields, expected) {
			return "schema_weakened"
		}
		if kind == "SentinelAdmissionGuard" {
			specProperties, ok := spec["properties"].(map[string]any)
			if !ok {
				return "schema_weakened"
			}
			for field := range expected {
				property, ok := specProperties[field].(map[string]any)
				if !ok || property["type"] != "array" ||
					property["x-kubernetes-list-type"] != "set" {
					return "schema_weakened"
				}
			}
		}
		return ""
	}
	return "version_missing"
}

func validateWorkloadPolicy(resource *unstructured.Unstructured) string {
	spec, ok, err := unstructured.NestedMap(resource.Object, "spec")
	if err != nil || !ok {
		return "spec_missing"
	}
	if reason := validatePolicyStatus(resource); reason != "" {
		return reason
	}
	if spec["failurePolicy"] != "Fail" || !validParamKind(spec) {
		return "fail_closed_contract_changed"
	}
	expectedVariables := map[string]string{
		"isDeployment":  "request.resource.group == 'apps' && request.resource.resource == 'deployments'",
		"isRemediation": "request.resource.group == 'ops.sentinelops.io' && request.resource.resource == 'sentinelremediations'",
	}
	expectedValidations := []string{
		"!variables.isDeployment || request.userInfo.username in params.spec.allowedDeploymentWriters",
		"!variables.isRemediation || request.operation != 'CREATE' || request.userInfo.username in params.spec.allowedRemediationCreators",
		"!variables.isRemediation || request.operation != 'UPDATE' || request.subResource == 'status'",
		"!variables.isRemediation || request.operation != 'UPDATE' || request.subResource != 'status' || request.userInfo.username in params.spec.allowedRemediationStatusWriters",
		"!variables.isRemediation || request.operation != 'DELETE' || request.userInfo.username in params.spec.allowedRemediationDeleters",
	}
	if !sameVariables(spec["variables"], expectedVariables) ||
		!sameValidations(spec["validations"], expectedValidations) {
		return "authorization_expression_changed"
	}
	expectedRules := []ruleContract{
		{[]string{"apps"}, []string{"v1"}, []string{"CREATE", "DELETE", "UPDATE"}, []string{"deployments"}, "Namespaced"},
		{[]string{"ops.sentinelops.io"}, []string{"v1alpha1"}, []string{"CREATE", "DELETE", "UPDATE"}, []string{"sentinelremediations", "sentinelremediations/status"}, "Namespaced"},
	}
	if !sameRules(spec, expectedRules) {
		return "match_rules_changed"
	}
	return ""
}

func validateGovernancePolicy(resource *unstructured.Unstructured) string {
	spec, ok, err := unstructured.NestedMap(resource.Object, "spec")
	if err != nil || !ok {
		return "spec_missing"
	}
	if reason := validatePolicyStatus(resource); reason != "" {
		return reason
	}
	if spec["failurePolicy"] != "Fail" || !validParamKind(spec) {
		return "fail_closed_contract_changed"
	}
	expectedVariables := map[string]string{
		"isGuard":       "request.resource.group == 'ops.sentinelops.io' && request.resource.resource == 'sentineladmissionguards'",
		"isNamespace":   "request.resource.group == '' && request.resource.resource == 'namespaces'",
		"oldProtection": "variables.isNamespace && has(oldObject.metadata.labels) && 'sentinelops.io/admission-protected' in oldObject.metadata.labels ? oldObject.metadata.labels['sentinelops.io/admission-protected'] : ''",
		"newProtection": "variables.isNamespace && has(object.metadata.labels) && 'sentinelops.io/admission-protected' in object.metadata.labels ? object.metadata.labels['sentinelops.io/admission-protected'] : ''",
	}
	expectedValidations := []string{
		"!variables.isGuard || request.name != params.metadata.name || request.namespace != params.metadata.namespace || request.userInfo.username in params.spec.allowedPolicyManagers",
		"!variables.isNamespace || request.name != params.metadata.namespace || variables.oldProtection == variables.newProtection || request.userInfo.username in params.spec.allowedPolicyManagers",
	}
	if !sameVariables(spec["variables"], expectedVariables) ||
		!sameValidations(spec["validations"], expectedValidations) {
		return "authorization_expression_changed"
	}
	expectedRules := []ruleContract{
		{[]string{"ops.sentinelops.io"}, []string{"v1alpha1"}, []string{"DELETE", "UPDATE"}, []string{"sentineladmissionguards"}, "*"},
		{[]string{""}, []string{"v1"}, []string{"UPDATE"}, []string{"namespaces"}, "Cluster"},
	}
	if !sameRules(spec, expectedRules) {
		return "match_rules_changed"
	}
	return ""
}

func validatePolicyStatus(resource *unstructured.Unstructured) string {
	generation := resource.GetGeneration()
	observed, ok, err := unstructured.NestedInt64(
		resource.Object,
		"status",
		"observedGeneration",
	)
	if err != nil || !ok || observed != generation {
		return "generation_not_observed"
	}
	warnings, ok, err := unstructured.NestedSlice(
		resource.Object,
		"status",
		"typeChecking",
		"expressionWarnings",
	)
	if err != nil || (ok && len(warnings) > 0) {
		return "expression_warning"
	}
	return ""
}

func validParamKind(spec map[string]any) bool {
	paramKind, ok := spec["paramKind"].(map[string]any)
	return ok &&
		paramKind["apiVersion"] == "ops.sentinelops.io/v1alpha1" &&
		paramKind["kind"] == "SentinelAdmissionGuard"
}

func validateBinding(
	resource *unstructured.Unstructured,
	policyName string,
	actions []string,
	guardName string,
	namespace string,
	selector map[string]string,
) string {
	spec, ok, err := unstructured.NestedMap(resource.Object, "spec")
	if err != nil || !ok {
		return "spec_missing"
	}
	if spec["policyName"] != policyName ||
		!sameStringSlice(spec["validationActions"], actions) {
		return "policy_or_actions_changed"
	}
	paramRef, ok := spec["paramRef"].(map[string]any)
	if !ok || paramRef["name"] != guardName ||
		paramRef["namespace"] != namespace ||
		paramRef["parameterNotFoundAction"] != "Deny" {
		return "parameter_reference_changed"
	}
	matchResources, _ := spec["matchResources"].(map[string]any)
	namespaceSelector, _ := matchResources["namespaceSelector"].(map[string]any)
	matchLabels, _ := namespaceSelector["matchLabels"].(map[string]any)
	if selector == nil {
		if len(matchLabels) != 0 {
			return "namespace_selector_changed"
		}
		return ""
	}
	expected := map[string]any{}
	for key, value := range selector {
		expected[key] = value
	}
	if !equalJSON(matchLabels, expected) {
		return "namespace_selector_changed"
	}
	return ""
}

type ruleContract struct {
	groups     []string
	versions   []string
	operations []string
	resources  []string
	scope      string
}

func sameRules(spec map[string]any, expected []ruleContract) bool {
	constraints, ok := spec["matchConstraints"].(map[string]any)
	if !ok || constraints["matchPolicy"] != "Equivalent" {
		return false
	}
	rawRules, ok := constraints["resourceRules"].([]any)
	if !ok || len(rawRules) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(rawRules))
	for _, raw := range rawRules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		actual = append(actual, ruleKey(ruleContract{
			groups:     stringSlice(rule["apiGroups"]),
			versions:   stringSlice(rule["apiVersions"]),
			operations: stringSlice(rule["operations"]),
			resources:  stringSlice(rule["resources"]),
			scope:      optionalString(rule["scope"]),
		}))
	}
	wanted := make([]string, 0, len(expected))
	for _, rule := range expected {
		wanted = append(wanted, ruleKey(rule))
	}
	sort.Strings(actual)
	sort.Strings(wanted)
	return strings.Join(actual, "\x00") == strings.Join(wanted, "\x00")
}

func ruleKey(rule ruleContract) string {
	sort.Strings(rule.groups)
	sort.Strings(rule.versions)
	sort.Strings(rule.operations)
	sort.Strings(rule.resources)
	return strings.Join([]string{
		strings.Join(rule.groups, ","),
		strings.Join(rule.versions, ","),
		strings.Join(rule.operations, ","),
		strings.Join(rule.resources, ","),
		rule.scope,
	}, "|")
}

func sameVariables(raw any, expected map[string]string) bool {
	items, ok := raw.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	actual := map[string]string{}
	for _, item := range items {
		variable, ok := item.(map[string]any)
		if !ok {
			return false
		}
		actual[fmt.Sprint(variable["name"])] = compact(
			fmt.Sprint(variable["expression"]),
		)
	}
	for name, expression := range expected {
		if actual[name] != compact(expression) {
			return false
		}
	}
	return true
}

func sameValidations(raw any, expected []string) bool {
	items, ok := raw.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(items))
	for _, item := range items {
		validation, ok := item.(map[string]any)
		if !ok || validation["reason"] != "Forbidden" {
			return false
		}
		actual = append(actual, compact(fmt.Sprint(validation["expression"])))
	}
	wanted := make([]string, 0, len(expected))
	for _, expression := range expected {
		wanted = append(wanted, compact(expression))
	}
	sort.Strings(actual)
	sort.Strings(wanted)
	return strings.Join(actual, "\x00") == strings.Join(wanted, "\x00")
}

func compact(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func optionalString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func sameStringSlice(raw any, expected []string) bool {
	actual := stringSlice(raw)
	wanted := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(wanted)
	return strings.Join(actual, "\x00") == strings.Join(wanted, "\x00")
}

func stringSlice(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok {
			return nil
		}
		values = append(values, value)
	}
	return values
}

func stringSet(raw any) map[string]struct{} {
	values := map[string]struct{}{}
	for _, value := range stringSlice(raw) {
		values[value] = struct{}{}
	}
	return values
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			return false
		}
	}
	return true
}

type Monitor struct {
	Checker  *Checker
	Interval time.Duration
}

func (m *Monitor) Start(ctx context.Context) error {
	if m.Checker == nil {
		return errors.New("admission integrity checker is required")
	}
	if m.Interval <= 0 {
		return errors.New("admission integrity interval must be positive")
	}
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		m.Checker.Check(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *Monitor) NeedLeaderElection() bool {
	return false
}

var _ interface {
	Start(context.Context) error
} = (*Monitor)(nil)
