package main

import (
	"flag"
	"os"
	"strconv"
	"time"

	opsv1alpha1 "github.com/q741242673/sentinelops/controller/api/v1alpha1"
	"github.com/q741242673/sentinelops/controller/internal/admissionintegrity"
	"github.com/q741242673/sentinelops/controller/internal/remediation"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(opsv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddress string
	var healthAddress string
	var watchNamespace string
	var leaderElectionNamespace string
	var maxConcurrent int
	var enableLeaderElection bool

	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "metrics endpoint")
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "health probes")
	flag.StringVar(
		&watchNamespace,
		"watch-namespace",
		os.Getenv("SENTINELOPS_KUBERNETES_NAMESPACE"),
		"single workload namespace to reconcile",
	)
	flag.StringVar(
		&leaderElectionNamespace,
		"leader-election-namespace",
		"sentinelops-system",
		"namespace containing the controller leader lease",
	)
	flag.IntVar(&maxConcurrent, "max-concurrent-reconciles", 4, "reconcile concurrency")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "enable leader election")
	logOptions := zap.Options{Development: false}
	logOptions.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))
	setupLog := ctrl.Log.WithName("setup")
	if watchNamespace == "" {
		setupLog.Error(nil, "watch namespace is required")
		os.Exit(1)
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress: metricsAddress,
		},
		HealthProbeBindAddress:        healthAddress,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "sentinelops-remediation-controller.ops.sentinelops.io",
		LeaderElectionNamespace:       leaderElectionNamespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	controllerID := os.Getenv("HOSTNAME")
	var integrityChecker *admissionintegrity.Checker
	integrityRequired, err := strconv.ParseBool(
		envOrDefault("SENTINELOPS_ADMISSION_INTEGRITY_REQUIRED", "false"),
	)
	if err != nil {
		setupLog.Error(err, "invalid admission integrity required setting")
		os.Exit(1)
	}
	if integrityRequired {
		expectedGuardSpec, err := admissionintegrity.ParseGuardSpec(
			os.Getenv("SENTINELOPS_ADMISSION_EXPECTED_GUARD_SPEC"),
		)
		if err != nil {
			setupLog.Error(err, "invalid expected admission guard spec")
			os.Exit(1)
		}
		requestTimeout, err := time.ParseDuration(
			envOrDefault("SENTINELOPS_ADMISSION_REQUEST_TIMEOUT", "5s"),
		)
		if err != nil {
			setupLog.Error(err, "invalid admission request timeout")
			os.Exit(1)
		}
		integrityChecker, err = admissionintegrity.NewChecker(
			manager.GetAPIReader(),
			admissionintegrity.Config{
				Namespace:            watchNamespace,
				PolicyName:           envOrDefault("SENTINELOPS_ADMISSION_POLICY_NAME", "sentinelops-workload-write-fence"),
				GovernancePolicyName: envOrDefault("SENTINELOPS_ADMISSION_GOVERNANCE_POLICY_NAME", "sentinelops-admission-governance"),
				GuardName:            envOrDefault("SENTINELOPS_ADMISSION_GUARD_NAME", "sentinelops-workload-write-fence"),
				ExpectedGuardSpec:    expectedGuardSpec,
				RequestTimeout:       requestTimeout,
			},
		)
		if err != nil {
			setupLog.Error(err, "unable to create admission integrity checker")
			os.Exit(1)
		}
		interval, err := time.ParseDuration(
			envOrDefault("SENTINELOPS_ADMISSION_RECONCILE_INTERVAL", "15s"),
		)
		if err != nil {
			setupLog.Error(err, "invalid admission reconcile interval")
			os.Exit(1)
		}
		if err := manager.Add(&admissionintegrity.Monitor{
			Checker:  integrityChecker,
			Interval: interval,
		}); err != nil {
			setupLog.Error(err, "unable to add admission integrity monitor")
			os.Exit(1)
		}
	}
	reconciler := &remediation.Reconciler{
		Client:       manager.GetClient(),
		Scheme:       manager.GetScheme(),
		ControllerID: controllerID,
	}
	if integrityChecker != nil {
		reconciler.AdmissionIntegrity = integrityChecker.Check
	}
	if err := reconciler.SetupWithManager(manager, maxConcurrent); err != nil {
		setupLog.Error(err, "unable to create remediation controller")
		os.Exit(1)
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to add health check")
		os.Exit(1)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to add readiness check")
		os.Exit(1)
	}

	setupLog.Info(
		"starting remediation controller",
		"watchNamespace",
		watchNamespace,
		"leaderElection",
		enableLeaderElection,
	)
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager stopped")
		os.Exit(1)
	}
}

func envOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
