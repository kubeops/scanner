/*
Copyright AppsCode Inc. and Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiserver

import (
	"context"
	"fmt"
	"os"
	"strings"

	"kubeops.dev/scanner/apis/cves"
	"kubeops.dev/scanner/apis/cves/install"
	api "kubeops.dev/scanner/apis/cves/v1alpha1"
	"kubeops.dev/scanner/client/clientset/versioned"
	"kubeops.dev/scanner/pkg/backend"
	scannerctrl "kubeops.dev/scanner/pkg/controllers/scanner"
	"kubeops.dev/scanner/pkg/fileserver"
	"kubeops.dev/scanner/pkg/registry"
	reportstorage "kubeops.dev/scanner/pkg/registry/cves/report"
	requeststorage "kubeops.dev/scanner/pkg/registry/cves/request"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2/klogr"
	cu "kmodules.xyz/client-go/client"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
)

func init() {
	install.Install(Scheme)
	utilruntime.Must(clientgoscheme.AddToScheme(Scheme))

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

// ExtraConfig holds custom apiserver config
type ExtraConfig struct {
	ClientConfig         *restclient.Config
	LicenseFile          string
	CacheDir             string
	NATSAddr             string
	NATSCredFile         string
	FileServerPathPrefix string
	FileServerFilesDir   string
	ScannerImage         string
}

// Config defines the config for the apiserver
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

// LicenseProxyServer contains state for a Kubernetes cluster master/api server.
type LicenseProxyServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
	Manager          manager.Manager
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

// CompletedConfig embeds a private pointer that cannot be instantiated outside of this package.
type CompletedConfig struct {
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	c.GenericConfig.Version = &version.Info{
		Major: "1",
		Minor: "0",
	}

	return CompletedConfig{&c}
}

// New returns a new instance of LicenseProxyServer from the given config.
func (c completedConfig) New(ctx context.Context) (*LicenseProxyServer, error) {
	genericServer, err := c.GenericConfig.New("scanner", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	// ctrl.SetLogger(...)
	log.SetLogger(klogr.New())
	setupLog := log.Log.WithName("setup")

	cfg := c.ExtraConfig.ClientConfig
	mgr, err := manager.New(cfg, manager.Options{
		Scheme:                 Scheme,
		MetricsBindAddress:     "",
		Port:                   0,
		HealthProbeBindAddress: "",
		LeaderElection:         false,
		LeaderElectionID:       "5b87adeb.scanner.appscode.com",
		ClientDisableCacheFor: []client.Object{
			&core.Pod{},
		},
		NewClient: cu.NewClient,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to start manager, reason: %v", err)
	}

	cid, err := cu.ClusterUID(mgr.GetAPIReader())
	if err != nil {
		return nil, err
	}

	nc, err := backend.NewConnection(c.ExtraConfig.NATSAddr, c.ExtraConfig.NATSCredFile)
	if err != nil {
		return nil, err
	}

	client_set, err := versioned.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	if err = (scannerctrl.NewWorkloadReconciler(nc, client_set, c.ExtraConfig.ScannerImage)).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Workload")
		os.Exit(1)
	}

	setupLog.Info("setup done!")

	s := &LicenseProxyServer{
		GenericAPIServer: genericServer,
		Manager:          mgr,
	}
	{
		apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(cves.GroupName, Scheme, metav1.ParameterCodec, Codecs)

		v1alpha1storage := map[string]rest.Storage{}
		v1alpha1storage[api.ResourceImageScanRequests] = requeststorage.NewScanReportStorage(cid, nc, mgr.GetClient())
		v1alpha1storage[api.ResourceImageScanReports] = registry.RESTInPeace(reportstorage.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter))

		apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

		if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
			return nil, err
		}
	}
	{
		prefix := c.ExtraConfig.FileServerPathPrefix
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix = prefix + "/"
		}
		genericServer.Handler.NonGoRestfulMux.HandlePrefix(prefix, fileserver.Router(prefix, c.ExtraConfig.FileServerFilesDir))
	}
	return s, nil
}
