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

package server

import (
	"context"
	"fmt"
	"io"
	"net"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/pkg/apiserver"

	"github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/util/feature"
	"kmodules.xyz/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const defaultEtcdPathPrefix = "/registry/scanner.appscode.com"

// ScannerServerOptions contains state for master/api server
type ScannerServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions
	ExtraOptions       *ExtraOptions

	StdOut io.Writer
	StdErr io.Writer
}

// NewScannerServerOptions returns a new ScannerServerOptions
func NewScannerServerOptions(out, errOut io.Writer) *ScannerServerOptions {
	_ = feature.DefaultMutableFeatureGate.Set(fmt.Sprintf("%s=false", features.APIPriorityAndFairness))
	o := &ScannerServerOptions{
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(
				api.SchemeGroupVersion,
			),
		),
		ExtraOptions: NewExtraOptions(),
		StdOut:       out,
		StdErr:       errOut,
	}
	// o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil
	return o
}

func (o ScannerServerOptions) AddFlags(fs *pflag.FlagSet) {
	o.RecommendedOptions.AddFlags(fs)
	o.ExtraOptions.AddFlags(fs)
}

// Validate validates ScannerServerOptions
func (o ScannerServerOptions) Validate(args []string) error {
	var errors []error
	errors = append(errors, o.RecommendedOptions.Validate()...)
	errors = append(errors, o.ExtraOptions.Validate()...)
	return utilerrors.NewAggregate(errors)
}

// Complete fills in fields required to have valid data
func (o *ScannerServerOptions) Complete() error {
	return nil
}

// Config returns config for the api server given ScannerServerOptions
func (o *ScannerServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}
	// Fixes https://github.com/Azure/AKS/issues/522
	clientcmd.Fix(serverConfig.ClientConfig)

	ignore := []string{
		"/swaggerapi",
		fmt.Sprintf("/apis/%s", api.SchemeGroupVersion),
		fmt.Sprintf("/apis/%s/%s", api.SchemeGroupVersion, api.ResourceImageScanRequests),
		fmt.Sprintf("/apis/%s/%s", api.SchemeGroupVersion, api.ResourceImageScanReports),
	}

	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
		api.GetOpenAPIDefinitions,
		openapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIConfig.Info.Title = "scanner"
	serverConfig.OpenAPIConfig.Info.Version = api.SchemeGroupVersion.Version
	serverConfig.OpenAPIConfig.IgnorePrefixes = ignore

	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(
		api.GetOpenAPIDefinitions,
		openapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIV3Config.Info.Title = "scanner"
	serverConfig.OpenAPIV3Config.Info.Version = api.SchemeGroupVersion.Version
	serverConfig.OpenAPIV3Config.IgnorePrefixes = ignore

	extraConfig := apiserver.ExtraConfig{
		ClientConfig:         serverConfig.ClientConfig,
		ScannerImage:         o.ExtraOptions.ScannerImage,
		TrivyImage:           o.ExtraOptions.TrivyImage,
		TrivyDBCacherImage:   o.ExtraOptions.TrivyDBCacherImage,
		FileServerAddr:       o.ExtraOptions.FileServerAddr,
		ScanRequestTTLPeriod: o.ExtraOptions.ScanRequestTTLPeriod,
		Workspace:            o.ExtraOptions.Workspace,
	}
	if err := o.ExtraOptions.ApplyTo(&extraConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig:   extraConfig,
	}
	return config, nil
}

// Run starts a new ScannerServer given ScannerServerOptions
func (o ScannerServerOptions) Run(ctx context.Context) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New(ctx)
	if err != nil {
		return err
	}

	server.GenericAPIServer.AddPostStartHookOrDie("start-scanner-informers", func(context genericapiserver.PostStartHookContext) error {
		config.GenericConfig.SharedInformerFactory.Start(context.StopCh)
		return nil
	})

	err = server.Manager.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
	}))
	if err != nil {
		return err
	}

	setupLog := log.Log.WithName("setup")
	setupLog.Info("starting manager")
	err = server.Manager.Start(ctx)
	if err != nil {
		return err
	}

	<-ctx.Done()
	if server.NatsClient != nil {
		return server.NatsClient.Drain()
	}
	return nil
}
