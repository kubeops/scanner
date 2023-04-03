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
	"fmt"
	"time"

	"kubeops.dev/scanner/pkg/apiserver"

	"github.com/spf13/pflag"
	licenseapi "go.bytebuilders.dev/license-verifier/apis/licenses/v1alpha1"
	license "go.bytebuilders.dev/license-verifier/kubernetes"
	"gomodules.xyz/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

type ExtraOptions struct {
	QPS          float64
	Burst        int
	ResyncPeriod time.Duration

	LicenseFile string
	CacheDir    string

	NATSAddr     string
	NATSCredFile string

	FileServerPathPrefix string
	FileServerFilesDir   string

	ScannerImage       string
	TrivyImage         string
	TrivyDBCacherImage string
	FileServerAddr     string
	ScanInCluster      bool

	GarbageCollectionPeriod time.Duration
}

func NewExtraOptions() *ExtraOptions {
	return &ExtraOptions{
		ResyncPeriod:            10 * time.Minute,
		QPS:                     1e6,
		Burst:                   1e6,
		NATSAddr:                "this-is-nats.appcode.ninja:4222",
		FileServerPathPrefix:    "files",
		FileServerFilesDir:      "/var/data/files",
		TrivyImage:              "aquasec/trivy",
		GarbageCollectionPeriod: time.Hour * 24,
	}
}

func (s *ExtraOptions) AddFlags(fs *pflag.FlagSet) {
	fs.DurationVar(&s.ResyncPeriod, "resync-period", s.ResyncPeriod, "If non-zero, will re-list this often. Otherwise, re-list will be delayed aslong as possible (until the upstream source closes the watch or times out.")
	fs.Float64Var(&s.QPS, "qps", s.QPS, "The maximum QPS to the master from this client")
	fs.IntVar(&s.Burst, "burst", s.Burst, "The maximum burst for throttle")
	fs.StringVar(&s.LicenseFile, "license-file", s.LicenseFile, "Path to license file")
	fs.StringVar(&s.CacheDir, "cache-dir", s.CacheDir, "Path to license cache directory")

	fs.StringVar(&s.NATSAddr, "nats-addr", s.NATSAddr, "NATS serve address")
	fs.StringVar(&s.NATSCredFile, "nats-credential-file", s.NATSCredFile, "PATH to NATS credential file")

	fs.StringVar(&s.FileServerAddr, "file-server-addr", s.FileServerAddr, "The fileserver address to get the trivydb tar file")
	fs.StringVar(&s.FileServerPathPrefix, "file-server-path-prefix", s.FileServerPathPrefix, "URL prefix for file server")
	fs.StringVar(&s.FileServerFilesDir, "file-server-files-dir", s.FileServerFilesDir, "Dir used to store user uploaded files")

	fs.StringVar(&s.ScannerImage, "scanner-image", s.ScannerImage, "The image used to upload scan report")
	fs.StringVar(&s.TrivyImage, "trivy-image", s.TrivyImage, "The image used for Trivy cli")
	fs.StringVar(&s.TrivyDBCacherImage, "trivydb-cacher-image", s.TrivyDBCacherImage, "The image used for TrivyDB caching")
	fs.BoolVar(&s.ScanInCluster, "scan-public-image-incluster", s.ScanInCluster, "If true public images will be scanned in cluster. Set true for air-gaped cluster")

	fs.DurationVar(&s.GarbageCollectionPeriod, "garbage-collection-period", s.GarbageCollectionPeriod, "ImageScanRequest older than this period will be garbage collected")
}

func (s *ExtraOptions) ApplyTo(cfg *apiserver.ExtraConfig) error {
	cfg.LicenseFile = s.LicenseFile
	cfg.CacheDir = s.CacheDir
	cfg.NATSAddr = s.NATSAddr
	cfg.NATSCredFile = s.NATSCredFile
	cfg.FileServerPathPrefix = s.FileServerPathPrefix
	cfg.FileServerFilesDir = s.FileServerFilesDir
	cfg.ScannerImage = s.ScannerImage
	cfg.TrivyImage = s.TrivyImage
	cfg.TrivyDBCacherImage = s.TrivyDBCacherImage
	cfg.FileServerAddr = s.FileServerAddr
	cfg.ClientConfig.QPS = float32(s.QPS)
	cfg.ClientConfig.Burst = s.Burst
	cfg.ResyncPeriod = s.ResyncPeriod
	cfg.GarbageCollectionPeriod = s.GarbageCollectionPeriod

	var err error
	if cfg.KubeClient, err = kubernetes.NewForConfig(cfg.ClientConfig); err != nil {
		return err
	}
	cfg.KubeInformerFactory = informers.NewSharedInformerFactory(cfg.KubeClient, cfg.ResyncPeriod)
	if cfg.LicenseProvided() {
		info := license.MustLicenseEnforcer(cfg.ClientConfig, cfg.LicenseFile).LoadLicense()
		if info.Status != licenseapi.LicenseActive {
			return fmt.Errorf("license status %s, reason: %s", info.Status, info.Reason)
		}
		if sets.NewString(info.Features...).Has("scanner") {
		} else if !sets.NewString(info.Features...).Has("scanner") {
			return fmt.Errorf("not a valid license for this product")
		}
		cfg.License = info
	}

	return nil
}

func (s *ExtraOptions) Validate() []error {
	return nil
}
