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
	"kubeops.dev/scanner/pkg/apiserver"

	"github.com/spf13/pflag"
)

type ExtraOptions struct {
	QPS   float64
	Burst int

	LicenseFile string
	CacheDir    string

	NATSAddr     string
	NATSCredFile string

	FileServerPathPrefix string
	FileServerFilesDir   string
}

func NewExtraOptions() *ExtraOptions {
	return &ExtraOptions{
		QPS:                  1e6,
		Burst:                1e6,
		NATSAddr:             "this-is-nats.appcode.ninja:4222",
		FileServerPathPrefix: "files",
		FileServerFilesDir:   "/var/data/files",
	}
}

func (s *ExtraOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Float64Var(&s.QPS, "qps", s.QPS, "The maximum QPS to the master from this client")
	fs.IntVar(&s.Burst, "burst", s.Burst, "The maximum burst for throttle")
	fs.StringVar(&s.LicenseFile, "license-file", s.LicenseFile, "Path to license file")
	fs.StringVar(&s.CacheDir, "cache-dir", s.CacheDir, "Path to license cache directory")

	fs.StringVar(&s.NATSAddr, "nats-addr", s.NATSAddr, "NATS serve address")
	fs.StringVar(&s.NATSCredFile, "nats-credential-file", s.NATSCredFile, "PATH to NATS credential file")

	fs.StringVar(&s.FileServerPathPrefix, "file-server-path-prefix", s.FileServerPathPrefix, "URL prefix for file server")
	fs.StringVar(&s.FileServerFilesDir, "file-server-files-dir", s.FileServerFilesDir, "Dir used to store user uploaded files")
}

func (s *ExtraOptions) ApplyTo(cfg *apiserver.ExtraConfig) error {
	cfg.LicenseFile = s.LicenseFile
	cfg.CacheDir = s.CacheDir
	cfg.NATSAddr = s.NATSAddr
	cfg.NATSCredFile = s.NATSCredFile
	cfg.FileServerPathPrefix = s.FileServerPathPrefix
	cfg.FileServerFilesDir = s.FileServerFilesDir
	cfg.ClientConfig.QPS = float32(s.QPS)
	cfg.ClientConfig.Burst = s.Burst

	return nil
}

func (s *ExtraOptions) Validate() []error {
	return nil
}
