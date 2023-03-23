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

package cmds

import (
	"path/filepath"
	"time"

	"kubeops.dev/scanner/pkg/backend"

	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
	"gomodules.xyz/blobfs"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
	"kmodules.xyz/client-go/tools/parser"
	api "kubedb.dev/apimachinery/apis/catalog/v1alpha1"
)

func NewCmdScanKubeDB() *cobra.Command {
	var (
		addr = "this-is-nats.appscode.ninja:4222"
		dir  = filepath.Join(homedir.HomeDir(), "/go/src/kubedb.dev/installer/catalog/raw")
	)
	cmd := &cobra.Command{
		Use:               "scan-kubedb",
		Short:             "Scan KubeDB catalog",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			nc, err := backend.NewConnection(addr, "")
			if err != nil {
				return err
			}
			fs := backend.NewBlobFS()

			return processDir(nc, fs, dir)
		},
	}

	cmd.Flags().StringVar(&dir, "dir", dir, "Path to KubeDB catalog dir")
	return cmd
}

func processDir(nc *nats.Conn, fs blobfs.Interface, dir string) error {
	return parser.ProcessPath(dir, func(ri parser.ResourceInfo) error {
		switch ri.Object.GetKind() {
		case api.ResourceKindElasticsearchVersion:
			var v api.ElasticsearchVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.InitContainer.Image,
				v.Spec.Exporter.Image,
				v.Spec.Dashboard.Image,
				v.Spec.DashboardInitContainer.YQImage)
		case api.ResourceKindMemcachedVersion:
			var v api.MemcachedVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image)
		case api.ResourceKindMariaDBVersion:
			var v api.MariaDBVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image,
				v.Spec.InitContainer.Image,
				v.Spec.Coordinator.Image)
		case api.ResourceKindMongoDBVersion:
			var v api.MongoDBVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image,
				v.Spec.InitContainer.Image,
				v.Spec.ReplicationModeDetector.Image)
		case api.ResourceKindMySQLVersion:
			var v api.MySQLVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image,
				v.Spec.InitContainer.Image,
				v.Spec.ReplicationModeDetector.Image,
				v.Spec.Coordinator.Image,
				v.Spec.Router.Image,
				v.Spec.RouterInitContainer.Image)
		case api.ResourceKindPerconaXtraDBVersion:
			var v api.PerconaXtraDBVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image,
				v.Spec.InitContainer.Image)
		case api.ResourceKindPgBouncerVersion:
			var v api.PgBouncerVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.PgBouncer.Image,
				v.Spec.Exporter.Image)
		case api.ResourceKindProxySQLVersion:
			var v api.ProxySQLVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.Proxysql.Image,
				v.Spec.Exporter.Image)
		case api.ResourceKindRedisVersion:
			var v api.RedisVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Exporter.Image,
				v.Spec.Coordinator.Image,
				v.Spec.InitContainer.Image)
		case api.ResourceKindPostgresVersion:
			var v api.PostgresVersion
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.UnstructuredContent(), &v)
			if err != nil {
				return err
			}
			scanImages(nc, fs,
				v.Spec.DB.Image,
				v.Spec.Coordinator.Image,
				v.Spec.Exporter.Image,
				v.Spec.InitContainer.Image)
		}
		return nil
	})
}

func scanImages(nc *nats.Conn, fs blobfs.Interface, refs ...string) {
	for _, img := range refs {
		if img == "" {
			continue
		}
		if exists, _ := backend.ExistsReport(fs, img); !exists {
			if _, err := nc.Request(backend.ScanSubject, []byte(img), 100*time.Millisecond); err != nil {
				klog.ErrorS(err, "failed submit scan request", "image", img)
			} else {
				klog.InfoS("submitted scan request", "image", img)
			}
		}
	}
}
