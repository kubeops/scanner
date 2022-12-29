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

package backend

import (
	"context"
	"fmt"
	"os"
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	"github.com/nats-io/nats.go"
	"k8s.io/klog/v2"
)

const (
	natsConnectionTimeout       = 350 * time.Millisecond
	natsConnectionRetryInterval = 100 * time.Millisecond
	NatsRequestTimeout          = 10 * time.Second
	natsScanRequestTimeout      = 500 * time.Millisecond
	dockerHubRateLimitDelay     = 1 * time.Hour
)

// NewConnection creates a new NATS connection
func NewConnection(addr, credFile string) (nc *nats.Conn, err error) {
	hostname, _ := os.Hostname()
	opts := []nats.Option{
		nats.Name(fmt.Sprintf("scanner-backend.%s", hostname)),
		nats.MaxReconnects(-1),
		nats.ErrorHandler(errorHandler),
		nats.ReconnectHandler(reconnectHandler),
		nats.DisconnectErrHandler(disconnectHandler),
		// nats.UseOldRequestStyle(),
	}

	if _, err := os.Stat(credFile); os.IsNotExist(err) {
		var username, password string
		if v, ok := os.LookupEnv("NATS_USERNAME"); ok {
			username = v
		} else {
			username = os.Getenv("THIS_IS_NATS_USERNAME")
		}
		if v, ok := os.LookupEnv("NATS_PASSWORD"); ok {
			password = v
		} else {
			password = os.Getenv("THIS_IS_NATS_PASSWORD")
		}
		if username != "" && password != "" {
			opts = append(opts, nats.UserInfo(username, password))
		}
	} else {
		opts = append(opts, nats.UserCredentials(credFile))
	}

	//if os.Getenv("NATS_CERTIFICATE") != "" && os.Getenv("NATS_KEY") != "" {
	//	opts = append(opts, nats.ClientCert(os.Getenv("NATS_CERTIFICATE"), os.Getenv("NATS_KEY")))
	//}
	//
	//if os.Getenv("NATS_CA") != "" {
	//	opts = append(opts, nats.RootCAs(os.Getenv("NATS_CA")))
	//}

	// initial connections can error due to DNS lookups etc, just retry, eventually with backoff
	ctx, cancel := context.WithTimeout(context.Background(), natsConnectionTimeout)
	defer cancel()

	ticker := time.NewTicker(natsConnectionRetryInterval)
	for {
		select {
		case <-ticker.C:
			nc, err := nats.Connect(addr, opts...)
			if err == nil {
				return nc, nil
			}
			klog.V(5).InfoS("failed to connect to event receiver", "error", err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// called during errors subscriptions etc
func errorHandler(nc *nats.Conn, s *nats.Subscription, err error) {
	if s != nil {
		klog.V(5).Infof("error in event receiver connection: %s: subscription: %s: %s", nc.ConnectedUrl(), s.Subject, err)
		return
	}
	klog.V(5).Infof("Error in event receiver connection: %s: %s", nc.ConnectedUrl(), err)
}

// called after reconnection
func reconnectHandler(nc *nats.Conn) {
	klog.V(5).Infof("Reconnected to %s", nc.ConnectedUrl())
}

// called after disconnection
func disconnectHandler(nc *nats.Conn, err error) {
	if err != nil {
		klog.V(5).Infof("Disconnected from event receiver due to error: %v", err)
	} else {
		klog.V(5).Infof("Disconnected from event receiver")
	}
}

func GetReport(nc *nats.Conn, isr api.ImageScanRequest) (trivy.SingleReport, error) {
	msg, err := nc.Request("scanner.report", []byte(isr.Spec.Image), NatsRequestTimeout)
	if err != nil {
		return trivy.SingleReport{}, err
	}
	var report trivy.SingleReport
	err = trivy.JSON.Unmarshal(msg.Data, &report)
	if err != nil {
		return trivy.SingleReport{}, err
	}
	return report, nil
}

func GetVersionInfo(nc *nats.Conn, isr api.ImageScanRequest) (trivy.Version, error) {
	msg, err := nc.Request("scanner.version", []byte(isr.Spec.Image), NatsRequestTimeout)
	if err != nil {
		return trivy.Version{}, err
	}
	var ver trivy.Version
	err = trivy.JSON.Unmarshal(msg.Data, &ver)
	if err != nil {
		return trivy.Version{}, err
	}
	return ver, nil
}
