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
	"fmt"
	"net/http"
	"reflect"

	"gocloud.dev/gcerrors"
	_ "gocloud.dev/gcerrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
)

// statusError is an object that can be converted into an metav1.Status
type statusError interface {
	Status() metav1.Status
}

// ErrorToAPIStatus converts an error to an metav1.Status object.
func ErrorToAPIStatus(err error) *metav1.Status {
	// WARNING: https://stackoverflow.com/a/46275411/244009
	if err == nil || reflect.ValueOf(err).IsNil() /*for error wrapper interfaces*/ {
		return &metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Status",
				APIVersion: "v1",
			},
			Status: metav1.StatusSuccess,
			Code:   http.StatusOK,
		}
	}

	code := gcerrors.Code(err)
	if code != gcerrors.Unknown {
		return &metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Status",
				APIVersion: "v1",
			},
			Status:  metav1.StatusFailure,
			Code:    HTTPStatusFromCode(code),
			Message: err.Error(),
		}
	}

	switch t := err.(type) {
	case statusError:
		s := t.Status()
		if len(s.Status) == 0 {
			s.Status = metav1.StatusFailure
		}
		switch s.Status {
		case metav1.StatusSuccess:
			if s.Code == 0 {
				s.Code = http.StatusOK
			}
		case metav1.StatusFailure:
			if s.Code == 0 {
				s.Code = http.StatusInternalServerError
			}
		default:
			runtime.HandleError(fmt.Errorf("apiserver received an error with wrong status field : %#+v", err))
			if s.Code == 0 {
				s.Code = http.StatusInternalServerError
			}
		}
		s.Kind = "Status"
		s.APIVersion = "v1"
		// TODO: check for invalid responses
		return &s
	default:
		s := http.StatusInternalServerError
		// Log errors that were not converted to an error status
		// by REST storage - these typically indicate programmer
		// error by not using pkg/api/errors, or unexpected failure
		// cases.
		runtime.HandleError(fmt.Errorf("apiserver received an error that is not an metav1.Status: %#+v: %v", err, err))
		return &metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Status",
				APIVersion: "v1",
			},
			Status:  metav1.StatusFailure,
			Code:    int32(s),
			Reason:  metav1.StatusReasonUnknown,
			Message: err.Error(),
		}
	}
}

// HTTPStatusFromCode converts a gRPC error code into the corresponding HTTP response status.
// See: https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
// See: https://github.com/grpc-ecosystem/grpc-gateway/blob/v2.11.3/runtime/errors.go#L34-L77
func HTTPStatusFromCode(code gcerrors.ErrorCode) int32 {
	switch code {
	case gcerrors.OK:
		return http.StatusOK
	case gcerrors.Canceled:
		return http.StatusRequestTimeout
	case gcerrors.Unknown:
		return http.StatusInternalServerError
	case gcerrors.InvalidArgument:
		return http.StatusBadRequest
	case gcerrors.DeadlineExceeded:
		return http.StatusGatewayTimeout
	case gcerrors.NotFound:
		return http.StatusNotFound
	case gcerrors.AlreadyExists:
		return http.StatusConflict
	case gcerrors.PermissionDenied:
		return http.StatusForbidden
	// case gcerrors.Unauthenticated:
	//	return http.StatusUnauthorized
	case gcerrors.ResourceExhausted:
		return http.StatusTooManyRequests
	case gcerrors.FailedPrecondition:
		// Note, this deliberately doesn't translate to the similarly named '412 Precondition Failed' HTTP response status.
		return http.StatusBadRequest
	// case gcerrors.Aborted:
	//	return http.StatusConflict
	// case gcerrors.OutOfRange:
	//	return http.StatusBadRequest
	case gcerrors.Unimplemented:
		return http.StatusNotImplemented
	case gcerrors.Internal:
		return http.StatusInternalServerError
		// case gcerrors.Unavailable:
		//	return http.StatusServiceUnavailable
		// case gcerrors.DataLoss:
		//	return http.StatusInternalServerError
	}

	grpclog.Infof("Unknown gRPC error code: %v", code)
	return http.StatusInternalServerError
}

// GRPCCode extracts the gRPC status code and converts it into an ErrorCode.
// It returns Unknown if the error isn't from gRPC.
func GRPCCode(err error) gcerrors.ErrorCode {
	switch status.Code(err) {
	case codes.NotFound:
		return gcerrors.NotFound
	case codes.AlreadyExists:
		return gcerrors.AlreadyExists
	case codes.InvalidArgument:
		return gcerrors.InvalidArgument
	case codes.Internal:
		return gcerrors.Internal
	case codes.Unimplemented:
		return gcerrors.Unimplemented
	case codes.FailedPrecondition:
		return gcerrors.FailedPrecondition
	case codes.PermissionDenied:
		return gcerrors.PermissionDenied
	case codes.ResourceExhausted:
		return gcerrors.ResourceExhausted
	case codes.Canceled:
		return gcerrors.Canceled
	case codes.DeadlineExceeded:
		return gcerrors.DeadlineExceeded
	default:
		return gcerrors.Unknown
	}
}
