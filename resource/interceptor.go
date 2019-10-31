package resource

import (
	"context"

	"github.com/morikuni/failure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errorUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		resp, err = handler(ctx, req)
		if err == nil {
			return resp, nil
		}

		// Convert gRPC error
		st := status.New(codes.Unknown, err.Error())

		if c, ok := failure.CodeOf(err); ok {
			switch c {
			case ErrInvalidToken:
				st = status.New(codes.Unauthenticated, err.Error())
			}
		}
		return resp, st.Err()
	}
}
