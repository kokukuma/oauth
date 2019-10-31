package gateway

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"html/template"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	auth_pb "github.com/kokukuma/oauth/auth/pb"
	cli_pb "github.com/kokukuma/oauth/client/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// Config represents gateway config
type Config struct {
	GatewayAddr  string
	AuthAddr     string
	AuthGrpcOpts []grpc.DialOption
	CliAddr      string
	CliGrpcOpts  []grpc.DialOption
}

// RunGateway start gateway for client server
func RunGateway(config Config) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux(
		runtime.WithForwardResponseOption(func(ctx context.Context, w http.ResponseWriter, msg proto.Message) error {
			switch v := msg.(type) {
			case *cli_pb.TopPageResponse:
				return topPage(ctx, w, v)
			case *cli_pb.CallbackResponse:
				return callback(ctx, w, v)
			case *cli_pb.ResourceResponse:
				return resource(ctx, w, v)
			case *auth_pb.AuthorizationResponse:
				return authorization(ctx, w, v)
			}
			return nil
		}),
	)

	// Access to Client
	err := cli_pb.RegisterClientHandlerFromEndpoint(ctx, mux, config.CliAddr, config.CliGrpcOpts)
	if err != nil {
		return err
	}

	// Access to Authorization
	err = auth_pb.RegisterAuthHandlerFromEndpoint(ctx, mux, config.AuthAddr, config.AuthGrpcOpts)
	if err != nil {
		return err
	}

	return http.ListenAndServe(config.GatewayAddr, mux)
}

func topPage(ctx context.Context, w http.ResponseWriter, resp *cli_pb.TopPageResponse) error {
	log.Println("/client/top")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.New("/client/top").Parse(topHTML)
	if err != nil {
		fmt.Fprintf(w, "Unable to load template")
		return nil
	}
	t.Execute(w, resp)
	return nil
}

func callback(ctx context.Context, w http.ResponseWriter, resp *cli_pb.CallbackResponse) error {
	log.Println("/client/callback")

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("location", resp.GetUrl())
	w.WriteHeader(http.StatusFound) // 302 StatusFound
	return nil
}

func resource(ctx context.Context, w http.ResponseWriter, resp *cli_pb.ResourceResponse) error {
	log.Println("/client/resource")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.New("/client/resource").Parse(resourceHTML)
	if err != nil {
		fmt.Fprintf(w, "Unable to load template")
		return nil
	}

	t.Execute(w, resp)
	return nil
}

func authorization(ctx context.Context, w http.ResponseWriter, resp *auth_pb.AuthorizationResponse) error {
	log.Println("/auth/authorization")

	v := url.Values{}
	v.Set("code", resp.GetCode())
	v.Add("state", resp.GetState())
	v.Add("user_id", resp.GetUserId())
	url := fmt.Sprintf("%s?%s", resp.GetRedirectUri(), v.Encode())

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("location", url)
	w.WriteHeader(http.StatusFound) // 302 StatusFound
	return nil
}
