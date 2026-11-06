package pb

import "context"

type SendRequest struct{ Entry string }

func (r *SendRequest) GetEntry() string { return r.Entry }

type SendResponse struct{ Ok bool }

// PingServer is the generated gRPC server interface.
type PingServer interface {
	Send(context.Context, *SendRequest) (*SendResponse, error)
}

// UnimplementedPingServer is embedded by server implementations.
type UnimplementedPingServer struct{}

func (UnimplementedPingServer) Send(context.Context, *SendRequest) (*SendResponse, error) {
	return nil, nil
}
