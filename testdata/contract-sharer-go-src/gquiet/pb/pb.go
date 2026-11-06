package pb

import "context"

// Vendored client types of the ping service (the generated gRPC client the
// resolver calls across the boundary).

type SendRequest struct{ Entry string }

type SendResponse struct{ Ok bool }

// PingClient is the generated gRPC client interface (vendored copy).
type PingClient interface {
	Send(ctx context.Context, in *SendRequest) (*SendResponse, error)
}
