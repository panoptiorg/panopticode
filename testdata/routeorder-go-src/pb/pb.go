// Package pb — a generated-shape gRPC stub: a request message with three string
// fields, its getters, and the server interface. Handlers on the interface are
// seeded structurally (request params = source_params; the frontend needs the
// package path to contain "/pb"), so `req` itself is the source.
package pb

import "context"

type OrderRequest struct {
	Query string
	Mask  string
	Note  string
}

func (r *OrderRequest) GetQuery() string { return r.Query }
func (r *OrderRequest) GetMask() string  { return r.Mask }
func (r *OrderRequest) GetNote() string  { return r.Note }

type OrderServer interface {
	HandleJoin(context.Context, *OrderRequest) error
}

type UnimplementedOrderServer struct{}

func (UnimplementedOrderServer) HandleJoin(context.Context, *OrderRequest) error { return nil }
