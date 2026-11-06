package graph

import (
	"context"

	"example.com/gviolet/pb"
)

// queryResolver implements generated.QueryResolver. The untrusted GraphQL arg
// crosses the ledger service boundary, whose handler holds the SQL sink — so
// THIS repo's contract view for Query.searchByToken carries a sink.
type queryResolver struct{ client pb.LedgerClient }

func (r *queryResolver) SearchByToken(ctx context.Context, token string) (string, error) {
	resp, err := r.client.Record(ctx, &pb.RecordRequest{Entry: token})
	if err != nil {
		return "", err
	}
	if resp.Ok {
		return "recorded", nil
	}
	return "", nil
}

// generated-style wiring (mirrors gqlgen's Resolver root).
type Resolver struct{ Client pb.LedgerClient }

func (r *Resolver) Query() interface {
	SearchByToken(ctx context.Context, token string) (string, error)
} {
	return &queryResolver{client: r.Client}
}

// Exec is the generated entrypoint (keeps the resolver reachable).
func (r *Resolver) Exec(ctx context.Context, token string) (string, error) {
	return r.Query().SearchByToken(ctx, token)
}
