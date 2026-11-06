package graph

import (
	"context"

	"example.com/gquiet/pb"
)

// queryResolver implements generated.QueryResolver. The untrusted GraphQL arg
// crosses the ping service boundary, whose handler DROPS it — so THIS repo's
// contract view for Query.searchByToken carries neither flows nor sinks. Both
// this repo and gviolet define the same field name, so both resolvers compete
// for one contract iid; which view wins used to be a per-process coin toss.
type queryResolver struct{ client pb.PingClient }

func (r *queryResolver) SearchByToken(ctx context.Context, token string) (string, error) {
	resp, err := r.client.Send(ctx, &pb.SendRequest{Entry: token})
	if err != nil {
		return "", err
	}
	if resp.Ok {
		return "sent", nil
	}
	return "", nil
}

// generated-style wiring (mirrors gqlgen's Resolver root).
type Resolver struct{ Client pb.PingClient }

func (r *Resolver) Query() interface {
	SearchByToken(ctx context.Context, token string) (string, error)
} {
	return &queryResolver{client: r.Client}
}

// Exec is the generated entrypoint (keeps the resolver reachable).
func (r *Resolver) Exec(ctx context.Context, token string) (string, error) {
	return r.Query().SearchByToken(ctx, token)
}
