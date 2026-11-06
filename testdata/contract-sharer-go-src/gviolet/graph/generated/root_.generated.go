// Package generated mimics the gqlgen exec package (root_.generated.go shape):
// ResolverRoot + DirectiveRoot + ComplexityRoot declarations plus a
// ResolveField-style dispatcher (v0.17.x). graphql.Extract identifies a gqlgen
// service by exactly this structural triple — no gqlgen.yml needed.
package generated

import (
	"context"
)

type ResolverRoot interface {
	Query() QueryResolver
}

type DirectiveRoot struct{}

type ComplexityRoot struct {
	Query struct{ SearchByToken int }
}

// QueryResolver: root resolver — args start after ctx.
type QueryResolver interface {
	SearchByToken(ctx context.Context, token string) (string, error)
}

// executionContext mirrors gqlgen's generated dispatcher: the resolver call
// sits inside a closure with args read from the field-context map.
type executionContext struct{ Resolvers ResolverRoot }

func (ec *executionContext) _Query_searchByToken(ctx context.Context, args map[string]any) (string, error) {
	fn := func(ctx context.Context) (string, error) {
		return ec.Resolvers.Query().SearchByToken(ctx, args["token"].(string))
	}
	return fn(ctx)
}
