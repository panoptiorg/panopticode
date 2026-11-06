# fixtures/webapp

A minimal SvelteKit app, used by `scripts/extract-fixture.sh`, the tests and
the README quickstart. It has no `node_modules`, so it also shows that a
repository can be extracted without installing it.

- `schema.graphql`: the schema snapshot. `Query.searchByToken(token)` is the
  field the Go `federation` fixture in the core repository resolves, so the two
  extracts join on `graphql:Query.searchByToken`.
- `src/service/gateway/endpoints/search/index.ts`: the operation document and
  `getClientHandler('search')`, the shape the `bff-gateway` adapter models.
- `src/service/gateway/core/client.ts`: a stand-in for the gateway library.
- `src/routes/search/+page.svelte`: `$page.url.searchParams.get('q')` flows
  into the GraphQL client, into `goto()` (open redirect) and into `{@html}`
  (XSS).
- `src/routes/search/+page.server.ts`: a `load({ url })` endpoint.
- `svelte.config.js`: a `kit.alias` entry (`$service`) the extractor must read.

`package.json` declares no gateway dependency, so auto-detection finds no
adapter; extract with `--adapter bff-gateway`.
