import { browser, GatewayEndpoint, gql } from '$service/gateway/core/client';

export const $gateway = GatewayEndpoint.create({
	name: 'Search',
	gqlNode:
		!browser &&
		gql`
			query Search($token: String!) {
				searchByToken(token: $token)
			}
		`,
	mapper,
});

function mapper(value: { searchByToken: string }) {
	return value.searchByToken;
}

export const searchClient = $gateway.getClientHandler('search');
