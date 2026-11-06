import { searchClient } from '$service/gateway/endpoints/search';

// SvelteKit server load: the whole `event` (param 0) is untrusted input.
export const load = async ({ url }) => {
	const token = url.searchParams.get('token') ?? '';
	const result = await searchClient.call({ token });
	return { result };
};
