<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { searchClient } from '$service/gateway/endpoints/search';

	let res = '';
	let typed = '';

	async function run() {
		const q = $page.url.searchParams.get('q') ?? '';
		res = await searchClient.call({ token: q });
		await goto(q);
	}
</script>

<input bind:value={typed} />
<button on:click={run}>search</button>
{@html res}
