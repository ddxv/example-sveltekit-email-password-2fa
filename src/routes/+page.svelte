<script lang="ts">

	import type { PageData } from "./$types";
	export let data: PageData;
</script>

<header>
	<a href="/">Home</a>
	<a href="/settings">Settings</a>
	<a href="/specialroute">Special Route</a>
</header>
<main>
{data.message}
</main>
