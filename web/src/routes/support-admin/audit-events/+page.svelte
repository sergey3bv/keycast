<script lang="ts">
	import { onMount } from 'svelte';
	import { BRAND } from '$lib/brand';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import {
		ArrowLeft,
		Warning,
		CaretDown,
		CaretRight,
		List,
		MagnifyingGlass
	} from 'phosphor-svelte';

	const api = new KeycastApi();

	interface AuditEventRow {
		id: number;
		occurred_at: string;
		tenant_id: number;
		actor_pubkey: string;
		action: string;
		target_resource_type: string;
		target_resource_id: string | null;
		target_client_id: string | null;
		metadata_json: unknown;
	}

	let status = $state<'loading' | 'not-admin' | 'ready'>('loading');

	let filterAction = $state('');
	let filterClientId = $state('');
	let filterOccurredAfter = $state('');
	let filterOccurredBefore = $state('');
	let filterLimit = $state('50');

	let events = $state<AuditEventRow[]>([]);
	let isLoading = $state(false);
	let listError = $state<string | null>(null);
	let expandedId = $state<number | null>(null);

	onMount(async () => {
		try {
			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			if (!response.is_admin) {
				status = 'not-admin';
				return;
			}
		} catch {
			goto('/login?redirect=/support-admin/audit-events', { replaceState: true });
			return;
		}
		status = 'ready';
		await fetchEvents();
	});

	function buildQueryParams(): Record<string, string> {
		const params: Record<string, string> = {};
		const action = filterAction.trim();
		const clientId = filterClientId.trim();
		if (action) params.action = action;
		if (clientId) params.target_client_id = clientId;
		if (filterOccurredAfter.trim()) {
			const d = new Date(filterOccurredAfter);
			if (!Number.isNaN(d.getTime())) params.occurred_after = d.toISOString();
		}
		if (filterOccurredBefore.trim()) {
			const d = new Date(filterOccurredBefore);
			if (!Number.isNaN(d.getTime())) params.occurred_before = d.toISOString();
		}
		const lim = Math.min(200, Math.max(1, parseInt(filterLimit, 10) || 50));
		params.limit = String(lim);
		return params;
	}

	async function fetchEvents() {
		isLoading = true;
		listError = null;
		try {
			const result = await api.get<{ events: AuditEventRow[] }>('/admin/audit-events', {
				params: buildQueryParams()
			});
			events = result.events;
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : 'Failed to load audit events';
			listError = msg;
			toast.error(msg);
		} finally {
			isLoading = false;
		}
	}

	function formatWhen(iso: string): string {
		return new Date(iso).toLocaleString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit'
		});
	}

	function truncateActor(hex: string): string {
		if (hex.length <= 16) return hex;
		return `${hex.slice(0, 8)}…${hex.slice(-6)}`;
	}

	function prettyJson(value: unknown): string {
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return String(value);
		}
	}

	function hasBeforeAfter(
		m: unknown
	): m is { before: unknown; after: unknown } {
		return (
			typeof m === 'object' &&
			m !== null &&
			'before' in m &&
			'after' in m
		);
	}

	function toggleExpand(id: number) {
		expandedId = expandedId === id ? null : id;
	}
</script>

<svelte:head>
	<title>Admin audit log - {BRAND.name}</title>
</svelte:head>

{#if status === 'loading'}
	<div class="page">
		<div class="loading">Loading...</div>
	</div>
{:else if status === 'not-admin'}
	<div class="page">
		<div class="access-denied">
			<Warning size={48} weight="fill" />
			<h2>Access Denied</h2>
			<p>Admin access is required to view the audit log.</p>
		</div>
	</div>
{:else}
	<div class="page">
		<div class="header">
			<a href="/support-admin" class="back-link">
				<ArrowLeft size={16} />
				Back to Support Admin
			</a>
			<h1>Admin audit log</h1>
			<p class="subtitle">
				Read-only forensic trail for admin actions on this tenant (e.g. registered OAuth clients).
				Updates show before/after snapshots when available.
			</p>
		</div>

		<div class="section">
			<div class="section-header">
				<div class="section-icon"><MagnifyingGlass size={24} weight="duotone" /></div>
				<div>
					<h2>Filters</h2>
					<p>Scope is always the current tenant. Times use your local timezone; the API receives RFC3339.</p>
				</div>
			</div>

			<form
				class="filter-form"
				onsubmit={(e) => {
					e.preventDefault();
					fetchEvents();
				}}
			>
				<label>
					<span class="label">Action</span>
					<input type="text" bind:value={filterAction} placeholder="e.g. registered_client.update" disabled={isLoading} />
				</label>
				<label>
					<span class="label">Target client id</span>
					<input type="text" bind:value={filterClientId} placeholder="OAuth client_id" disabled={isLoading} />
				</label>
				<label>
					<span class="label">Occurred after</span>
					<input type="datetime-local" bind:value={filterOccurredAfter} disabled={isLoading} />
				</label>
				<label>
					<span class="label">Occurred before</span>
					<input type="datetime-local" bind:value={filterOccurredBefore} disabled={isLoading} />
				</label>
				<label>
					<span class="label">Limit</span>
					<input type="number" min="1" max="200" bind:value={filterLimit} disabled={isLoading} />
				</label>
				<button type="submit" class="btn-primary" disabled={isLoading}>
					<List size={18} />
					{isLoading ? 'Loading…' : 'Apply filters'}
				</button>
			</form>
		</div>

		<div class="section">
			<div class="section-header">
				<div class="section-icon"><List size={24} weight="duotone" /></div>
				<div>
					<h2>Events</h2>
					<p>Newest first. Expand a row for full metadata.</p>
				</div>
			</div>

			{#if listError}
				<div class="list-error">
					<Warning size={16} />
					<span>{listError}</span>
				</div>
			{/if}

			{#if !isLoading && events.length === 0}
				<p class="empty-text">No events match the current filters.</p>
			{:else}
				<div class="table-wrap">
					<table class="events-table">
						<thead>
							<tr>
								<th class="col-expand"></th>
								<th>When</th>
								<th>Action</th>
								<th>Actor</th>
								<th>Client</th>
								<th>Resource</th>
							</tr>
						</thead>
						<tbody>
							{#each events as row (row.id)}
								<tr>
									<td class="col-expand">
										<button
											type="button"
											class="expand-btn"
											onclick={() => toggleExpand(row.id)}
											aria-expanded={expandedId === row.id}
										>
											{#if expandedId === row.id}
												<CaretDown size={14} weight="bold" />
											{:else}
												<CaretRight size={14} weight="bold" />
											{/if}
										</button>
									</td>
									<td class="date-cell">{formatWhen(row.occurred_at)}</td>
									<td><code>{row.action}</code></td>
									<td class="mono" title={row.actor_pubkey}>{truncateActor(row.actor_pubkey)}</td>
									<td><code>{row.target_client_id ?? '—'}</code></td>
									<td class="resource-cell">
										<code>{row.target_resource_type}</code>
										{#if row.target_resource_id}
											<span class="rid">#{row.target_resource_id}</span>
										{/if}
									</td>
								</tr>
								{#if expandedId === row.id}
									<tr class="detail-row">
										<td colspan="6">
											{#if hasBeforeAfter(row.metadata_json)}
												<div class="diff-grid">
													<div class="diff-col">
														<span class="diff-label">Before</span>
														<pre class="json-block">{prettyJson(row.metadata_json.before)}</pre>
													</div>
													<div class="diff-col">
														<span class="diff-label">After</span>
														<pre class="json-block">{prettyJson(row.metadata_json.after)}</pre>
													</div>
												</div>
											{:else}
												<span class="diff-label">Metadata</span>
												<pre class="json-block">{prettyJson(row.metadata_json)}</pre>
											{/if}
										</td>
									</tr>
								{/if}
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	</div>
{/if}

<style>
	.page {
		max-width: 1100px;
		margin: 0 auto;
		padding: 1.5rem 1.25rem 3rem;
	}

	.loading,
	.access-denied {
		text-align: center;
		padding: 3rem 1rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.access-denied h2 {
		margin: 1rem 0 0.5rem;
		color: var(--color-text, #f1f5f9);
	}

	.header {
		margin-bottom: 1.75rem;
	}

	.back-link {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		color: var(--color-accent, #8b5cf6);
		text-decoration: none;
		font-size: 0.9rem;
		margin-bottom: 0.75rem;
	}

	.back-link:hover {
		text-decoration: underline;
	}

	h1 {
		font-size: 1.65rem;
		font-weight: 700;
		margin: 0 0 0.35rem;
		color: var(--color-text, #f1f5f9);
	}

	.subtitle {
		color: var(--color-text-muted, #94a3b8);
		font-size: 0.95rem;
		line-height: 1.5;
		margin: 0;
	}

	.section {
		background: var(--color-surface-elevated, rgba(15, 23, 42, 0.6));
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.15));
		border-radius: 0.65rem;
		padding: 1.25rem 1.35rem;
		margin-bottom: 1.25rem;
	}

	.section-header {
		display: flex;
		gap: 0.85rem;
		align-items: flex-start;
		margin-bottom: 1rem;
	}

	.section-header h2 {
		font-size: 1.05rem;
		font-weight: 600;
		margin: 0 0 0.2rem;
		color: var(--color-text, #f1f5f9);
	}

	.section-header p {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.section-icon {
		color: var(--color-accent, #8b5cf6);
		flex-shrink: 0;
	}

	.filter-form {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 1rem;
		align-items: end;
	}

	.filter-form label {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		font-size: 0.85rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.filter-form input {
		padding: 0.5rem 0.65rem;
		border-radius: 0.4rem;
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.25));
		background: var(--color-bg, #0f172a);
		color: var(--color-text, #f1f5f9);
		font-size: 0.9rem;
	}

	.label {
		font-weight: 500;
	}

	.btn-primary {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.55rem 1rem;
		background: var(--color-accent, #8b5cf6);
		color: white;
		border: none;
		border-radius: 0.4rem;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
		height: fit-content;
	}

	.btn-primary:hover:not(:disabled) {
		opacity: 0.92;
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.list-error {
		display: flex;
		gap: 0.4rem;
		align-items: center;
		color: #fca5a5;
		font-size: 0.9rem;
		margin-bottom: 0.75rem;
	}

	.empty-text {
		color: var(--color-text-muted, #94a3b8);
		font-style: italic;
		margin: 0;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.events-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.88rem;
	}

	.events-table th,
	.events-table td {
		padding: 0.6rem 0.65rem;
		border-bottom: 1px solid var(--color-border, rgba(148, 163, 184, 0.12));
		text-align: left;
		vertical-align: top;
	}

	.events-table th {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted, #94a3b8);
		font-weight: 600;
	}

	.col-expand {
		width: 2rem;
		padding-right: 0;
	}

	.expand-btn {
		background: transparent;
		border: none;
		color: var(--color-text-muted, #94a3b8);
		cursor: pointer;
		padding: 0.2rem;
		border-radius: 0.25rem;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.expand-btn:hover {
		color: var(--color-text, #f1f5f9);
		background: rgba(148, 163, 184, 0.12);
	}

	.date-cell {
		white-space: nowrap;
		font-size: 0.82rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.mono {
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
		font-size: 0.82rem;
	}

	.events-table code {
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
		font-size: 0.82em;
		background: rgba(148, 163, 184, 0.12);
		padding: 0.1rem 0.3rem;
		border-radius: 0.25rem;
	}

	.resource-cell {
		font-size: 0.85rem;
	}

	.rid {
		margin-left: 0.35rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.detail-row td {
		background: rgba(148, 163, 184, 0.06);
		padding-top: 0.85rem;
		padding-bottom: 0.85rem;
	}

	.diff-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}

	@media (max-width: 720px) {
		.diff-grid {
			grid-template-columns: 1fr;
		}
	}

	.diff-label {
		display: block;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted, #94a3b8);
		margin-bottom: 0.4rem;
	}

	.json-block {
		margin: 0;
		padding: 0.75rem;
		background: var(--color-bg, #0f172a);
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.2));
		border-radius: 0.4rem;
		font-size: 0.78rem;
		line-height: 1.45;
		overflow-x: auto;
		max-height: 320px;
		overflow-y: auto;
	}
</style>
