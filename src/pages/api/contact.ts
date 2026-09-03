import type { APIRoute } from 'astro';
import { isRecord } from '../../lib/guards';

export const prerender = false;

type SiteVerifyResponse = {
	success: boolean;
	hostname?: string;
	action?: string;
	'error-codes'?: string[];
};

type RuntimeEnv = Record<string, string | undefined>;

function getEnv(locals: unknown): RuntimeEnv {
	if (isRecord(locals) && 'runtime' in locals) {
		const runtime = locals.runtime;
		if (isRecord(runtime) && 'env' in runtime) {
			const env = runtime.env;
			if (isRecord(env)) return env as RuntimeEnv;
		}
	}
	const meta = import.meta as unknown as Record<string, unknown>;
	if (isRecord(meta) && 'env' in meta && isRecord(meta.env)) {
		return meta.env as RuntimeEnv;
	}
	if (typeof process !== 'undefined') {
		const proc = process as unknown as Record<string, unknown>;
		if (isRecord(proc) && 'env' in proc && isRecord(proc.env)) {
			return proc.env as RuntimeEnv;
		}
	}
	return {};
}

function getClientIp(request: Request): string | undefined {
	// Cloudflare Workers: CF-Connecting-IP is canonical
	const cfIp = request.headers.get('CF-Connecting-IP');
	if (cfIp) return cfIp;
	const forwarded = request.headers.get('X-Forwarded-For');
	if (forwarded) return forwarded.split(',')[0]?.trim();
	return undefined;
}

export const POST: APIRoute = async ({ request, locals }) => {
	const env = getEnv(locals);
	const secret = env.TURNSTILE_SECRET;
	const hostnamesRaw = env.TURNSTILE_HOSTNAMES ?? '';

	if (!secret) {
		return new Response(JSON.stringify({ error: 'server misconfigured' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	let body: Record<string, unknown>;
	const contentType = request.headers.get('content-type') ?? '';
	try {
		if (contentType.includes('application/json')) {
			body = (await request.json()) as Record<string, unknown>;
		} else if (contentType.includes('application/x-www-form-urlencoded')) {
			const form = await request.formData();
			body = Object.fromEntries(form.entries()) as Record<string, unknown>;
		} else {
			// try json fallback, then formData
			try {
				body = (await request.clone().json()) as Record<string, unknown>;
			} catch {
				const form = await request.formData();
				body = Object.fromEntries(form.entries()) as Record<string, unknown>;
			}
		}
	} catch {
		return new Response(JSON.stringify({ error: 'invalid request' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	const token = body['cf-turnstile-response'] as string | undefined;
	const expectedAction = 'contact';
	const expectedHostnames = new Set(
		hostnamesRaw
			.split(',')
			.map((h) => h.trim())
			.filter(Boolean),
	);

	if (
		typeof token !== 'string' ||
		token.length === 0 ||
		token.length > 2048 ||
		expectedHostnames.size === 0
	) {
		return new Response(JSON.stringify({ error: 'forbidden' }), {
			status: 403,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	const clientIp = getClientIp(request);

	let result: SiteVerifyResponse;
	try {
		const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			signal: AbortSignal.timeout(10_000),
			body: new URLSearchParams({
				secret,
				response: token,
				...(clientIp ? { remoteip: clientIp } : {}),
			}),
		});
		if (!r.ok) throw new Error(`siteverify ${r.status}`);
		result = (await r.json()) as SiteVerifyResponse;
	} catch {
		return new Response(JSON.stringify({ error: 'forbidden' }), {
			status: 403,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	if (!result.success || result.action !== expectedAction || !result.hostname || !expectedHostnames.has(result.hostname)) {
		return new Response(JSON.stringify({ error: 'forbidden', codes: result['error-codes'] }), {
			status: 403,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	// --- existing handler logic runs here, unchanged ---
	// For this portfolio, we gate the contact submission and echo success.
	// Replace with real mail / persistence as needed; do NOT add notification delivery here.
	const name = typeof body.name === 'string' ? body.name.slice(0, 200) : undefined;
	const email = typeof body.email === 'string' ? body.email.slice(0, 320) : undefined;
	const message = typeof body.message === 'string' ? body.message.slice(0, 5000) : undefined;

	if (!name || !email || !message) {
		return new Response(JSON.stringify({ error: 'missing fields' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	return new Response(JSON.stringify({ ok: true }), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});
};
