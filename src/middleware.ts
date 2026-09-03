import { defineMiddleware } from 'astro:middleware';

// Simple in-memory rate limit (per Worker isolate). For durable limits use Cloudflare Rate Limiting dashboard.
const hits = new Map<string, { count: number; reset: number }>();
const WINDOW_MS = 60_000;
const MAX_HITS = 60; // 60 req/min per IP per path prefix

function isRateLimited(ip: string, path: string): boolean {
	const key = `${ip}:${path.slice(0, 20)}`;
	const now = Date.now();
	const entry = hits.get(key);
	if (!entry || now > entry.reset) {
		hits.set(key, { count: 1, reset: now + WINDOW_MS });
		return false;
	}
	entry.count += 1;
	return entry.count > MAX_HITS;
}

export const onRequest = defineMiddleware(async (context, next) => {
	const request = context.request;
	const url = new URL(request.url);
	const ip = request.headers.get('CF-Connecting-IP') ?? request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ?? '0.0.0.0';

	// Block obvious probes on sensitive paths
	if (url.pathname.startsWith('/.env') || url.pathname.startsWith('/.git') || url.pathname.includes('wp-') || url.pathname.includes('.php')) {
		return new Response('Not found', { status: 404 });
	}

	// Rate limit API
	if (url.pathname.startsWith('/api/')) {
		if (isRateLimited(ip, url.pathname)) {
			return new Response('Too many requests', { status: 429, headers: { 'Retry-After': '60' } });
		}
	}

	const response = await next();

	// Security headers for probing resilience
	response.headers.set('X-Frame-Options', 'DENY');
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
	response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
	response.headers.set('X-Robots-Tag', 'noai, noimageai');
	// HSTS only when not localhost
	if (!url.hostname.includes('localhost') && !url.hostname.includes('127.0.0.1')) {
		response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
	}
	response.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com");

	return response;
});
