// middleware.ts

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { Redis } from '@upstash/redis';

let redis: ReturnType<typeof Redis.fromEnv> | null = null;

function getRedis() {
  if (redis) return redis;
  try {
    redis = Redis.fromEnv();
    return redis;
  } catch (err) {
    // Upstash may not be configured in some environments (local dev/build).
    // Fail gracefully: middleware should still work without rate-limiting.
    // eslint-disable-next-line no-console
    console.warn('Upstash Redis init failed in middleware:', err);
    redis = null;
    return null;
  }
}

export async function middleware(request: NextRequest) {
  const ip =
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    'unknown';
  const path = request.nextUrl.pathname;

  // Rate limiting untuk API voting (gunakan Redis jika tersedia)
  if (path.startsWith('/api/voting')) {
    const client = getRedis();
    if (client) {
      try {
        const rateLimitKey = `rate_limit:${ip}`;
        const current = await client.incr(rateLimitKey);

        if (current === 1) {
          await client.expire(rateLimitKey, 60); // 1 menit
        }

        if (current > 100) {
          return NextResponse.json(
            { error: 'Too many requests' },
            { status: 429 }
          );
        }
      } catch (err) {
        // If Redis fails at runtime, log and allow the request through.
        // eslint-disable-next-line no-console
        console.warn('Redis rate-limit error in middleware:', err);
      }
    }
    // If no Redis client is available, skip rate limiting (fail open).
  }

  // Protect admin routes
  if (path.startsWith('/admin') || path.startsWith('/api/admin')) {
    const session = request.cookies.get('admin_session')?.value;
    
    if (!session) {
      if (path.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        );
      }
      return NextResponse.redirect(new URL('/admin/login', request.url));
    }
  }

  // Add security headers
  const response = NextResponse.next();
  
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
  );

  return response;
}

export const config = {
  matcher: ['/api/:path*', '/admin/:path*', '/vote/:path*'],
};