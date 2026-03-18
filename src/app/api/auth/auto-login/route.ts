import { saveAuth } from '@/lib/auth';
import { secret } from '@/lib/crypto';
import { createSecureToken } from '@/lib/jwt';
import redis from '@/lib/redis';
import { ROLES } from '@/lib/constants';
import { getUserByUsername } from '@/queries/prisma';

/**
 * Auto-login endpoint for Forglen dashboard iframe embedding.
 *
 * Validates a shared secret, creates a session for the configured
 * service account, and returns an HTML page that stores the JWT
 * in localStorage (where Umami's frontend expects it) then redirects.
 *
 * Usage: GET /api/auth/auto-login?secret=xxx&redirect=/
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const autoLoginSecret = url.searchParams.get('secret');
  const redirect = url.searchParams.get('redirect') || '/';

  const expectedSecret = process.env.AUTO_LOGIN_SECRET;

  if (!expectedSecret || !autoLoginSecret || autoLoginSecret !== expectedSecret) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Use the admin user (first user created during setup)
  const username = process.env.AUTO_LOGIN_USERNAME || 'admin';
  const user = await getUserByUsername(username, { includePassword: false });

  if (!user) {
    return new Response('User not found', { status: 404 });
  }

  const { id, role } = user;

  let token: string;

  if (redis.enabled) {
    token = await saveAuth({ userId: id, role });
  } else {
    token = createSecureToken({ userId: id, role }, secret());
  }

  // Return HTML that stores the token in localStorage and redirects.
  // This runs inside the iframe's origin, so localStorage is scoped correctly.
  const html = `<!DOCTYPE html>
<html>
<head><title>Logging in...</title></head>
<body>
<script>
  try {
    const data = ${JSON.stringify(JSON.stringify({ token, user: { id, username: user.username, role, isAdmin: role === ROLES.admin } }))};
    localStorage.setItem('umami.auth', data);
    window.location.href = ${JSON.stringify(redirect)};
  } catch (e) {
    document.body.textContent = 'Auto-login failed: ' + e.message;
  }
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
