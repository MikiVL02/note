import { Hono } from 'hono'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { eq } from 'drizzle-orm'
import { db, users } from '../db'

export const oauthRouter = new Hono()

// OAuth2 客户端配置（运行时读取，避免 dotenv 在模块初始化后才加载导致空值）
function getClientId() { return process.env.OAUTH_CLIENT_ID || 'resume-app' }
function getClientSecret() { return process.env.OAUTH_CLIENT_SECRET || '' }
function getAllowedRedirectUris() {
  return (process.env.OAUTH_ALLOWED_REDIRECT_URIS || '').split(',').map(s => s.trim()).filter(Boolean)
}

// 内存存储授权码（5 分钟有效期）
const authCodes = new Map<string, { userId: string; expiresAt: number; redirectUri: string }>()

function generateCode(): string {
  return [...Array(32)].map(() => Math.random().toString(36)[2]).join('')
}

function isRedirectUriAllowed(uri: string): boolean {
  const allowed = getAllowedRedirectUris()
  if (allowed.length === 0) return true
  return allowed.some(a => uri.startsWith(a))
}

// GET /api/oauth/authorize
// 显示登录授权页
oauthRouter.get('/authorize', async (c) => {
  const { client_id, redirect_uri, state, response_type } = c.req.query()

  if (client_id !== getClientId()) {
    return c.html('<h1>错误</h1><p>无效的 client_id</p>', 400)
  }
  if (response_type !== 'code') {
    return c.html('<h1>错误</h1><p>仅支持 response_type=code</p>', 400)
  }
  if (!redirect_uri || !isRedirectUriAllowed(redirect_uri)) {
    return c.html('<h1>错误</h1><p>不允许的 redirect_uri</p>', 400)
  }

  const stateParam = state ? `<input type="hidden" name="state" value="${escapeHtml(state)}">` : ''
  const html = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>授权登录 — mikivl.online</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; width: 100%; max-width: 380px; }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
    .logo p { font-size: 0.85rem; color: #94a3b8; margin-top: 0.4rem; }
    label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.4rem; margin-top: 1rem; }
    input { width: 100%; padding: 0.6rem 0.8rem; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f1f5f9; font-size: 0.95rem; outline: none; transition: border-color 0.15s; }
    input:focus { border-color: #6366f1; }
    button { width: 100%; margin-top: 1.5rem; padding: 0.7rem; background: #6366f1; color: white; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 500; cursor: pointer; transition: background 0.15s; }
    button:hover { background: #4f46e5; }
    .error { color: #f87171; font-size: 0.85rem; margin-top: 0.8rem; text-align: center; }
    .app-name { color: #6366f1; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>mikivl.online</h1>
      <p><span class="app-name">简历工具</span> 申请访问你的账号</p>
    </div>
    <form method="POST" action="/api/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
      <input type="hidden" name="response_type" value="code">
      ${stateParam}
      <label for="username">用户名</label>
      <input type="text" id="username" name="username" autocomplete="username" required>
      <label for="password">密码</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
      <button type="submit">授权登录</button>
    </form>
  </div>
</body>
</html>`
  return c.html(html)
})

// POST /api/oauth/authorize
// 验证密码，生成授权码并重定向
oauthRouter.post('/authorize', async (c) => {
  const body = await c.req.parseBody()
  const { client_id, redirect_uri, state, username, password } = body as Record<string, string>

  if (client_id !== getClientId() || !isRedirectUriAllowed(redirect_uri)) {
    return c.html('<h1>错误</h1><p>无效请求</p>', 400)
  }

  const [user] = db.select().from(users).where(eq(users.username, username)).all()
  const errorHtml = (msg: string) => {
    const stateParam = state ? `<input type="hidden" name="state" value="${escapeHtml(state)}">` : ''
    return c.html(`<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>授权登录 — mikivl.online</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; width: 100%; max-width: 380px; }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
    .logo p { font-size: 0.85rem; color: #94a3b8; margin-top: 0.4rem; }
    label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.4rem; margin-top: 1rem; }
    input { width: 100%; padding: 0.6rem 0.8rem; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f1f5f9; font-size: 0.95rem; outline: none; transition: border-color 0.15s; }
    input:focus { border-color: #6366f1; }
    button { width: 100%; margin-top: 1.5rem; padding: 0.7rem; background: #6366f1; color: white; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 500; cursor: pointer; transition: background 0.15s; }
    button:hover { background: #4f46e5; }
    .error { color: #f87171; font-size: 0.85rem; margin-top: 0.8rem; text-align: center; }
    .app-name { color: #6366f1; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>mikivl.online</h1>
      <p><span class="app-name">简历工具</span> 申请访问你的账号</p>
    </div>
    <form method="POST" action="/api/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
      <input type="hidden" name="response_type" value="code">
      ${stateParam}
      <label for="username">用户名</label>
      <input type="text" id="username" name="username" value="${escapeHtml(username)}" autocomplete="username" required>
      <label for="password">密码</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
      <button type="submit">授权登录</button>
      <p class="error">${escapeHtml(msg)}</p>
    </form>
  </div>
</body>
</html>`, 401)
  }

  if (!user || user.banned) return errorHtml('用户名或密码错误')
  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return errorHtml('用户名或密码错误')

  const code = generateCode()
  authCodes.set(code, { userId: user.id, expiresAt: Date.now() + 5 * 60 * 1000, redirectUri: redirect_uri })

  const url = new URL(redirect_uri)
  url.searchParams.set('code', code)
  if (state) url.searchParams.set('state', state)
  return c.redirect(url.toString())
})

// POST /api/oauth/token
// 授权码换 access_token
oauthRouter.post('/token', async (c) => {
  let body: Record<string, string>
  const contentType = c.req.header('content-type') || ''
  if (contentType.includes('application/json')) {
    body = await c.req.json()
  } else {
    body = await c.req.parseBody() as Record<string, string>
  }

  const { grant_type, code, redirect_uri, client_id, client_secret } = body

  if (grant_type !== 'authorization_code') {
    return c.json({ error: 'unsupported_grant_type' }, 400)
  }

  // 支持 Basic Auth 或 body 参数
  let effectiveClientId = client_id
  let effectiveClientSecret = client_secret
  const authHeader = c.req.header('authorization')
  if (authHeader?.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString()
    const [id, secret] = decoded.split(':')
    effectiveClientId = id
    effectiveClientSecret = secret
  }

  if (effectiveClientId !== getClientId() || effectiveClientSecret !== getClientSecret()) {
    return c.json({ error: 'invalid_client' }, 401)
  }

  const entry = authCodes.get(code)
  if (!entry || Date.now() > entry.expiresAt) {
    authCodes.delete(code)
    return c.json({ error: 'invalid_grant' }, 400)
  }
  if (entry.redirectUri !== redirect_uri) {
    return c.json({ error: 'invalid_grant' }, 400)
  }

  authCodes.delete(code)

  const [user] = db.select().from(users).where(eq(users.id, entry.userId)).all()
  if (!user) return c.json({ error: 'invalid_grant' }, 400)

  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, scope: 'profile email' },
    process.env.JWT_SECRET!,
    { expiresIn: '1h', issuer: 'mikivl.online' }
  )

  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
  })
})

// GET /api/oauth/userinfo
// 返回用户信息
oauthRouter.get('/userinfo', async (c) => {
  const header = c.req.header('authorization')
  if (!header?.startsWith('Bearer ')) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  const token = header.slice(7)
  let payload: { sub: string; username: string }
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET!, { issuer: 'mikivl.online' }) as { sub: string; username: string }
  } catch {
    return c.json({ error: 'invalid_token' }, 401)
  }

  const [user] = db.select().from(users).where(eq(users.id, payload.sub)).all()
  if (!user) return c.json({ error: 'user_not_found' }, 404)

  return c.json({
    sub: user.id,
    name: user.nickname || user.username,
    preferred_username: user.username,
    email: user.email || `${user.username}@mikivl.online`,
    email_verified: user.emailVerified,
    picture: user.avatar || null,
  })
})

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
