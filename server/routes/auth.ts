import { Hono } from 'hono'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { eq } from 'drizzle-orm'
import { db, users, inviteCodes } from '../db'
import { requireAuth } from '../middleware/auth'
import { sendVerifyCode, sendResetCode, sendRegisterCode } from '../lib/email'

export const authRouter = new Hono()

function nanoid() {
  return Math.random().toString(36).slice(2, 11) + Date.now().toString(36)
}

function randomCode() {
  return String(Math.floor(100000 + Math.random() * 900000))
}

// 待注册信息临时存储（key 为邮箱）
const registerPending = new Map<string, {
  username: string
  passwordHash: string
  code: string
  expiry: number
  sentAt: number
}>()

// 发送注册验证码
authRouter.post('/register/send-code', async (c) => {
  const { username, password, email } = await c.req.json<{ username: string; password: string; email: string }>()
  if (!username || !password || !email) return c.json({ error: '请填写所有字段' }, 400)
  if (username.length < 2 || username.length > 20) return c.json({ error: '用户名长度 2-20 位' }, 400)
  if (password.length < 6) return c.json({ error: '密码至少 6 位' }, 400)
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: '邮箱格式不正确' }, 400)

  // 检查用户名是否已存在
  const existingUser = db.select().from(users).where(eq(users.username, username)).all()
  if (existingUser.length > 0) return c.json({ error: '用户名已存在' }, 409)

  // 检查邮箱是否已被验证用户使用
  const existingEmail = db.select().from(users).where(eq(users.email, email)).all()
  if (existingEmail.some(u => u.emailVerified)) return c.json({ error: '该邮箱已被其他账号绑定' }, 409)

  // 60秒冷却
  const pending = registerPending.get(email)
  if (pending && Date.now() - pending.sentAt < 60 * 1000) {
    return c.json({ error: '请等待 60 秒后再重新发送' }, 429)
  }

  const passwordHash = await bcrypt.hash(password, 10)
  const code = randomCode()
  registerPending.set(email, { username, passwordHash, code, expiry: Date.now() + 10 * 60 * 1000, sentAt: Date.now() })

  try {
    await sendRegisterCode(email, code)
  } catch (err) {
    console.error('[email]', err)
    registerPending.delete(email)
    return c.json({ error: '邮件发送失败，请稍后再试' }, 500)
  }
  return c.json({ success: true })
})

// 完成注册（验证验证码）
authRouter.post('/register', async (c) => {
  const { email, code } = await c.req.json<{ email: string; code: string }>()
  if (!email || !code) return c.json({ error: '参数不完整' }, 400)

  const pending = registerPending.get(email)
  if (!pending) return c.json({ error: '请先发送验证码' }, 400)
  if (Date.now() > pending.expiry) {
    registerPending.delete(email)
    return c.json({ error: '验证码已过期，请重新发送' }, 400)
  }
  if (pending.code !== code.trim()) return c.json({ error: '验证码错误' }, 400)

  // 再次检查用户名/邮箱唯一性（防止并发）
  const existingUser = db.select().from(users).where(eq(users.username, pending.username)).all()
  if (existingUser.length > 0) {
    registerPending.delete(email)
    return c.json({ error: '用户名已被注册，请更换用户名重新发送验证码' }, 409)
  }

  const id = nanoid()
  db.insert(users).values({
    id, username: pending.username, passwordHash: pending.passwordHash,
    email, emailVerified: true, cloudEnabled: false, createdAt: Date.now(),
  }).run()
  registerPending.delete(email)

  const token = jwt.sign({ userId: id, username: pending.username }, process.env.JWT_SECRET!, { expiresIn: '30d' })
  return c.json({ token, user: { id, username: pending.username, cloudEnabled: false, role: 'user', email, emailVerified: true, nickname: null, avatar: null } })
})

authRouter.post('/login', async (c) => {
  const { username, password } = await c.req.json<{ username: string; password: string }>()
  if (!username || !password) return c.json({ error: '用户名和密码不能为空' }, 400)

  const [user] = db.select().from(users).where(eq(users.username, username)).all()
  if (!user) return c.json({ error: '用户名或密码错误' }, 401)

  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return c.json({ error: '用户名或密码错误' }, 401)
  if (user.banned) return c.json({ error: '账号已被封禁，请联系管理员' }, 403)

  const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET!, { expiresIn: '30d' })
  return c.json({ token, user: { id: user.id, username: user.username, cloudEnabled: user.cloudEnabled, role: user.role, email: user.email, emailVerified: user.emailVerified, nickname: user.nickname ?? null, avatar: user.avatar ?? null } })
})

authRouter.post('/activate', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { code } = await c.req.json<{ code: string }>()
  if (!code) return c.json({ error: '邀请码不能为空' }, 400)

  const [invite] = db.select().from(inviteCodes).where(eq(inviteCodes.code, code.trim().toUpperCase())).all()
  if (!invite) return c.json({ error: '邀请码不存在' }, 404)
  if (invite.usedByUserId) return c.json({ error: '邀请码已被使用' }, 409)

  db.update(inviteCodes).set({ usedByUserId: userId, usedAt: Date.now() }).where(eq(inviteCodes.code, code.trim().toUpperCase())).run()
  db.update(users).set({ cloudEnabled: true }).where(eq(users.id, userId)).run()

  // 激活成功后推送到简历站，非阻塞
  const resumeUrl = process.env.RESUME_URL
  const internalSecret = process.env.INTERNAL_SECRET
  if (resumeUrl && internalSecret) {
    const [activatedUser] = db.select({ username: users.username }).from(users).where(eq(users.id, userId)).all()
    if (activatedUser) {
      fetch(`${resumeUrl}/api/internal/activate-by-username`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-internal-secret': internalSecret },
        body: JSON.stringify({ username: activatedUser.username }),
      }).catch(() => {})
    }
  }

  return c.json({ success: true })
})

// 获取当前用户信息
authRouter.get('/me', requireAuth, async (c) => {
  const userId = c.get('userId')
  const [user] = db.select().from(users).where(eq(users.id, userId)).all()
  if (!user) return c.json({ error: '用户不存在' }, 404)
  return c.json({ id: user.id, username: user.username, cloudEnabled: user.cloudEnabled, role: user.role, email: user.email, emailVerified: user.emailVerified, nickname: user.nickname ?? null, avatar: user.avatar ?? null })
})

// 更新个人资料（昵称、头像）
authRouter.put('/me', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { nickname, avatar } = await c.req.json<{ nickname?: string; avatar?: string }>()
  const updates: Record<string, any> = {}
  if (nickname !== undefined) {
    if (nickname.length > 20) return c.json({ error: '昵称不超过 20 字' }, 400)
    updates.nickname = nickname.trim() || null
  }
  if (avatar !== undefined) {
    // 限制头像大小（base64 约 100KB）
    if (avatar && avatar.length > 150000) return c.json({ error: '头像不能超过 100KB' }, 400)
    updates.avatar = avatar || null
  }
  if (Object.keys(updates).length === 0) return c.json({ error: '无更新内容' }, 400)
  db.update(users).set(updates).where(eq(users.id, userId)).run()
  const [user] = db.select().from(users).where(eq(users.id, userId)).all()
  return c.json({ id: user.id, username: user.username, cloudEnabled: user.cloudEnabled, role: user.role, email: user.email, emailVerified: user.emailVerified, nickname: user.nickname ?? null, avatar: user.avatar ?? null })
})

// 发送邮箱绑定验证码
authRouter.post('/email/send-verify', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { email } = await c.req.json<{ email: string }>()
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: '邮箱格式不正确' }, 400)

  // 检查邮箱是否已被其他已验证用户绑定
  const existing = db.select().from(users).where(eq(users.email, email)).all()
  if (existing.some(u => u.id !== userId)) return c.json({ error: '该邮箱已被其他账号绑定' }, 409)

  // 60 秒冷却：上次发送时间在 60 秒内则拒绝
  const [user] = db.select().from(users).where(eq(users.id, userId)).all()
  if (user?.emailVerifyExpiry && user.emailVerifyExpiry - Date.now() > 9 * 60 * 1000) {
    return c.json({ error: '请等待 60 秒后再重新发送' }, 429)
  }

  const code = randomCode()
  const expiry = Date.now() + 10 * 60 * 1000
  // 只写入 pendingEmail，不修改 email 字段
  db.update(users).set({ pendingEmail: email, emailVerifyCode: code, emailVerifyExpiry: expiry }).where(eq(users.id, userId)).run()

  try {
    await sendVerifyCode(email, code)
  } catch (err) {
    console.error('[email]', err)
    return c.json({ error: '邮件发送失败，请稍后再试' }, 500)
  }
  return c.json({ success: true })
})

// 验证邮箱绑定验证码
authRouter.post('/email/verify', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { code } = await c.req.json<{ code: string }>()
  if (!code) return c.json({ error: '请输入验证码' }, 400)

  const [user] = db.select().from(users).where(eq(users.id, userId)).all()
  if (!user) return c.json({ error: '用户不存在' }, 404)
  if (!user.emailVerifyCode || user.emailVerifyCode !== code.trim()) return c.json({ error: '验证码错误' }, 400)
  if (!user.emailVerifyExpiry || Date.now() > user.emailVerifyExpiry) return c.json({ error: '验证码已过期，请重新发送' }, 400)

  // 验证成功：将 pendingEmail 写入正式 email 字段
  db.update(users).set({ email: user.pendingEmail, emailVerified: true, pendingEmail: null, emailVerifyCode: null, emailVerifyExpiry: null }).where(eq(users.id, userId)).run()
  return c.json({ success: true })
})

// 忘记密码：发送重置验证码
authRouter.post('/forgot-password', async (c) => {
  const { email } = await c.req.json<{ email: string }>()
  if (!email) return c.json({ error: '请输入邮箱' }, 400)

  const [user] = db.select().from(users).where(eq(users.email, email)).all()
  // 无论是否找到用户都返回成功，避免枚举攻击
  if (!user || !user.emailVerified) return c.json({ success: true })

  const code = randomCode()
  const expiry = Date.now() + 10 * 60 * 1000
  db.update(users).set({ resetCode: code, resetCodeExpiry: expiry }).where(eq(users.id, user.id)).run()

  try {
    await sendResetCode(email, code)
  } catch {
    return c.json({ error: '邮件发送失败，请稍后再试' }, 500)
  }
  return c.json({ success: true })
})

// 重置密码：验证码 + 新密码
authRouter.post('/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json<{ email: string; code: string; newPassword: string }>()
  if (!email || !code || !newPassword) return c.json({ error: '参数不完整' }, 400)
  if (newPassword.length < 6) return c.json({ error: '新密码至少 6 位' }, 400)

  const [user] = db.select().from(users).where(eq(users.email, email)).all()
  if (!user) return c.json({ error: '邮箱未绑定任何账号' }, 404)
  if (!user.resetCode || user.resetCode !== code.trim()) return c.json({ error: '验证码错误' }, 400)
  if (!user.resetCodeExpiry || Date.now() > user.resetCodeExpiry) return c.json({ error: '验证码已过期，请重新获取' }, 400)

  const passwordHash = await bcrypt.hash(newPassword, 10)
  db.update(users).set({ passwordHash, resetCode: null, resetCodeExpiry: null }).where(eq(users.id, user.id)).run()
  return c.json({ success: true })
})

// 修改密码（需要旧密码）
authRouter.post('/change-password', requireAuth, async (c) => {
  const userId = c.get('userId')
  const { oldPassword, newPassword } = await c.req.json<{ oldPassword: string; newPassword: string }>()
  if (!oldPassword || !newPassword) return c.json({ error: '参数不完整' }, 400)
  if (newPassword.length < 6) return c.json({ error: '新密码至少 6 位' }, 400)

  const [user] = db.select().from(users).where(eq(users.id, userId)).all()
  if (!user) return c.json({ error: '用户不存在' }, 404)
  const ok = await bcrypt.compare(oldPassword, user.passwordHash)
  if (!ok) return c.json({ error: '当前密码错误' }, 400)

  const passwordHash = await bcrypt.hash(newPassword, 10)
  db.update(users).set({ passwordHash }).where(eq(users.id, userId)).run()
  return c.json({ success: true })
})

