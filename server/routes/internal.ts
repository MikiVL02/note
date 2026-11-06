import { Hono } from 'hono'
import { eq } from 'drizzle-orm'
import { db, users } from '../db'

export const internalRouter = new Hono()

function checkSecret(c: any) {
  return process.env.INTERNAL_SECRET && c.req.header('x-internal-secret') === process.env.INTERNAL_SECRET
}

// GET /api/internal/user-status?username=xxx
// 供简历后端查询用户激活状态，需 x-internal-secret 鉴权
internalRouter.get('/user-status', (c) => {
  if (!checkSecret(c)) return c.json({ error: 'forbidden' }, 403)
  const username = c.req.query('username')
  if (!username) return c.json({ error: 'missing username' }, 400)
  const [user] = db.select({ cloudEnabled: users.cloudEnabled })
    .from(users).where(eq(users.username, username)).all()
  return c.json({ cloudEnabled: user?.cloudEnabled ?? false })
})
