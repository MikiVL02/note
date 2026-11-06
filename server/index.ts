import dotenv from 'dotenv'
import path from 'node:path'
dotenv.config({ path: path.resolve(process.cwd(), '.env') })
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import Anthropic from '@anthropic-ai/sdk'
import fs from 'node:fs'
import { initDb, db, siteContent } from './db'
import { authRouter } from './routes/auth'
import { notesRouter } from './routes/notes'
import { foldersRouter } from './routes/folders'
import { commentsRouter } from './routes/comments'
import { adminRouter } from './routes/admin'
import { oauthRouter } from './routes/oauth'
import { internalRouter } from './routes/internal'
import { requireAuth } from './middleware/auth'
import { db as _db, users } from './db'
import { eq } from 'drizzle-orm'

const app = new Hono()
app.use('*', cors())

// ── Model config persistence ──────────────────────────────────────────────────
const MODELS_FILE = process.env.MODELS_FILE ?? path.resolve('models.json')

type ModelConfig = {
  id: string
  name: string
  apiKey: string
  baseURL: string
  modelId?: string
  isActive: boolean
}

function readModels(): ModelConfig[] {
  try {
    return JSON.parse(fs.readFileSync(MODELS_FILE, 'utf-8')) as ModelConfig[]
  } catch {
    // First run: seed from .env
    const defaults: ModelConfig[] = [
      {
        id: 'default',
        name: 'Claude Sonnet 4.6',
        apiKey: process.env.ANTHROPIC_API_KEY ?? '',
        baseURL: process.env.ANTHROPIC_BASE_URL ?? 'https://api.anthropic.com',
        isActive: true,
      },
    ]
    fs.writeFileSync(MODELS_FILE, JSON.stringify(defaults, null, 2))
    return defaults
  }
}

function writeModels(models: ModelConfig[]) {
  fs.writeFileSync(MODELS_FILE, JSON.stringify(models, null, 2))
}

function getActiveClient(): Anthropic {
  const models = readModels()
  const active = models.find(m => m.isActive) ?? models[0]
  return new Anthropic({ apiKey: active.apiKey, baseURL: active.baseURL })
}

function getActiveModel(): string {
  const models = readModels()
  const active = models.find(m => m.isActive) ?? models[0]
  // model id stored in name field as identifier; use a known default if not specified
  return active.modelId ?? 'claude-sonnet-4-6'
}

// ── Model CRUD endpoints ──────────────────────────────────────────────────────
app.route('/api/auth', authRouter)
app.route('/api/admin', adminRouter)
app.route('/api/oauth', oauthRouter)
app.route('/api/internal', internalRouter)
app.route('/api/note/notes', notesRouter)
app.route('/api/note/folders', foldersRouter)
app.route('/api/note/comments', commentsRouter)

// 公共站点内容接口（无需认证）
app.get('/api/site-content', (c) => {
  const rows = db.select().from(siteContent).all()
  const result: Record<string, string> = {}
  for (const row of rows) result[row.key] = row.value
  return c.json(result)
})

app.get('/api/note/models', (c) => {
  const models = readModels()
  // strip apiKey from response for security
  return c.json(models.map(({ apiKey: _, ...rest }) => rest))
})

app.post('/api/note/models', async (c) => {
  const body = await c.req.json<{ name: string; apiKey: string; baseURL: string; modelId?: string }>()
  const models = readModels()
  const newModel: ModelConfig = {
    id: crypto.randomUUID(),
    name: body.name.trim(),
    apiKey: body.apiKey.trim(),
    baseURL: body.baseURL.trim(),
    isActive: false,
    ...(body.modelId ? { modelId: body.modelId.trim() } : {}),
  }
  models.push(newModel)
  writeModels(models)
  const { apiKey: _, ...safe } = newModel
  return c.json(safe)
})

app.patch('/api/note/models/:id/activate', (c) => {
  const { id } = c.req.param()
  const models = readModels()
  models.forEach(m => { m.isActive = m.id === id })
  writeModels(models)
  return c.json({ ok: true })
})

app.delete('/api/note/models/:id', (c) => {
  const { id } = c.req.param()
  let models = readModels()
  const target = models.find(m => m.id === id)
  if (!target) return c.json({ error: 'not found' }, 404)
  if (models.length === 1) return c.json({ error: 'cannot delete last model' }, 400)
  const wasActive = target.isActive
  models = models.filter(m => m.id !== id)
  if (wasActive) models[0].isActive = true
  writeModels(models)
  return c.json({ ok: true })
})

// ── AI types ──────────────────────────────────────────────────────────────────
type AIStreamRequest = {
  type: 'continue' | 'polish' | 'summarize' | 'translate' | 'chat'
  noteContent: string
  selection?: string
  messages?: { role: 'user' | 'assistant'; content: string }[]
  userMessage?: string
}

function buildMessages(req: AIStreamRequest): Anthropic.MessageParam[] {
  const { type, noteContent, selection, messages, userMessage } = req

  if (type === 'chat') {
    const history: Anthropic.MessageParam[] = (messages ?? []).map(m => ({
      role: m.role,
      content: m.content,
    }))
    if (userMessage) history.push({ role: 'user', content: userMessage })
    return history
  }

  if (type === 'continue') {
    return [{ role: 'user', content: `请基于以下笔记内容，从最后一段自然地续写下去，风格保持一致，直接输出续写内容，不要重复原文：\n\n${noteContent}` }]
  }

  if (type === 'polish') {
    return [{ role: 'user', content: `请润色以下文字，改善语法、流畅度和表达，保持原意，直接输出润色后的结果，不要有任何解释：\n\n${selection ?? noteContent}` }]
  }

  if (type === 'translate') {
    return [{ role: 'user', content: `请将以下文字翻译成英文，保持原文风格和格式，直接输出翻译结果，不要有任何解释：\n\n${selection ?? noteContent}` }]
  }

  return [{ role: 'user', content: `请为以下内容提炼要点摘要，用简洁的中文输出，不超过 150 字：\n\n${selection ?? noteContent}` }]
}

function buildSystemPrompt(type: AIStreamRequest['type'], noteContent: string): string {
  if (type === 'chat') {
    return `你是一个智能笔记助手。用户正在阅读以下笔记，请根据笔记内容回答用户的问题，回答要简洁、准确：\n\n---\n${noteContent}\n---`
  }
  return '你是一个专业的写作助手，擅长中英文写作、润色和摘要。直接输出结果，不要加多余的说明。'
}

// ── Stream endpoint ───────────────────────────────────────────────────────────
app.post('/api/note/ai/stream', requireAuth, async (c) => {
  const userId = c.get('userId')
  const [user] = _db.select({ cloudEnabled: users.cloudEnabled }).from(users).where(eq(users.id, userId)).all()
  if (!user?.cloudEnabled) {
    return c.json({ error: '请先用邀请码激活云功能后才能使用 AI' }, 403)
  }

  const req = await c.req.json<AIStreamRequest>()
  const aiClient = getActiveClient()
  const modelId = getActiveModel()

  const stream = await aiClient.messages.stream({
    model: modelId,
    max_tokens: 4096,
    system: buildSystemPrompt(req.type, req.noteContent),
    messages: buildMessages(req),
  })

  return new Response(
    new ReadableStream({
      async start(controller) {
        const encoder = new TextEncoder()
        try {
          for await (const event of stream) {
            if (
              event.type === 'content_block_delta' &&
              event.delta.type === 'text_delta'
            ) {
              const data = JSON.stringify({ delta: event.delta.text })
              controller.enqueue(encoder.encode(`data: ${data}\n\n`))
            }
          }
          controller.enqueue(encoder.encode('data: [DONE]\n\n'))
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Unknown error'
          controller.enqueue(encoder.encode(`data: {"error":"${msg}"}\n\n`))
        } finally {
          controller.close()
        }
      },
    }),
    {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      },
    }
  )
})

initDb()

serve({ fetch: app.fetch, port: Number(process.env.PORT ?? 3003) }, () => {
  console.log(`AI proxy server running on http://localhost:${process.env.PORT ?? 3003}`)
})
