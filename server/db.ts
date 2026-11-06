import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core'
import path from 'path'
import fs from 'fs'

const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), 'data', 'app.db')
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })

const sqlite = new Database(DB_PATH)
sqlite.pragma('journal_mode = WAL')
sqlite.pragma('foreign_keys = ON')

export const db = drizzle(sqlite)

export const users = sqliteTable('users', {
  id:                 text('id').primaryKey(),
  username:           text('username').notNull().unique(),
  passwordHash:       text('password_hash').notNull(),
  cloudEnabled:       integer('cloud_enabled', { mode: 'boolean' }).notNull().default(false),
  role:               text('role').notNull().default('user'),
  banned:             integer('banned', { mode: 'boolean' }).notNull().default(false),
  nickname:           text('nickname'),
  avatar:             text('avatar'),
  email:              text('email'),
  emailVerified:      integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  pendingEmail:       text('pending_email'),
  emailVerifyCode:    text('email_verify_code'),
  emailVerifyExpiry:  integer('email_verify_expiry'),
  resetCode:          text('reset_code'),
  resetCodeExpiry:    integer('reset_code_expiry'),
  createdAt:          integer('created_at').notNull(),
})

export const notes = sqliteTable('notes', {
  id:        text('id').primaryKey(),
  userId:    text('user_id').notNull().references(() => users.id),
  title:     text('title').notNull().default(''),
  content:   text('content').notNull().default(''),
  folderId:  text('folder_id'),
  tags:      text('tags').notNull().default('[]'),
  starred:   integer('starred', { mode: 'boolean' }).notNull().default(false),
  wordCount: integer('word_count').notNull().default(0),
  deletedAt: integer('deleted_at'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
})

export const folders = sqliteTable('folders', {
  id:        text('id').primaryKey(),
  userId:    text('user_id').notNull().references(() => users.id),
  name:      text('name').notNull(),
  parentId:  text('parent_id'),
  order:     integer('order').notNull().default(0),
  createdAt: integer('created_at').notNull(),
})

export const comments = sqliteTable('comments', {
  id:        text('id').primaryKey(),
  userId:    text('user_id').notNull().references(() => users.id),
  content:   text('content').notNull(),
  createdAt: integer('created_at').notNull(),
})

export const inviteCodes = sqliteTable('invite_codes', {
  code:         text('code').primaryKey(),
  usedByUserId: text('used_by_user_id'),
  usedAt:       integer('used_at'),
})

export const siteContent = sqliteTable('site_content', {
  key:   text('key').primaryKey(),
  value: text('value').notNull(),
})

export function initDb() {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      cloud_enabled INTEGER NOT NULL DEFAULT 0,
      email TEXT,
      email_verified INTEGER NOT NULL DEFAULT 0,
      email_verify_code TEXT,
      email_verify_expiry INTEGER,
      reset_code TEXT,
      reset_code_expiry INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      title TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL DEFAULT '',
      folder_id TEXT,
      tags TEXT NOT NULL DEFAULT '[]',
      starred INTEGER NOT NULL DEFAULT 0,
      word_count INTEGER NOT NULL DEFAULT 0,
      deleted_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      parent_id TEXT,
      "order" INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invite_codes (
      code TEXT PRIMARY KEY,
      used_by_user_id TEXT,
      used_at INTEGER
    );
  `)

  const INVITE_CODES = [
    'MIKI-A7X2-KP9Q', 'MIKI-B3N8-WR4L', 'MIKI-C6M1-ZT7Y',
    'MIKI-D9F5-HJ2V', 'MIKI-E4K3-QN6U', 'MIKI-F8R7-XG1S',
    'MIKI-G2W4-LB5E', 'MIKI-H5T9-MC8D', 'MIKI-J1P6-VF3O',
    'MIKI-K7Q2-YH4N',
  ]
  const insert = sqlite.prepare(`INSERT OR IGNORE INTO invite_codes (code) VALUES (?)`)
  for (const code of INVITE_CODES) insert.run(code)

  // 迁移：为已有数据库添加邮箱相关字段
  const cols = sqlite.prepare(`PRAGMA table_info(users)`).all() as { name: string }[]
  const colNames = cols.map(c => c.name)
  if (!colNames.includes('email'))               sqlite.exec(`ALTER TABLE users ADD COLUMN email TEXT`)
  if (!colNames.includes('email_verified'))       sqlite.exec(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`)
  if (!colNames.includes('email_verify_code'))    sqlite.exec(`ALTER TABLE users ADD COLUMN email_verify_code TEXT`)
  if (!colNames.includes('email_verify_expiry'))  sqlite.exec(`ALTER TABLE users ADD COLUMN email_verify_expiry INTEGER`)
  if (!colNames.includes('reset_code'))           sqlite.exec(`ALTER TABLE users ADD COLUMN reset_code TEXT`)
  if (!colNames.includes('reset_code_expiry'))    sqlite.exec(`ALTER TABLE users ADD COLUMN reset_code_expiry INTEGER`)
  if (!colNames.includes('nickname'))             sqlite.exec(`ALTER TABLE users ADD COLUMN nickname TEXT`)
  if (!colNames.includes('avatar'))               sqlite.exec(`ALTER TABLE users ADD COLUMN avatar TEXT`)
  if (!colNames.includes('pending_email'))        sqlite.exec(`ALTER TABLE users ADD COLUMN pending_email TEXT`)
  if (!colNames.includes('role'))                 sqlite.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`)
  if (!colNames.includes('banned'))               sqlite.exec(`ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0`)

  // 将 MikiVL 用户设为管理员
  sqlite.exec(`UPDATE users SET role = 'admin' WHERE username = 'MikiVL'`)

  // 创建站点内容表
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS site_content (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `)

  // 预设站点内容默认值
  const siteDefaults = [
    ['tagline', '探索·创造·分享'],
    ['subtitle', '个人项目与技术探索的集合地'],
    ['news', JSON.stringify([
      { date: '2025-06', text: '开放笔记系统公测' },
      { date: '2025-03', text: '网站正式上线' },
    ])],
    ['projects', '[]'],
  ]
  const insertContent = sqlite.prepare(`INSERT OR IGNORE INTO site_content (key, value) VALUES (?, ?)`)
  for (const [key, value] of siteDefaults) insertContent.run(key, value)
}
