// StyleVerse API — Express + Postgres (Neon free tier).
// One service for storefront + admin. Deploy as a Vercel project.
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { pool, initDb } from './db.js'
import { toProduct, toCoupon, toOrder, toUser } from './rows.js'
import { signToken, authRequired, adminRequired } from './auth.js'
import { ensureAdmin } from './ensure-admin.js'

dotenv.config()

const app = express()
app.use(cors())
app.use(express.json({ limit: '1mb' }))

await initDb().catch((e) => {
  console.error('❌ initDb failed — check DATABASE_URL:', e.message)
})

app.get('/', (_req, res) => res.json({ ok: true, name: 'StyleVerse API', health: '/api/health' }))
app.get('/api/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }))

// ── Auth (storefront) ───────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, phone, password } = req.body || {}
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' })
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' })
  const id = 'u' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex')
  const hash = await bcrypt.hash(String(password), 10)
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (id, name, email, phone, password, is_admin)
       VALUES ($1,$2,$3,$4,$5,FALSE) RETURNING *`,
      [id, String(name).trim(), String(email).toLowerCase().trim(), String(phone || ''), hash]
    )
    const user = toUser(rows[0])
    res.status(201).json({ user, token: signToken(rows[0]) })
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' })
    throw e
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {}
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [String(email || '').toLowerCase().trim()])
  const row = rows[0]
  if (!row || !(await bcrypt.compare(String(password || ''), row.password))) {
    return res.status(401).json({ error: 'Invalid email or password' })
  }
  res.json({ user: toUser(row), token: signToken(row) })
})

app.get('/api/auth/me', authRequired, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.auth.uid])
  if (!rows[0]) return res.status(404).json({ error: 'User not found' })
  res.json(toUser(rows[0]))
})

app.patch('/api/auth/me', authRequired, async (req, res) => {
  const allowed = {}
  if (req.body.name !== undefined) allowed.name = req.body.name
  if (req.body.phone !== undefined) allowed.phone = req.body.phone
  if (req.body.addresses !== undefined) allowed.addresses = JSON.stringify(req.body.addresses)
  const keys = Object.keys(allowed)
  if (!keys.length) return res.status(400).json({ error: 'Nothing to update' })
  const sets = keys.map((k, i) => `${k} = $${i + 2}`).join(', ')
  const { rows } = await pool.query(
    `UPDATE users SET ${sets} WHERE id = $1 RETURNING *`,
    [req.auth.uid, ...keys.map((k) => allowed[k])]
  )
  res.json(toUser(rows[0]))
})

// Seed the default admin account (admin@styleverse.com / admin123)
// if it doesn't exist yet. Runs on boot when SEED_ADMIN is set,
// or via POST /api/admin/seed from the admin panel once.
if (process.env.SEED_ADMIN === 'true') {
  ensureAdmin().catch((e) => console.error('admin seed failed:', e.message))
}
app.post('/api/admin/seed', async (_req, res) => {
  const created = await ensureAdmin()
  res.json({ ok: true, created })
})

// ── Products ────────────────────────────────────────────────────
app.get('/api/products', async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM products ORDER BY created_at DESC')
  res.json(rows.map(toProduct))
})

app.get('/api/products/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id])
  if (!rows[0]) return res.status(404).json({ error: 'Product not found' })
  res.json(toProduct(rows[0]))
})

app.post('/api/products', adminRequired, async (req, res) => {
  const b = req.body || {}
  if (!b.name?.trim()) return res.status(400).json({ error: 'Name is required' })
  if (!(Number(b.price) > 0)) return res.status(400).json({ error: 'Valid price required' })
  const id = 'p' + Date.now().toString().slice(-6)
  const { rows } = await pool.query(
    `INSERT INTO products
      (id, name, description, price, original_price, discount, category, subcategory,
       sizes, colors, images, in_stock, is_featured, is_new, tags, rating, review_count)
     VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14,$15::jsonb,$16,$17)
     RETURNING *`,
    [
      id, b.name.trim(), b.description || '', Number(b.price),
      b.originalPrice != null ? Number(b.originalPrice) : Number(b.price),
      Number(b.discount || 0), b.category || 'men', b.subcategory || '',
      JSON.stringify(b.sizes || []), JSON.stringify(b.colors || []),
      JSON.stringify((b.images || []).filter((u) => String(u || '').trim())),
      b.inStock !== false, !!b.isFeatured, b.isNew !== false,
      JSON.stringify(b.tags || []), Number(b.rating || 0), Number(b.reviewCount || 0)
    ]
  )
  res.status(201).json(toProduct(rows[0]))
})

app.put('/api/products/:id', adminRequired, async (req, res) => {
  const b = req.body || {}
  const { rows: existing } = await pool.query('SELECT id FROM products WHERE id = $1', [req.params.id])
  if (!existing.length) return res.status(404).json({ error: 'Product not found' })
  const map = {
    name: b.name, description: b.description, price: b.price, original_price: b.originalPrice,
    discount: b.discount, category: b.category, subcategory: b.subcategory,
    sizes: b.sizes && JSON.stringify(b.sizes), colors: b.colors && JSON.stringify(b.colors),
    images: b.images && JSON.stringify(b.images), in_stock: b.inStock,
    is_featured: b.isFeatured, is_new: b.isNew, tags: b.tags && JSON.stringify(b.tags)
  }
  const sets = []
  const vals = []
  for (const [col, val] of Object.entries(map)) {
    if (val === undefined) continue
    vals.push(val)
    const cast = ['sizes', 'colors', 'images', 'tags'].includes(col) ? '::jsonb' : ''
    sets.push(`${col} = $${vals.length + 1}${cast}`)
  }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update' })
  const { rows } = await pool.query(
    `UPDATE products SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
    [req.params.id, ...vals]
  )
  res.json(toProduct(rows[0]))
})

app.delete('/api/products/:id', adminRequired, async (req, res) => {
  await pool.query('DELETE FROM products WHERE id = $1', [req.params.id])
  res.json({ ok: true })
})

app.patch('/api/products/:id/stock', adminRequired, async (req, res) => {
  const { rows } = await pool.query(
    'UPDATE products SET in_stock = NOT in_stock WHERE id = $1 RETURNING *',
    [req.params.id]
  )
  if (!rows[0]) return res.status(404).json({ error: 'Product not found' })
  res.json(toProduct(rows[0]))
})

// ── Coupons ─────────────────────────────────────────────────────
app.get('/api/coupons', async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM coupons ORDER BY code ASC')
  res.json(rows.map(toCoupon))
})

app.post('/api/coupons', adminRequired, async (req, res) => {
  const b = req.body || {}
  const code = String(b.code || '').toUpperCase().trim()
  if (!code) return res.status(400).json({ error: 'Code required' })
  const id = 'coupon-' + Date.now()
  try {
    const { rows } = await pool.query(
      `INSERT INTO coupons
        (id, code, description, discount_type, discount_value, min_order, max_discount, valid_till, category, is_active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [id, code, b.description || '', b.discountType || 'percentage',
        Number(b.discountValue || 0), Number(b.minOrder || 0), Number(b.maxDiscount || 0),
        b.validTill || '2026-12-31', b.category || null, b.isActive !== false]
    )
    res.status(201).json(toCoupon(rows[0]))
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Coupon code already exists' })
    throw e
  }
})

app.patch('/api/coupons/:id', adminRequired, async (req, res) => {
  const { rows } = await pool.query(
    'UPDATE coupons SET is_active = NOT is_active WHERE id = $1 RETURNING *',
    [req.params.id]
  )
  if (!rows[0]) return res.status(404).json({ error: 'Coupon not found' })
  res.json(toCoupon(rows[0]))
})

app.delete('/api/coupons/:id', adminRequired, async (req, res) => {
  await pool.query('DELETE FROM coupons WHERE id = $1', [req.params.id])
  res.json({ ok: true })
})

// ── Orders ──────────────────────────────────────────────────────
// NOTE: every write is awaited — the API only responds AFTER Postgres
// confirms. This is what fixes the old "Order Placed 🎉 → Order not
// found" bug where the Firebase write failed silently in background.
app.post('/api/orders', async (req, res) => {
  const b = req.body || {}
  if (!Array.isArray(b.items) || !b.items.length) return res.status(400).json({ error: 'Order has no items' })
  if (!(Number(b.total) > 0)) return res.status(400).json({ error: 'Invalid order total' })
  const orderId = 'ORD' + Date.now().toString().slice(-8)
  const now = new Date().toISOString()
  const history = [
    { status: 'placed', date: now },
    { status: 'confirmed', date: now }
  ]
  const { rows } = await pool.query(
    `INSERT INTO orders
      (id, user_id, user_name, user_email, items, address, payment_method, utr_number,
       subtotal, shipping, coupon, coupon_discount, total, status, status_history, estimated_delivery)
     VALUES
      ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,'confirmed',$14::jsonb,$15)
     RETURNING *`,
    [
      orderId, b.userId || 'guest', b.userName || 'Guest', b.userEmail || '',
      JSON.stringify(b.items), JSON.stringify(b.address || {}),
      b.paymentMethod || 'cod', b.utrNumber || null,
      Number(b.subtotal || 0), Number(b.shipping || 0),
      b.coupon || null, Number(b.couponDiscount || 0), Number(b.total),
      JSON.stringify(history), new Date(Date.now() + 5 * 24 * 3600 * 1000).toISOString()
    ]
  )
  res.status(201).json(toOrder(rows[0]))
})

app.get('/api/orders', adminRequired, async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders ORDER BY created_at DESC')
  res.json(rows.map(toOrder))
})

app.get('/api/orders/mine', authRequired, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC',
    [req.auth.uid]
  )
  res.json(rows.map(toOrder))
})

// Public tracking by ID (guest checkout needs this — no login required)
app.get('/api/orders/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id])
  if (!rows[0]) return res.status(404).json({ error: 'Order not found' })
  res.json(toOrder(rows[0]))
})

app.patch('/api/orders/:id/status', adminRequired, async (req, res) => {
  const { status } = req.body || {}
  const valid = ['placed', 'confirmed', 'shipped', 'delivered', 'cancelled']
  if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' })
  const { rows: existing } = await pool.query('SELECT status_history FROM orders WHERE id = $1', [req.params.id])
  if (!existing.length) return res.status(404).json({ error: 'Order not found' })
  let history = existing[0].status_history
  if (typeof history === 'string') { try { history = JSON.parse(history) } catch { history = [] } }
  history = [...(Array.isArray(history) ? history : []), { status, date: new Date().toISOString() }]
  const { rows } = await pool.query(
    'UPDATE orders SET status = $2, status_history = $3 WHERE id = $1 RETURNING *',
    [req.params.id, status, JSON.stringify(history)]
  )
  res.json(toOrder(rows[0]))
})

app.delete('/api/orders/:id', adminRequired, async (req, res) => {
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id])
  res.json({ ok: true })
})

// ── Users (admin) ───────────────────────────────────────────────
app.get('/api/users', adminRequired, async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE is_admin = FALSE ORDER BY created_at DESC"
  )
  res.json(rows.map(toUser))
})

app.delete('/api/users/:id', adminRequired, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1 AND is_admin = FALSE', [req.params.id])
  res.json({ ok: true })
})

// ── Error handler (JSON, never HTML) ────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('API error:', err.message)
  res.status(500).json({ error: 'Something went wrong. Please try again.' })
})

const port = Number(process.env.PORT || 3001)
if (process.env.VERCEL !== '1') {
  app.listen(port, () => console.log(`✅ StyleVerse API on :${port}`))
}

export default app
