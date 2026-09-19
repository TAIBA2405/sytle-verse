// Vercel serverless entrypoint — re-exports the Express app.
// Local dev still uses `npm run dev` → src/index.js (which calls app.listen).
import app from '../src/index.js'

export default app
