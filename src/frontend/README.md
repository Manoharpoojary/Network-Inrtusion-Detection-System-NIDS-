# IoT NIDS dashboard (frontend)

React 19 + TypeScript + Vite 8 + Tailwind CSS 4 + Recharts dashboard for the FastAPI backend.
Every number shown comes from the API; nothing is hard-coded or simulated.

```bash
npm install          # once
npm run dev          # http://127.0.0.1:5173 — proxies /api to http://127.0.0.1:8000
npm run lint         # oxlint
npm run typecheck    # tsc -b
npm test             # vitest (unit/component tests; fetch is mocked)
npm run build        # production build to dist/
npm run preview      # serve dist/ on http://127.0.0.1:4173 with the same /api proxy
```

Set `NIDS_API_URL` to point the proxy at a backend on another port.

The end-to-end test renders pages against a running backend and is skipped by default:

```bash
E2E_BASE_URL=http://127.0.0.1:5173 npx vitest run src/test/e2e.test.tsx
```

See the project README for the full setup.
