# enprot documentation site

Built with Astro 7, Vite 8, Vue islands, Tailwind 4.

## Develop

```sh
cd docs/
npm install
npm run dev
```

## Build

```sh
npm run build       # output: dist/
npm run preview     # serve dist/ locally
```

## Structure

- `src/pages/index.astro` — landing page with roadmap + examples
- `src/pages/docs/architecture.astro` — deep architecture
- `src/pages/docs/capability-model.astro` — four-tier capability model (interactive)
- `src/pages/docs/merge-semantics.astro` — distributed / lock-free merge
- `src/pages/docs/chain-dag.astro` — Stage 1 chain anchor DAG deep dive
- `src/pages/docs/stages.astro` — roadmap index
- `src/pages/docs/stages/{0,1,2,3,4a,5}.astro` — per-stage deep dives
- `src/pages/docs/examples.astro` — worked-examples index
- `src/pages/docs/examples/{audit-log,contract,provenance,snapshot-pin,supply-chain}.astro` — real-life usage
- `src/components/CapabilityExplorer.vue` — interactive Vue island
- `src/layouts/Base.astro` — common chrome
- `src/styles/global.css` — Tailwind theme

Each page is self-contained Markdown-style content with the capability framing
explicit: which participant holds which capability for the scenario shown.
