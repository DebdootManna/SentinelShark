# SentinelShark Website

Standalone marketing/product website for the SentinelShark desktop security
application — a real-time EDR & Chronicle SecOps workstation
(Python 3.10+, PyQt6, PyShark).

The website is a separate presentation layer. It does not modify or integrate
with the desktop application. All website dependencies and tooling are scoped
to this directory.

- Framework: React 19 + Vite 8 + Tailwind CSS v4 (same stack as the Figma export)
- Design source of truth: `./Design/` (Figma export — read-only, do not edit)
- Production site source: `./src/` (`App.tsx`, `index.css`, `main.tsx`)

## Run

Requires Node.js 22+ and npm or pnpm.

```bash
cd Website
npm install
npm run dev      # local dev server (default http://127.0.0.1:5173)
npm run build    # typecheck + production build to dist/
npm run preview  # preview the production build
```

With pnpm:

```bash
cd Website
pnpm install
pnpm dev
pnpm build
pnpm preview
```

## Structure

```text
Website/
├── Design/          # Figma-generated export (visual source of truth, untouched)
├── src/
│   ├── App.tsx      # All website sections (hero, workstation, capabilities,
│   │                # pipeline, threat intel, MITRE, UDM, response,
│   │                # architecture, forensics, developer, open-source, footer)
│   │                # + Lenis smooth scroll, scroll parallax, hover states.
│   │                # Body text uses JetBrains Mono; titles use Barlow Condensed.
│   ├── index.css    # Design tokens, typography, animations, responsive rules
│   ├── main.tsx     # React entrypoint
│   └── vite-env.d.ts
├── public/
│   ├── favicon.svg  # Shark-fin site icon (also used for social cards)
│   ├── robots.txt   # Allow all + sitemap reference
│   └── sitemap.xml  # Canonical URL entry
├── index.html       # HTML shell: SEO/OG/Twitter meta, canonical, JSON-LD
├── vite.config.ts   # Clean standalone config (no Figma Make plugins)
├── tsconfig.json
└── package.json     # Website-scoped dependencies only
```

## Notes

- External links: GitHub button →
  `https://github.com/DebdootManna/SentinelShark`; documentation links →
  the SentinelShark GitHub Wiki (`ARCHITECTURE.md`, `USERGUIDE.md`,
  `DEVELOPERGUIDE.md`).
- Product visuals use realistic synthetic telemetry (documentation IPs,
  example hashes). No API keys, secrets, or real private data.
- Response actions (Kill Process, Block Remote IP, Quarantine Binary) are
  presented as operator-triggered containment, never automatic.
- Animations respect `prefers-reduced-motion`; the live telemetry ticker is
  static when reduced motion is requested.
