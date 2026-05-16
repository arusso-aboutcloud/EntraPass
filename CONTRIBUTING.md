# Contributing to EntraPass

Thanks for your interest in improving EntraPass! This project is an open-source
(MIT) passkey-readiness assessment tool for Microsoft Entra ID. Contributions of
all kinds are welcome — bug reports, documentation fixes, new analysis rules,
and UI improvements.

## Ways to contribute

- **Report a bug** — open a [GitHub Issue](https://github.com/arusso-aboutcloud/EntraPass/issues)
  with steps to reproduce, expected vs. actual behavior, and your browser/OS.
- **Suggest a feature** — open an issue describing the use case before sending a PR.
- **Improve the docs** — fixes to anything under `docs/` or the `README` are very welcome.
- **Submit code** — see the workflow below.

## Development setup

```bash
git clone https://github.com/arusso-aboutcloud/EntraPass.git
cd EntraPass
npm install
npm run dev          # http://localhost:5173
```

To run a scan locally you also need an App Registration in an Entra ID tenant —
see the [Installation Guide](docs/installation.md), Option C.

Useful scripts:

| Command | Description |
|---|---|
| `npm run dev` | Start the Vite dev server with hot reload |
| `npm run build` | Production build into `dist/` |
| `npm run preview` | Serve the production build locally |

## Pull request workflow

1. **Fork** the repository and create a feature branch from `main`
   (e.g. `fix/policy-parsing`, `docs/installation-typos`).
2. **Make your change.** Keep PRs focused — one logical change per PR.
3. **Verify it builds:** `npm run build` must succeed.
4. **Test in the browser:** run `npm run dev` and confirm the affected flow
   (setup wizard, scan, the relevant dashboard tab) still works.
5. **Open a PR** against `main` with a clear description of what changed and why.
   Link any related issue.
6. CI runs the Cloudflare Pages build and the Trivy security scan on every PR —
   please make sure both pass.

## Coding guidelines

- The app is **vanilla JavaScript** (ES modules) plus Vite — no framework. Keep
  new code dependency-free unless there is a strong reason to add a package.
- Match the existing style in `src/` (2-space indentation, ES modules).
- Keep EntraPass **read-only and browser-only**: no write operations against
  Microsoft Graph, no backend, no telemetry of tenant data, no persistent storage beyond
  `sessionStorage`. PRs that change this contract will not be merged.
- Save files as **UTF-8** with no BOM.
- Update the relevant document under `docs/` when behavior changes.

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. Report them
privately via [GitHub Security Advisories](https://github.com/arusso-aboutcloud/EntraPass/security/advisories/new).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
