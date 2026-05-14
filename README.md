# ?? EntraPass - Passkey Migration Assistant

**Open-source, browser-only tool for Microsoft Entra ID passkey readiness assessment.**

## ?? Features

- **? Passkey Readiness Scan** - See which users can use passkeys today
- **?? Policy Advisor** - Find CA policies blocking passkey registration + misconfigurations
- **?? Entra Tip: App Check** - Bonus analysis of app compatibility (incl. substrate)
- **?? AI Assistant (optional)** - Ask questions about your passkey migration
- **?? 100% Browser-Only** - Your data never leaves your browser
- **?? Free to Deploy** - Runs on Cloudflare free tier

## ??? Architecture

```
Browser (SPA) ? PKCE OAuth ? Microsoft Graph API
         ?
    Local JS engine (analyzes in your browser)
         ?
    Optional: Cloudflare AI Worker or BYO AI key
```

## ?? Prerequisites

1. **Azure App Registration** with:
   - SPA redirect URI
   - Delegated Graph API permissions
   - [See setup guide](./docs/AZURE_SETUP.md)

2. **Cloudflare Account** (free tier works)

3. **GitHub Repository** secrets:
   - `AZURE_CLIENT_ID` - Your app registration client ID
   - `AZURE_TENANT_ID` - Your tenant ID
   - `CLOUDFLARE_API_TOKEN` - Cloudflare API token
   - `CLOUDFLARE_ACCOUNT_ID` - Cloudflare account ID

## ??? Development

```bash
npm install
npm run dev
```

## ?? Deployment

Push to `main` branch ? GitHub Actions deploys to Cloudflare Pages.

## ?? License

MIT - See [LICENSE](./LICENSE) file.

## ?? Contributing

PRs welcome! Focus on passkey analysis features.

---
First deployment trigger: 05/14/2026 16:33:11


