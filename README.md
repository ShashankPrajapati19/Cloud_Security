# Shashank Prajapati · CloudGuard Security Auditor

CloudGuard is a local React, Express, and SQLite security configuration auditor. It provides simulated cloud analysis, CIS/NIST compliance mapping, risk scoring, safe remediation, encrypted summaries, and HTML/CSV/JSON exports.

## Requirements

- Node.js 18 or newer
- npm

## Run locally on Windows

The project folder contains an ampersand, so use `-LiteralPath` in PowerShell:

```powershell
Set-Location -LiteralPath 'C:\Users\kakuv\Downloads\cloudguard---security-configuration-auditor-&-compliance-vault'
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

If Windows cannot resolve `npm` from this folder, run the local TypeScript server directly:

```powershell
& 'C:\Program Files\nodejs\node.exe' '.\node_modules\tsx\dist\cli.mjs' '.\server.ts'
```

## Validate and build

```powershell
npm run lint
npm run build
```

The backend health endpoint is available at `/api/health`. The application uses local simulated data and SQLite; it does not connect to live cloud credentials.
