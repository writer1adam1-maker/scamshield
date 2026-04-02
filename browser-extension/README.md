# ScamShield Browser Extension

Scan any URL or text for scams directly from your browser using the VERIDICT AI engine.

## Features
- Auto-fills the current tab URL when you open the popup
- One-click "Scan current tab" button
- Shows threat level, score, WHOIS domain age, SSL validity, and evidence
- Works in Chrome and Firefox

## Install (Developer Mode)

### Chrome
1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select this `browser-extension/` folder

### Firefox
1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `manifest.json` inside this folder

## Icons
The extension uses emoji-based SVG icons. For production, replace `icons/icon16.png`, `icons/icon48.png`, `icons/icon128.png` with proper PNG files.

To generate SVG placeholders: `node generate-icons.js`

## API
Calls `https://scamshield-indol.vercel.app/api/scan` — no API key required.
