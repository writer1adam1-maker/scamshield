// Run with: node generate-icons.js
// Generates PNG icons for the extension using canvas (requires node-canvas)
// OR outputs inline SVG-based PNGs without dependencies

const fs = require("fs");
const path = require("path");

// SVG shield icon at different sizes
function svgIcon(size) {
  const s = size;
  const r = Math.round(s * 0.18); // border radius
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${s}" height="${s}" viewBox="0 0 ${s} ${s}">
  <rect width="${s}" height="${s}" rx="${r}" fill="#0d1322"/>
  <rect width="${s}" height="${s}" rx="${r}" fill="none" stroke="rgba(0,212,255,0.3)" stroke-width="1"/>
  <text x="50%" y="56%" text-anchor="middle" dominant-baseline="middle" font-size="${Math.round(s*0.6)}" font-family="system-ui">🛡</text>
</svg>`;
}

// Write SVG files (browsers accept SVG for extension icons in Firefox; for Chrome we'd need PNG)
const sizes = [16, 48, 128];
const dir = path.join(__dirname, "icons");
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

for (const size of sizes) {
  fs.writeFileSync(path.join(dir, `icon${size}.svg`), svgIcon(size));
  console.log(`Written icon${size}.svg`);
}

console.log("Icons generated. For production, convert SVGs to PNGs.");
