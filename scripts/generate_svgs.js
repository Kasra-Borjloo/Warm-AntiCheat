const { LUCIDE_ICONS } = require('../assets/icons/lucide/icons.js');
const fs = require('fs');
const path = require('path');

const dir = path.resolve(__dirname, '../assets/icons/lucide/svg');
if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
}

for (const [name, pathD] of Object.entries(LUCIDE_ICONS)) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">\n  ${pathD}\n</svg>\n`;
  fs.writeFileSync(path.join(dir, `${name}.svg`), svg, 'utf8');
}

console.log(`Successfully generated ${Object.keys(LUCIDE_ICONS).length} SVG icons in ${dir}`);
