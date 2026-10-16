const fs = require('fs');
const content = fs.readFileSync('server/src/routes/auth.js', 'utf8');
const lines = content.split('\n');

console.log('Searching in auth.js:');
lines.forEach((l, i) => {
  if (l.includes("'/login'") || l.includes('"/login"') || l.includes("'/refresh'") || l.includes('"/refresh"') || l.includes('require_2fa') || l.includes('deactivated')) {
    console.log(`Line ${i + 1}: ${l.trim()}`);
  }
});
