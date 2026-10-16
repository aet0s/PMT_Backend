const fs = require('fs');
const path = require('path');
const { PERMISSIONS } = require('../../rbac/registry');

const CLIENT_SRC_DIR = path.resolve(__dirname, '../../../../client/src');
const components = [
  'components/Board/Board.jsx',
  'components/Board/List.jsx',
  'components/Board/Card.jsx',
  'components/Card/AttachmentsSection.jsx',
  'components/Card/ChecklistSection.jsx',
  'components/Card/ActivityItem.jsx',
  'components/Card/CommentsActivitySidebar.jsx',
  'components/Card/CardHeader.jsx',
  'components/Card/QuickAddRow.jsx',
  'components/Sidebar/WorkspaceSidebar.jsx',
  'components/Archive/ArchivePage.jsx',
  'pages/CompanyMembersPage.jsx'
];

const permMeta = new Map(PERMISSIONS.map(p => [p.key, p]));

console.log('| Component | Line | Permission Key | Scope | Target ID Passed | Match Code |');
console.log('|---|---|---|---|---|---|');

components.forEach(rel => {
  const file = path.join(CLIENT_SRC_DIR, rel);
  if (!fs.existsSync(file)) return;
  const content = fs.readFileSync(file, 'utf8');
  const lines = content.split('\n');

  lines.forEach((l, idx) => {
    // Check can(...) calls
    const m = l.match(/\bcan\(\s*['"]([^'"]+)['"](?:\s*,\s*([^)]+))?\)/);
    if (m) {
      const key = m[1];
      const target = m[2] ? m[2].trim() : '(none)';
      const meta = permMeta.get(key);
      const scope = meta ? meta.scope : 'unknown';
      console.log(`| \`${rel}\` | ${idx + 1} | \`${key}\` | ${scope} | \`${target}\` | \`${l.trim().slice(0, 60)}\` |`);
    }
    // Check <Can I="..." ...> calls
    const m2 = l.match(/<Can\s+[^>]*I=['"]([^'"]+)['"](?:\s+[^>]*id={([^}]+)})?/);
    if (m2) {
      const key = m2[1];
      const target = m2[2] ? m2[2].trim() : '(none)';
      const meta = permMeta.get(key);
      const scope = meta ? meta.scope : 'unknown';
      console.log(`| \`${rel}\` | ${idx + 1} | \`${key}\` | ${scope} | \`${target}\` | \`${l.trim().slice(0, 60)}\` |`);
    }
  });
});
