-- 0006_map_legacy_board_backgrounds.sql
-- Map all 12 legacy dark and light board backgrounds to the 10 soft light backgrounds

UPDATE boards
SET background_color = 'bg-board-lavender'
WHERE background_color = 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950';

UPDATE boards
SET background_color = 'bg-board-mist-blue'
WHERE background_color = 'bg-gradient-to-br from-blue-700 via-sky-800 to-indigo-900';

UPDATE boards
SET background_color = 'bg-board-sage'
WHERE background_color = 'bg-gradient-to-br from-emerald-800 via-teal-900 to-slate-900';

UPDATE boards
SET background_color = 'bg-board-blush'
WHERE background_color = 'bg-gradient-to-br from-rose-800 via-purple-900 to-slate-900';

UPDATE boards
SET background_color = 'bg-board-sand'
WHERE background_color = 'bg-gradient-to-br from-amber-700 via-orange-900 to-slate-950';

UPDATE boards
SET background_color = 'bg-board-stone'
WHERE background_color = 'bg-gradient-to-br from-slate-900 via-gray-900 to-zinc-950';

UPDATE boards
SET background_color = 'bg-board-lavender'
WHERE background_color = 'bg-gradient-to-br from-indigo-200 via-purple-100 to-violet-200';

UPDATE boards
SET background_color = 'bg-board-sky'
WHERE background_color = 'bg-gradient-to-br from-sky-200 via-blue-100 to-cyan-200';

UPDATE boards
SET background_color = 'bg-board-blush'
WHERE background_color = 'bg-gradient-to-br from-rose-200 via-pink-100 to-fuchsia-200';

UPDATE boards
SET background_color = 'bg-board-mint'
WHERE background_color = 'bg-gradient-to-br from-emerald-200 via-teal-100 to-green-200';

UPDATE boards
SET background_color = 'bg-board-peach'
WHERE background_color = 'bg-gradient-to-br from-amber-200 via-orange-100 to-yellow-200';

UPDATE boards
SET background_color = 'bg-board-mist-blue'
WHERE background_color = 'bg-gradient-to-br from-slate-300 via-blue-200 to-indigo-200';

-- Fallback for any unknown or empty legacy value
UPDATE boards
SET background_color = 'bg-board-neutral'
WHERE background_color IS NULL 
   OR background_color = '' 
   OR background_color NOT LIKE 'bg-board-%';
