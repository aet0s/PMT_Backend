-- 0007_decode_html_entities_in_names.sql
-- Decodes legacy HTML entities (&amp;, &#39;, &quot;, &lt;, &gt;) stored in plain text name and title columns.

UPDATE workspaces
SET name = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(name, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE name LIKE '%&amp;%' OR name LIKE '%&#39;%' OR name LIKE '%&quot;%' OR name LIKE '%&lt;%' OR name LIKE '%&gt;%';

UPDATE boards
SET name = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(name, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE name LIKE '%&amp;%' OR name LIKE '%&#39;%' OR name LIKE '%&quot;%' OR name LIKE '%&lt;%' OR name LIKE '%&gt;%';

UPDATE lists
SET name = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(name, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE name LIKE '%&amp;%' OR name LIKE '%&#39;%' OR name LIKE '%&quot;%' OR name LIKE '%&lt;%' OR name LIKE '%&gt;%';

UPDATE cards
SET title = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(title, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE title LIKE '%&amp;%' OR title LIKE '%&#39;%' OR title LIKE '%&quot;%' OR title LIKE '%&lt;%' OR title LIKE '%&gt;%';

UPDATE labels
SET name = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(name, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE name LIKE '%&amp;%' OR name LIKE '%&#39;%' OR name LIKE '%&quot;%' OR name LIKE '%&lt;%' OR name LIKE '%&gt;%';

UPDATE checklists
SET title = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(title, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE title LIKE '%&amp;%' OR title LIKE '%&#39;%' OR title LIKE '%&quot;%' OR title LIKE '%&lt;%' OR title LIKE '%&gt;%';

UPDATE checklist_items
SET text = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(text, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE text LIKE '%&amp;%' OR text LIKE '%&#39;%' OR text LIKE '%&quot;%' OR text LIKE '%&lt;%' OR text LIKE '%&gt;%';

UPDATE roles
SET name = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(name, '&amp;', '&'), '&#39;', '\''), '&quot;', '\"'), '&lt;', '<'), '&gt;', '>')
WHERE name LIKE '%&amp;%' OR name LIKE '%&#39;%' OR name LIKE '%&quot;%' OR name LIKE '%&lt;%' OR name LIKE '%&gt;%';
