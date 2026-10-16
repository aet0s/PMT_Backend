-- Migration: 0024_card_description_mediumtext.sql
-- Description: Expand cards.description to MEDIUMTEXT so rich text cards with embedded/pasted images can be stored.

ALTER TABLE cards MODIFY COLUMN description MEDIUMTEXT NULL;
