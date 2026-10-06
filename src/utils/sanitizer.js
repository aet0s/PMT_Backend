// server/src/utils/sanitizer.js
const sanitizeHtml = require('sanitize-html');

/**
 * Decodes standard HTML entities so plain text remains literal characters
 * (e.g. '&amp;' becomes '&', '&lt;' becomes '<', '&gt;' becomes '>', '&quot;' becomes '"', etc.)
 */
function decodeEntities(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&#x2F;/gi, '/')
    .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec))
    .replace(/&#x([0-9a-f]+);/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * Strips all HTML/script tags and attributes completely for plain text fields
 * (workspace names, board names, list titles, usernames, role names, etc.)
 * Ensures plain text characters like '&' remain literal plain text and are not encoded.
 */
function sanitizePlain(str) {
  if (typeof str !== 'string') return str;
  const cleaned = sanitizeHtml(str, {
    allowedTags: [],
    allowedAttributes: {},
    disallowedTagsMode: 'discard'
  });
  return decodeEntities(cleaned).trim();
}

/**
 * Sanitizes rich text content (card descriptions, comments) allowing only safe formatting tags
 */
function sanitizeRich(html) {
  if (!html || typeof html !== 'string') return '';
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
      'img', 'h1', 'h2', 'h3', 'span', 'u', 's', 'strong', 'em', 'a', 'p', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'hr', 'br'
    ]),
    allowedAttributes: {
      ...sanitizeHtml.defaults.allowedAttributes,
      img: ['src', 'alt', 'title', 'width', 'height', 'class', 'style'],
      a: ['href', 'name', 'target', 'rel']
    }
  });
}

module.exports = {
  decodeEntities,
  sanitizePlain,
  sanitizeRich
};

