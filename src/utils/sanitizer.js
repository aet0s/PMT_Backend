// server/src/utils/sanitizer.js
const sanitizeHtml = require('sanitize-html');

/**
 * Strips all HTML/script tags and attributes completely for plain text fields
 * (workspace names, board names, list titles, usernames, role names, etc.)
 */
function sanitizePlain(str) {
  if (typeof str !== 'string') return str;
  return sanitizeHtml(str, {
    allowedTags: [],
    allowedAttributes: {},
    disallowedTagsMode: 'discard'
  }).trim();
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
  sanitizePlain,
  sanitizeRich
};
