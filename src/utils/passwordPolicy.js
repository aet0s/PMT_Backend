// server/src/utils/passwordPolicy.js
// Password policy: min 10 characters, mixed character classes (uppercase, lowercase, number, symbol)
const crypto = require('crypto');

const MIN_LENGTH = 10;
const UPPER_REGEX = /[A-Z]/;
const LOWER_REGEX = /[a-z]/;
const DIGIT_REGEX = /[0-9]/;
const SYMBOL_REGEX = /[^A-Za-z0-9]/;

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return {
      isValid: false,
      error: 'Password is required and must be a string'
    };
  }

  if (password.length < MIN_LENGTH) {
    return {
      isValid: false,
      error: `Password must be at least ${MIN_LENGTH} characters long`
    };
  }

  if (!UPPER_REGEX.test(password)) {
    return {
      isValid: false,
      error: 'Password must contain at least one uppercase letter (A-Z)'
    };
  }

  if (!LOWER_REGEX.test(password)) {
    return {
      isValid: false,
      error: 'Password must contain at least one lowercase letter (a-z)'
    };
  }

  if (!DIGIT_REGEX.test(password)) {
    return {
      isValid: false,
      error: 'Password must contain at least one number (0-9)'
    };
  }

  if (!SYMBOL_REGEX.test(password)) {
    return {
      isValid: false,
      error: 'Password must contain at least one special character or symbol (e.g. !@#$%^&*)'
    };
  }

  return { isValid: true };
}

function generateCompliantPassword(length = 14) {
  const uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lowers = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*_-+=';

  // Ensure at least one from each class
  let pwd = [
    uppers[crypto.randomInt(0, uppers.length)],
    lowers[crypto.randomInt(0, lowers.length)],
    digits[crypto.randomInt(0, digits.length)],
    symbols[crypto.randomInt(0, symbols.length)]
  ];

  const allChars = uppers + lowers + digits + symbols;
  for (let i = pwd.length; i < length; i++) {
    pwd.push(allChars[crypto.randomInt(0, allChars.length)]);
  }

  // Shuffle array using Fisher-Yates
  for (let i = pwd.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
  }

  return pwd.join('');
}

module.exports = {
  validatePassword,
  generateCompliantPassword,
  MIN_LENGTH
};
