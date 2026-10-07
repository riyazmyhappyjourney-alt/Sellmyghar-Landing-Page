// Production-grade validation, normalization & injection detection

// Known fake mobile numbers (all repeated digits)
const REPEATED_FAKE_PHONES = new Set([
  '0000000000', '1111111111', '2222222222', '3333333333', '4444444444',
  '5555555555', '6666666666', '7777777777', '8888888888', '9999999999'
]);

// Known sequential numbers
const SEQUENTIAL_FAKE_PHONES = new Set([
  '1234567890', '9876543210', '0123456789', '2345678901', '8765432109'
]);

// Common fake / junk names
const SPAM_NAMES = new Set([
  'test', 'testing', 'tester', 'asdf', 'asdfgh', 'qwerty', 'abc', 'abcd',
  'aaaa', 'aaaaa', 'aaaaaa', 'aaaaaaa', 'xxxxx', 'xxxxxx', '123456',
  '9876543210', 'admin', 'user', 'fake', 'junk', 'demo', 'sample', 'none',
  'null', 'undefined', 'anonymous', 'unknown', 'name', 'your name'
]);

// SQL Injection and Script pattern heuristics
const INJECTION_PATTERNS = [
  /(\b(select|insert|update|delete|drop|alter|create|truncate|exec|union|declare)\b)/i,
  /(--|\/\*|\*\/|;|\bwaitfor\b|\bdelay\b)/i,
  /(<script\b[^>]*>|<\/script>|javascript:|onerror\s*=|onload\s*=|onclick\s*=|eval\s*\(|alert\s*\()/i,
  /(<iframe\b|<object\b|<embed\b|<applet\b|<meta\b|<link\b)/i,
  /(\.\.\/|\.\.\\)/, // Path traversal
  /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/ // Dangerous control characters
];

// URL patterns in name
const URL_PATTERN = /(https?:\/\/|www\.|\.com\b|\.in\b|\.org\b|\.net\b|\.io\b|\.co\b)/i;

export interface ValidationResult {
  isValid: boolean;
  errorMessage?: string;
  normalizedValue?: string;
  isSpamSignal?: boolean;
}

/**
 * Normalizes and validates Indian Human Names
 */
export function validateAndNormalizeName(rawName: unknown): ValidationResult {
  if (typeof rawName !== 'string') {
    return { isValid: false, errorMessage: 'Name is required and must be text.' };
  }

  // 1. Strip dangerous control characters and trim
  let name = rawName.replace(/[\x00-\x1F\x7F]/g, '').trim();

  // 2. Collapse repeated whitespace
  name = name.replace(/\s+/g, ' ');

  // 3. Length checks (2 to 80 characters)
  if (name.length < 2) {
    return { isValid: false, errorMessage: 'Please enter your full name (minimum 2 characters).' };
  }
  if (name.length > 80) {
    return { isValid: false, errorMessage: 'Name cannot exceed 80 characters.' };
  }

  // 4. Reject numbers
  if (/\d/.test(name)) {
    return { isValid: false, errorMessage: 'Name must not contain numbers.' };
  }

  // 5. Reject URLs
  if (URL_PATTERN.test(name)) {
    return { isValid: false, errorMessage: 'Name must not contain web links.' };
  }

  // 6. Reject injection payloads
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(name)) {
      return { isValid: false, errorMessage: 'Invalid characters in name.', isSpamSignal: true };
    }
  }

  // 7. Check for obvious spam strings
  const lowerName = name.toLowerCase();
  if (SPAM_NAMES.has(lowerName)) {
    return { isValid: false, errorMessage: 'Please enter a genuine name.', isSpamSignal: true };
  }

  // Reject single repeated character (e.g., "aaaaa", "zzzzz")
  if (/^(.)\1+$/i.test(name.replace(/\s/g, ''))) {
    return { isValid: false, errorMessage: 'Please enter a genuine name.', isSpamSignal: true };
  }

  // 8. Allowed character set for Indian names:
  // Supports letters, spaces, dots, single quotes/apostrophes, hyphens
  // Examples: "Ramesh Kumar", "Dr. Suresh", "Priya S.", "Mary-Anne", "D'Souza", "K. R. Rao"
  const nameCharRegex = /^[A-Za-z\s.'-]+$/;
  if (!nameCharRegex.test(name)) {
    return { isValid: false, errorMessage: 'Name contains invalid characters. Use letters and spaces only.' };
  }

  // Must contain at least 2 alphabetic characters
  const letterCount = (name.match(/[A-Za-z]/g) || []).length;
  if (letterCount < 2) {
    return { isValid: false, errorMessage: 'Please enter a valid human name.' };
  }

  return { isValid: true, normalizedValue: name };
}

/**
 * Normalizes and validates Indian Mobile Numbers
 * Accepts: 10 digits starting with 6, 7, 8, 9
 * Strips +91, 91, or leading 0 prefix
 */
export function validateAndNormalizePhone(rawPhone: unknown): ValidationResult {
  if (typeof rawPhone !== 'string' && typeof rawPhone !== 'number') {
    return { isValid: false, errorMessage: 'Mobile number is required.' };
  }

  const str = String(rawPhone).trim();

  // Extract only digits
  let digits = str.replace(/\D/g, '');

  // Normalize Indian Country Code prefixes
  // If user passed +91 9876543210 -> 12 digits starting with 91
  if (digits.length === 12 && digits.startsWith('91')) {
    digits = digits.slice(2);
  }
  // If user passed leading 0 (e.g. 09876543210) -> 11 digits
  else if (digits.length === 11 && digits.startsWith('0')) {
    digits = digits.slice(1);
  }

  // Strict 10-digit requirement
  if (digits.length !== 10) {
    return {
      isValid: false,
      errorMessage: 'Please enter a valid 10-digit Indian mobile number.'
    };
  }

  // First digit must be 6, 7, 8, or 9 for Indian cellular networks
  if (!/^[6-9]/.test(digits)) {
    return {
      isValid: false,
      errorMessage: 'Indian mobile numbers must start with 6, 7, 8, or 9.'
    };
  }

  // Reject repeated fake numbers (0000000000, 9999999999, etc.)
  if (REPEATED_FAKE_PHONES.has(digits)) {
    return {
      isValid: false,
      errorMessage: 'Please enter an active mobile number.',
      isSpamSignal: true
    };
  }

  // Reject sequential numbers
  if (SEQUENTIAL_FAKE_PHONES.has(digits)) {
    return {
      isValid: false,
      errorMessage: 'Please enter a valid personal mobile number.',
      isSpamSignal: true
    };
  }

  return { isValid: true, normalizedValue: digits };
}

/**
 * Normalizes and validates Email Address
 */
export function validateAndNormalizeEmail(rawEmail: unknown): ValidationResult {
  if (typeof rawEmail !== 'string') {
    return { isValid: false, errorMessage: 'Email address is required.' };
  }

  let email = rawEmail.trim();

  if (email.length < 5 || email.length > 100) {
    return { isValid: false, errorMessage: 'Please enter a valid email address.' };
  }

  // Reject spaces, dangerous characters, or multiple @
  if (/\s/.test(email) || (email.match(/@/g) || []).length !== 1) {
    return { isValid: false, errorMessage: 'Please enter a valid email format.' };
  }

  // Injection and control char check
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(email)) {
      return { isValid: false, errorMessage: 'Invalid characters in email address.', isSpamSignal: true };
    }
  }

  // RFC compliant standard email format
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!emailRegex.test(email)) {
    return { isValid: false, errorMessage: 'Please enter a valid email address (e.g., name@gmail.com).' };
  }

  // Normalize: lower-case the domain part, trim
  const [localPart, domainPart] = email.split('@');
  if (!domainPart || !domainPart.includes('.')) {
    return { isValid: false, errorMessage: 'Please enter a valid email domain.' };
  }

  const normalized = `${localPart.trim()}@${domainPart.toLowerCase().trim()}`;
  return { isValid: true, normalizedValue: normalized };
}

/**
 * Sanitizes optional text fields (like source_intent or property)
 */
export function sanitizeTextField(rawText: unknown, maxLength = 100): string {
  if (typeof rawText !== 'string') return '';
  return rawText
    .replace(/[\x00-\x1F\x7F]/g, '') // remove control chars
    .replace(/[<>]/g, '')             // strip html brackets
    .trim()
    .slice(0, maxLength);
}

/**
 * Detects injection payloads in arbitrary strings
 */
export function containsInjection(text: string): boolean {
  return INJECTION_PATTERNS.some(pattern => pattern.test(text));
}
