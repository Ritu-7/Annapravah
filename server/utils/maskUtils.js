/**
 * maskUtils.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Helpers for masking Personally Identifiable Information (PII) before
 * returning user profiles to non-admin views.
 */

/**
 * Masks a Government-issued ID number (Aadhaar or PAN).
 *
 * Aadhaar (12 digits, may be space-separated in groups of 4):
 *   Input  → "1234 5678 9012"  or  "123456789012"
 *   Output → "XXXX-XXXX-9012"   (only last 4 digits visible)
 *
 * PAN (10 characters: 5 alpha + 4 digits + 1 alpha):
 *   Input  → "ABCDE1234F"
 *   Output → "ABCDE****F"       (first 5 chars + last char visible)
 *
 * Any other value returns a fully redacted string of the same length.
 *
 * @param {string} idNumber - Raw Aadhaar or PAN string.
 * @returns {string} Masked identifier safe for non-admin display.
 */
function maskGovtId(idNumber) {
  if (!idNumber || typeof idNumber !== "string") return "";

  // Normalise: remove spaces for matching
  const clean = idNumber.replace(/\s/g, "").toUpperCase();

  // ── Aadhaar: exactly 12 digits ────────────────────────────────────────────
  const aadhaarRegex = /^\d{12}$/;
  if (aadhaarRegex.test(clean)) {
    const last4 = clean.slice(-4);
    return `XXXX-XXXX-${last4}`;
  }

  // ── PAN: 5 alpha + 4 digits + 1 alpha (standard Indian PAN format) ────────
  const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
  if (panRegex.test(clean)) {
    // e.g. ABCDE1234F → ABCDE****F
    return `${clean.slice(0, 5)}****${clean.slice(-1)}`;
  }

  // ── Unknown format: replace all alphanumeric chars with * ─────────────────
  return clean.replace(/[A-Z0-9]/g, "*");
}

module.exports = { maskGovtId };
