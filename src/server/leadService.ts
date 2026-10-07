import {
  validateAndNormalizeName,
  validateAndNormalizePhone,
  validateAndNormalizeEmail,
  sanitizeTextField
} from './validator.js';
import { checkLeadRateLimits } from './rateLimiter.js';
import { evaluateLeadQuality } from './qualityScorer.js';
import { findRecentLead, updateDuplicateLead, insertLead, StoredLead } from './db.js';

export interface LeadSubmissionPayload {
  name: unknown;
  phone: unknown;
  email: unknown;
  source_intent?: unknown;
  _honey?: unknown;
  form_loaded_at?: unknown;
  [key: string]: unknown;
}

export interface ProcessLeadResult {
  statusCode: number;
  response: {
    success: boolean;
    message: string;
    errors?: Record<string, string>;
  };
}

const ALLOWED_KEYS = new Set(['name', 'phone', 'email', 'source_intent', '_honey', 'form_loaded_at']);

/**
 * Forwards verified lead data to the sales notification endpoint in the background
 */
async function notifySalesTeam(lead: { name: string; phone: string; email: string; source_intent: string; quality_score: string }) {
  try {
    const formData = new FormData();
    formData.append('name', lead.name);
    formData.append('phone', `+91 ${lead.phone}`);
    formData.append('email', lead.email);
    formData.append('source_intent', lead.source_intent || 'Website Lead');
    formData.append('_subject', `New Verified Lead - Brigade Granada (${lead.name})`);
    formData.append('_template', 'table');
    formData.append('_captcha', 'false');

    await fetch('https://formsubmit.co/ajax/blrrealestates@gmail.com', {
      method: 'POST',
      body: formData,
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(8000)
    }).catch(err => {
      console.warn('Background sales forward notice:', err.message);
    });
  } catch (err) {
    console.warn('Background dispatch caught:', err);
  }
}

export async function processLeadSubmission(
  body: LeadSubmissionPayload,
  clientIp: string,
  userAgent: string
): Promise<ProcessLeadResult> {
  // 1. Strict Schema Validation - Reject unexpected nested structures or arbitrary keys
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      statusCode: 400,
      response: {
        success: false,
        message: 'Invalid request format.'
      }
    };
  }

  // Ensure no unexpected extra fields
  for (const key of Object.keys(body)) {
    if (!ALLOWED_KEYS.has(key)) {
      return {
        statusCode: 400,
        response: {
          success: false,
          message: 'Invalid request payload structure.'
        }
      };
    }
  }

  // 2. Honeypot Bot Trap: If filled, silently accept to avoid bot adaptation, but quarantine
  const honeypotVal = typeof body._honey === 'string' ? body._honey.trim() : '';
  const honeypotFilled = honeypotVal.length > 0;

  if (honeypotFilled) {
    // Log suspicious bot activity securely (no personal info)
    console.warn(`[BOT BLOCKED] Honeypot triggered from IP: ${clientIp.replace(/\d+$/, 'xxx')}`);
    // Return standard success message so the bot does not adapt
    return {
      statusCode: 200,
      response: {
        success: true,
        message: 'Thank you. Your enquiry has been received successfully. Our team will contact you shortly.'
      }
    };
  }

  // 3. Field Normalization & Strict Server-side Validation
  const errors: Record<string, string> = {};

  const nameResult = validateAndNormalizeName(body.name);
  if (!nameResult.isValid) {
    errors.name = nameResult.errorMessage || 'Please enter a valid full name.';
  }

  const phoneResult = validateAndNormalizePhone(body.phone);
  if (!phoneResult.isValid) {
    errors.phone = phoneResult.errorMessage || 'Please enter a valid 10-digit Indian mobile number.';
  }

  const emailResult = validateAndNormalizeEmail(body.email);
  if (!emailResult.isValid) {
    errors.email = emailResult.errorMessage || 'Please enter a valid email address.';
  }

  // If any validation failed, return controlled generic error response
  if (Object.keys(errors).length > 0) {
    return {
      statusCode: 422,
      response: {
        success: false,
        message: Object.values(errors)[0],
        errors
      }
    };
  }

  const normalizedName = nameResult.normalizedValue!;
  const normalizedPhone = phoneResult.normalizedValue!;
  const normalizedEmail = emailResult.normalizedValue!;
  const sanitizedSource = sanitizeTextField(body.source_intent, 100) || 'Direct Lead';

  // 4. Rate Limiting Protection (IP, Phone, Email sliding windows)
  const rateLimitCheck = checkLeadRateLimits(clientIp, normalizedPhone, normalizedEmail);
  if (!rateLimitCheck.allowed) {
    return {
      statusCode: 429,
      response: {
        success: false,
        message: 'Too many requests. Please try again later.'
      }
    };
  }

  // 5. Submission Timing Protection
  let submissionTimeMs = 0;
  if (body.form_loaded_at) {
    const loadedAt = Number(body.form_loaded_at);
    if (!isNaN(loadedAt) && loadedAt > 0) {
      submissionTimeMs = Date.now() - loadedAt;
    }
  }

  // 6. Duplicate Lead Detection (Check within the last 24 hours)
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const existingLead = findRecentLead(normalizedPhone, normalizedEmail, twentyFourHoursAgo);

  const nowIso = new Date().toISOString();

  if (existingLead) {
    updateDuplicateLead(existingLead.id, sanitizedSource, nowIso);
  } else {
    // 7. Lead Quality Scoring
    const assessment = evaluateLeadQuality({
      name: normalizedName,
      phone: normalizedPhone,
      email: normalizedEmail,
      submissionTimeMs,
      userAgent,
      honeypotFilled: false,
      isDuplicate: false
    });

    // 8. Secure Database Storage using Parameterized Query
    const leadRecord: StoredLead = {
      name: normalizedName,
      phone: normalizedPhone,
      email: normalizedEmail,
      source_intent: sanitizedSource,
      quality_score: assessment.score,
      quality_points: assessment.points,
      quality_reasons: assessment.reasons.join('; '),
      ip_address: clientIp,
      user_agent: userAgent.slice(0, 250),
      submission_time_ms: submissionTimeMs,
      submission_count: 1,
      is_duplicate: 0,
      created_at: nowIso,
      updated_at: nowIso
    };

    insertLead(leadRecord);

    // 9. Dispatch to sales notification for legitimate leads
    if (assessment.score !== 'SPAM') {
      notifySalesTeam({
        name: normalizedName,
        phone: normalizedPhone,
        email: normalizedEmail,
        source_intent: sanitizedSource,
        quality_score: assessment.score
      });
    }
  }

  // 10. Clean, professional response (does not reveal duplicate status, internal score, or lead ID)
  return {
    statusCode: 200,
    response: {
      success: true,
      message: 'Thank you. Your enquiry has been received successfully. Our team will contact you shortly.'
    }
  };
}
