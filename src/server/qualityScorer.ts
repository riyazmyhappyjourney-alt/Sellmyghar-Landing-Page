export interface LeadScoringInput {
  name: string;
  phone: string;
  email: string;
  submissionTimeMs: number;
  userAgent?: string;
  honeypotFilled: boolean;
  isDuplicate: boolean;
}

export interface QualityAssessment {
  score: 'HIGH_QUALITY' | 'NORMAL' | 'SUSPICIOUS' | 'SPAM';
  points: number;
  reasons: string[];
}

export function evaluateLeadQuality(input: LeadScoringInput): QualityAssessment {
  const reasons: string[] = [];
  let points = 0;

  // 1. Honeypot check: If filled, instant SPAM
  if (input.honeypotFilled) {
    return {
      score: 'SPAM',
      points: 0,
      reasons: ['Honeypot field was filled by automated bot']
    };
  }

  // 2. Name quality scoring
  const trimmedName = input.name.trim();
  const wordCount = trimmedName.split(/\s+/).length;
  if (wordCount >= 2 && trimmedName.length >= 4) {
    points += 30;
    reasons.push('Full human name provided with multiple words');
  } else if (trimmedName.length >= 3) {
    points += 20;
    reasons.push('Single word valid name provided');
  } else {
    points += 10;
    reasons.push('Short name provided');
  }

  // 3. Indian cellular phone format check
  if (/^[6-9]\d{9}$/.test(input.phone)) {
    // Check digit variety (genuine numbers rarely repeat one digit > 5 times)
    const uniqueDigits = new Set(input.phone.split('')).size;
    if (uniqueDigits >= 5) {
      points += 35;
      reasons.push('Strong Indian cellular number with natural digit distribution');
    } else if (uniqueDigits >= 3) {
      points += 20;
      reasons.push('Valid cellular number with low digit diversity');
    } else {
      points += 5;
      reasons.push('Suspicious low digit diversity');
    }
  }

  // 4. Email quality check
  const domain = (input.email.split('@')[1] || '').toLowerCase();
  const reputableDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'rediffmail.com', 'zoho.com'];
  if (reputableDomains.includes(domain)) {
    points += 25;
    reasons.push('Recognized primary email provider');
  } else if (domain.includes('.') && domain.length > 4) {
    points += 20;
    reasons.push('Standard corporate or private email domain');
  }

  // 5. Submission Timing Protection (Human vs Bot speed)
  if (input.submissionTimeMs >= 3500) {
    points += 10;
    reasons.push('Natural human interaction time (>3.5s)');
  } else if (input.submissionTimeMs >= 1800) {
    points += 5;
    reasons.push('Fast but plausible human entry');
  } else if (input.submissionTimeMs > 0 && input.submissionTimeMs < 1800) {
    points -= 25;
    reasons.push('Unrealistically fast form completion (<1.8s)');
  }

  // 6. User Agent Check
  const ua = (input.userAgent || '').toLowerCase();
  if (!ua || ua.length < 10) {
    points -= 30;
    reasons.push('Missing or suspiciously short user-agent');
  } else if (ua.includes('curl') || ua.includes('python') || ua.includes('bot') || ua.includes('crawl') || ua.includes('wget')) {
    points -= 40;
    reasons.push('Automated scraper / bot user-agent identified');
  }

  // 7. Duplicate Lead Consideration
  if (input.isDuplicate) {
    reasons.push('Recent repeat submission from same contact within 24h');
  }

  // Final Classification based on accumulated points
  let score: 'HIGH_QUALITY' | 'NORMAL' | 'SUSPICIOUS' | 'SPAM';
  if (points >= 80) {
    score = 'HIGH_QUALITY';
  } else if (points >= 50) {
    score = 'NORMAL';
  } else if (points >= 25) {
    score = 'SUSPICIOUS';
  } else {
    score = 'SPAM';
  }

  return {
    score,
    points: Math.max(0, points),
    reasons
  };
}
