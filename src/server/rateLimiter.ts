// In-memory sliding window rate limiter with configurable limits

interface RateWindow {
  timestamps: number[];
}

class SlidingWindowLimiter {
  private store: Map<string, RateWindow> = new Map();
  private cleanupIntervalMs = 5 * 60 * 1000; // clean every 5 mins

  constructor() {
    // Periodic garbage collection to prevent memory leaks
    setInterval(() => {
      const now = Date.now();
      for (const [key, window] of this.store.entries()) {
        window.timestamps = window.timestamps.filter(ts => now - ts < 3600000);
        if (window.timestamps.length === 0) {
          this.store.delete(key);
        }
      }
    }, this.cleanupIntervalMs).unref();
  }

  /**
   * Checks and consumes 1 token if within limits
   * Returns true if allowed, false if rate limited
   */
  public isAllowed(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    let record = this.store.get(key);
    if (!record) {
      record = { timestamps: [] };
      this.store.set(key, record);
    }

    // Filter out timestamps older than the window
    record.timestamps = record.timestamps.filter(ts => now - ts < windowMs);

    if (record.timestamps.length >= limit) {
      return false; // Limit exceeded
    }

    record.timestamps.push(now);
    return true;
  }
}

const limiter = new SlidingWindowLimiter();

// Configurable via environment variables with safe defaults
const LIMIT_IP_15M = Number(process.env.RATE_LIMIT_IP_15M) || 5;
const LIMIT_IP_1H = Number(process.env.RATE_LIMIT_IP_1H) || 10;
const LIMIT_PHONE_1H = Number(process.env.RATE_LIMIT_PHONE_1H) || 3;
const LIMIT_EMAIL_1H = Number(process.env.RATE_LIMIT_EMAIL_1H) || 3;

export interface RateLimitCheckResult {
  allowed: boolean;
  reason?: string;
}

export function checkLeadRateLimits(ip: string, phone: string, email: string): RateLimitCheckResult {
  const WINDOW_15M = 15 * 60 * 1000;
  const WINDOW_1H = 60 * 60 * 1000;

  // 1. Check IP 15-minute window
  if (!limiter.isAllowed(`ip_15m:${ip}`, LIMIT_IP_15M, WINDOW_15M)) {
    return { allowed: false, reason: 'IP rate limit 15m exceeded' };
  }

  // 2. Check IP 1-hour window
  if (!limiter.isAllowed(`ip_1h:${ip}`, LIMIT_IP_1H, WINDOW_1H)) {
    return { allowed: false, reason: 'IP rate limit 1h exceeded' };
  }

  // 3. Check Phone 1-hour window
  if (phone && !limiter.isAllowed(`phone_1h:${phone}`, LIMIT_PHONE_1H, WINDOW_1H)) {
    return { allowed: false, reason: 'Phone rate limit 1h exceeded' };
  }

  // 4. Check Email 1-hour window
  if (email && !limiter.isAllowed(`email_1h:${email}`, LIMIT_EMAIL_1H, WINDOW_1H)) {
    return { allowed: false, reason: 'Email rate limit 1h exceeded' };
  }

  return { allowed: true };
}
