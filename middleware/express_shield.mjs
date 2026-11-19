/**
 * AI Bot & Automated Hacker Defense Middleware for Node.js / Express / Edge APIs
 * Traps autonomous AI exploit scanners, enforces adaptive rate limits & tarpits abusers.
 */

const HONEYPOT_PATHS = new Set([
  '/.env', '/.git/config', '/wp-login.php', '/phpmyadmin', '/actuator/env', '/api/debug/secrets'
]);

const EXPLOIT_UA_RX = /(sqlmap|nikto|nuclei|gobuster|ffuf|masscan|zgrab|acunetix|nessus)/i;

export function createAiBotDefense({ maxRpm = 90, banMs = 15 * 60 * 1000 } = {}) {
  const hits = new Map();
  const bans = new Map();

  return function aiBotDefenseMiddleware(req, res, next) {
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
    const path = (req.path || req.url || '/').split('?')[0].toLowerCase();
    const ua = String(req.headers['user-agent'] || '');
    const now = Date.now();

    if ((bans.get(ip) || 0) > now) {
      return res.status(403).json({ error: 'Access denied by AI Bot Defense Shield.' });
    }

    if (HONEYPOT_PATHS.has(path)) {
      bans.set(ip, now + banMs);
      return setTimeout(() => res.status(403).json({ error: 'Forbidden' }), 1500);
    }

    if (EXPLOIT_UA_RX.test(ua)) {
      return res.status(403).json({ error: 'Automated scanner blocked.' });
    }

    const bucket = (hits.get(ip) || []).filter((ts) => now - ts < 60_000);
    bucket.push(now);
    hits.set(ip, bucket);

    if (bucket.length > maxRpm) {
      bans.set(ip, now + 5 * 60 * 1000);
      return res.status(429).json({ error: 'Too many requests — automated swarm throttled.' });
    }

    return next();
  };
}
