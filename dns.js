const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveNs = promisify(dns.resolveNs);

function validate(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_]+$/.test(target)) throw new Error('Invalid target');
  return target.trim();
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const target = validate(req.body?.target);
    const results = {};
    const safe = async (fn, key) => {
      try { results[key] = await fn(target); } catch { results[key] = []; }
    };
    await Promise.all([
      safe(resolve4, 'A'),
      safe(resolveMx, 'MX'),
      safe(resolveTxt, 'TXT'),
      safe(resolveNs, 'NS'),
    ]);
    res.json({ success: true, target, records: results, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
