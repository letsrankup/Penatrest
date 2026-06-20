const http = require('http');
const https = require('https');

function validate(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_:/]+$/.test(target)) throw new Error('Invalid target');
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
    const url = target.startsWith('http') ? target : `https://${target}`;

    const result = await new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const r = mod.request(url, { method: 'HEAD', timeout: 10000 }, (resp) => {
        resolve({ headers: resp.headers, statusCode: resp.statusCode });
      });
      r.on('error', reject);
      r.on('timeout', () => { r.destroy(); reject(new Error('Timeout')); });
      r.end();
    });

    const SEC_HEADERS = [
      { name: 'strict-transport-security', severity: 'HIGH' },
      { name: 'content-security-policy', severity: 'HIGH' },
      { name: 'x-frame-options', severity: 'MEDIUM' },
      { name: 'x-content-type-options', severity: 'MEDIUM' },
      { name: 'referrer-policy', severity: 'LOW' },
      { name: 'permissions-policy', severity: 'LOW' },
    ];

    const missing = SEC_HEADERS.filter(h => !result.headers[h.name]);
    const present = SEC_HEADERS.filter(h => result.headers[h.name]);
    const score = Math.round((present.length / SEC_HEADERS.length) * 100);

    res.json({
      success: true, target,
      status: result.statusCode,
      all_headers: result.headers,
      server: result.headers['server'] || 'Hidden',
      powered_by: result.headers['x-powered-by'] || 'Hidden',
      security_analysis: { score, missing, present: present.map(h => h.name) },
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
