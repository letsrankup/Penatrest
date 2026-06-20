const http = require('http');
const https = require('https');

function validate(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_:/]+$/.test(target)) throw new Error('Invalid target');
  return target.trim();
}

const PATHS = [
  'admin','login','dashboard','api','backup','config','.env','robots.txt',
  'sitemap.xml','.htaccess','wp-admin','phpMyAdmin','uploads','logs',
  'test.php','phpinfo.php','wp-config.php','.git/config','README.md',
  'swagger','actuator','console','panel','shell.php','info.php',
  'phpmyadmin','pma','db','database','secret','credentials','private'
];

function checkPath(base, path) {
  return new Promise((resolve) => {
    try {
      const url = new URL(`/${path}`, base);
      const mod = url.protocol === 'https:' ? https : http;
      const r = mod.request({
        hostname: url.hostname, path: url.pathname,
        method: 'GET', timeout: 5000,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible)' }
      }, (resp) => {
        resolve({
          path, url: url.href,
          status: resp.statusCode,
          interesting: [200,201,301,302,403,500].includes(resp.statusCode)
        });
        resp.resume();
      });
      r.on('error', () => resolve({ path, status: 0, interesting: false }));
      r.on('timeout', () => { r.destroy(); resolve({ path, status: 408, interesting: false }); });
      r.end();
    } catch {
      resolve({ path, status: 0, interesting: false });
    }
  });
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const target = validate(req.body?.target);
    const base = target.startsWith('http') ? target : `https://${target}`;
    const all = [];
    for (let i = 0; i < PATHS.length; i += 8) {
      const batch = await Promise.all(PATHS.slice(i, i+8).map(p => checkPath(base, p)));
      all.push(...batch);
    }
    const interesting = all.filter(r => r.interesting);
    res.json({
      success: true, target,
      total_checked: all.length,
      interesting_count: interesting.length,
      interesting_paths: interesting,
      all_results: all,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
