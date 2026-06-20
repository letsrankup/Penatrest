const dns = require('dns');

function validate(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_]+$/.test(target)) throw new Error('Invalid target');
  return target.replace(/^https?:\/\//,'').split('/')[0].trim();
}

const WORDLIST = [
  'www','mail','ftp','smtp','api','dev','staging','test','m','app',
  'blog','shop','admin','portal','vpn','cdn','static','assets','media',
  'db','backup','beta','docs','support','auth','login','dashboard',
  'panel','git','jenkins','grafana','kibana','internal','intranet',
  'remote','cpanel','whm','plesk','smtp2','ns1','ns2','webmail',
  'secure','status','monitor','help','forum','community','id','accounts'
];

function checkSub(domain, sub) {
  return new Promise((resolve) => {
    dns.resolve4(`${sub}.${domain}`, (err, ips) => {
      resolve(err ? null : { subdomain: `${sub}.${domain}`, ips });
    });
  });
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const domain = validate(req.body?.target);
    const found = [];
    for (let i = 0; i < WORDLIST.length; i += 15) {
      const batch = await Promise.all(WORDLIST.slice(i, i+15).map(s => checkSub(domain, s)));
      found.push(...batch.filter(Boolean));
    }
    res.json({
      success: true, target: domain,
      total_checked: WORDLIST.length,
      found_count: found.length,
      subdomains: found,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
