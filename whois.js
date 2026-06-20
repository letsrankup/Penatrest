const { exec } = require('child_process');

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
    const raw = await new Promise((resolve, reject) => {
      exec(`whois "${target}"`, { timeout: 15000 }, (err, stdout, stderr) => {
        if (err && !stdout) return reject(new Error('whois command failed — install whois on server'));
        resolve(stdout || stderr || '');
      });
    });

    const p = (rx) => { const m = raw.match(rx); return m ? m[1].trim() : null; };

    res.json({
      success: true, target,
      parsed: {
        registrar: p(/Registrar:\s*(.+)/i),
        created: p(/Creation Date:\s*(.+)/i),
        expires: p(/Expir\w+ Date:\s*(.+)/i),
        updated: p(/Updated Date:\s*(.+)/i),
        status: raw.match(/Domain Status:\s*(.+)/gi)?.map(s => s.replace(/Domain Status:\s*/i,'').trim()),
        nameservers: raw.match(/Name Server:\s*(.+)/gi)?.map(s => s.replace(/Name Server:\s*/i,'').trim().toLowerCase()),
        registrant_country: p(/Registrant Country:\s*(.+)/i),
        dnssec: p(/DNSSEC:\s*(.+)/i),
        admin_email: p(/Admin Email:\s*(.+)/i),
      },
      raw,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
