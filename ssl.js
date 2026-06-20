const tls = require('tls');

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
    const info = await new Promise((resolve, reject) => {
      const s = tls.connect(443, target, { servername: target, rejectUnauthorized: false }, () => {
        const cert = s.getPeerCertificate(true);
        const protocol = s.getProtocol();
        const cipher = s.getCipher();
        s.end();
        resolve({ cert, protocol, cipher });
      });
      s.on('error', reject);
      s.setTimeout(10000, () => { s.destroy(); reject(new Error('Connection timeout')); });
    });

    const cert = info.cert;
    const expiry = new Date(cert.valid_to);
    const daysLeft = Math.floor((expiry - new Date()) / 86400000);

    res.json({
      success: true, target,
      ssl: {
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        days_remaining: daysLeft,
        expired: daysLeft < 0,
        expiring_soon: daysLeft < 30 && daysLeft >= 0,
        fingerprint256: cert.fingerprint256,
        san: cert.subjectaltname,
        protocol: info.protocol,
        cipher: info.cipher,
        self_signed: cert.issuer?.CN === cert.subject?.CN,
        wildcard: cert.subject?.CN?.startsWith('*.'),
        serial: cert.serialNumber,
      },
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
