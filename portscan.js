const net = require('net');

function validate(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_]+$/.test(target)) throw new Error('Invalid target');
  if (['localhost','127.','192.168.','10.'].some(b => target.includes(b)))
    throw new Error('Private IPs not allowed');
  return target.trim();
}

const SERVICES = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
  80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
  993:'IMAPS', 995:'POP3S', 3306:'MySQL', 3389:'RDP',
  5900:'VNC', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB'
};

const PORTS = Object.keys(SERVICES).map(Number);

function scanPort(host, port) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(2000);
    s.connect(port, host, () => {
      s.destroy();
      resolve({ port, status: 'open', service: SERVICES[port] || 'unknown' });
    });
    s.on('error', () => { s.destroy(); resolve({ port, status: 'closed' }); });
    s.on('timeout', () => { s.destroy(); resolve({ port, status: 'filtered' }); });
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
    const results = await Promise.all(PORTS.map(p => scanPort(target, p)));
    const open = results.filter(r => r.status === 'open');
    res.json({
      success: true, target,
      total_scanned: PORTS.length,
      open_ports: open,
      all_results: results,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
