const dns = require('dns');
const http = require('http');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);

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
    let ip = target;

    if (!/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      try { const a = await resolve4(target); ip = a[0]; } catch {}
    }

    const geo = await new Promise((resolve, reject) => {
      http.get(
        `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,mobile,query`,
        (resp) => {
          let d = '';
          resp.on('data', c => d += c);
          resp.on('end', () => {
            try { resolve(JSON.parse(d)); }
            catch { reject(new Error('Parse error')); }
          });
        }
      ).on('error', reject);
    });

    const rdns = await new Promise(r => dns.reverse(ip, (e, h) => r(e ? [] : h)));

    res.json({
      success: true,
      original_target: target,
      resolved_ip: ip,
      geolocation: geo,
      reverse_dns: rdns,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
