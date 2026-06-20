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
    const domain = target.replace(/^https?:\/\//, '').split('/')[0];
    const base = `https://${req.headers.host}`;

    const call = async (endpoint, body) => {
      try {
        const r = await fetch(`${base}/api/tools/${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        return await r.json();
      } catch (e) {
        return { success: false, error: e.message };
      }
    };

    const [dns_r, ssl_r, hdr_r, tech_r, sub_r] = await Promise.all([
      call('dns', { target: domain }),
      call('ssl', { target: domain }),
      call('headers', { target: domain }),
      call('techstack', { target: domain }),
      call('subdomains', { target: domain }),
    ]);

    const issues = [];

    if (ssl_r?.ssl?.expired)
      issues.push({ severity: 'CRITICAL', issue: 'SSL certificate is expired', category: 'SSL' });
    if (ssl_r?.ssl?.expiring_soon)
      issues.push({ severity: 'HIGH', issue: `SSL expires in ${ssl_r.ssl.days_remaining} days`, category: 'SSL' });
    if (ssl_r?.ssl?.self_signed)
      issues.push({ severity: 'HIGH', issue: 'Self-signed SSL certificate detected', category: 'SSL' });

    hdr_r?.security_analysis?.missing?.forEach(m => {
      issues.push({ severity: m.severity, issue: `Missing security header: ${m.header}`, category: 'Headers' });
    });

    if (sub_r?.found_count > 5)
      issues.push({ severity: 'LOW', issue: `${sub_r.found_count} subdomains exposed`, category: 'Reconnaissance' });

    const score = Math.max(0,
      100
      - issues.filter(i => i.severity === 'CRITICAL').length * 30
      - issues.filter(i => i.severity === 'HIGH').length * 15
      - issues.filter(i => i.severity === 'MEDIUM').length * 8
      - issues.filter(i => i.severity === 'LOW').length * 3
    );

    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : 'F';

    res.json({
      success: true,
      target: domain,
      security_score: score,
      grade,
      total_issues: issues.length,
      issues,
      modules: {
        dns: dns_r,
        ssl: ssl_r,
        headers: hdr_r,
        techstack: tech_r,
        subdomains: sub_r,
      },
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
