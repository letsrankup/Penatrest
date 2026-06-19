const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const net = require('net');
const dns = require('dns');
const tls = require('tls');
const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);

function validateTarget(target) {
  if (!target) throw new Error('Target required');
  if (!/^[a-zA-Z0-9.\-_:/]+$/.test(target)) throw new Error('Invalid target');
  if (['localhost','127.','192.168.','10.0.'].some(b => target.includes(b)))
    throw new Error('Private IPs not allowed');
  return target.trim();
}

function safeExec(cmd, ms = 15000) {
  return new Promise((res, rej) => {
    exec(cmd, { timeout: ms }, (err, stdout, stderr) => {
      if (err && !stdout) return rej(new Error(stderr || err.message));
      res(stdout || stderr || '');
    });
  });
}

// ── TOOL 1: DNS ──────────────────────────────────────────────────────────
app.post('/api/tools/dns', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const results = {};
    const safe = async (fn, key) => {
      try { results[key] = await fn(target); } catch { results[key] = []; }
    };
    await Promise.all([
      safe(dnsResolve4, 'A'),
      safe(dnsResolveMx, 'MX'),
      safe(dnsResolveTxt, 'TXT'),
      safe(dnsResolveNs, 'NS'),
    ]);
    res.json({ success: true, target, records: results, timestamp: new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 2: PORT SCANNER ─────────────────────────────────────────────────
app.post('/api/tools/portscan', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const ports = [21,22,23,25,53,80,110,139,143,443,445,
                   993,995,3306,3389,5900,8080,8443,27017];
    const services = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',
      80:'HTTP',110:'POP3',139:'NetBIOS',143:'IMAP',443:'HTTPS',
      445:'SMB',993:'IMAPS',995:'POP3S',3306:'MySQL',3389:'RDP',
      5900:'VNC',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};

    const scan = (port) => new Promise((resolve) => {
      const s = new net.Socket();
      s.setTimeout(2000);
      s.connect(port, target, () => { s.destroy(); resolve({ port, status:'open', service: services[port]||'unknown' }); });
      s.on('error', () => { s.destroy(); resolve({ port, status:'closed' }); });
      s.on('timeout', () => { s.destroy(); resolve({ port, status:'filtered' }); });
    });

    const results = await Promise.all(ports.map(scan));
    const open = results.filter(r => r.status === 'open');
    res.json({ success: true, target, total_scanned: ports.length, open_ports: open, timestamp: new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 3: SSL CHECKER ──────────────────────────────────────────────────
app.post('/api/tools/ssl', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const info = await new Promise((resolve, reject) => {
      const s = tls.connect(443, target, { servername: target, rejectUnauthorized: false }, () => {
        const cert = s.getPeerCertificate(true);
        const protocol = s.getProtocol();
        const cipher = s.getCipher();
        s.end();
        resolve({ cert, protocol, cipher });
      });
      s.on('error', reject);
      s.setTimeout(10000, () => { s.destroy(); reject(new Error('Timeout')); });
    });
    const cert = info.cert;
    const expiry = new Date(cert.valid_to);
    const daysLeft = Math.floor((expiry - new Date()) / 86400000);
    res.json({
      success: true, target,
      ssl: {
        subject: cert.subject, issuer: cert.issuer,
        valid_from: cert.valid_from, valid_to: cert.valid_to,
        days_remaining: daysLeft, expired: daysLeft < 0,
        expiring_soon: daysLeft < 30 && daysLeft >= 0,
        fingerprint256: cert.fingerprint256,
        san: cert.subjectaltname,
        protocol: info.protocol, cipher: info.cipher,
        self_signed: cert.issuer?.CN === cert.subject?.CN,
      },
      timestamp: new Date().toISOString()
    });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 4: HTTP HEADERS ─────────────────────────────────────────────────
app.post('/api/tools/headers', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
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
    const secHeaders = ['strict-transport-security','content-security-policy',
      'x-frame-options','x-content-type-options','referrer-policy','permissions-policy'];
    const missing = secHeaders
      .filter(h => !result.headers[h])
      .map(h => ({ header: h, severity: ['strict-transport-security','content-security-policy'].includes(h) ? 'HIGH' : 'MEDIUM' }));
    const score = Math.round(((secHeaders.length - missing.length) / secHeaders.length) * 100);
    res.json({
      success: true, target,
      status: result.statusCode,
      all_headers: result.headers,
      server: result.headers['server'] || 'Hidden',
      security_analysis: { score, missing },
      timestamp: new Date().toISOString()
    });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 5: WHOIS ────────────────────────────────────────────────────────
app.post('/api/tools/whois', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const raw = await safeExec(`whois "${target}"`);
    const p = (rx) => { const m = raw.match(rx); return m ? m[1].trim() : null; };
    res.json({
      success: true, target,
      parsed: {
        registrar: p(/Registrar:\s*(.+)/i),
        created: p(/Creation Date:\s*(.+)/i),
        expires: p(/Expiry Date:\s*(.+)/i) || p(/Expiration Date:\s*(.+)/i),
        updated: p(/Updated Date:\s*(.+)/i),
        nameservers: raw.match(/Name Server:\s*(.+)/gi)?.map(s => s.replace(/Name Server:\s*/i,'').trim()),
        registrant_country: p(/Registrant Country:\s*(.+)/i),
        dnssec: p(/DNSSEC:\s*(.+)/i),
      },
      raw,
      timestamp: new Date().toISOString()
    });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 6: SUBDOMAIN FINDER ─────────────────────────────────────────────
app.post('/api/tools/subdomains', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const domain = target.replace(/^https?:\/\//,'').split('/')[0];
    const wordlist = ['www','mail','ftp','smtp','api','dev','staging','test',
      'm','app','blog','shop','admin','portal','vpn','cdn','static','assets',
      'media','db','backup','beta','docs','support','auth','login','dashboard',
      'panel','git','jenkins','grafana','kibana','internal','intranet'];

    const check = (sub) => new Promise((resolve) => {
      dns.resolve4(`${sub}.${domain}`, (err, ips) => {
        resolve(err ? null : { subdomain: `${sub}.${domain}`, ips });
      });
    });

    const results = [];
    for (let i = 0; i < wordlist.length; i += 15) {
      const batch = await Promise.all(wordlist.slice(i, i+15).map(check));
      results.push(...batch.filter(Boolean));
    }
    res.json({ success: true, target: domain, total_checked: wordlist.length, found_count: results.length, subdomains: results, timestamp: new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 7: DIRECTORY SCANNER ────────────────────────────────────────────
app.post('/api/tools/dirscan', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const base = target.startsWith('http') ? target : `https://${target}`;
    const paths = ['admin','login','dashboard','api','backup','config','.env',
      'robots.txt','sitemap.xml','.htaccess','wp-admin','phpMyAdmin',
      'uploads','logs','test.php','phpinfo.php','wp-config.php',
      '.git/config','README.md','swagger','actuator','console'];

    const check = (path) => new Promise((resolve) => {
      const url = new URL(`/${path}`, base);
      const mod = url.protocol === 'https:' ? https : http;
      const r = mod.request({ hostname: url.hostname, path: url.pathname, method: 'GET', timeout: 5000,
        headers: { 'User-Agent': 'Mozilla/5.0' } }, (resp) => {
        resolve({ path, status: resp.statusCode, interesting: [200,301,302,403,500].includes(resp.statusCode) });
        resp.resume();
      });
      r.on('error', () => resolve({ path, status: 0, interesting: false }));
      r.on('timeout', () => { r.destroy(); resolve({ path, status: 408, interesting: false }); });
      r.end();
    });

    const all = [];
    for (let i = 0; i < paths.length; i += 8) {
      const batch = await Promise.all(paths.slice(i, i+8).map(check));
      all.push(...batch);
    }
    const interesting = all.filter(r => r.interesting);
    res.json({ success: true, target, total_checked: all.length, interesting_count: interesting.length, interesting_paths: interesting, timestamp: new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 8: TECH STACK ───────────────────────────────────────────────────
app.post('/api/tools/techstack', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const url = target.startsWith('http') ? target : `https://${target}`;
    const { headers, body } = await new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      let body = '';
      mod.get(url, { timeout: 15000, headers: { 'User-Agent': 'Mozilla/5.0' } }, (resp) => {
        resp.on('data', c => { body += c; if (body.length > 150000) resp.destroy(); });
        resp.on('end', () => resolve({ headers: resp.headers, body }));
      }).on('error', reject);
    });

    const detected = [];
    const add = (tech, cat, evidence, version=null) => {
      if (!detected.find(d => d.tech === tech)) detected.push({ tech, category: cat, evidence, version });
    };

    const hdr = (h) => headers[h] || '';
    if (/nginx\/([\d.]+)/i.test(hdr('server'))) add('Nginx','Server','Header',hdr('server').match(/nginx\/([\d.]+)/i)?.[1]);
    if (/apache\/([\d.]+)/i.test(hdr('server'))) add('Apache','Server','Header',hdr('server').match(/apache\/([\d.]+)/i)?.[1]);
    if (/cloudflare/i.test(hdr('server'))) add('Cloudflare','CDN','Header');
    if (/PHP/i.test(hdr('x-powered-by'))) add('PHP','Language','Header');
    if (/Express/i.test(hdr('x-powered-by'))) add('Express.js','Framework','Header');
    if (/Next\.js/i.test(hdr('x-powered-by'))) add('Next.js','Framework','Header');
    if (/wp-content|wp-includes/i.test(body)) add('WordPress','CMS','HTML');
    if (/react[\-\.]dom/i.test(body)) add('React','JS Framework','HTML');
    if (/angular(\.min)?\.js/i.test(body)) add('Angular','JS Framework','HTML');
    if (/vue(\.min)?\.js/i.test(body)) add('Vue.js','JS Framework','HTML');
    if (/jquery/i.test(body)) add('jQuery','JS Library','HTML');
    if (/bootstrap/i.test(body)) add('Bootstrap','CSS Framework','HTML');
    if (/tailwind/i.test(body)) add('Tailwind CSS','CSS Framework','HTML');
    if (/_next\/static/i.test(body)) add('Next.js','Framework','HTML');
    if (/gtag\(|google-analytics/i.test(body)) add('Google Analytics','Analytics','HTML');
    if (/vercel/i.test(body)) add('Vercel','Hosting','HTML');
    if (/stripe/i.test(body)) add('Stripe','Payment','HTML');

    res.json({
      success: true, target, total_found: detected.length,
      technologies: detected,
      by_category: detected.reduce((a,d) => { (a[d.category]=a[d.category]||[]).push(d); return a; }, {}),
      timestamp: new Date().toISOString()
    });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 9: IP GEOLOCATION ───────────────────────────────────────────────
app.post('/api/tools/ipinfo', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    let ip = target;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      try { const a = await dnsResolve4(target); ip = a[0]; } catch {}
    }
    const geo = await new Promise((resolve, reject) => {
      http.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,mobile,query`, (r) => {
        let d=''; r.on('data',c=>d+=c); r.on('end',()=>{ try{resolve(JSON.parse(d))}catch{reject(new Error('Parse error'))} });
      }).on('error', reject);
    });
    const rdns = await new Promise(r => dns.reverse(ip, (e,h) => r(e?[]:h)));
    res.json({ success: true, original_target: target, resolved_ip: ip, geolocation: geo, reverse_dns: rdns, timestamp: new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── TOOL 10: FULL AUDIT ──────────────────────────────────────────────────
app.post('/api/tools/audit', async (req, res) => {
  try {
    const target = validateTarget(req.body.target);
    const domain = target.replace(/^https?:\/\//,'').split('/')[0];
    const call = (endpoint, body) =>
      fetch(`http://localhost:${PORT}/api/tools/${endpoint}`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body)
      }).then(r=>r.json()).catch(e=>({ success:false, error:e.message }));

    const [dns_r, ssl_r, hdr_r] = await Promise.all([
      call('dns',{target:domain}),
      call('ssl',{target:domain}),
      call('headers',{target:domain}),
    ]);

    const issues = [];
    if (ssl_r?.ssl?.expired) issues.push({ severity:'CRITICAL', issue:'SSL certificate expired' });
    if (ssl_r?.ssl?.expiring_soon) issues.push({ severity:'HIGH', issue:`SSL expires in ${ssl_r.ssl.days_remaining} days` });
    if (ssl_r?.ssl?.self_signed) issues.push({ severity:'HIGH', issue:'Self-signed SSL certificate' });
    hdr_r?.security_analysis?.missing?.forEach(m =>
      issues.push({ severity: m.severity, issue:`Missing header: ${m.header}` })
    );

    const score = Math.max(0, 100
      - issues.filter(i=>i.severity==='CRITICAL').length * 30
      - issues.filter(i=>i.severity==='HIGH').length * 15
      - issues.filter(i=>i.severity==='MEDIUM').length * 8);
    const grade = score>=90?'A':score>=75?'B':score>=60?'C':score>=45?'D':'F';

    res.json({ success:true, target:domain, security_score:score, grade, total_issues:issues.length, issues,
      modules:{ dns:dns_r, ssl:ssl_r, headers:hdr_r }, timestamp:new Date().toISOString() });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// ── HEALTH ───────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ status:'online', timestamp: new Date().toISOString() }));

app.listen(PORT, () => console.log(`✅ PenTest Pro Backend: http://localhost:${PORT}`));
