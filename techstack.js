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

    const { headers, body } = await new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      let body = '';
      const r = mod.get(url, {
        timeout: 15000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
      }, (resp) => {
        resp.on('data', c => { body += c; if (body.length > 150000) resp.destroy(); });
        resp.on('end', () => resolve({ headers: resp.headers, body }));
      });
      r.on('error', reject);
      r.on('timeout', () => { r.destroy(); reject(new Error('Timeout')); });
    });

    const detected = [];
    const add = (tech, cat, evidence, version = null) => {
      if (!detected.find(d => d.tech === tech))
        detected.push({ tech, category: cat, evidence, version });
    };

    const h = (name) => headers[name] || '';
    const srv = h('server');
    const xpb = h('x-powered-by');

    // Header based
    const nginxM = srv.match(/nginx\/([\d.]+)/i);
    if (nginxM) add('Nginx', 'Server', 'Header: server', nginxM[1]);
    const apacheM = srv.match(/Apache\/([\d.]+)/i);
    if (apacheM) add('Apache', 'Server', 'Header: server', apacheM[1]);
    if (/cloudflare/i.test(srv)) add('Cloudflare', 'CDN', 'Header: server');
    if (/LiteSpeed/i.test(srv)) add('LiteSpeed', 'Server', 'Header: server');
    if (/Microsoft-IIS\/([\d.]+)/i.test(srv)) add('IIS', 'Server', 'Header: server', srv.match(/IIS\/([\d.]+)/i)?.[1]);
    if (/PHP/i.test(xpb)) add('PHP', 'Language', 'Header: x-powered-by', xpb.match(/PHP\/([\d.]+)/i)?.[1]);
    if (/Express/i.test(xpb)) add('Express.js', 'Framework', 'Header: x-powered-by');
    if (/Next\.js/i.test(xpb)) add('Next.js', 'Framework', 'Header: x-powered-by');
    if (/ASP\.NET/i.test(xpb)) add('ASP.NET', 'Framework', 'Header: x-powered-by');

    // Body based
    if (/wp-content|wp-includes|WordPress/i.test(body)) add('WordPress', 'CMS', 'HTML source');
    if (/Drupal/i.test(body)) add('Drupal', 'CMS', 'HTML source');
    if (/Joomla/i.test(body)) add('Joomla', 'CMS', 'HTML source');
    if (/shopify/i.test(body)) add('Shopify', 'E-commerce', 'HTML source');
    if (/react[\-\.]dom/i.test(body)) add('React', 'JS Framework', 'HTML source');
    if (/angular(\.min)?\.js/i.test(body)) add('Angular', 'JS Framework', 'HTML source');
    if (/vue(\.min)?\.js/i.test(body)) add('Vue.js', 'JS Framework', 'HTML source');
    if (/jquery/i.test(body)) add('jQuery', 'JS Library', 'HTML source');
    if (/bootstrap/i.test(body)) add('Bootstrap', 'CSS Framework', 'HTML source');
    if (/tailwind/i.test(body)) add('Tailwind CSS', 'CSS Framework', 'HTML source');
    if (/_next\/static/i.test(body)) add('Next.js', 'Framework', 'HTML source');
    if (/nuxt/i.test(body)) add('Nuxt.js', 'Framework', 'HTML source');
    if (/gtag\(|google-analytics|UA-\d+/i.test(body)) add('Google Analytics', 'Analytics', 'HTML source');
    if (/vercel/i.test(body)) add('Vercel', 'Hosting', 'HTML source');
    if (/netlify/i.test(body)) add('Netlify', 'Hosting', 'HTML source');
    if (/stripe/i.test(body)) add('Stripe', 'Payment', 'HTML source');
    if (/recaptcha/i.test(body)) add('reCAPTCHA', 'Security', 'HTML source');
    if (/graphql/i.test(body)) add('GraphQL', 'API', 'HTML source');
    if (/amazonaws\.com/i.test(body)) add('Amazon AWS', 'Cloud', 'HTML source');

    // Cookie based
    const cookies = headers['set-cookie'] || [];
    if (cookies.some(c => c.includes('PHPSESSID'))) add('PHP Sessions', 'Language', 'Cookie');
    if (cookies.some(c => c.includes('JSESSIONID'))) add('Java/Tomcat', 'Server', 'Cookie');
    if (cookies.some(c => c.includes('laravel_session'))) add('Laravel', 'Framework', 'Cookie');
    if (cookies.some(c => c.includes('django'))) add('Django', 'Framework', 'Cookie');

    const by_category = detected.reduce((a, d) => {
      (a[d.category] = a[d.category] || []).push(d); return a;
    }, {});

    res.json({
      success: true, target,
      total_found: detected.length,
      technologies: detected,
      by_category,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
};
