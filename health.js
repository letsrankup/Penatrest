module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({
    status: 'online',
    version: '1.0.0',
    tools: ['dns','portscan','ssl','headers','whois','subdomains','dirscan','techstack','ipinfo','audit'],
    timestamp: new Date().toISOString()
  });
};
