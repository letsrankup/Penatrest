import { useState, useCallback, useRef, useEffect } from "react";

const API_BASE = "/api";

const TOOLS = [
  { id:"dns", name:"DNS Lookup", icon:"🌐", category:"Reconnaissance", desc:"Full DNS record enumeration — A, MX, NS, TXT records", color:"#00ff88", placeholder:"example.com" },
  { id:"portscan", name:"Port Scanner", icon:"🔌", category:"Network", desc:"TCP port scanner — detect open services & running daemons", color:"#ff6b35", placeholder:"example.com or 1.2.3.4" },
  { id:"ssl", name:"SSL/TLS Checker", icon:"🔒", category:"Cryptography", desc:"SSL certificate analysis — expiry, cipher, issuer, vulnerabilities", color:"#4ecdc4", placeholder:"example.com" },
  { id:"headers", name:"HTTP Headers", icon:"📋", category:"Web Security", desc:"Security header audit — CSP, HSTS, X-Frame-Options scoring", color:"#ffe66d", placeholder:"example.com" },
  { id:"whois", name:"WHOIS Lookup", icon:"📁", category:"Reconnaissance", desc:"Domain registration info — registrar, owner, nameservers", color:"#a8edea", placeholder:"example.com" },
  { id:"subdomains", name:"Subdomain Finder", icon:"🔍", category:"Reconnaissance", desc:"DNS brute-force subdomain enumeration with 45+ wordlist", color:"#fed9b7", placeholder:"example.com" },
  { id:"dirscan", name:"Dir/Path Scanner", icon:"📂", category:"Web Security", desc:"Discover hidden directories, admin panels, config files", color:"#f7b731", placeholder:"example.com" },
  { id:"techstack", name:"Tech Detector", icon:"⚙️", category:"Fingerprinting", desc:"Identify CMS, frameworks, servers, JS libraries, CDNs", color:"#a29bfe", placeholder:"example.com" },
  { id:"ipinfo", name:"IP Geolocation", icon:"📍", category:"Intelligence", desc:"IP info — country, ISP, ASN, reverse DNS, proxy detection", color:"#fd79a8", placeholder:"example.com or IP" },
  { id:"audit", name:"Full Security Audit", icon:"🛡️", category:"Comprehensive", desc:"Complete assessment — DNS + SSL + Headers + Score + Grade", color:"#e17055", placeholder:"example.com", featured:true },
];

const SEV_COLOR = { CRITICAL:"#ff0040", HIGH:"#ff6b35", MEDIUM:"#ffe66d", LOW:"#00ff88", INFO:"#74b9ff" };

function Badge({ level }) {
  return (
    <span style={{ background: SEV_COLOR[level] || "#666", color:"#000", padding:"2px 8px", borderRadius:"4px", fontSize:"11px", fontWeight:"700" }}>
      {level}
    </span>
  );
}

function ResultRenderer({ toolId, data }) {
  if (!data?.success) return null;

  if (toolId === "dns") return (
    <div>
      {Object.entries(data.records).map(([type, records]) =>
        Array.isArray(records) && records.length > 0 && (
          <div key={type} style={{ marginBottom:"14px" }}>
            <div style={{ color:"#00ff88", fontSize:"12px", fontFamily:"monospace", marginBottom:"6px" }}>[{type} Records]</div>
            {records.map((r, i) => (
              <div key={i} style={{ background:"#0d1117", padding:"8px 12px", borderRadius:"6px", fontFamily:"monospace", fontSize:"12px", color:"#cdd9e5", marginBottom:"4px", borderLeft:"3px solid #00ff88" }}>
                {typeof r === "object" ? JSON.stringify(r) : String(r)}
              </div>
            ))}
          </div>
        )
      )}
    </div>
  );

  if (toolId === "portscan") return (
    <div>
      <div style={{ display:"flex", gap:"16px", marginBottom:"16px" }}>
        {[{l:"Scanned",v:data.total_scanned,c:"#74b9ff"},{l:"Open",v:data.open_ports?.length,c:"#00ff88"}].map(({l,v,c}) => (
          <div key={l} style={{ background:"#0d1117", padding:"12px 20px", borderRadius:"8px", textAlign:"center", border:`1px solid ${c}30` }}>
            <div style={{ color:c, fontSize:"24px", fontWeight:"700" }}>{v}</div>
            <div style={{ color:"#666", fontSize:"11px" }}>{l}</div>
          </div>
        ))}
      </div>
      {data.open_ports?.length === 0 && <div style={{ color:"#666", textAlign:"center", padding:"20px" }}>No open ports found</div>}
      {data.open_ports?.map(p => (
        <div key={p.port} style={{ display:"flex", alignItems:"center", gap:"12px", background:"#0d1117", padding:"10px 14px", borderRadius:"6px", marginBottom:"6px", borderLeft:"3px solid #00ff88" }}>
          <span style={{ color:"#00ff88", fontFamily:"monospace", width:"60px" }}>{p.port}</span>
          <span style={{ background:"#00ff8820", color:"#00ff88", padding:"2px 10px", borderRadius:"4px", fontSize:"12px" }}>OPEN</span>
          <span style={{ color:"#cdd9e5", fontFamily:"monospace", fontSize:"13px" }}>{p.service}</span>
        </div>
      ))}
    </div>
  );

  if (toolId === "ssl") {
    const s = data.ssl;
    const statusColor = s.expired ? "#ff0040" : s.expiring_soon ? "#ffe66d" : "#00ff88";
    return (
      <div>
        <div style={{ display:"flex", gap:"8px", marginBottom:"16px", flexWrap:"wrap" }}>
          <span style={{ background:statusColor+"20", color:statusColor, border:`1px solid ${statusColor}50`, padding:"4px 14px", borderRadius:"20px", fontSize:"12px", fontWeight:"600" }}>
            {s.expired ? "EXPIRED" : s.expiring_soon ? "EXPIRING SOON" : "VALID"}
          </span>
          <span style={{ background:"#74b9ff20", color:"#74b9ff", border:"1px solid #74b9ff50", padding:"4px 14px", borderRadius:"20px", fontSize:"12px", fontWeight:"600" }}>{s.protocol}</span>
          <span style={{ background:s.self_signed?"#ff6b3520":"#00ff8820", color:s.self_signed?"#ff6b35":"#00ff88", border:`1px solid ${s.self_signed?"#ff6b35":"#00ff88"}50`, padding:"4px 14px", borderRadius:"20px", fontSize:"12px", fontWeight:"600" }}>
            {s.self_signed ? "SELF-SIGNED" : "CA-SIGNED"}
          </span>
        </div>
        {[["Subject CN",s.subject?.CN],["Issuer",s.issuer?.O||s.issuer?.CN],["Valid From",s.valid_from],["Valid To",s.valid_to],["Days Left",s.days_remaining],["Protocol",s.protocol],["Cipher",s.cipher?.name],["Wildcard",s.wildcard?"Yes":"No"],["SAN",s.san]].map(([l,v]) => v!=null && (
          <div key={l} style={{ display:"flex", gap:"12px", padding:"8px 0", borderBottom:"1px solid #1a1a1a", fontFamily:"monospace", fontSize:"13px" }}>
            <span style={{ color:"#666", minWidth:"150px" }}>{l}</span>
            <span style={{ color:"#cdd9e5", wordBreak:"break-all" }}>{String(v)}</span>
          </div>
        ))}
      </div>
    );
  }

  if (toolId === "headers") return (
    <div>
      <div style={{ display:"flex", alignItems:"center", gap:"16px", background:"#0d1117", padding:"16px", borderRadius:"10px", marginBottom:"16px" }}>
        <div style={{ width:"60px", height:"60px", borderRadius:"50%", background:`conic-gradient(#00ff88 ${data.security_analysis?.score*3.6}deg, #1a2a1a 0deg)`, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div style={{ width:"46px", height:"46px", borderRadius:"50%", background:"#0d1117", display:"flex", alignItems:"center", justifyContent:"center", color:"#00ff88", fontWeight:"700", fontSize:"14px" }}>{data.security_analysis?.score}%</div>
        </div>
        <div>
          <div style={{ color:"#fff", fontSize:"16px", fontWeight:"600" }}>Security Score</div>
          <div style={{ color:"#666", fontSize:"12px" }}>{data.security_analysis?.missing?.length} missing headers · Server: {data.server}</div>
        </div>
      </div>
      <div style={{ marginBottom:"12px", color:"#444", fontSize:"11px", letterSpacing:"1px" }}>MISSING HEADERS</div>
      {data.security_analysis?.missing?.map(m => (
        <div key={m.name||m.header} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", background:"#0d1117", padding:"10px 14px", borderRadius:"6px", marginBottom:"6px", borderLeft:`3px solid ${m.severity==="HIGH"?"#ff6b35":m.severity==="MEDIUM"?"#ffe66d":"#666"}` }}>
          <span style={{ fontFamily:"monospace", color:"#cdd9e5", fontSize:"13px" }}>{m.name||m.header}</span>
          <Badge level={m.severity} />
        </div>
      ))}
    </div>
  );

  if (toolId === "whois") return (
    <div>
      {Object.entries(data.parsed).map(([k,v]) => v && (
        <div key={k} style={{ display:"flex", gap:"12px", padding:"9px 0", borderBottom:"1px solid #111", fontFamily:"monospace", fontSize:"13px" }}>
          <span style={{ color:"#666", minWidth:"180px", textTransform:"capitalize" }}>{k.replace(/_/g," ")}</span>
          <span style={{ color:"#cdd9e5", wordBreak:"break-all" }}>{Array.isArray(v)?v.join(", "):String(v)}</span>
        </div>
      ))}
    </div>
  );

  if (toolId === "subdomains") return (
    <div>
      <div style={{ display:"flex", gap:"16px", marginBottom:"16px" }}>
        {[{l:"Checked",v:data.total_checked,c:"#74b9ff"},{l:"Found",v:data.found_count,c:"#00ff88"}].map(({l,v,c}) => (
          <div key={l} style={{ background:"#0d1117", padding:"12px 20px", borderRadius:"8px", textAlign:"center", border:`1px solid ${c}30` }}>
            <div style={{ color:c, fontSize:"24px", fontWeight:"700" }}>{v}</div>
            <div style={{ color:"#666", fontSize:"11px" }}>{l}</div>
          </div>
        ))}
      </div>
      {data.found_count === 0 && <div style={{ color:"#666", textAlign:"center", padding:"20px" }}>No subdomains found</div>}
      {data.subdomains?.map(s => (
        <div key={s.subdomain} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", background:"#0d1117", padding:"10px 14px", borderRadius:"6px", marginBottom:"6px", borderLeft:"3px solid #00ff88" }}>
          <span style={{ color:"#00ff88", fontFamily:"monospace", fontSize:"13px" }}>{s.subdomain}</span>
          <span style={{ color:"#666", fontFamily:"monospace", fontSize:"12px" }}>{s.ips?.join(", ")}</span>
        </div>
      ))}
    </div>
  );

  if (toolId === "dirscan") return (
    <div>
      <div style={{ display:"flex", gap:"16px", marginBottom:"16px" }}>
        {[{l:"Checked",v:data.total_checked,c:"#74b9ff"},{l:"Interesting",v:data.interesting_count,c:"#ffe66d"}].map(({l,v,c}) => (
          <div key={l} style={{ background:"#0d1117", padding:"12px 20px", borderRadius:"8px", textAlign:"center", border:`1px solid ${c}30` }}>
            <div style={{ color:c, fontSize:"24px", fontWeight:"700" }}>{v}</div>
            <div style={{ color:"#666", fontSize:"11px" }}>{l}</div>
          </div>
        ))}
      </div>
      {data.interesting_paths?.map(p => {
        const c = p.status===200?"#00ff88":p.status===403?"#ffe66d":p.status>=300&&p.status<400?"#74b9ff":"#ff6b35";
        return (
          <div key={p.path} style={{ display:"flex", alignItems:"center", gap:"12px", background:"#0d1117", padding:"10px 14px", borderRadius:"6px", marginBottom:"6px", borderLeft:`3px solid ${c}` }}>
            <span style={{ background:c+"20", color:c, padding:"2px 10px", borderRadius:"4px", fontSize:"12px", fontFamily:"monospace", minWidth:"44px", textAlign:"center" }}>{p.status}</span>
            <span style={{ color:"#cdd9e5", fontFamily:"monospace", fontSize:"13px" }}>/{p.path}</span>
          </div>
        );
      })}
    </div>
  );

  if (toolId === "techstack") return (
    <div>
      <div style={{ color:"#666", fontSize:"12px", marginBottom:"16px" }}>{data.total_found} technologies detected</div>
      {Object.entries(data.by_category || {}).map(([cat, techs]) => (
        <div key={cat} style={{ marginBottom:"16px" }}>
          <div style={{ color:"#a29bfe", fontSize:"11px", fontFamily:"monospace", marginBottom:"8px", letterSpacing:"1px" }}>── {cat.toUpperCase()} ──</div>
          <div style={{ display:"flex", flexWrap:"wrap", gap:"8px" }}>
            {techs.map(t => (
              <div key={t.tech} style={{ background:"#0d1117", border:"1px solid #a29bfe30", borderRadius:"8px", padding:"8px 14px" }}>
                <div style={{ color:"#cdd9e5", fontSize:"13px", fontWeight:"600" }}>{t.tech}</div>
                {t.version && <div style={{ color:"#666", fontSize:"11px" }}>v{t.version}</div>}
                <div style={{ color:"#444", fontSize:"10px", marginTop:"2px" }}>{t.evidence}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
      {data.total_found === 0 && <div style={{ color:"#666", textAlign:"center", padding:"20px" }}>No technologies detected</div>}
    </div>
  );

  if (toolId === "ipinfo") return (
    <div>
      {[
        ["IP Address", data.resolved_ip],
        ["Country", `${data.geolocation?.country} (${data.geolocation?.countryCode})`],
        ["Region", data.geolocation?.regionName],
        ["City", data.geolocation?.city],
        ["Timezone", data.geolocation?.timezone],
        ["ISP", data.geolocation?.isp],
        ["Organization", data.geolocation?.org],
        ["AS Number", data.geolocation?.as],
        ["Coordinates", `${data.geolocation?.lat}, ${data.geolocation?.lon}`],
        ["Reverse DNS", data.reverse_dns?.join(", ") || "None"],
        ["Proxy/VPN", data.geolocation?.proxy ? "⚠️ YES" : "No"],
        ["Datacenter", data.geolocation?.hosting ? "YES" : "No"],
        ["Mobile", data.geolocation?.mobile ? "Yes" : "No"],
      ].map(([l,v]) => (
        <div key={l} style={{ display:"flex", gap:"12px", padding:"9px 0", borderBottom:"1px solid #111", fontFamily:"monospace", fontSize:"13px" }}>
          <span style={{ color:"#666", minWidth:"150px" }}>{l}</span>
          <span style={{ color: l==="Proxy/VPN" && data.geolocation?.proxy ? "#ff6b35" : "#cdd9e5" }}>{v || "N/A"}</span>
        </div>
      ))}
    </div>
  );

  if (toolId === "audit") {
    const gc = { A:"#00ff88", B:"#74b9ff", C:"#ffe66d", D:"#ff6b35", F:"#ff0040" };
    const g = gc[data.grade] || "#666";
    return (
      <div>
        <div style={{ display:"flex", alignItems:"center", gap:"24px", background:"#0d1117", padding:"20px", borderRadius:"12px", marginBottom:"20px" }}>
          <div style={{ width:"80px", height:"80px", borderRadius:"12px", background:g+"20", border:`2px solid ${g}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:"36px", fontWeight:"700", color:g, fontFamily:"monospace" }}>{data.grade}</div>
          <div>
            <div style={{ color:"#fff", fontSize:"24px", fontWeight:"700" }}>{data.security_score}<span style={{ color:"#666", fontSize:"16px" }}>/100</span></div>
            <div style={{ color:"#666", fontSize:"13px" }}>Security Score</div>
            <div style={{ color:"#ff6b35", fontSize:"13px", marginTop:"4px" }}>{data.total_issues} issues found</div>
          </div>
        </div>
        {data.issues?.length === 0 && (
          <div style={{ color:"#00ff88", textAlign:"center", padding:"20px", fontFamily:"monospace" }}>✓ No security issues detected</div>
        )}
        {data.issues?.map((issue, i) => (
          <div key={i} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", background:"#0d1117", padding:"10px 14px", borderRadius:"6px", marginBottom:"6px", borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#666"}` }}>
            <span style={{ color:"#cdd9e5", fontSize:"13px" }}>{issue.issue}</span>
            <Badge level={issue.severity} />
          </div>
        ))}
      </div>
    );
  }

  return (
    <pre style={{ background:"#0a0a0a", color:"#00ff88", padding:"16px", borderRadius:"8px", fontSize:"12px", overflow:"auto" }}>
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export default function App() {
  const [activeTool, setActiveTool] = useState(null);
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [backendOk, setBackendOk] = useState(null);
  const inputRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then(r => r.json())
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
  }, []);

  const selectTool = useCallback((tool) => {
    setActiveTool(tool);
    setResult(null);
    setError(null);
    setTarget("");
    setTimeout(() => inputRef.current?.focus(), 100);
  }, []);

  const runScan = useCallback(async () => {
    if (!activeTool || !target.trim()) return;
    setLoading(true); setResult(null); setError(null);
    const t0 = Date.now();
    try {
      const r = await fetch(`${API_BASE}/tools/${activeTool.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() })
      });
      const data = await r.json();
      if (!data.success) throw new Error(data.error || "Scan failed");
      setResult(data);
      setHistory(prev => [{ tool: activeTool.name, target: target.trim(), elapsed: ((Date.now()-t0)/1000).toFixed(1), time: new Date().toLocaleTimeString(), ok: true }, ...prev.slice(0,14)]);
    } catch (e) {
      setError(e.message);
      setHistory(prev => [{ tool: activeTool.name, target: target.trim(), elapsed:"—", time: new Date().toLocaleTimeString(), ok: false }, ...prev.slice(0,14)]);
    } finally { setLoading(false); }
  }, [activeTool, target]);

  const S = { minHeight:"100vh", background:"#060a0f", color:"#cdd9e5", fontFamily:"'JetBrains Mono','Fira Code','Courier New',monospace", display:"flex", flexDirection:"column" };

  return (
    <div style={S}>
      {/* HEADER */}
      <header style={{ background:"#0d1117", borderBottom:"1px solid #00ff8820", padding:"0 24px", display:"flex", alignItems:"center", justifyContent:"space-between", height:"60px", position:"sticky", top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap:"12px" }}>
          <div style={{ width:"34px", height:"34px", background:"#00ff8815", border:"1px solid #00ff8840", borderRadius:"8px", display:"flex", alignItems:"center", justifyContent:"center", fontSize:"18px" }}>🔐</div>
          <div>
            <div style={{ color:"#00ff88", fontWeight:"700", fontSize:"15px", letterSpacing:"2px" }}>PENTEST PRO</div>
            <div style={{ color:"#444", fontSize:"10px" }}>Self-Hosted · Vercel · No Paid APIs</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
          <div style={{ width:"8px", height:"8px", borderRadius:"50%", background: backendOk===null?"#ffe66d":backendOk?"#00ff88":"#ff0040", boxShadow: backendOk?"0 0 8px #00ff88":"none" }} />
          <span style={{ fontSize:"12px", color:"#666" }}>{backendOk===null?"Checking...":backendOk?"API Online":"API Offline"}</span>
        </div>
      </header>

      <div style={{ display:"flex", flex:1 }}>
        {/* SIDEBAR */}
        <aside style={{ width:"230px", background:"#0a0f16", borderRight:"1px solid #111827", padding:"16px 0", overflowY:"auto", position:"sticky", top:"60px", height:"calc(100vh - 60px)" }}>
          <div style={{ padding:"0 16px 10px", fontSize:"10px", color:"#444", letterSpacing:"2px" }}>TOOLS ({TOOLS.length})</div>
          {TOOLS.map(tool => (
            <button key={tool.id} onClick={() => selectTool(tool)} style={{ width:"100%", padding:"10px 16px", background:activeTool?.id===tool.id?"#0d1117":"transparent", border:"none", borderLeft:`3px solid ${activeTool?.id===tool.id?tool.color:"transparent"}`, color:activeTool?.id===tool.id?"#fff":"#666", cursor:"pointer", textAlign:"left", display:"flex", alignItems:"center", gap:"10px", transition:"all 0.15s" }}>
              <span style={{ fontSize:"15px" }}>{tool.icon}</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:"12px", fontWeight:activeTool?.id===tool.id?"600":"400" }}>{tool.name}</div>
                <div style={{ fontSize:"10px", color:"#444" }}>{tool.category}</div>
              </div>
              {tool.featured && <span style={{ background:"#e1700520", color:"#e17005", padding:"1px 5px", borderRadius:"4px", fontSize:"9px" }}>ALL</span>}
            </button>
          ))}

          {history.length > 0 && (
            <div style={{ padding:"14px 16px 8px", borderTop:"1px solid #111827", marginTop:"12px" }}>
              <div style={{ fontSize:"10px", color:"#444", letterSpacing:"2px", marginBottom:"10px" }}>HISTORY</div>
              {history.slice(0,7).map((h,i) => (
                <div key={i} style={{ padding:"5px 0", fontSize:"11px", borderBottom:"1px solid #0d1117" }}>
                  <div style={{ display:"flex", justifyContent:"space-between" }}>
                    <span style={{ color:h.ok?"#00ff88":"#ff6b35" }}>{h.ok?"✓":"✗"} {h.tool}</span>
                    <span style={{ color:"#444" }}>{h.elapsed}s</span>
                  </div>
                  <div style={{ color:"#444", fontSize:"10px" }}>{h.target} · {h.time}</div>
                </div>
              ))}
            </div>
          )}
        </aside>

        {/* MAIN */}
        <main style={{ flex:1, padding:"24px", overflowY:"auto" }}>
          {!activeTool ? (
            <div>
              <div style={{ marginBottom:"28px" }}>
                <h1 style={{ fontSize:"22px", fontWeight:"700", color:"#fff", margin:"0 0 6px" }}>Security Toolkit</h1>
                <p style={{ color:"#666", fontSize:"13px", margin:0 }}>Self-hosted on Vercel · No API keys · No paid services · Real live results</p>
              </div>

              {backendOk === false && (
                <div style={{ background:"#ff003010", border:"1px solid #ff003030", borderRadius:"10px", padding:"16px", marginBottom:"24px" }}>
                  <div style={{ color:"#ff0040", fontWeight:"600", marginBottom:"6px" }}>⚠️ API Not Responding</div>
                  <div style={{ color:"#cdd9e5", fontSize:"13px" }}>Make sure Vercel deployment is complete and api/ folder is deployed.</div>
                </div>
              )}

              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))", gap:"16px" }}>
                {TOOLS.map(tool => (
                  <button key={tool.id} onClick={() => selectTool(tool)}
                    style={{ background:"#0d1117", border:`1px solid ${tool.color}20`, borderRadius:"12px", padding:"20px", cursor:"pointer", textAlign:"left", transition:"all 0.2s", gridColumn:tool.featured?"1 / -1":"auto" }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor=tool.color+"60"; e.currentTarget.style.background="#111827"; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor=tool.color+"20"; e.currentTarget.style.background="#0d1117"; }}>
                    <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:"10px" }}>
                      <span style={{ fontSize:"22px", width:"40px", height:"40px", display:"flex", alignItems:"center", justifyContent:"center", background:tool.color+"15", borderRadius:"10px" }}>{tool.icon}</span>
                      <div>
                        <div style={{ color:"#fff", fontWeight:"600", fontSize:"14px" }}>{tool.name}</div>
                        <div style={{ color:tool.color, fontSize:"11px" }}>{tool.category}</div>
                      </div>
                      {tool.featured && <span style={{ marginLeft:"auto", background:tool.color+"20", color:tool.color, padding:"3px 10px", borderRadius:"20px", fontSize:"10px", fontWeight:"600" }}>FEATURED</span>}
                    </div>
                    <p style={{ color:"#666", fontSize:"12px", margin:0, lineHeight:"1.6" }}>{tool.desc}</p>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div>
              <button onClick={() => setActiveTool(null)} style={{ background:"none", border:"none", color:"#666", cursor:"pointer", fontSize:"13px", padding:"0 0 20px", display:"flex", alignItems:"center", gap:"6px" }}>
                ← Dashboard
              </button>

              <div style={{ display:"flex", alignItems:"center", gap:"16px", marginBottom:"24px" }}>
                <span style={{ fontSize:"28px", width:"52px", height:"52px", display:"flex", alignItems:"center", justifyContent:"center", background:activeTool.color+"15", border:`1px solid ${activeTool.color}30`, borderRadius:"12px" }}>{activeTool.icon}</span>
                <div>
                  <h2 style={{ margin:0, color:"#fff", fontSize:"18px", fontWeight:"700" }}>{activeTool.name}</h2>
                  <p style={{ margin:0, color:"#666", fontSize:"13px" }}>{activeTool.desc}</p>
                </div>
              </div>

              <div style={{ background:"#0d1117", border:`1px solid ${activeTool.color}30`, borderRadius:"12px", padding:"20px", marginBottom:"20px" }}>
                <label style={{ color:"#666", fontSize:"10px", letterSpacing:"1px", display:"block", marginBottom:"10px" }}>TARGET</label>
                <div style={{ display:"flex", gap:"10px" }}>
                  <input ref={inputRef} value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key==="Enter" && runScan()}
                    placeholder={activeTool.placeholder}
                    style={{ flex:1, background:"#060a0f", border:`1px solid ${activeTool.color}20`, borderRadius:"8px", padding:"12px 16px", color:"#fff", fontSize:"14px", fontFamily:"monospace", outline:"none" }} />
                  <button onClick={runScan} disabled={loading || !target.trim()}
                    style={{ background:loading||!target.trim()?"#1a1a1a":activeTool.color, color:loading||!target.trim()?"#444":"#000", border:"none", borderRadius:"8px", padding:"12px 24px", cursor:loading||!target.trim()?"not-allowed":"pointer", fontWeight:"700", fontSize:"13px", fontFamily:"monospace", minWidth:"110px", transition:"all 0.2s" }}>
                    {loading ? "RUNNING..." : "RUN SCAN"}
                  </button>
                </div>
              </div>

              {loading && (
                <div style={{ background:"#0d1117", border:`1px solid ${activeTool.color}20`, borderRadius:"12px", padding:"32px", textAlign:"center" }}>
                  <div style={{ color:activeTool.color, fontSize:"14px", marginBottom:"8px" }}>⟳ Scanning {target}...</div>
                  <div style={{ color:"#444", fontSize:"12px" }}>Running {activeTool.name}</div>
                </div>
              )}

              {error && !loading && (
                <div style={{ background:"#ff003010", border:"1px solid #ff003030", borderRadius:"12px", padding:"16px" }}>
                  <div style={{ color:"#ff0040", fontWeight:"600", marginBottom:"6px" }}>✗ Error</div>
                  <div style={{ color:"#cdd9e5", fontSize:"13px", fontFamily:"monospace" }}>{error}</div>
                </div>
              )}

              {result && !loading && (
                <div style={{ background:"#0d1117", border:`1px solid ${activeTool.color}20`, borderRadius:"12px", padding:"20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #111827" }}>
                    <div style={{ color:"#00ff88", fontSize:"13px" }}>✓ Complete — {result.target || target}</div>
                    <div style={{ color:"#444", fontSize:"11px" }}>{new Date(result.timestamp).toLocaleTimeString()}</div>
                  </div>
                  <ResultRenderer toolId={activeTool.id} data={result} />
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
