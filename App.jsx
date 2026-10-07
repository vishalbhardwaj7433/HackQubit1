import { useRef, useState } from "react";
import "./App.css";


const threats = [
  { icon: "↗", title: "Phishing links", text: "Lookalike websites imitate trusted brands to capture payment or sign-in details.", tip: "Check the full domain, not just the brand name in the URL." },
  { icon: "▣", title: "Fake payment pages", text: "Fraudulent checkout pages can mimic familiar payment flows and apps.", tip: "Open payment apps directly; never trust an unexpected payment page." },
  { icon: "✦", title: "Fake rewards & cashback", text: "Surprise prizes and cashback offers are often used to lure people into sharing details.", tip: "Treat unexpected rewards as suspicious until verified with the official provider." },
  { icon: "◎", title: "Impersonation scams", text: "Scammers pose as support staff, merchants, or people you know.", tip: "Verify requests using a trusted contact method you already have." },
  { icon: "▦", title: "Malicious QR codes", text: "A QR code can send you to an unknown website or a payment request.", tip: "Review the destination and recipient in your UPI app before approving." },
  { icon: "!", title: "Urgent verification", text: "Threats of account suspension create pressure to act before thinking.", tip: "Banks and payment apps will never ask you to reveal your UPI PIN or OTP." },
];

const steps = [
  { number: "01", icon: "↗", title: "Submit", text: "Paste a link, check a UPI ID, or add a QR image for a demo review." },
  { number: "02", icon: "⌕", title: "Analyze", text: "A local ruleset looks for common suspicious words and URL patterns." },
  { number: "03", icon: "◉", title: "Risk score", text: "See a simple score, contributing indicators, and a clear next step." },
  { number: "04", icon: "✓", title: "Protect", text: "Pause, verify through official channels, and only pay when confident." },
];

const safetyTips = [
  ["⌑", "Never share your UPI PIN", "Your PIN is only for authorizing payments in your UPI app."],
  ["⌁", "Keep OTPs private", "No legitimate support agent needs you to read them an OTP."],
  ["◎", "Verify the receiver", "Check the name and amount shown in your app before approving."],
  ["↗", "Inspect every URL", "Watch for misspellings, strange domains, and shortened links."],
  ["✦", "Question surprise rewards", "Unexpected cashback links are a common way to create urgency."],
  ["✓", "Pause before paying", "A moment to verify can prevent a costly mistake."],
];

function Brand({ compact = false }) {
  return (
    <a className={`brand${compact ? " brand-compact" : ""}`} href="#home" aria-label="UPI Shield home">
      <span className="brand-mark"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3.4 26 7v8.1c0 6.2-4.1 11.2-10 13.5C10.1 26.3 6 21.3 6 15.1V7l10-3.6Z" /><path d="m11.7 15.7 2.8 2.8 6-6.2" /></svg></span>
      <span>UPI<span className="brand-accent">Shield</span></span>
    </a>
  );
}

function DemoPill({ children = "Frontend demo" }) {
  return <span className="demo-pill"><span />{children}</span>;
}

function SectionHeading({ eyebrow, title, description, align = "center" }) {
  return (
    <div className={`section-heading section-heading-${align}`}>
      <span className="eyebrow">{eyebrow}</span>
      <h2>{title}</h2>
      {description && <p>{description}</p>}
    </div>
  );
}

function riskFromText(value) {
  const text = value.toLowerCase();
  const reasons = [];
  let score = 8;
  const patterns = [
    { test: /bit\.ly|tinyurl|t\.co|shorturl|cutt\.ly|is\.gd/, score: 32, reason: "Shortened link hides its final destination" },
    { test: /verify|verification|account.?suspend|blocked|urgent|immediately|act.?now|expire/, score: 25, reason: "Urgent or account-verification wording" },
    { test: /cashback|cash.?back|reward|winner|claim|prize|free.?gift|bonus/, score: 28, reason: "Unexpected reward or cashback wording" },
    { test: /login|sign.?in|password|pin|otp|bank.?detail/, score: 24, reason: "Sensitive account or payment language" },
    { test: /paytm-[a-z0-9-]+\.|phonepe-[a-z0-9-]+\.|gpay-[a-z0-9-]+\.|secure[-.]?upi|upi[-.]?secure/, score: 38, reason: "Possible brand-lookalike or suspicious domain" },
    { test: /[a-z0-9-]+\.(xyz|top|click|work|rest|buzz)(\/|$|[?#])/, score: 24, reason: "Uncommon top-level domain in a payment context" },
    { test: /xn--|@/, score: 28, reason: "URL contains a potentially deceptive character pattern" },
  ];

  patterns.forEach(({ test, score: points, reason }) => {
    if (test.test(text)) {
      score += points;
      reasons.push(reason);
    }
  });

  let status = "Safe";
  if (score >= 70) status = "High Risk";
  else if (score >= 35) status = "Suspicious";

  if (reasons.length === 0) reasons.push("No common demo warning patterns were found in this input.");
  const action = status === "High Risk"
    ? "Do not open this link or approve a payment. Verify with the organization through its official app or website."
    : status === "Suspicious"
      ? "Pause and verify the destination independently before opening or paying."
      : "No common warning pattern was detected. This demo cannot confirm that the link is safe.";
  return { score: Math.min(score, 99), status, reasons, action };
}

function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [upi, setUpi] = useState("");
  const [upiResult, setUpiResult] = useState(null);
  const [upiError, setUpiError] = useState("");
  const [qrFile, setQrFile] = useState(null);
  const [qrResult, setQrResult] = useState(null);
  const [qrScanning, setQrScanning] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [report, setReport] = useState({ url: "", type: "", description: "" });
  const [reportError, setReportError] = useState("");
  const [reportSuccess, setReportSuccess] = useState(false);
  const qrInput = useRef(null);
  const totalScans = scanHistory.length;
  const safeScans = scanHistory.filter((scan) => scan.status === "Safe").length;
  const warningScans = scanHistory.filter((scan) => scan.status !== "Safe").length;
  const threatScans = scanHistory.filter((scan) => scan.status === "High Risk").length;
  const suspiciousScans = scanHistory.filter((scan) => scan.status === "Suspicious").length;
  const percentage = (count) => totalScans === 0 ? 0 : Math.round((count / totalScans) * 1000) / 10;

  const scanUrl = (event) => {
    event.preventDefault();
    const value = url.trim();
    if (!value) {
      setScanError("Enter a URL to run the demo analysis.");
      setScanResult(null);
      return;
    }
    const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`;
    try {
      const parsed = new URL(candidate);
      if (!parsed.hostname.includes(".") || parsed.hostname.length < 4) throw new Error("Invalid host");
    } catch {
      setScanError("Enter a valid website address, such as example.com.");
      setScanResult(null);
      return;
    }
    setScanError("");
    setScanning(true);
    setScanResult(null);
    window.setTimeout(() => {
      const result = riskFromText(candidate);
      setScanResult(result);
      setScanHistory((items) => [{
        url: value,
        status: result.status,
        score: result.score,
        time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      }, ...items]);
      setScanning(false);
    }, 950);
  };

  const checkUpi = (event) => {
    event.preventDefault();
    const value = upi.trim();
    if (!/^[\w.-]{2,256}@[a-zA-Z][a-zA-Z0-9.-]{1,63}$/.test(value)) {
      setUpiError("Enter a UPI ID in a format like name@bank.");
      setUpiResult(null);
      return;
    }
    setUpiError("");
    const demo = riskFromText(value.replace("@", "."));
    setUpiResult({
      status: demo.status === "Safe" ? "Format looks valid" : demo.status,
      explanation: demo.reasons[0] === "No common demo warning patterns were found in this input."
        ? "The ID matches a basic UPI ID format. This demo does not verify whether it exists or who owns it."
        : `${demo.reasons.join("; ")}. This pattern check cannot verify the account.`,
      recommendation: "Confirm the recipient name shown inside your trusted UPI app before approving any payment.",
      risky: demo.status !== "Safe",
    });
  };

  const analyzeQr = (file) => {
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setQrFile(null);
      setQrResult({ error: "Choose an image file to continue." });
      return;
    }
    setQrFile(file);
    setQrResult(null);
    setQrScanning(true);
    window.setTimeout(() => {
      setQrScanning(false);
      setQrResult({
        demo: true,
        status: "QR image received",
        explanation: "This prototype does not decode QR contents yet, so no UPI destination was extracted or verified.",
        recommendation: "Only scan QR codes from people or merchants you trust. Check the destination and recipient in your UPI app before paying.",
      });
    }, 1000);
  };

  const handleReport = (event) => {
    event.preventDefault();
    if (!report.url.trim() || !report.type || report.description.trim().length < 12) {
      setReportError("Complete every field. Description must be at least 12 characters.");
      setReportSuccess(false);
      return;
    }
    try {
      const parsed = new URL(/^https?:\/\//i.test(report.url.trim()) ? report.url.trim() : `https://${report.url.trim()}`);
      if (!parsed.hostname.includes(".")) throw new Error("Invalid URL");
    } catch {
      setReportError("Enter a valid suspicious URL.");
      setReportSuccess(false);
      return;
    }
    setReportError("");
    setReportSuccess(true);
    setReport({ url: "", type: "", description: "" });
  };

  const navItems = [
    ["Home", "#home"], ["Scanner", "#scanner"], ["UPI Checker", "#upi-checker"],
    ["Dashboard", "#dashboard"], ["How It Works", "#how-it-works"], ["Threat Intel", "#threats"],
  ];
  const closeMenu = () => setMenuOpen(false);

  return (
    <div className="app">
      <nav className="navbar">
        <Brand />
        <div className={`nav-links${menuOpen ? " nav-links-open" : ""}`}>
          {navItems.map(([label, href]) => <a key={href} href={href} onClick={closeMenu}>{label}</a>)}
        </div>
        <a className="nav-report" href="#report" onClick={closeMenu}>Report Threat <span>↗</span></a>
        <button className={`menu-toggle${menuOpen ? " menu-toggle-open" : ""}`} onClick={() => setMenuOpen(!menuOpen)} aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"} aria-expanded={menuOpen}>
          <span /><span /><span />
        </button>
      </nav>

      <main>
        <section className="hero" id="home">
          <div className="hero-grid-lines" />
          <div className="hero-content">
            <div className="hero-kicker"><span className="live-dot" /> YOUR FIRST LINE OF PAYMENT DEFENSE</div>
            <h1>Detect fake payment pages <span>before you pay.</span></h1>
            <p>Pause before you pay. UPI Shield helps you spot common warning signs in suspicious links and payment destinations — before you take the next step.</p>
            <div className="hero-actions">
              <a href="#scanner" className="button button-primary">Scan a link <span>↗</span></a>
              <a href="#how-it-works" className="button button-quiet"><span className="play-icon">▶</span> Explore security</a>
            </div>
            <div className="demo-note"><span>ⓘ</span> Hackathon prototype · Local demo analysis only</div>
            <div className="hero-stats">
              <div><strong>{totalScans.toLocaleString()}</strong><small>Links scanned <i>this session</i></small></div>
              <div><strong>{safeScans.toLocaleString()}</strong><small>Safe links <i>this session</i></small></div>
              <div><strong>{warningScans.toLocaleString()}</strong><small>Warnings <i>this session</i></small></div>
            </div>
          </div>
          <div className="hero-visual" aria-label="UPI Shield demo security illustration">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" />
            <div className="orbit-node node-one">⌁</div><div className="orbit-node node-two">✓</div><div className="orbit-node node-three">✦</div>
            <div className="shield-halo" />
            <div className="shield-illustration">
              <svg viewBox="0 0 190 210" role="img" aria-label="Shield">
                <defs><linearGradient id="shieldGradient" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stopColor="#89f6ff" /><stop offset=".48" stopColor="#26c6ec" /><stop offset="1" stopColor="#4267ff" /></linearGradient></defs>
                <path className="shield-shadow" d="M95 9 165 34v57c0 48-29 88-70 110C54 179 25 139 25 91V34L95 9Z" />
                <path className="shield-face" d="M95 9 165 34v57c0 48-29 88-70 110C54 179 25 139 25 91V34L95 9Z" />
                <path className="shield-check" d="m63 99 21 21 45-48" />
                <path className="shield-glint" d="M48 48 95 31" />
              </svg>
            </div>
            <div className="visual-tag tag-top"><span className="tag-pulse" /> DEMO ENGINE <b>READY</b></div>
            <div className="visual-tag tag-bottom"><span>◉</span> THINK BEFORE YOU TAP</div>
            <div className="visual-caption">An extra moment.<br /><strong>A safer payment.</strong></div>
          </div>
        </section>

        <div className="trust-strip"><span>BUILT FOR SAFER DIGITAL PAYMENTS</span><i /> <span>EDUCATIONAL PROJECT</span><i /> <span>NOT A BANK OR PAYMENT PROVIDER</span></div>

        <section className="section scanner-section" id="scanner">
          <SectionHeading eyebrow="01 / LINK CHECK" title="A second look before you click." description="Paste a suspicious URL to see how the local demo rules flag common scam patterns." />
          <div className="scanner-layout">
            <div className="glass-panel scanner-panel">
              <div className="panel-topline"><div className="panel-title"><span className="panel-icon">⌕</span><div><strong>Smart URL scanner</strong><small>Pattern-based demo analysis</small></div></div><DemoPill /></div>
              <form onSubmit={scanUrl} noValidate>
                <label className="input-label" htmlFor="url-input">Website or payment link</label>
                <div className="input-row">
                  <span className="input-prefix">↗</span>
                  <input id="url-input" type="text" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="Paste a link, e.g. example.com/pay" autoComplete="url" />
                  <button className="button button-primary scan-button" type="submit" disabled={scanning}>{scanning ? <><span className="spinner" /> Scanning</> : <>Analyze link <span>→</span></>}</button>
                </div>
                <div className="form-footnote"><span>ⓘ</span> Demo only — no link is opened or sent to a server.</div>
                {scanError && <p className="form-error" role="alert">{scanError}</p>}
              </form>
              {scanning && <div className="scan-progress"><span /><p>Checking the URL against common demo patterns…</p></div>}
              {scanResult && <div className={`scan-result risk-${scanResult.status.toLowerCase().replace(" ", "-")}`} aria-live="polite">
                <div className="result-score"><div className="score-ring" style={{ "--score": `${scanResult.score * 3.6}deg` }}><span>{scanResult.score}<small>/100</small></span></div><small>DEMO RISK SCORE</small></div>
                <div className="result-details"><div className="result-status"><strong>{scanResult.status}</strong><span>Demo Analysis</span></div><ul>{scanResult.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul><p className="result-recommendation"><b>Recommended action</b>{scanResult.action}</p></div>
              </div>}
            </div>
            <aside className="scanner-side">
              <div className="side-heading"><span className="eyebrow">RECENT ACTIVITY</span><span className="history-tag">THIS SESSION</span></div>
              <div className="history-list">
                {scanHistory.length === 0 && <p className="history-empty">No scans yet. Your completed link scans will appear here.</p>}
                {scanHistory.map((item, index) => <div className="history-item" key={`${item.url}-${index}`}>
                  <span className={`history-status status-${item.status.toLowerCase().replace(" ", "-")}`} />
                  <div className="history-url"><strong>{item.url}</strong><small>{item.time}</small></div>
                  <span className={`history-score status-text-${item.status.toLowerCase().replace(" ", "-")}`}>{item.score}</span>
                </div>)}
              </div>
              <div className="side-callout"><span>✳</span><p><strong>Never enter sensitive details</strong>Your PIN, password and OTP should never be shared with a link or a person.</p></div>
            </aside>
          </div>
        </section>

        <section className="section checkers-section" id="upi-checker">
          <SectionHeading eyebrow="02 / DESTINATION CHECK" title="Check where your money is going." description="A basic format and pattern check can help you pause — but only your payment app can show the verified recipient." />
          <div className="checker-grid">
            <div className="glass-panel checker-card">
              <div className="checker-card-head"><span className="checker-icon">◎</span><DemoPill /></div>
              <h3>UPI ID checker</h3>
              <p>Check a UPI ID format and common suspicious patterns. This does not look up real accounts.</p>
              <form onSubmit={checkUpi} noValidate>
                <label className="input-label" htmlFor="upi-input">UPI ID</label>
                <div className="inline-form"><input id="upi-input" value={upi} onChange={(event) => setUpi(event.target.value)} placeholder="name@bank" autoComplete="off" /><button className="button button-primary" type="submit">Check <span>→</span></button></div>
                {upiError && <p className="form-error" role="alert">{upiError}</p>}
              </form>
              {upiResult && <div className={`checker-result ${upiResult.risky ? "checker-risky" : ""}`} aria-live="polite"><strong>{upiResult.status}</strong><p>{upiResult.explanation}</p><small>Safety tip: {upiResult.recommendation}</small></div>}
              <div className="checker-disclaimer">Frontend demo verification · No bank/payment API connected</div>
            </div>
            <div className="glass-panel checker-card qr-card">
              <div className="checker-card-head"><span className="checker-icon qr-icon">▦</span><DemoPill>Demo QR Analysis</DemoPill></div>
              <h3>QR code checker</h3>
              <p>Add an image for a demo upload flow. QR decoding and destination verification are not connected.</p>
              <div className={`dropzone${dragging ? " dropzone-active" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); analyzeQr(event.dataTransfer.files[0]); }}>
                <input ref={qrInput} type="file" accept="image/*" className="visually-hidden" onChange={(event) => analyzeQr(event.target.files[0])} aria-label="Upload a QR code image" />
                <span className="dropzone-symbol">▦</span><strong>{qrFile ? qrFile.name : "Drop a QR image here"}</strong><small>PNG or JPG · Image stays in this browser</small>
                <button type="button" className="button button-outline" onClick={() => qrInput.current?.click()}>Upload QR image <span>↑</span></button>
              </div>
              {qrScanning && <div className="qr-state"><span className="spinner" /> Preparing demo analysis…</div>}
              {qrResult && <div className={`checker-result ${qrResult.error ? "checker-risky" : ""}`} aria-live="polite"><strong>{qrResult.error || qrResult.status}</strong>{!qrResult.error && <><p>{qrResult.explanation}</p><small>Safety recommendation: {qrResult.recommendation}</small></>}</div>}
              <div className="checker-disclaimer">No QR contents are decoded or verified in this prototype.</div>
            </div>
          </div>
        </section>

        <section className="section dashboard-section" id="dashboard">
          <SectionHeading eyebrow="03 / SECURITY OVERVIEW" title="A clearer picture of risk." description="Your link scans and their results from this session. Counts update when a demo scan completes." />
          <div className="dashboard">
            <div className="dashboard-top"><div><div className="dashboard-title"><span className="dashboard-mark">◈</span><div><strong>Security overview</strong><small>Current session · Local demo analysis</small></div></div></div><span className="dashboard-status"><i /> Demo environment</span></div>
            <div className="metric-grid">
              <div className="metric-card"><span>Total scans</span><strong>{totalScans.toLocaleString()}</strong><small>Completed this session</small></div>
              <div className="metric-card"><span>Safe links</span><strong>{safeScans.toLocaleString()}</strong><small>{percentage(safeScans)}% of scans</small></div>
              <div className="metric-card"><span>Warnings</span><strong>{warningScans.toLocaleString()}</strong><small>Suspicious or high-risk</small></div>
              <div className="metric-card"><span>Threats</span><strong>{threatScans.toLocaleString()}</strong><small>High-risk results</small></div>
            </div>
            <div className="dashboard-lower">
              <div className="chart-panel">
                <div className="subpanel-heading"><div><strong>Risk distribution</strong><small>Results from this session</small></div><span>{totalScans.toLocaleString()} total</span></div>
                <div className="distribution-row"><div><span><i className="dot-safe" /> Safe ({safeScans})</span><strong>{percentage(safeScans)}%</strong></div><div className="bar-track"><span className="bar-safe" style={{ width: `${percentage(safeScans)}%` }} /></div></div>
                <div className="distribution-row"><div><span><i className="dot-suspicious" /> Suspicious ({suspiciousScans})</span><strong>{percentage(suspiciousScans)}%</strong></div><div className="bar-track"><span className="bar-suspicious" style={{ width: `${percentage(suspiciousScans)}%` }} /></div></div>
                <div className="distribution-row"><div><span><i className="dot-high" /> High risk ({threatScans})</span><strong>{percentage(threatScans)}%</strong></div><div className="bar-track"><span className="bar-high" style={{ width: `${percentage(threatScans)}%` }} /></div></div>
                <div className="threat-total"><span>Threats flagged this session</span><strong>{threatScans.toLocaleString()}</strong></div>
              </div>
              <div className="table-panel">
                <div className="subpanel-heading"><div><strong>Scan history</strong><small>Actual scans from this session</small></div><a href="#scanner">Scan a link ↗</a></div>
                <div className="scan-table">
                  {scanHistory.length === 0 && <p className="history-empty">No scans yet. Complete a link scan to build your history.</p>}
                  {scanHistory.map((item, index) => <div className="table-row" key={`${item.url}-table-${index}`}><div className="table-domain"><span className={`history-status status-${item.status.toLowerCase().replace(" ", "-")}`} /><span>{item.url}</span></div><span className={`table-badge table-${item.status.toLowerCase().replace(" ", "-")}`}>{item.status}</span><strong>{item.score}</strong></div>)}
                </div>
                <div className="table-footnote">Demo pattern checks only · Not threat intelligence</div>
              </div>
            </div>
          </div>
        </section>

        <section className="section threats-section" id="threats">
          <SectionHeading eyebrow="04 / THREAT INTELLIGENCE" title="Know the tricks. Spot the signs." description="Common scam patterns to watch for — shared for awareness and safer online payments." />
          <div className="threat-grid">
            {threats.map((item, index) => <article className="threat-card" key={item.title}><span className="threat-index">0{index + 1}</span><span className="threat-icon">{item.icon}</span><h3>{item.title}</h3><p>{item.text}</p><div className="threat-tip"><strong>SAFETY TIP</strong><span>{item.tip}</span></div></article>)}
          </div>
        </section>

        <section className="section how-section" id="how-it-works">
          <SectionHeading eyebrow="05 / THE PROCESS" title="Four steps. One safer habit." description="A simple pause can help you make a more informed payment decision." />
          <div className="steps-grid">
            {steps.map((step) => <article className="step-card" key={step.number}><div className="step-top"><span className="step-number">{step.number}</span><span className="step-icon">{step.icon}</span></div><h3>{step.title}</h3><p>{step.text}</p><span className="step-line" /></article>)}
          </div>
        </section>

        <section className="section report-section" id="report">
          <div className="report-intro"><span className="eyebrow">06 / COMMUNITY SAFETY</span><h2>See something suspicious?<br /><span>Speak up.</span></h2><p>Share a suspected threat with this local demo form. Your report is not sent to a security team or stored on a server.</p><div className="report-promise"><span>◌</span> Reports stay in this demo session</div></div>
          <div className="glass-panel report-card">
            <div className="report-card-heading"><div><strong>Report a threat</strong><small>Help raise awareness</small></div><span className="report-icon">↗</span></div>
            {reportSuccess ? <div className="report-success" role="status"><span>✓</span><h3>Report received</h3><p>Thanks for helping raise awareness. This confirmation is local to the demo; nothing was transmitted or stored.</p><button className="button button-outline" onClick={() => setReportSuccess(false)}>Submit another report</button></div> : <form onSubmit={handleReport} noValidate>
              <label className="input-label" htmlFor="report-url">Suspicious URL</label><input id="report-url" className="field-input" value={report.url} onChange={(event) => setReport({ ...report, url: event.target.value })} placeholder="https://suspicious-site.com" />
              <label className="input-label" htmlFor="threat-type">Threat type</label><select id="threat-type" className="field-input" value={report.type} onChange={(event) => setReport({ ...report, type: event.target.value })}><option value="">Select a threat type</option><option>Phishing link</option><option>Fake payment page</option><option>Fake cashback / reward</option><option>Impersonation scam</option><option>Malicious QR code</option><option>Urgent verification</option><option>Other suspicious activity</option></select>
              <label className="input-label" htmlFor="report-description">What happened?</label><textarea id="report-description" className="field-input" value={report.description} onChange={(event) => setReport({ ...report, description: event.target.value })} placeholder="Describe what made this seem suspicious…" rows="3" />
              {reportError && <p className="form-error" role="alert">{reportError}</p>}
              <button className="button button-primary report-submit" type="submit">Submit demo report <span>→</span></button><small className="report-disclaimer">Please do not include personal, banking, or payment information.</small>
            </form>}
          </div>
        </section>

        <section className="section safety-section" id="safety-tips">
          <SectionHeading eyebrow="07 / STAY ONE STEP AHEAD" title="Small habits. Stronger safety." description="Keep these simple UPI safety practices in mind every time you pay." />
          <div className="safety-grid">{safetyTips.map(([icon, title, text]) => <article className="safety-item" key={title}><span>{icon}</span><div><h3>{title}</h3><p>{text}</p></div></article>)}</div>
          <div className="safety-banner"><span className="banner-shield">✓</span><div><strong>When in doubt, don't pay.</strong><p>Close the link and contact the organization using its official website or app.</p></div><a href="#scanner">Check a link <span>↗</span></a></div>
        </section>
      </main>

      <footer className="footer">
        <div className="footer-main"><div className="footer-brand"><Brand /><p>A cybersecurity hackathon prototype built to encourage safer digital payments and smarter clicks.</p><DemoPill>Hackathon prototype</DemoPill></div><div className="footer-links"><div><strong>Explore</strong><a href="#home">Home</a><a href="#scanner">URL scanner</a><a href="#upi-checker">UPI & QR checker</a><a href="#dashboard">Dashboard</a></div><div><strong>Learn</strong><a href="#how-it-works">How it works</a><a href="#threats">Threat intelligence</a><a href="#safety-tips">Safety tips</a><a href="#report">Report a threat</a></div></div></div>
        <div className="footer-disclaimer"><span>IMPORTANT DISCLAIMER</span><p>UPI Shield is a frontend demo only. It does not provide real-time fraud detection, verify bank or payment accounts, decode QR codes, or guarantee that any link is safe. Always verify payment details in your official UPI app.</p></div>
        <div className="footer-bottom"><span>© 2026 UPI Shield · Cybersecurity Hackathon Project</span><span>Built for awareness. Not a financial service.</span></div>
      </footer>
    </div>
  );
}

export default App;
