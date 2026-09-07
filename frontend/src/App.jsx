import { useState, useEffect } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

function RiskBadge({ level }) {
  const colors = {
    HIGH: "#ef4444",
    MEDIUM: "#f59e0b",
    LOW: "#eab308",
    CLEAN: "#22c55e",
  };
  const color = colors[level] || "#6b7280";
  return (
    <span
      className="badge"
      style={{ backgroundColor: color + "22", color: color, borderColor: color }}
    >
      {level}
    </span>
  );
}

function ScoreCard({ title, score, level, reasons }) {
  return (
    <div className="card">
      <div className="card-header">
        <h3>{title}</h3>
        {level && <RiskBadge level={level} />}
      </div>
      {score !== undefined && (
        <div className="score-row">
          <div className="score-bar-bg">
            <div className="score-bar-fill" style={{ width: `${score}%` }}></div>
          </div>
          <span className="score-number">{score}/100</span>
        </div>
      )}
      {reasons && reasons.length > 0 && (
        <ul className="reasons-list">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      {reasons && reasons.length === 0 && <p className="no-issues">No issues detected.</p>}
    </div>
  );
}

function LoginScreen({ onLoginSuccess }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const body = new URLSearchParams();
      body.append("username", username);
      body.append("password", password);

      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Login failed");

      localStorage.setItem("access_token", data.access_token);
      onLoginSuccess(data.access_token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Registration failed");

      setInfo("Account created. You can log in now.");
      setMode("login");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="hero-wrapper">
      <div className="hero-glow"></div>

      <div className="hero-content">
        <span className="hero-badge">Built for AICTE cybersecurity investigations</span>

        <h1 className="hero-headline">
          Catch phishing before it reaches an inbox
        </h1>
        <p className="hero-subtext">
          Header forensics, AI classification, threat intelligence and
          geolocation, combined into one forensic verdict per email.
        </p>

        <div className="hero-login-card">
          <p className="hero-form-label">
            {mode === "login" ? "Sign in to your workspace" : "Create your analyst account"}
          </p>

          <form onSubmit={mode === "login" ? handleLogin : handleRegister}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button type="submit" className="hero-cta" disabled={loading}>
              {loading ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>

          {error && <div className="error-box">⚠ {error}</div>}
          {info && <div className="info-box">{info}</div>}

          <p className="switch-mode">
            {mode === "login" ? (
              <>
                New analyst?{" "}
                <span onClick={() => { setMode("register"); setError(null); }}>Create an account</span>
              </>
            ) : (
              <>
                Already have access?{" "}
                <span onClick={() => { setMode("login"); setError(null); }}>Sign in</span>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

function Dashboard({ token, onLogout }) {
  const [view, setView] = useState("analyze");
  const [cases, setCases] = useState([]);
  const [casesLoading, setCasesLoading] = useState(false);
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_BASE}/api/emails/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      if (response.status === 401) {
        onLogout();
        throw new Error("Session expired. Please log in again.");
      }
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Upload failed");
      }
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchCases = async () => {
    setCasesLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/cases/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 401) {
        onLogout();
        return;
      }
      const data = await response.json();
      setCases(data);
    } catch (err) {
      console.error("Failed to load cases", err);
    } finally {
      setCasesLoading(false);
    }
  };

  const handleDownloadReport = async (caseId) => {
    try {
      const response = await fetch(`${API_BASE}/api/reports/${caseId}/generate`);
      if (!response.ok) throw new Error("Report generation failed");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${caseId}_report.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Could not download report: " + err.message);
    }
  };

  useEffect(() => {
    if (view === "history") fetchCases();
  }, [view]);

  return (
    <div className="app">
      <header className="header">
        <div className="header-top">
          <div>
            <h1>🛡️ Email Threat Intelligence Platform</h1>
            <p className="subtitle">AI-Powered Email Threat Detection & Forensic Analysis</p>
          </div>
          <button className="logout-btn" onClick={onLogout}>Log Out</button>
        </div>
      </header>

      <div className="nav-tabs">
        <button
          className={view === "analyze" ? "nav-tab active" : "nav-tab"}
          onClick={() => setView("analyze")}
        >
          Analyze Email
        </button>
        <button
          className={view === "history" ? "nav-tab active" : "nav-tab"}
          onClick={() => setView("history")}
        >
          Case History
        </button>
      </div>

      {view === "analyze" && (
        <>
          <div className="upload-section">
            <input type="file" accept=".eml" onChange={(e) => setFile(e.target.files[0])} />
            <button onClick={handleUpload} disabled={!file || loading}>
              {loading ? "Analyzing..." : "Analyze Email"}
            </button>
          </div>

          {error && <div className="error-box">⚠ {error}</div>}

          {result && (
            <div className="results">
              <div className="filename-row">
                <strong>Case ID:</strong> {result.case_id} &nbsp;|&nbsp; <strong>File:</strong> {result.filename}
              </div>

              {result.final_verdict && (
                <div className={`verdict-banner verdict-${result.final_verdict.risk_level.toLowerCase()}`}>
                  <div className="verdict-top">
                    <span className="verdict-classification">{result.final_verdict.classification}</span>
                    <span className="verdict-score">{result.final_verdict.final_risk_score}/100</span>
                  </div>
                  <div className="verdict-breakdown">
                    <span>ML: {result.final_verdict.breakdown.ml_score}</span>
                    <span>Header: {result.final_verdict.breakdown.header_risk}</span>
                    <span>NLP: {result.final_verdict.breakdown.nlp_risk}</span>
                    <span>URL: {result.final_verdict.breakdown.url_risk}</span>
                    <span>Attachment: {result.final_verdict.breakdown.attachment_risk}</span>
                    <span>Domain Intel: {result.final_verdict.breakdown.domain_intel_risk}</span>
                  </div>
                  <p className="verdict-note">{result.final_verdict.methodology_note}</p>
                </div>
              )}

              {result.ml_prediction && (
                <div className="card ml-card">
                  <div className="card-header">
                    <h3>🤖 AI Classification</h3>
                    <RiskBadge level={result.ml_prediction.classification === "PHISHING" ? "HIGH" : "CLEAN"} />
                  </div>
                  <p className="ml-classification">
                    {result.ml_prediction.classification} — {result.ml_prediction.confidence}% confidence
                  </p>
                  {result.ml_prediction.top_contributing_words.length > 0 && (
                    <div className="word-tags">
                      {result.ml_prediction.top_contributing_words.map((w, i) => (
                        <span key={i} className="word-tag">{w}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="grid">
                <ScoreCard
                  title="Header & Authentication"
                  score={result.header_analysis?.header_risk_score}
                  level={result.header_analysis?.risk_level}
                  reasons={result.header_analysis?.reasons}
                />
                <ScoreCard
                  title="NLP Phishing Language"
                  score={result.nlp_analysis?.nlp_risk_score}
                  level={result.nlp_analysis?.risk_level}
                  reasons={result.nlp_analysis?.reasons}
                />
              </div>

              {result.url_analysis?.length > 0 && (
                <div className="card">
                  <h3>URL Analysis</h3>
                  {result.url_analysis.map((u, i) => (
                    <div key={i} className="sub-item">
                      <div className="card-header">
                        <span className="mono">{u.url}</span>
                        <RiskBadge level={u.risk_level} />
                      </div>
                      <ul className="reasons-list">
                        {u.reasons.map((r, j) => (
                          <li key={j}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              {result.attachment_analysis?.length > 0 && (
                <div className="card">
                  <h3>Attachments</h3>
                  {result.attachment_analysis.map((a, i) => (
                    <div key={i} className="sub-item">
                      <div className="card-header">
                        <span className="mono">{a.filename}</span>
                        <RiskBadge level={a.risk_level} />
                      </div>
                      <ul className="reasons-list">
                        {a.reasons.map((r, j) => (
                          <li key={j}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              {result.ip_analysis?.length > 0 && (
                <div className="card">
                  <h3>IP Addresses</h3>
                  {result.ip_analysis.map((ip, i) => (
                    <div key={i} className="ip-row">
                      <span className="mono">{ip.ip}</span>
                      <span className="ip-type">{ip.ip_type}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.threat_intelligence?.domain_check && (
                <div className="card">
                  <h3>Threat Intelligence — Domain</h3>
                  <div className="card-header">
                    <span className="mono">{result.threat_intelligence.domain_check.domain}</span>
                    <span className="source-tag">{result.threat_intelligence.domain_check.source}</span>
                  </div>
                  {result.threat_intelligence.domain_check.reasons.length > 0 ? (
                    <ul className="reasons-list">
                      {result.threat_intelligence.domain_check.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="no-issues">No suspicious domain characteristics found (local heuristics only).</p>
                  )}
                </div>
              )}

              {result.threat_intelligence?.ip_reputation?.length > 0 && (
                <div className="card">
                  <h3>Threat Intelligence — IP Reputation</h3>
                  {result.threat_intelligence.ip_reputation.map((ip, i) => (
                    <div key={i} className="sub-item">
                      <div className="card-header">
                        <span className="mono">{ip.ip}</span>
                        <span className="source-tag">{ip.source}</span>
                      </div>
                      {ip.note && <p className="no-issues">{ip.note}</p>}
                      {ip.abuse_confidence_score !== null && ip.abuse_confidence_score !== undefined && (
                        <p>Abuse confidence: {ip.abuse_confidence_score}% ({ip.total_reports} reports)</p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {result.geo_intelligence?.length > 0 && (
                <div className="card">
                  <h3>🌍 GeoLocation Intelligence</h3>
                  {result.geo_intelligence.map((geo, i) => (
                    <div key={i} className="sub-item">
                      <div className="card-header">
                        <span className="mono">{geo.ip}</span>
                        <span className="source-tag">{geo.source}</span>
                      </div>
                      {geo.note ? (
                        <p className="no-issues">{geo.note}</p>
                      ) : (
                        <>
                          <p>
                            {geo.city ? `${geo.city}, ` : ""}
                            {geo.region ? `${geo.region}, ` : ""}
                            {geo.country}
                          </p>
                          <p className="mono" style={{ fontSize: "0.75rem" }}>
                            ISP: {geo.isp} | Timezone: {geo.timezone}
                          </p>
                          <p className="accuracy-note">{geo.accuracy_note}</p>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {view === "history" && (
        <div className="history-section">
          {casesLoading && <p className="no-issues">Loading cases...</p>}
          {!casesLoading && cases.length === 0 && (
            <p className="no-issues">No cases analyzed yet. Go to "Analyze Email" to get started.</p>
          )}
          {cases.map((c) => (
            <div key={c.id} className="card case-row">
              <div className="case-row-main">
                <div>
                  <div className="case-id">{c.case_id}</div>
                  <div className="case-subject">{c.subject || "(no subject)"}</div>
                  <div className="case-sender mono">{c.sender || "(unknown sender)"}</div>
                </div>
                <div className="case-meta">
                  <RiskBadge level={c.threat_level || "CLEAN"} />
                  <span className="case-status">{c.status}</span>
                  <span className="case-date">
                    {c.created_at ? new Date(c.created_at).toLocaleString() : ""}
                  </span>
                  <button className="download-btn" onClick={() => handleDownloadReport(c.case_id)}>
                    📄 Download Report
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function App() {
  const [token, setToken] = useState(null);
  const [checkedStorage, setCheckedStorage] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("access_token");
    if (saved) setToken(saved);
    setCheckedStorage(true);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    setToken(null);
  };

  if (!checkedStorage) return null;

  return token ? (
    <Dashboard token={token} onLogout={handleLogout} />
  ) : (
    <LoginScreen onLoginSuccess={setToken} />
  );
}

export default App;