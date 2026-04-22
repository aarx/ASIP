import ChatAssistant from "./components/ChatAssistant";
import React, { useEffect, useState } from "react";
import { getSummary, getSources, getHttpStatus, getRiskLeaderboard } from "./services/api";
import { Grid, Card, CardContent, Typography, TextField } from "@mui/material";
import SourceChart from "./components/SourceChart";
import HttpStatusChart from "./components/HttpStatusChart";
import { getProviders, getTech } from "./services/api";
import ProviderChart from "./components/ProviderChart";
import TechChart from "./components/TechChart";
import { getExposureDrift } from "./services/api";
import HygieneChart from "./components/HygieneChart";
import InvestigationTable from "./components/InvestigationTable";
import ShadowChart from "./components/ShadowChart";

function App() {

  const [summary, setSummary] = useState(null);
  const [sources, setSources] = useState(null);
  const [httpStatus, setHttpStatus] = useState(null);
  const [risk, setRisk] = useState(null);
  const [providers, setProviders] = useState([]);
  const [tech, setTech] = useState(null);
  const [drift, setDrift] = useState(null);
  const [investigationFilter, setInvestigationFilter] = useState(null);
  const [findings, setFindings] = useState([]);
  const [sensitive, setSensitive] = useState([]);
  const [certs, setCerts] = useState([]);
  const [shadowProvider, setShadowProvider] = useState(null);
  const [nonWebSummary, setNonWebSummary] = useState(null);
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState([]);
  const [showRisk, setShowRisk] = useState(false);
  const [showSensitive, setShowSensitive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showChat, setShowChat] = useState(false);

  const downloadCSV = async () => {
    window.open("http://localhost:8555/export", "_blank");
  };

  const formatResponse = (data) => {
    if (Array.isArray(data)) {
      return data.map((d) => d.domain || JSON.stringify(d)).join("\n");
    }
    if (data.domain) {
      return `
Domain: ${data.domain}
IP: ${data.ip}
Risk: ${data.risk_score}
Reason: ${data.reasons}
`;
    }
    return JSON.stringify(data, null, 2);
  };

  const sendChat = async () => {
    if (!chatInput) return;
    const userMsg = { type: "user", text: chatInput };
    setChatHistory((prev) => [...prev, userMsg]);
    setChatInput("");
    setLoading(true);
    try {
      const res = await fetch(`http://localhost:8555/chat?q=${encodeURIComponent(chatInput)}`);
      const data = await res.json();
      const botMsg = { type: "bot", text: formatResponse(data) };
      setChatHistory((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  useEffect(() => {
    async function fetchData() {
      const summaryData = await getSummary();
      const sourceData = await getSources();
      const httpData = await getHttpStatus();
      const riskData = await getRiskLeaderboard();
      const providerData = await getProviders();
      const techData = await getTech();
      const driftData = await getExposureDrift();
      const findingsData = await fetch("http://localhost:8555/findings").then(r => r.json());
      const sensitiveData = await fetch("http://localhost:8555/sensitive-exposure").then(res => res.json());
      const certData = await fetch("http://localhost:8555/cert-expiry").then(r => r.json());
      const shadowProviderData = await fetch("http://localhost:8555/shadow-by-provider").then(r => r.json());
      const nonWebSummaryData = await fetch("http://localhost:8555/non-web-summary").then(r => r.json());

      setFindings(findingsData);
      setSummary(summaryData);
      setSources(sourceData);
      setHttpStatus(httpData);
      setRisk(riskData);
      setProviders(providerData);
      setTech(techData);
      setDrift(driftData);
      setSensitive(sensitiveData);
      setCerts(certData);
      setShadowProvider(shadowProviderData);
      setNonWebSummary(nonWebSummaryData);
    }
    fetchData();
  }, []);

  return (
    <div style={{ padding: "40px", background: "#f5f7fa", minHeight: "100vh" }}>

      <Typography variant="h4" gutterBottom>
        External Attack Surface Dashboard
      </Typography>

      <button
        onClick={downloadCSV}
        style={{
          marginBottom: "20px",
          padding: "10px 15px",
          background: "#1976d2",
          color: "white",
          border: "none",
          borderRadius: "5px",
          cursor: "pointer"
        }}
      >
        ⬇ Download CSV
      </button>

      {summary && (
        <Grid container spacing={3} style={{ marginTop: "20px" }}>

          {/* KPI ROW */}
          <Grid container spacing={3}>
            {[
              ["Total Domains", summary.total_domains],
              ["Live Domains", summary.live_domains],
              ["Known Domains", summary.known_domains],
              ["New Domains", summary.new_domains],
              ["Shadow Assets", summary.shadow_assets || 0],
              ["DNS Issues", summary.findings || 0],
              ["Non-Web Assets", summary.non_web_assets || 0],
            ].map(([label, value], i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Card>
                  <CardContent>
                    <Typography variant="h6">{label}</Typography>
                    <Typography variant="h4">{value}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* CHARTS */}
          <Grid container spacing={3} style={{ marginTop: "20px" }}>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Discovery Sources</Typography>
                {sources && <SourceChart data={sources} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">HTTP Status</Typography>
                {httpStatus && <HttpStatusChart data={httpStatus} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Providers</Typography>
                {providers && <ProviderChart data={providers} onProviderClick={(p) => setInvestigationFilter({ provider: p })} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Exposure Drift</Typography>
                {drift && <HygieneChart data={drift} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Shadow Assets</Typography>
                {shadowProvider && <ProviderChart data={shadowProvider} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Non-Web Risk</Typography>
                {nonWebSummary && <ShadowChart data={nonWebSummary} />}
              </CardContent></Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Tech Stack</Typography>
                {tech && <TechChart data={tech} />}
              </CardContent></Card>
            </Grid>
          </Grid>

        </Grid>
      )}

      {/* 🔥 Risk Leaderboard */}
      <div style={{ marginTop: "50px" }}>
        <Card>
          <CardContent>
            <Typography variant="h5" style={{ cursor: "pointer" }} onClick={() => setShowRisk(!showRisk)}>
              Risk Leaderboard {showRisk ? "▲" : "▼"}
            </Typography>
            {showRisk && risk && (
              <table style={{ width: "100%", marginTop: "15px", background: "white", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "#eee" }}>
                    <th style={{ padding: "10px" }}>Domain</th>
                    <th>Risk</th>
                    <th>Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {risk.slice(0, 20).map((r, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #ddd" }}>
                      <td style={{ padding: "10px", cursor: "pointer", color: "#1976d2" }}
                        onClick={() => window.open(`http://localhost:8555/domain/${r.domain}`, "_blank")}>
                        {r.domain}
                      </td>
                      <td>{r.risk}</td>
                      <td>{r.reasons.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 🔍 Investigation */}
      <InvestigationTable filter={investigationFilter} setFilter={setInvestigationFilter} />

      {/* 🔥 Findings */}
      <div style={{ marginTop: "40px" }}>
        <h3>Potential DNS Findings ({findings.length})</h3>
        {findings.length === 0 ? <p>No findings</p> : (
          <table border="1" cellPadding="8" style={{ width: "100%", background: "white" }}>
            <thead><tr><th>Domain</th><th>Finding</th><th>Severity</th><th>Evidence</th></tr></thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td>{f.domain}</td>
                  <td>{f.finding}</td>
                  <td style={{ color: f.severity === "HIGH" ? "red" : f.severity === "MEDIUM" ? "orange" : "gray" }}>{f.severity}</td>
                  <td>{f.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 🔥 Sensitive Exposure */}
      <div style={{ marginTop: "30px" }}>
        <Card>
          <CardContent>
            <Typography variant="h5" style={{ cursor: "pointer" }} onClick={() => setShowSensitive(!showSensitive)}>
              Sensitive Exposure ({sensitive.length}) {showSensitive ? "▲" : "▼"}
            </Typography>
            {showSensitive && (sensitive.length === 0 ? <p>No sensitive exposures</p> : (
              <table style={{ width: "100%", marginTop: "15px", background: "white", borderCollapse: "collapse" }}>
                <thead><tr><th>Domain</th><th>Port</th><th>Risk</th><th>Service</th></tr></thead>
                <tbody>
                  {sensitive.sort((a, b) => b.risk - a.risk).map((s, i) => (
                    <tr key={i}>
                      <td>{s.domain}</td>
                      <td>{s.port}</td>
                      <td style={{ color: s.risk >= 9 ? "red" : s.risk >= 6 ? "orange" : "gray" }}>{s.risk}</td>
                      <td>{s.service}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* 🔥 Certificate Expiry */}
      <div style={{ marginTop: "40px" }}>
        <h3>Certificate Expiry ({certs.length})</h3>
        {certs.length === 0 ? <p>No certificate data</p> : (
          <table border="1" cellPadding="8" style={{ width: "100%", background: "white" }}>
            <thead><tr><th>Domain</th><th>Days Left</th><th>Status</th><th>Expiry Date</th></tr></thead>
            <tbody>
              {certs.map((c, i) => (
                <tr key={i}>
                  <td>{c.domain}</td>
                  <td>{c.days ?? "-"}</td>
                  <td style={{ color: c.status === "expired" ? "red" : c.status === "critical" ? "orange" : c.status === "warning" ? "goldenrod" : "green" }}>{c.status}</td>
                  <td>{c.expiry || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 💬 Floating Chat Bubble */}
      <div style={{ position: "fixed", bottom: 30, right: 30, zIndex: 9999 }}>

        {showChat && (
          <div style={{
            position: "absolute",
            bottom: 70,
            right: 0,
            width: "320px",
            background: "white",
            borderRadius: "12px",
            boxShadow: "0 8px 32px rgba(0,0,0,0.2)",
            overflow: "hidden"
          }}>
            <div style={{ background: "#1976d2", padding: "12px 16px" }}>
              <Typography style={{ color: "white", fontWeight: "bold" }}>ASM Assistant</Typography>
            </div>
            <div style={{ padding: "12px" }}>
              <ChatAssistant />
            </div>
          </div>
        )}

        <button
          onClick={() => setShowChat(!showChat)}
          style={{
            width: "56px",
            height: "56px",
            borderRadius: "50%",
            background: "#1976d2",
            color: "white",
            border: "none",
            fontSize: "24px",
            cursor: "pointer",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center"
          }}
        >
          💬
        </button>

      </div>

    </div>
  );
}

export default App;
