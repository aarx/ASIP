import ChatAssistant from "./components/ChatAssistant";
import React, { useEffect, useState } from "react";
import { getSummary, getSources, getHttpStatus, getRiskLeaderboard } from "./services/api";
import { Grid, Card, CardContent, Typography, TextField, Tooltip } from "@mui/material";
import SourceChart from "./components/SourceChart";
import HttpStatusChart from "./components/HttpStatusChart";
import { getProviders, getTech } from "./services/api";
import ProviderChart from "./components/ProviderChart";
import TechChart from "./components/TechChart";
import { getExposureDrift } from "./services/api";
import HygieneChart from "./components/HygieneChart";
import InvestigationTable from "./components/InvestigationTable";
import AssetGrowthChart from "./components/AssetGrowthChart";
import EnvironmentExposureChart from "./components/EnvironmentExposureChart";


const UnvalidatedBreakdownCard = () => {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://localhost:8555/metrics/unvalidated-breakdown")
      .then(res => res.json())
      .then(setData);
  }, []);

  if (!data) return null;

  return (
    <Card style={{ borderLeft: "6px solid #faad14" }}>
      <CardContent>
        <Typography variant="h6">
          🎯 Unvalidated Assets Breakdown
        </Typography>
        <Typography variant="h3" style={{ marginTop: 8 }}>
          {data.high + data.medium + data.low}
        </Typography>
        <Typography variant="body2" style={{ marginTop: 8 }}>
          High: {data.high} · Medium: {data.medium} · Low: {data.low}
        </Typography>
        <Typography variant="caption">
          unvalidated assets across all confidence levels
        </Typography>
      </CardContent>
    </Card>
  );
};

const UnvalidatedBrandCard = () => {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://localhost:8555/metrics/unvalidated-brand-footprint")
      .then(res => res.json())
      .then(setData);
  }, []);

  if (!data) return null;

  return (
    <Card style={{ background: "#fff3f3", borderLeft: "6px solid #ff4d4f" }}>
      <CardContent>
        <Typography variant="h6">
          🚨 Unvalidated Brand Footprint
        </Typography>
        <Typography variant="h3" style={{ marginTop: 8 }}>
          {data.count}
        </Typography>
        <Typography variant="body2" style={{ marginTop: 8 }}>
          {data.count} domains match brand patterns but remain unvalidated
        </Typography>
        <Typography variant="caption">
          {data.percentage}% of total discovered assets
        </Typography>
      </CardContent>
    </Card>
  );
};

const RedirectDistributionCard = ({ data }) => {

  if (!data) return null;

  return (
    <Card style={{ borderLeft: "6px solid #722ed1" }}>
      <CardContent>

        <Typography variant="h6">
          🔁 Redirect Distribution
        </Typography>

        <Typography
          variant="h3"
          style={{ marginTop: 8 }}
        >
          {data.total}
        </Typography>

        <Typography
          variant="body2"
          style={{ marginTop: 8 }}
        >
          Internal: {data.internal}
          {" · "}
          Trusted External: {data.trusted_external}
          {" · "}
          Untrusted External: {data.untrusted_external}
        </Typography>

        <Typography variant="caption">
          all observed redirects across discovered assets
        </Typography>

      </CardContent>
    </Card>
  );
};  

const DiscoverySourceCard = () => {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://localhost:8555/metrics/discovery-sources")
      .then(res => res.json())
      .then(setData);
  }, []);

  if (!data) return null;

  const total = Object.values(data).reduce((a, b) => a + b, 0);

  return (
    <Card style={{ borderLeft: "6px solid #1890ff" }}>
      <CardContent>
        <Typography variant="h6">
          📡 Discovery Sources
        </Typography>
        <Typography variant="h3" style={{ marginTop: 8 }}>
          {total}
        </Typography>
        <Typography variant="body2" style={{ marginTop: 8 }}>
          {Object.entries(data).map(([k, v]) => `${k}: ${v}`).join(" · ")}
        </Typography>
        <Typography variant="caption">
          total assets discovered across all sources
        </Typography>
      </CardContent>
    </Card>
  );
};

function App() {

  const kpiTooltips = {
    "Total Domains":
      "Total number of domains discovered across all scans.",
  
    "New Domains":
      "Domains discovered for the first time during the latest scan.",
  
    "Live Domains":
      "Domains that successfully resolved and responded during the latest scan.",
  
    "Known Domains":
      "Domains present in the documented repository.",
  
    "Shadow Assets":
      "Active domains that are not present in the documented repository.",
  
    "Non-Web Assets":
      "Assets discovered on non-web infrastructure services or ports.",

    "Suspicious Redirects":
      "Domains redirecting outside trusted seed domains.",
      
      "Environment Assets":
        "Internet-facing domains containing DEV, TEST, QA, UAT, STAGE, ADMIN or similar environment indicators."      
      
  };
  const [summary, setSummary] = useState(null);
  const [assetGrowth, setAssetGrowth] = useState(null);
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
  const [environmentExposure, setEnvironmentExposure] = useState(null);
  const [redirectSummary, setRedirectSummary] = useState(null);
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
      const redirectData =
        await fetch("http://localhost:8555/redirect-summary")
        .then(r => r.json());      
      const assetGrowthData =
        await fetch("http://localhost:8555/asset-growth")
          .then(r => r.json());      
      const findingsData = await fetch("http://localhost:8555/findings").then(r => r.json());
      const sensitiveData = await fetch("http://localhost:8555/sensitive-exposure").then(res => res.json());
      const certData = await fetch("http://localhost:8555/cert-expiry").then(r => r.json());
      const shadowProviderData = await fetch("http://localhost:8555/shadow-by-provider").then(r => r.json());
      const environmentData =
        await fetch("http://localhost:8555/environment-exposure")
          .then(r => r.json());      

      setFindings(findingsData);
      setSummary(summaryData);
      setAssetGrowth(assetGrowthData);
      setSources(sourceData);
      setHttpStatus(httpData);
      setRisk(riskData);
      setProviders(providerData);
      setTech(techData);
      setDrift(driftData);
      setSensitive(sensitiveData);
      setCerts(certData);
      setShadowProvider(shadowProviderData);
      setRedirectSummary(redirectData);
      setEnvironmentExposure(environmentData);
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
                ["New Domains", summary.new_domains],
                ["Live Domains", summary.live_domains],
                ["Known Domains", summary.known_domains],
                ["Shadow Assets", summary.shadow_assets || 0],
                ["Non-Web Assets", summary.non_web_assets || 0],
                [
                  "Suspicious Redirects",
                  redirectSummary?.untrusted_external || 0
              ],
                [
                  "Environment Assets",
                  environmentExposure
                    ? environmentExposure.reduce(
                        (sum, item) => sum + item.count,
                        0
                      )
                    : 0
                ]             
            ].map(([label, value], i) => (
              <Grid item xs={12} sm={6} md={3} key={i}>
                <Card>
                  <CardContent>
                    <Tooltip
                      title={kpiTooltips[label]}
                      arrow
                      placement="top"
                    >
                      <Typography
                        variant="h6"
                        style={{
                          cursor: "help",
                          borderBottom: "1px dotted #999",
                          display: "inline-block"
                        }}
                      >
                        {label} ⓘ
                      </Typography>
                    </Tooltip>
                    <Typography variant="h4">{value}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* 🎯 SIGNAL CARDS ROW */}
          <Grid container spacing={3} style={{ marginTop: "10px" }}>
          
            <Grid item xs={12} md={3}>
              <UnvalidatedBreakdownCard />
            </Grid>
          
            <Grid item xs={12} md={3}>
              <UnvalidatedBrandCard />
            </Grid>
          
            <Grid item xs={12} md={3}>
              <DiscoverySourceCard />
            </Grid>
          
            <Grid item xs={12} md={3}>
              <RedirectDistributionCard
                data={redirectSummary}
              />
            </Grid>
          
          </Grid>

          {/* CHARTS */}
          <Grid container spacing={3} style={{ marginTop: "20px" }}>
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}><CardContent>
                <Typography variant="h6">Seeds Distribution</Typography>
                {sources && <SourceChart data={sources} />}
              </CardContent></Card>
            </Grid>
            
            <Grid item xs={12} md={4}>
              <Card style={{ height: 320 }}>
                <CardContent>
                  <Typography variant="h6">
                    Asset Growth Trend
                  </Typography>
            
                  {assetGrowth && (
                    <AssetGrowthChart data={assetGrowth} />
                  )}
                </CardContent>
              </Card>
            </Grid>            
            
            <Grid item xs={12} md={6}>
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
            <Grid item xs={12} md={6}>
              <Card style={{ height: 320 }}>
                <CardContent>
                  <Typography variant="h6">
                    Environment Exposure
                  </Typography>
            
                  {environmentExposure && (
                    <EnvironmentExposureChart
                      data={environmentExposure}
                    />
                  )}
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Card style={{ height: 320 }}>
                <CardContent>
                  <Typography variant="h6">
                    Tech Stack
                  </Typography>
            
                  {tech && <TechChart data={tech} />}
                </CardContent>
              </Card>
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
                  <td
                    title={
                      c.status === "healthy"
                        ? "Certificate has many days remaining before expiry."
                        : c.status === "warning"
                        ? "Certificate expiry is approaching."
                        : c.status === "critical"
                        ? "Certificate requires immediate attention."
                        : c.status === "expired"
                        ? "Certificate has expired."
                        : ""
                    }
                    style={{
                      color:
                        c.status === "expired"
                          ? "red"
                          : c.status === "critical"
                          ? "orange"
                          : c.status === "warning"
                          ? "goldenrod"
                          : "green",
                      cursor: "help"
                    }}
                  >
                    {c.status}
                  </td>
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
