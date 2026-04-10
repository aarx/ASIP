import React, { useEffect, useState } from "react";
import { getSummary, getSources, getHttpStatus, getRiskLeaderboard } from "./services/api";
import { Grid, Card, CardContent, Typography } from "@mui/material";
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
  const downloadCSV = async () => {
    window.open("http://localhost:8555/export", "_blank");
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
      const sensitiveData = await fetch("http://localhost:8555/sensitive-exposure")
  .then(res => res.json());
      const certData = await fetch("http://localhost:8555/cert-expiry").then(r => r.json());
      const shadowProvider = await fetch("http://localhost:8555/shadow-by-provider").then(r => r.json());    
      const nonWebSummary = await fetch("http://localhost:8555/non-web-summary").then(r => r.json());
      
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
      setShadowProvider(shadowProvider);
      setNonWebSummary(nonWebSummary);
    }

    fetchData();

  }, []);


  return (
    <div style={{padding:"40px", background:"#f5f7fa", minHeight:"100vh"}}>

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
        <Grid container spacing={3}>
      
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Total Domains</Typography>
              <Typography variant="h4">{summary.total_domains}</Typography>
            </CardContent></Card>
          </Grid>
      
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Live Domains</Typography>
              <Typography variant="h4">{summary.live_domains}</Typography>
            </CardContent></Card>
          </Grid>
                
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Known Domains</Typography>
              <Typography variant="h4">{summary.known_domains}</Typography>
            </CardContent></Card>
          </Grid>
      
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">New Domains</Typography>
              <Typography variant="h4">{summary.new_domains}</Typography>
            </CardContent></Card>
          </Grid>
      
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Shadow Assets</Typography>
              <Typography variant="h4" style={{ color: "#d32f2f" }}>
                {summary.shadow_assets || 0}
              </Typography>
            </CardContent></Card>
          </Grid>
      
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Potential DNS Issues</Typography>
              <Typography variant="h4">{summary.findings || 0}</Typography>
            </CardContent></Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2}>
            <Card><CardContent>
              <Typography variant="h6">Non-Web Assets</Typography>
              <Typography variant="h4">
                {summary.non_web_assets || 0}
              </Typography>
            </CardContent></Card>
          </Grid>          
          
      
        </Grid>
      )}
      <div style={{marginTop:"40px"}}>
        <Typography variant="h5">Discovery Sources</Typography>
        {sources && <SourceChart data={sources} />}
      </div>

      <div style={{marginTop:"40px"}}>
        <Typography variant="h5">HTTP Status Distribution</Typography>
        {httpStatus && <HttpStatusChart data={httpStatus} />}
      </div>
      
      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">Cloud / Provider Distribution</Typography>
        {providers && (
          <ProviderChart
            data={providers}
            onProviderClick={(p) => {
              setInvestigationFilter({ provider: p });
            }}
          />
        )}

      </div>
      
      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">
          Exposure Hygiene Drift
        </Typography>
        {drift && <HygieneChart data={drift}/>}
      </div>

      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">Shadow Assets by Provider</Typography>
        {shadowProvider && <ProviderChart data={shadowProvider} />}
      </div>
      
      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">Non-Web Risk Distribution</Typography>
        {nonWebSummary && <ShadowChart data={nonWebSummary} />}
      </div>

      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">Technology Fingerprint</Typography>
        {tech && <TechChart data={tech}/>}
      </div>

      <div style={{marginTop:"50px"}}>
        <Typography variant="h5">Risk Leaderboard</Typography>

        {risk && (
          <table style={{width:"100%", background:"white", borderCollapse:"collapse"}}>
            <thead>
              <tr style={{background:"#eee"}}>
                <th style={{padding:"10px"}}>Domain</th>
                <th>Risk</th>
                <th>Reasons</th>
              </tr>
            </thead>

            <tbody>
              {risk.slice(0,20).map((r,i)=>(
                <tr key={i} style={{borderBottom:"1px solid #ddd"}}>
                  <td
                    style={{padding:"10px", cursor:"pointer", color:"#1976d2"}}
                    onClick={() => window.open(`http://localhost:8555/domain/${r.domain}`, "_blank")}
                  >
                    {r.domain}
                  </td>
                  <td>{r.risk}</td>
                  <td>{r.reasons.join(", ")}</td>
                </tr>
              ))}
            </tbody>
            
          </table>
        )}
        <InvestigationTable
          filter={investigationFilter}
          setFilter={setInvestigationFilter}
        />
        
      <div style={{ marginTop: "40px" }}>
        <h3>Findings ({findings.length})</h3>
      
        {findings.length === 0 ? (
          <p>No findings</p>
        ) : (
          <table border="1" cellPadding="8" style={{ width: "100%", background: "white" }}>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td>{f.domain}</td>
                  <td>{f.finding}</td>
                  <td
                    style={{
                      color:
                        f.severity === "HIGH"
                          ? "red"
                          : f.severity === "MEDIUM"
                          ? "orange"
                          : "gray"
                    }}
                  >
                    {f.severity}
                  </td>
                  <td>{f.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>      
      
        
      <div style={{ marginTop: "50px" }}>
        <h3>Sensitive Exposure ({sensitive.length})</h3>
      
        {sensitive.length === 0 ? (
          <p>No sensitive exposures</p>
        ) : (
          <table border="1" cellPadding="8" style={{ width: "100%", background: "white" }}>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Port</th>
                <th>Risk</th>
                <th>Service</th>
              </tr>
            </thead>
            <tbody>
              {sensitive
                .sort((a, b) => b.risk - a.risk)
                .map((s, i) => (
                  <tr key={i}>
                    <td>{s.domain}</td>
                    <td>{s.port}</td>
                    <td
                      style={{
                        color:
                          s.risk >= 9
                            ? "red"
                            : s.risk >= 6
                            ? "orange"
                            : "gray"
                      }}
                    >
                      {s.risk}
                    </td>
                    <td>{s.service}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </div>
      
      
      <div style={{ marginTop: "40px" }}>
        <h3>Certificate Expiry ({certs.length})</h3>
      
        {certs.length === 0 ? (
          <p>No certificate data</p>
        ) : (
          <table border="1" cellPadding="8" style={{ width: "100%", background: "white" }}>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Days Left</th>
                <th>Status</th>
                <th>Expiry Date</th>
              </tr>
            </thead>
      
            <tbody>
              {certs.map((c, i) => (
                <tr key={i}>
                  <td>{c.domain}</td>
      
                  <td>{c.days ?? "-"}</td>
      
                  <td
                    style={{
                      color:
                        c.status === "expired"
                          ? "red"
                          : c.status === "critical"
                          ? "orange"
                          : c.status === "warning"
                          ? "goldenrod"
                          : "green"
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
        
        
      </div>

    </div>
  );
}

export default App;
