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

function App() {

  const [summary, setSummary] = useState(null);
  const [sources, setSources] = useState(null);
  const [httpStatus, setHttpStatus] = useState(null);
  const [risk, setRisk] = useState(null);
  const [providers, setProviders] = useState([]);
  const [tech, setTech] = useState(null);
  const [drift, setDrift] = useState(null);
  const [investigationFilter, setInvestigationFilter] = useState(null);
  const [providerFilter, setProviderFilter] = useState("all");

  useEffect(() => {

    async function fetchData() {

      const summaryData = await getSummary();
      const sourceData = await getSources();
      const httpData = await getHttpStatus();
      const riskData = await getRiskLeaderboard();
      const providerData = await getProviders();
      const techData = await getTech();
      const driftData = await getExposureDrift();

      setSummary(summaryData);
      setSources(sourceData);
      setHttpStatus(httpData);
      setRisk(riskData);
      setProviders(providerData);
      setTech(techData);
      setDrift(driftData);

    }

    fetchData();

  }, []);

  return (
    <div style={{padding:"40px", background:"#f5f7fa", minHeight:"100vh"}}>

      <Typography variant="h4" gutterBottom>
        External Attack Surface Dashboard
      </Typography>

      {summary && (
        <Grid container spacing={3}>

          <Grid item xs={3}>
            <Card><CardContent>
              <Typography variant="h6">Total Domains</Typography>
              <Typography variant="h4">{summary.total_domains}</Typography>
            </CardContent></Card>
          </Grid>

          <Grid item xs={3}>
            <Card><CardContent>
              <Typography variant="h6">Live Domains</Typography>
              <Typography variant="h4">{summary.live_domains}</Typography>
            </CardContent></Card>
          </Grid>

          <Grid item xs={3}>
            <Card><CardContent>
              <Typography variant="h6">Known Domains</Typography>
              <Typography variant="h4">{summary.known_domains}</Typography>
            </CardContent></Card>
          </Grid>

          <Grid item xs={3}>
            <Card><CardContent>
              <Typography variant="h6">New Domains</Typography>
              <Typography variant="h4">{summary.new_domains}</Typography>
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
              setProviderFilter(p);
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
                    onClick={() => window.open(`http://localhost:8000/domain/${r.domain}`, "_blank")}
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
          providerFilter={providerFilter}
          setProviderFilter = {setProviderFilter}
        />      
      </div>

    </div>
  );
}

export default App;
