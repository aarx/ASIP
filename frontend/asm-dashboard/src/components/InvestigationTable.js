import React, { useEffect, useState } from "react";
import { getInvestigationAssets } from "../services/api";

export default function InvestigationTable({ filter, providerFilter, setProviderFilter }) {

  const [data, setData] = useState([]);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [page, setPage] = useState(1);

  useEffect(() => {
    async function load() {
      const res = await getInvestigationAssets(page, 20);
  
      console.log("API RESPONSE:", res);
  
      if (Array.isArray(res)) {
        setData(res);
      } else if (res && Array.isArray(res.assets)) {
        setData(res.assets);
      } else {
        setData([]);  // SAFE fallback
      }
    }
  
    load();
  }, [page, filter]);
  
  useEffect(() => {
    setPage(1);
  }, [filter]);
 

  const filtered = data;

  const providers = [...new Set(
    data
      .map(d => d.provider)
      .filter(p => p && p !== "Unknown")
  )];
  
    console.log("FILTER:", filter, "PROVIDER FILTER:", providerFilter, "DATA:", data.length);
    if (!filter) {
          return (
            <div style={{ padding: "40px", textAlign: "center", opacity: 0.6 }}>
              <h3>🔍 Investigation Console</h3>
              <p>Click on charts (Provider / Risk / Tech) to explore assets</p>
            </div>
          );
        }  
        

  return (
    <div style={{marginTop:"60px"}}>

      <h2>Investigation Console</h2>

      <div style={{display:"flex", gap:"15px", marginBottom:"20px"}}>

        <input
          placeholder="Search domain..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />

        <select onChange={e => setRiskFilter(e.target.value)}>
          <option value="all">All Risk</option>
          <option value="1">Risk ≥ 1</option>
          <option value="2">Risk ≥ 2</option>
          <option value="3">Risk ≥ 3</option>
        </select>

        <select onChange={e => console.log("Provider filter change:", e.target.value)}>
          <option value="all">All Providers</option>
          {providers.map(p => (
            <option key={p} value = {p}>{p}</option>
          ))}
        </select>

      </div>

      <table style={{
        width:"100%",
        background:"white",
        borderCollapse:"collapse"
      }}>
        <thead style={{background:"#eee"}}>
          <tr>
            <th>Domain</th>
            <th>Risk</th>
            <th>IP</th>
            <th>Provider</th>
            <th>Ports</th>
            <th>Tech</th>
          </tr>
        </thead>

        <tbody>
          {filtered.map((d,i)=>(
            <tr key={i} style={{borderBottom:"1px solid #ddd"}}>
              <td>{d.domain}</td>
              <td>{d.risk}</td>
              <td>{d.ip}</td>
              <td>{d.provider}</td>
              <td>{d.ports}</td>
              <td>{d.tech}</td>
            </tr>
          ))}
        </tbody>

      </table>

      <div style={{marginTop:"10px"}}>
        Showing {filtered.length} assets
      </div>
      
      <div style={{ marginTop: "20px", display: "flex", gap: "10px" }}>
        
        <button 
          onClick={() => setPage(p => Math.max(p - 1, 1))}
          disabled={page === 1}
        >
          Prev
        </button>
      
        <span>Page {page}</span>
      
        <button 
          onClick={() => setPage(p => p + 1)}
        >
          Next
        </button>
      
      </div>      

    </div>
  );
}
