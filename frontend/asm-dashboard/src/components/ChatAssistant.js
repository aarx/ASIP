import React, { useState } from "react";
import { Card, CardContent, Typography, TextField } from "@mui/material";

const ChatAssistant = () => {
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState([]);
  const [loading, setLoading] = useState(false);

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
      const res = await fetch(
        `http://localhost:8555/chat?q=${encodeURIComponent(chatInput)}`
      );

      const data = await res.json();

      const botMsg = {
        type: "bot",
        text: formatResponse(data),
      };

      setChatHistory((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">ASM Assistant</Typography>

        <div style={{ maxHeight: 300, overflowY: "auto", marginBottom: 10 }}>
          {chatHistory.slice(-10).map((msg, i) => (
            <div key={i}>
              <strong>{msg.type === "user" ? "You" : "ASM"}:</strong>
              <div style={{ whiteSpace: "pre-wrap" }}>{msg.text}</div>
            </div>
          ))}

          {loading && <Typography>🤖 Thinking...</Typography>}
        </div>

        <TextField
          fullWidth
          placeholder="Ask something..."
          value={chatInput}
          onChange={(e) => setChatInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && sendChat()}
        />
      </CardContent>
    </Card>
  );
};

export default ChatAssistant;
