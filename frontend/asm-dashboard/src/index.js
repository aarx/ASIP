import React from 'react';
import ReactDOM from 'react-dom/client';
import { createTheme, CssBaseline, ThemeProvider } from '@mui/material';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

const theme = createTheme({
  palette: {
    mode: 'dark',
    background: { default: '#07111f', paper: '#101d2f' },
    primary: { main: '#28a9e2' },
    text: { primary: '#e7eef6', secondary: '#a9bacb' },
    divider: 'rgba(116, 145, 174, .17)',
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    button: { textTransform: 'none', fontWeight: 650, letterSpacing: '.01em' },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: { borderColor: 'rgba(61, 196, 255, .35)', fontSize: 12 },
      },
    },
  },
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <App />
    </ThemeProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
