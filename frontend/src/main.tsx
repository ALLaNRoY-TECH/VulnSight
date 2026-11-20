import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import History from "./pages/History";
import Home from "./pages/Home";
import ScanPage from "./pages/ScanPage";
import "./index.css";

function NotFound() {
  return (
    <div className="pt-32 text-center">
      <div className="font-mono text-7xl font-bold text-gradient">404</div>
      <p className="mt-4 text-slate-400">This page slipped past the radar.</p>
      <Link to="/" className="mt-6 inline-block text-neon hover:underline">← Back to the scanner</Link>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="scan/:id" element={<ScanPage />} />
          <Route path="history" element={<History />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
