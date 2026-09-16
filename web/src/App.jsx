import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Search, Activity, Cpu, Layers, Lock } from 'lucide-react';

const API_BASE = "http://localhost:8000/api/v1";

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/stats`)
      .then(res => res.json())
      .then(data => setStats(data))
      .catch(() => {});
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() })
      });

      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to scan URL. Ensure backend API is online.");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictBadge = (verdict) => {
    if (verdict === 'Phishing') return <span className="bg-red-500/20 text-red-400 border border-red-500/40 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5"><AlertTriangle className="w-4 h-4"/> Phishing</span>;
    if (verdict === 'Suspicious') return <span className="bg-amber-500/20 text-amber-400 border border-amber-500/40 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5"><AlertTriangle className="w-4 h-4"/> Suspicious</span>;
    return <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5"><CheckCircle className="w-4 h-4"/> Safe</span>;
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-gray-800 bg-[#111827]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-sky-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">SentinelPhish</h1>
              <p className="text-xs text-gray-400">AI Multi-Layer Phishing Defense</p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-medium text-gray-400">
            <span className="flex items-center gap-1.5"><Activity className="w-4 h-4 text-emerald-400" /> API Gateway: Online</span>
            <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="hover:text-sky-400 transition">API Docs</a>
          </div>
        </div>
      </header>

      {/* Main Content Hero */}
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-12">
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-sky-500/10 border border-sky-500/20 text-sky-400 text-xs font-semibold mb-4">
            <Cpu className="w-3.5 h-3.5" /> Powered by Groq Llama-3.3-70B & Ensemble ML
          </div>
          <h2 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight mb-4">
            Zero-Trust URL Threat Detection
          </h2>
          <p className="text-gray-400 text-base leading-relaxed">
            Run instant 8-layer parallel analysis across Lexical, Domain WHOIS, Content Extraction, Visual OCR, Threat-Intel feeds, and LLM reasoning.
          </p>
        </div>

        {/* URL Input Form */}
        <form onSubmit={handleScan} className="mb-10 max-w-3xl mx-auto">
          <div className="relative flex items-center">
            <input
              type="text"
              placeholder="Paste suspicious URL (e.g., http://paypal-secure-update.xyz)..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-[#111827] border border-gray-800 focus:border-sky-500 rounded-2xl py-4 pl-5 pr-36 text-gray-100 placeholder-gray-500 outline-none text-sm transition shadow-2xl"
            />
            <button
              type="submit"
              disabled={loading}
              className="absolute right-2 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white font-semibold text-sm px-6 py-2.5 rounded-xl transition flex items-center gap-2 shadow-lg disabled:opacity-50"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" /> Analyze
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="max-w-3xl mx-auto bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-xl text-sm mb-8 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            {error}
          </div>
        )}

        {/* Scan Results Display */}
        {result && (
          <div className="space-y-6 max-w-4xl mx-auto">
            {/* Overview Card */}
            <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
              <div className="flex flex-wrap justify-between items-start gap-4 mb-4">
                <div>
                  <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Target URL</span>
                  <h3 className="text-lg font-bold text-white break-all">{result.url}</h3>
                </div>
                <div>{getVerdictBadge(result.verdict)}</div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-4 border-y border-gray-800/80 my-4">
                <div>
                  <p className="text-xs text-gray-400">Risk Score</p>
                  <p className="text-2xl font-extrabold text-white">{result.risk_score} <span className="text-xs text-gray-500 font-normal">/ 100</span></p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Confidence</p>
                  <p className="text-xl font-bold uppercase text-sky-400">{result.confidence}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Processing Latency</p>
                  <p className="text-xl font-bold text-gray-200">{result.processing_time_ms} ms</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Result Cache</p>
                  <p className="text-xl font-bold text-gray-200">{result.cached ? "HIT (24h)" : "MISS (Live)"}</p>
                </div>
              </div>

              <div className="bg-[#0B0F19] p-4 rounded-xl border border-gray-800/60">
                <p className="text-xs text-sky-400 font-semibold mb-1 flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> AI Threat Assessment Narrative</p>
                <p className="text-sm text-gray-300 leading-relaxed">{result.explanation}</p>
              </div>
            </div>

            {/* Red Flags & Layer Breakdown Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Red Flags List */}
              <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl">
                <h4 className="font-bold text-sm text-gray-200 mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" /> Triggered Security Red Flags ({result.red_flags.length})
                </h4>
                {result.red_flags.length > 0 ? (
                  <div className="space-y-2.5 max-h-60 overflow-y-auto pr-1">
                    {result.red_flags.map((flag, idx) => (
                      <div key={idx} className="bg-[#0B0F19] p-3 rounded-xl border border-gray-800/60 text-xs flex items-start gap-2.5">
                        <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] shrink-0 ${flag.severity === 'high' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : flag.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'}`}>
                          {flag.severity}
                        </span>
                        <span className="text-gray-300 font-medium">{flag.flag}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500 italic">No red flags identified across standard layers.</p>
                )}
              </div>

              {/* Layer Scores */}
              <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl">
                <h4 className="font-bold text-sm text-gray-200 mb-4 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-sky-400" /> 8-Layer Risk Contribution
                </h4>
                <div className="space-y-3">
                  {Object.entries(result.layer_scores).map(([layer, score]) => (
                    <div key={layer}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="capitalize text-gray-400 font-medium">{layer.replace('_', ' ')}</span>
                        <span className="font-bold text-gray-200">{score} / 100</span>
                      </div>
                      <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${score > 70 ? 'bg-red-500' : score > 35 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${Math.max(4, score)}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Global Stats Footer Cards */}
        {stats && (
          <div className="mt-16 pt-8 border-t border-gray-800/80 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
            <div className="bg-[#111827]/50 border border-gray-800/60 p-4 rounded-xl">
              <p className="text-2xl font-extrabold text-white">{stats.total_scans}</p>
              <p className="text-xs text-gray-400">Total Scans Evaluated</p>
            </div>
            <div className="bg-[#111827]/50 border border-gray-800/60 p-4 rounded-xl">
              <p className="text-2xl font-extrabold text-red-400">{stats.phishing_detected}</p>
              <p className="text-xs text-gray-400">Phishing URLs Blocked</p>
            </div>
            <div className="bg-[#111827]/50 border border-gray-800/60 p-4 rounded-xl">
              <p className="text-2xl font-extrabold text-sky-400">{stats.avg_processing_time_ms} ms</p>
              <p className="text-xs text-gray-400">Average Processing Time</p>
            </div>
            <div className="bg-[#111827]/50 border border-gray-800/60 p-4 rounded-xl">
              <p className="text-2xl font-extrabold text-emerald-400">{stats.feedback_accuracy_percentage}%</p>
              <p className="text-xs text-gray-400">Detection Precision</p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
