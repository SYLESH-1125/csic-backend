'use client';
import { useEffect, useState } from 'react';

export default function EnginePage() {
    const [new_data, setNewData] = useState(null);
    const [new_gen, setNewGen] = useState(false);
    const [new_ghost, setNewGhost] = useState("");
    const [new_ready, setNewReady] = useState(false);
    const [new_temp, setNewTemp] = useState("executive");

    useEffect(() => {
        fetch("http://127.0.0.1:8000/latest")
            .then(new_res => new_res.json())
            .then(new_json => setNewData(new_json));
    }, []);

    const new_start = async () => {
        setNewGen(true);
        const new_phrases = ["ESTABLISHING SECURE UPLINK...", "PARSING JSON PAYLOAD...", "INJECTING HEX OFFSETS...", "COMPILING 30-PAGE DOSSIER...", "FINALIZING GHOSTWRITER ENGINE..."];
        let new_idx = 0;

        const new_interval = setInterval(() => {
            setNewGhost(new_phrases[new_idx]);
            new_idx += 1;
            if (new_idx === 5) {
                clearInterval(new_interval);
                setTimeout(() => {
                    setNewGen(false);
                    setNewReady(true);
                }, 2000);
            }
        }, 1200);
    };

    const new_fetch_pdf = () => {
        window.open("http://127.0.0.1:8000/generate", "_blank");
    };

    return (
         <div style={{ backgroundColor: "black", color: "#00FF41", height: "100vh", padding: "50px", fontFamily: "monospace" }}>
            <h1>GHOSTWRITER REPORT ENGINE</h1>
            
            <div style={{ border: "1px solid #00FF41", padding: "20px", marginBottom: "20px" }}>
                <h3>LATEST PAYLOAD ACQUIRED:</h3>
                {new_data ? <pre style={{ overflow: "hidden", maxHeight: "100px", color: "white" }}>{JSON.stringify(new_data).slice(0, 300)}...</pre> : <p>AWAITING DATA...</p>}
            </div>

            <div style={{ marginBottom: "20px" }}>
                <span style={{ marginRight: "10px" }}>SELECT DOSSIER TEMPLATE:</span>
                <select value={new_temp} onChange={(new_e) => setNewTemp(new_e.target.value)} style={{ backgroundColor: "black", color: "#00FF41", border: "1px solid #00FF41", padding: "5px" }}>
                    <option value="executive">EXECUTIVE SUMMARY</option>
                    <option value="deep_scan">DEEP SCAN HEX ANALYSIS</option>
                </select>
            </div>

            {!new_gen && !new_ready && (
                <button onClick={new_start} style={{ backgroundColor: "#00FF41", color: "black", padding: "15px 30px", fontWeight: "bold", cursor: "pointer", fontSize: "16px" }}>
                    ENGAGE DOSSIER GENERATION
                </button>
            )}

            {new_gen && (
                <div style={{ border: "1px dashed #00FF41", padding: "20px", marginTop: "20px" }}>
                    <h2>s {new_ghost}<span style={{ animation: "blink 1s step-end infinite" }}>_</span></h2>
                </div>
            )}

            {new_ready && (
                <div style={{ marginTop: "20px" }}>
                    <h2 style={{ color: "white" }}>[ SYSTEM ALERT: DOSSIER SECURED ]</h2>
                    <button onClick={new_fetch_pdf} style={{ backgroundColor: "white", color: "black", padding: "15px 30px", fontWeight: "bold", cursor: "pointer", fontSize: "16px" }}>
                        VIEW PDF DOSSIER
                    </button>
                </div>
            )}
         </div>
    );
}