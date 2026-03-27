'use client';

import { useEffect, useMemo, useState, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Sector, Legend } from 'recharts';

type ReportTemplate = {
  id: string;
  name: string;
  color: string;
  thumbnail?: string;
  covers: { id: string; name: string; image: string }[];
  fonts: { id: string; name: string }[];
  graphs: { id: string; name: string }[];
  tables: { id: string; name: string }[];
};

type ReportChart = {
  b64?: string;
  type?: string;
  data?: { name: string; value: number }[];
};
type ReportTable = { title?: string; columns?: string[]; rows?: string[][] };
type ReportList = { title?: string; items?: string[] };
type ReportPage = { title?: string; paragraphs?: string[]; charts?: ReportChart[]; tables?: ReportTable[]; lists?: ReportList[] };

type ReportPreview = {
  meta?: { case_id?: string; generated_at?: string; verdict?: string; verdict_reason?: string; };
  toc?: { no: number; title: string; page: number }[];
  pages?: ReportPage[];
};

type StreamBlock =
  | { new_page_index: number; new_type: 'title' | 'paragraph'; new_text: string; }
  | { new_page_index: number; new_type: 'chart'; new_chart: ReportChart; }
  | { new_page_index: number; new_type: 'table'; new_table: ReportTable; }
  | { new_page_index: number; new_type: 'list'; new_list: ReportList; };

export default function ProfessionalEngine() {
  const [new_templates, setNewTemplates] = useState<ReportTemplate[]>([]);
  const [new_selected_template, setNewSelectedTemplate] = useState('');
  const [new_json_file, setNewJsonFile] = useState<File | null>(null);
  const [new_json_data, setNewJsonData] = useState<any>(null);
  const [new_selected_cover, setNewSelectedCover] = useState('');
  const [new_setup_step, setNewSetupStep] = useState<'template' | 'cover' | 'customize'>('template');
  const [new_font_style, setNewFontStyle] = useState('times');
  const [new_graph_style, setNewGraphStyle] = useState('classic');
  const [new_table_style, setNewTableStyle] = useState('clean');
  const [new_custom_tab, setNewCustomTab] = useState<'fonts' | 'graphs' | 'tables'>('fonts');

  const [new_selected_graphs, setNewSelectedGraphs] = useState<string[]>(['timeline', 'top_entities', 'file_types']);

  const [new_phase, setNewPhase] = useState<'idle' | 'writing' | 'compiling' | 'done'>('idle');
  const [new_preview, setNewPreview] = useState<ReportPreview | null>(null);
  const [new_pdf_url, setNewPdfUrl] = useState('');
  const [new_loading, setNewLoading] = useState(false);
  const [new_error, setNewError] = useState('');
  const [new_view_mode, setNewViewMode] = useState<'pdf' | 'html'>('pdf');

  const [new_stream_index, setNewStreamIndex] = useState(0);
  const [new_stream_char, setNewStreamChar] = useState(0);
  
  const [new_pie_active_idx, setNewPieActiveIndex] = useState<number | undefined>(undefined);

  const new_scroll_ref = useRef<HTMLDivElement>(null);
  const new_user_scrolled = useRef(false);

  const new_handle_scroll = (e: any) => {
      const new_t = e.target;
      new_user_scrolled.current = (new_t.scrollHeight - new_t.scrollTop - new_t.clientHeight) > 150;
  };

  const new_api = 'http://127.0.0.1:8000';

  useEffect(() => {
    fetch(`${new_api}/api/report/templates`)
      .then((new_r) => new_r.json())
      .then((new_d) => {
        const new_list = new_d.templates || [];
        setNewTemplates(new_list);

        if (new_list.length > 0) {
          const new_first = new_list[ 0 ];
          setNewSelectedTemplate(new_first.id);
          setNewFontStyle(new_first.fonts?.[ 0 ]?.id || 'times');
          setNewGraphStyle(new_first.graphs?.[ 0 ]?.id || 'classic');
          setNewTableStyle(new_first.tables?.[ 0 ]?.id || 'clean');
        }
      })
      .catch(() => {});
  }, []);

  const new_active_template_obj = new_templates.find((new_t) => new_t.id === new_selected_template) || null;
  const new_cover_img = new_active_template_obj?.covers?.find(new_c => new_c.id === new_selected_cover)?.image;

  const new_pages = useMemo(() => new_preview?.pages || [], [new_preview]);
  
  const new_display_pages = useMemo(() => new_phase === 'done' ? new_pages : new_pages.slice(0, 5), [new_pages, new_phase]);
  
  const new_total_actual_pages = new_preview?.pages ? new_preview.pages.length + 2 : 0;

  const new_stream_blocks = useMemo<StreamBlock[]>(() => {
    const new_arr: StreamBlock[] = [];

    new_display_pages.forEach((new_page, new_page_index) => {
      if (new_page.title) new_arr.push({ new_page_index, new_type: 'title', new_text: new_page.title });
      (new_page.paragraphs || []).forEach((new_para) => new_arr.push({ new_page_index, new_type: 'paragraph', new_text: new_para }));
      (new_page.charts || []).forEach((new_chart) => new_arr.push({ new_page_index, new_type: 'chart', new_chart }));
      (new_page.tables || []).forEach((new_table) => new_arr.push({ new_page_index, new_type: 'table', new_table }));
      (new_page.lists || []).forEach((new_list) => new_arr.push({ new_page_index, new_type: 'list', new_list }));
    });

    return new_arr;
  }, [new_display_pages]);

  useEffect(() => {
    if (new_phase !== 'writing') return;
    if (!new_stream_blocks.length) return;

    if (new_stream_index >= new_stream_blocks.length) {
      const new_t = setTimeout(() => setNewPhase('compiling'), 600);
      return () => clearTimeout(new_t);
    }

    const new_current = new_stream_blocks[ new_stream_index ];

    if (new_current.new_type === 'title' || new_current.new_type === 'paragraph') {
      const new_text = new_current.new_text || '';

      if (new_stream_char < new_text.length) {
        const new_t = setTimeout(() => {
          setNewStreamChar((new_v) => new_v + 1);
        }, 8);
        return () => clearTimeout(new_t);
      } else {
        const new_t = setTimeout(() => {
          setNewStreamIndex((new_v) => new_v + 1);
          setNewStreamChar(0);
        }, 110);
        return () => clearTimeout(new_t);
      }
    } else {
      const new_t = setTimeout(() => {
        setNewStreamIndex((new_v) => new_v + 1);
        setNewStreamChar(0);
      }, 260);
      return () => clearTimeout(new_t);
    }
  }, [new_phase, new_stream_blocks, new_stream_index, new_stream_char]);

  useEffect(() => {
      if (new_phase === 'writing' && !new_user_scrolled.current) {
          const new_active_el = document.getElementById('active-typing-block');
          if (new_active_el) {
              new_active_el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
      }
  }, [new_stream_index, new_phase]);

  useEffect(() => {
    if (new_phase === 'compiling' && new_pdf_url) {
      const new_t = setTimeout(() => {
          setNewPhase('done');
          setNewViewMode('html'); 
      }, 2000); 
      return () => clearTimeout(new_t);
    }
  }, [new_phase, new_pdf_url]);

  const new_handle_file = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const new_f = e.target.files?.[ 0 ];
    if (!new_f) return;

    setNewJsonFile(new_f);
    setNewError('');

    try {
      const new_txt = await new_f.text();
      const new_parsed = JSON.parse(new_txt);
      setNewJsonData(new_parsed);
    } catch {
      setNewJsonData(null);
      setNewError('Invalid JSON file');
    }
  };

  const new_available_graphs = [
      { id: 'timeline', name: 'Risk Time (Line)' },
      { id: 'top_entities', name: 'Entities (Horiz)' },
      { id: 'signals', name: 'Behaviors (Bar)' },
      { id: 'file_types', name: 'File Types (Pie)' },
      { id: 'scores', name: 'Scores (Hist)' },
      { id: 'integrity', name: 'Integrity (Bar)' },
      { id: 'parse_errors', name: 'Errors (Bar)' },
      { id: 'duckdb', name: 'Database (Bar)' }
  ];

  const new_toggle_graph = (new_id: string) => {
      if (new_selected_graphs.includes(new_id)) {
          if (new_selected_graphs.length <= 1) {
              setNewError("You must select at least 1 graph type.");
              setTimeout(() => setNewError(''), 2000);
              return;
          }
          setNewSelectedGraphs(new_prev => new_prev.filter(new_g => new_g !== new_id));
      } else {
          if (new_selected_graphs.length >= 5) {
              setNewError("Maximum 5 graph types allowed for optimal layout.");
              setTimeout(() => setNewError(''), 2000);
              return;
          }
          setNewSelectedGraphs(new_prev => [...new_prev, new_id]);
      }
  };

  const new_start = async () => {
    if (!new_json_data) { setNewError('Upload a valid JSON first'); return; }
    if (!new_selected_template) { setNewError('Choose a template first'); return; }

    try {
      setNewLoading(true);
      setNewError('');
      setNewPreview(null);
      setNewPdfUrl('');
      setNewPhase('idle');
      setNewStreamIndex(0);
      setNewStreamChar(0);
      new_user_scrolled.current = false; 

      const new_body = {
        payload: new_json_data,
        template_id: new_selected_template,
        cover_id: new_selected_cover,
        font_style: new_font_style,
        graph_style: new_graph_style,
        table_style: new_table_style,
        selected_graphs: new_selected_graphs, 
      };
      
      const new_preview_res = await fetch(`${new_api}/api/report/preview`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(new_body),
      });

      const new_preview_data = await new_preview_res.json();

      if (!new_preview_res.ok) {
        setNewError('Preview failed');
        setNewLoading(false);
        return;
      }

      setNewPreview(new_preview_data.preview);
      setNewPhase('writing');

      const new_generate_res = await fetch(`${new_api}/api/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(new_body),
      });

      const new_generate_data = await new_generate_res.json();

      if (!new_generate_res.ok) {
        setNewError(`SYSTEM HALT: ${new_generate_data.detail || 'Unknown Server Crash'}`);
        setNewPhase('idle'); 
        setNewLoading(false);
        return;
      }

      setNewPdfUrl(`${new_api}${new_generate_data.pdf_url}`);
      setNewLoading(false);
    } catch {
      setNewError('Something went wrong. Verify Uvicorn is running.');
      setNewLoading(false);
    }
  };

  const new_font_family = new_font_style === 'times' ? 'Times New Roman, serif' : new_font_style === 'georgia' ? 'Georgia, serif' : 'Arial, sans-serif';

  const new_mock_palette = 
    new_graph_style === 'modern' ? { bg: '#0F172A', text: '#F8FAFC', grid: '#334155', c1: '#06B6D4', c2: '#6366F1', c3: '#8B5CF6', c4: '#64748B', colors: ['#06B6D4', '#6366F1', '#8B5CF6', '#F472B6', '#FB7185', '#34D399', '#FBBF24'] } : 
    (new_graph_style === 'clean' || new_graph_style === 'minimal') ? { bg: '#FFFFFF', text: '#0F172A', grid: '#E2E8F0', c1: '#0369A1', c2: '#0284C7', c3: '#38BDF8', c4: '#BAE6FD', colors: ['#0369A1', '#0284C7', '#38BDF8', '#7DD3FC', '#BAE6FD', '#E0F2FE', '#F0F9FF'] } : 
    { bg: '#FFFFFF', text: '#0F172A', grid: '#E2E8F0', c1: '#B91C1C', c2: '#1D4ED8', c3: '#15803D', c4: '#D97706', colors: ['#B91C1C', '#1D4ED8', '#15803D', '#D97706', '#7E22CE', '#0F766E', '#64748B'] };

  const new_render_active_shape = (props: any) => {
      const RADIAN = Math.PI / 180;
      const { cx, cy, midAngle, innerRadius, outerRadius, startAngle, endAngle, fill, payload, percent, value } = props;
      const sin = Math.sin(-RADIAN * midAngle);
      const cos = Math.cos(-RADIAN * midAngle);
      const sx = cx + (outerRadius + 5) * cos;
      const sy = cy + (outerRadius + 5) * sin;
      const mx = cx + (outerRadius + 20) * cos;
      const my = cy + (outerRadius + 20) * sin;
      const ex = mx + (cos >= 0 ? 1 : -1) * 20;
      const ey = my;
      const textAnchor = cos >= 0 ? 'start' : 'end';
  
      return (
        <g>
          <Sector cx={cx} cy={cy} innerRadius={innerRadius} outerRadius={outerRadius + 10} startAngle={startAngle} endAngle={endAngle} fill={fill} style={{ filter: `drop-shadow(0px 6px 8px rgba(0,0,0,0.3))` }} />
          <path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`} stroke={fill} strokeWidth={2} fill="none" />
          <circle cx={ex} cy={ey} r={4} fill={fill} stroke="none" />
          <text x={ex + (cos >= 0 ? 1 : -1) * 10} y={ey} textAnchor={textAnchor} fill={new_mock_palette.text} fontSize={13} fontWeight="bold">{payload.name}</text>
          <text x={ex + (cos >= 0 ? 1 : -1) * 10} y={ey} dy={18} textAnchor={textAnchor} fill="#64748B" fontSize={12}>{`Metric Value: ${value} (${(percent * 100).toFixed(1)}%)`}</text>
        </g>
      );
  };
  
  const new_render_custom_label = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) => {
      const RADIAN = Math.PI / 180;
      const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
      const x = cx + radius * Math.cos(-RADIAN * midAngle);
      const y = cy + radius * Math.sin(-RADIAN * midAngle);
      
      return percent > 0.07 ? (
        <text x={x} y={y} fill="#FFFFFF" textAnchor="middle" dominantBaseline="central" fontSize={12} fontWeight="bold" style={{ textShadow: "0px 1px 3px rgba(0,0,0,0.6)" }}>
          {`${(percent * 100).toFixed(0)}%`}
        </text>
      ) : null;
  };

  return (
    <div style={{ display: "flex", height: "100vh", backgroundColor: "#F8FAFC", color: "#0F172A", fontFamily: "Arial, sans-serif", overflow: "hidden" }}>
      <style>{`
        @keyframes new_blink { 50% { border-color: transparent; } }
        @keyframes new_fadein { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes new_spin { 100% { transform: rotate(360deg); } }
        
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #F1F5F9; }
        ::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 4px; }

        .mock-bar { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; }
        .mock-bar:hover { filter: brightness(1.2); transform: translateY(-8px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.2); }
        .mock-bar:hover::after { content: "Metric: 84"; position: absolute; top: -35px; left: 50%; transform: translateX(-50%); background: #0F172A; color: #FFF; padding: 4px 8px; border-radius: 6px; font-size: 11px; white-space: nowrap; pointer-events: none; z-index: 10; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }

        .mock-bar-horiz { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; }
        .mock-bar-horiz:hover { filter: brightness(1.2); transform: translateX(8px); box-shadow: 4px 4px 10px rgba(0,0,0,0.1); }
        .mock-bar-horiz:hover::after { content: "Score: 92"; position: absolute; right: -75px; top: 50%; transform: translateY(-50%); background: #0F172A; color: #FFF; padding: 4px 8px; border-radius: 6px; font-size: 11px; white-space: nowrap; pointer-events: none; z-index: 10; }

        .mock-pie { transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); }
        .mock-pie:hover { transform: scale(1.15) rotate(10deg); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2); }

        .pie-slice-hover { outline: none; transition: filter 0.2s ease; }
        .pie-slice-hover:hover { filter: brightness(1.2); cursor: pointer; }

        .mock-line-path { stroke-dasharray: 400; stroke-dashoffset: 400; animation: drawLine 2s ease-out forwards; transition: all 0.3s ease; }
        .mock-line-svg:hover .mock-line-path { filter: drop-shadow(0px 8px 4px rgba(0,0,0,0.3)); stroke-width: 4; cursor: crosshair; }
        @keyframes drawLine { to { stroke-dashoffset: 0; } }

        .generated-chart-img { transition: all 0.3s ease; border: 2px solid transparent; }
        .generated-chart-img:hover { transform: scale(1.02); box-shadow: 0 15px 30px rgba(0,0,0,0.15); border-color: #0284C7; border-radius: 8px; cursor: crosshair; }

        .table-clean { border-collapse: collapse; width: 100%; }
        .table-clean th { border-bottom: 2px solid #CBD5E1; padding: 12px; text-align: left; font-weight: bold; color: #0F172A; }
        .table-clean td { border-bottom: 1px solid #E2E8F0; padding: 12px; color: #334155; }
        .table-clean tr:hover td { background-color: #F8FAFC; transform: scale(1.01); transition: all 0.2s ease; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); color: #0284C7; font-weight: bold; cursor: help; }

        .table-grid { border-collapse: collapse; width: 100%; border: 1px solid #CBD5E1; }
        .table-grid th { border: 1px solid #CBD5E1; padding: 10px; text-align: left; background-color: #E2E8F0; color: #0F172A; font-weight: bold; }
        .table-grid td { border: 1px solid #CBD5E1; padding: 10px; color: #334155; }
        .table-grid tr:nth-child(even) td { background-color: #F8FAFC; }
        .table-grid tr:hover td { background-color: #E0F2FE; transition: background-color 0.2s ease; color: #0369A1; cursor: help; }

        .table-executive { border-collapse: collapse; width: 100%; border: 2px solid #0F172A; }
        .table-executive th { background-color: #0F172A; color: #FFFFFF; padding: 14px 12px; text-align: left; border: 1px solid #0F172A; font-weight: bold; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }
        .table-executive td { border: 1px solid #CBD5E1; padding: 12px; color: #0F172A; font-weight: 500; }
        .table-executive tr:hover td { background-color: #F1F5F9; border-top: 1px solid #0284C7; border-bottom: 1px solid #0284C7; color: #0284C7; transition: all 0.1s ease; cursor: help; }
      `}</style>

      <div style={{ width: "260px", backgroundColor: "#FFFFFF", borderRight: "1px solid #E2E8F0", display: "flex", flexDirection: "column", padding: "25px", boxShadow: "2px 0 10px rgba(0,0,0,0.03)", zIndex: 10 }}>
        <div style={{ fontSize: "20px", fontWeight: "bold", color: "#0284C7", letterSpacing: "1px", marginBottom: "40px", display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: "20px", height: "20px", backgroundColor: "#0284C7", borderRadius: "4px" }}></div>
          FORENIX
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", flexGrow: 1, color: "#475569", fontSize: "14px", fontWeight: "bold" }}>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", transition: "0.2s" }}>Dashboard</div>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", backgroundColor: "#F1F5F9", color: "#0F172A", borderLeft: "4px solid #0284C7" }}>Report Engine</div>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", transition: "0.2s" }}>Templates</div>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", transition: "0.2s" }}>Data Sources</div>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", transition: "0.2s" }}>Exports</div>
          <div style={{ cursor: "pointer", padding: "12px 16px", borderRadius: "6px", transition: "0.2s" }}>Settings</div>
        </div>
        <div style={{ backgroundColor: "#F8FAFC", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", fontSize: "12px", fontWeight: "bold" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px" }}><span style={{ color: "#64748B" }}>Engine Status</span><span style={{ color: "#10B981" }}>● Active</span></div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px" }}><span style={{ color: "#64748B" }}>Data Source</span><span style={{ color: "#0F172A" }}>Connected</span></div>
          <div style={{ display: "flex", justifyContent: "space-between" }}><span style={{ color: "#64748B" }}>Format</span><span style={{ color: "#0284C7" }}>PDF</span></div>
        </div>
      </div>

      <div style={{ flexGrow: 1, display: "flex", flexDirection: "column", backgroundColor: "#F8FAFC", position: "relative" }}>
        
        <div style={{ padding: "10px 30px", borderBottom: "1px solid #E2E8F0", backgroundColor: "#FFFFFF", display: "flex", gap: "20px", alignItems: "center", boxShadow: "0 2px 10px rgba(0,0,0,0.02)" }}>
          <div style={{ fontWeight: "bold", color: "#0F172A", fontSize: "16px", marginRight: "auto" }}>Report Generation Pipeline</div>
          <input type="file" accept=".json,application/json" onChange={new_handle_file} style={{ padding: "8px", border: "1px solid #CBD5E1", borderRadius: "6px", backgroundColor: "#F8FAFC", color: "#0F172A", cursor: "pointer", fontSize: "14px", fontWeight: "bold" }} />
          {new_phase === 'idle' && new_setup_step === 'customize' && (
            <button onClick={new_start} style={{ backgroundColor: "#0284C7", color: "#FFFFFF", padding: "10px 25px", borderRadius: "6px", fontWeight: "bold", border: "none", cursor: "pointer", fontSize: "14px", boxShadow: "0 4px 6px -1px rgba(2, 132, 199, 0.2)" }}>COMPILE REPORT</button>
          )}
        </div>

        <div style={{ padding: "10px 30px", borderBottom: "1px solid #E2E8F0", backgroundColor: "#FFFFFF" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
            <h2 style={{ color: "#0F172A", fontSize: "16px", fontWeight: "bold", margin: 0 }}>Your report is being dynamically drafted with verified telemetry.</h2>
          </div>
          
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            {['Upload Data', 'Configure Style', 'Ghostwriting', 'Compiling Ledger', 'Official PDF'].map((new_s_txt, new_i) => {
              const new_active = (new_i === 0 && new_phase === 'idle' && !new_json_data) || (new_i === 1 && new_phase === 'idle' && new_json_data) || (new_i === 2 && new_phase === 'writing') || (new_i === 3 && new_phase === 'compiling') || (new_i === 4 && new_phase === 'done');
              const new_past = (new_i === 0 && new_json_data) || (new_i === 1 && new_phase !== 'idle') || (new_i === 2 && (new_phase === 'compiling' || new_phase === 'done')) || (new_i === 3 && new_phase === 'done');
              return (
                <div key={new_i} style={{ display: "flex", alignItems: "center", flex: 1 }}>
                  <div style={{ width: "20px", height: "20px", borderRadius: "50%", backgroundColor: new_active ? "#0284C7" : new_past ? "#10B981" : "#F1F5F9", color: new_active || new_past ? "#FFFFFF" : "#94A3B8", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "10px", fontWeight: "bold" }}>
                    {new_past ? "✓" : new_i + 1}
                  </div>
                  <div style={{ color: new_active ? "#0F172A" : new_past ? "#0F172A" : "#94A3B8", fontSize: "12px", marginLeft: "8px", fontWeight: new_active ? "bold" : "normal" }}>{new_s_txt}</div>
                  {new_i < 4 && <div style={{ flexGrow: 1, height: "2px", backgroundColor: new_past ? "#10B981" : "#E2E8F0", margin: "0 10px" }}></div>}
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ flexGrow: 1, overflow: "hidden", display: "flex", flexDirection: "column", position: "relative" }}>
          
          {new_phase === 'idle' && !new_json_data && (
            <div style={{ flexGrow: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#64748B", fontWeight: "bold", fontSize: "18px" }}>
              Please upload a verified JSON payload to begin.
            </div>
          )}

          {new_error && <div style={{ margin: '20px', padding: '15px', background: '#FEE2E2', color: '#B91C1C', fontWeight: 'bold', borderRadius: '6px', border: '1px solid #F87171' }}>{new_error}</div>}

          <div ref={new_scroll_ref} onScroll={new_handle_scroll} style={{ flexGrow: 1, overflowY: "auto", padding: "20px", display: "flex", flexDirection: "column", alignItems: "center", scrollBehavior: "smooth" }}>
            
            {new_phase === 'done' && new_pdf_url && (
              <div style={{ width: "100%", maxWidth: "1000px", animation: "new_fadein 0.5s", marginBottom: "20px" }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: "center", background: "#FFFFFF", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", boxShadow: "0 4px 10px rgba(0,0,0,0.03)" }}>
                  <div>
                    <h2 style={{ color: "#0F172A", marginBottom: "5px" }}>Official Verified Dossier</h2>
                    <div style={{ color: "#64748B", fontSize: "14px", fontWeight: "bold" }}>Ready for secure distribution or presentation.</div>
                  </div>
                  <div style={{ display: "flex", gap: "15px", alignItems: "center" }}>
                    
                    <div style={{ display: "flex", background: "#F1F5F9", borderRadius: "6px", padding: "4px", border: "1px solid #CBD5E1" }}>
                      <button onClick={() => setNewViewMode('html')} style={{ padding: '8px 16px', background: new_view_mode === 'html' ? '#FFFFFF' : 'transparent', color: new_view_mode === 'html' ? '#0284C7' : '#64748B', border: 'none', borderRadius: '4px', fontWeight: 'bold', fontSize: '12px', cursor: 'pointer', boxShadow: new_view_mode === 'html' ? '0 2px 4px rgba(0,0,0,0.05)' : 'none', transition: "0.2s" }}>Interactive Web</button>
                      <button onClick={() => setNewViewMode('pdf')} style={{ padding: '8px 16px', background: new_view_mode === 'pdf' ? '#FFFFFF' : 'transparent', color: new_view_mode === 'pdf' ? '#0284C7' : '#64748B', border: 'none', borderRadius: '4px', fontWeight: 'bold', fontSize: '12px', cursor: 'pointer', boxShadow: new_view_mode === 'pdf' ? '0 2px 4px rgba(0,0,0,0.05)' : 'none', transition: "0.2s" }}>Static PDF View</button>
                    </div>

                    <button onClick={() => { setNewPhase('idle'); setNewSetupStep('template'); }} style={{ padding: '12px 20px', background: '#FFFFFF', color: '#0F172A', border: '1px solid #CBD5E1', borderRadius: '6px', fontWeight: 'bold', fontSize: '13px', cursor: 'pointer', transition: "0.2s" }}>Restart Process</button>
                    <a href={`${new_pdf_url}?download=true`} download style={{ padding: '12px 20px', background: '#0284C7', color: '#FFFFFF', textDecoration: 'none', borderRadius: '6px', fontWeight: 'bold', fontSize: '13px', boxShadow: '0 4px 6px -1px rgba(2, 132, 199, 0.2)', display: "flex", alignItems: "center" }}>Download Final PDF ↓</a>
                  </div>
                </div>
              </div>
            )}

            {new_json_data && new_phase === 'idle' && new_setup_step === 'template' && (
              <div style={{ width: "100%", maxWidth: "1000px" }}>
                <h3 style={{ marginBottom: "15px", color: "#0F172A" }}>1. Select Core Template</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  {new_templates.map((new_t) => (
                    <div
                      key={new_t.id}
                      onClick={() => { setNewSelectedTemplate(new_t.id); setNewSelectedCover(''); setNewError(''); }}
                      style={{ cursor: 'pointer', border: new_selected_template === new_t.id ? '2px solid #0284C7' : '1px solid #CBD5E1', borderRadius: '8px', padding: '20px', background: '#FFFFFF', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.05)', transition: 'all 0.2s', transform: new_selected_template === new_t.id ? 'translateY(-2px)' : 'none' }}
                    >
                      <img src={new_t.thumbnail} alt={new_t.name} style={{ width: "100%", height: "140px", objectFit: "contain", marginBottom: "15px", borderRadius: "4px", backgroundColor: "#F8FAFC", padding: "10px" }} />
                      <div style={{ fontWeight: 'bold', marginBottom: '6px', color: '#0F172A', fontSize: "16px" }}>{new_t.name}</div>
                      <div style={{ color: '#64748B', fontSize: '13px', fontWeight: "bold" }}>Standard Architecture</div>
                    </div>
                  ))}
                </div>

                {new_active_template_obj && (
                  <div style={{ animation: "new_fadein 0.4s" }}>
                    <h3 style={{ marginBottom: "15px", color: "#0F172A", borderTop: "1px solid #E2E8F0", paddingTop: "20px" }}>2. Select Cover Layout</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                      {(new_active_template_obj.covers || []).map((new_c) => (
                        <div
                          key={new_c.id}
                          onClick={() => setNewSelectedCover(new_c.id)}
                          style={{ cursor: 'pointer', border: new_selected_cover === new_c.id ? '2px solid #0284C7' : '1px solid #CBD5E1', borderRadius: '8px', padding: '15px', background: '#FFFFFF', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.05)', textAlign: 'center', transition: "all 0.2s" }}
                        >
                          <img src={new_c.image} alt={new_c.name} style={{ width: '100%', height: '260px', objectFit: 'contain', borderRadius: '4px', marginBottom: '15px', background: '#F8FAFC', padding: "5px", border: "1px solid #E2E8F0" }} />
                          <div style={{ fontWeight: 'bold', color: '#0F172A' }}>{new_c.name}</div>
                        </div>
                      ))}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <button
                        onClick={() => {
                          if (!new_selected_cover) { setNewError('Please select a cover page to proceed.'); return; }
                          setNewFontStyle(new_active_template_obj.fonts?.[ 0 ]?.id || 'times');
                          setNewGraphStyle(new_active_template_obj.graphs?.[ 0 ]?.id || 'classic');
                          setNewTableStyle(new_active_template_obj.tables?.[ 0 ]?.id || 'clean');
                          setNewError('');
                          setNewSetupStep('customize');
                        }}
                        style={{ padding: '14px 35px', background: '#0F172A', color: '#FFFFFF', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer', fontSize: '16px', boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)" }}
                      >
                        PROCEED TO CUSTOMIZATION →
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {new_json_data && new_phase === 'idle' && new_setup_step === 'customize' && new_active_template_obj && (
              <div style={{ width: "100%", maxWidth: "1200px", animation: "new_fadein 0.4s" }}>
                <div style={{ display: 'flex', justifyContent: 'flex-start', marginBottom: '15px' }}>
                  <button onClick={() => setNewSetupStep('template')} style={{ padding: '8px 16px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: '#FFFFFF', color: '#0F172A', fontWeight: 'bold', boxShadow: "0 2px 4px rgba(0,0,0,0.02)" }}>
                    ← Back to Layouts
                  </button>
                </div>

                <div style={{ display: "flex", gap: "30px" }}>
                  <div style={{ flex: 1.5, maxHeight: '700px', overflowY: 'auto', background: '#FFFFFF', color: '#0F172A', padding: '40px', borderRadius: '8px', boxShadow: '0 10px 30px rgba(0,0,0,0.08)', fontFamily: new_font_family, border: "1px solid #E2E8F0" }}>
                    <div style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '20px', borderBottom: "2px solid #E2E8F0", paddingBottom: "10px" }}>Sample Report Document</div>
                    <p style={{ lineHeight: '1.6', marginBottom: '25px', fontSize: "14px", color: "#334155" }}>This interactive preview accurately simulates your selected data grids and visual metrics. Hover over the elements to test interactivity.</p>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: new_selected_graphs.length > 1 ? '1fr 1fr' : '1fr', gap: '20px', marginBottom: '35px' }}>
                      {new_selected_graphs.map((new_gid) => (
                        <div key={new_gid} style={{ height: '180px', borderRadius: '8px', background: new_mock_palette.bg, border: `1px solid ${new_mock_palette.grid}`, padding: '15px', display: 'flex', flexDirection: 'column' }}>
                          <div style={{ fontSize: '12px', fontWeight: 'bold', color: new_mock_palette.text, marginBottom: '15px', textAlign: 'center' }}>
                            {new_available_graphs.find(g => g.id === new_gid)?.name || new_gid}
                          </div>
                          
                          {(new_gid === 'file_types') && (
                             <div className="mock-pie" style={{ width: '100px', height: '100px', borderRadius: '50%', background: `conic-gradient(${new_mock_palette.c1} 0% 40%, ${new_mock_palette.c2} 40% 75%, ${new_mock_palette.c4} 75% 90%, ${new_mock_palette.c3} 90% 100%)`, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <span style={{ color: '#FFF', fontSize: '12px', fontWeight: 'bold', textShadow: '0px 1px 3px rgba(0,0,0,0.6)' }}>40%</span>
                             </div>
                          )}
                          
                          {(new_gid === 'timeline') && (
                             <div className="mock-line-svg" style={{ flex: 1, borderBottom: `2px solid ${new_mock_palette.grid}`, borderLeft: `2px solid ${new_mock_palette.grid}`, position: 'relative' }}>
                                <svg viewBox="0 0 100 40" preserveAspectRatio="none" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
                                  <path d="M0,35 L20,25 L40,30 L60,10 L80,15 L100,5 L100,40 L0,40 Z" fill={new_mock_palette.c2} opacity="0.15" />
                                  <polyline className="mock-line-path" points="0,35 20,25 40,30 60,10 80,15 100,5" fill="none" stroke={new_mock_palette.c1} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                             </div>
                          )}
                          
                          {(new_gid === 'signals' || new_gid === 'scores' || new_gid === 'integrity' || new_gid === 'parse_errors' || new_gid === 'duckdb') && (
                             <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-around', gap: '8px', borderBottom: `2px solid ${new_mock_palette.grid}` }}>
                                <div className="mock-bar" style={{ width: '20%', height: '40%', background: new_mock_palette.c3, borderRadius: '3px 3px 0 0' }} />
                                <div className="mock-bar" style={{ width: '20%', height: '70%', background: new_mock_palette.c2, borderRadius: '3px 3px 0 0' }} />
                                <div className="mock-bar" style={{ width: '20%', height: '50%', background: new_mock_palette.c4, borderRadius: '3px 3px 0 0' }} />
                                <div className="mock-bar" style={{ width: '20%', height: '90%', background: new_mock_palette.c1, borderRadius: '3px 3px 0 0' }} />
                             </div>
                          )}

                          {(new_gid === 'top_entities') && (
                             <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'space-around', borderLeft: `2px solid ${new_mock_palette.grid}` }}>
                                <div className="mock-bar-horiz" style={{ width: '90%', height: '15px', background: new_mock_palette.c1, borderRadius: '0 3px 3px 0' }} />
                                <div className="mock-bar-horiz" style={{ width: '70%', height: '15px', background: new_mock_palette.c2, borderRadius: '0 3px 3px 0' }} />
                                <div className="mock-bar-horiz" style={{ width: '80%', height: '15px', background: new_mock_palette.c3, borderRadius: '0 3px 3px 0' }} />
                                <div className="mock-bar-horiz" style={{ width: '50%', height: '15px', background: new_mock_palette.c4, borderRadius: '0 3px 3px 0' }} />
                             </div>
                          )}
                        </div>
                      ))}
                    </div>

                    <div style={{ marginBottom: '15px', fontSize: '15px', fontWeight: 'bold', color: '#0F172A' }}>Extracted Telemetry Metrics</div>
                    <table className={`table-${new_table_style}`}>
                      <thead>
                        <tr>{['Target Entity', 'Observed Value', 'Verification'].map((new_h) => <th key={new_h}>{new_h}</th>)}</tr>
                      </thead>
                      <tbody>
                        <tr title="Hover test: This is a verified system artifact.">
                          <td>System Artifact ID</td>
                          <td>CASE-DEMO-2026</td>
                          <td style={{ color: "#10B981", fontWeight: "bold" }}>Verified</td>
                        </tr>
                        <tr title="Hover test: High-risk anomaly detected in lateral movement.">
                          <td>Threat Concentration</td>
                          <td>High-Risk Lateral Mvmt.</td>
                          <td style={{ color: "#EF4444", fontWeight: "bold" }}>Flagged</td>
                        </tr>
                        <tr title="Hover test: Hash chain remains intact across all jumps.">
                          <td>Data Continuity</td>
                          <td>Hash Chain Intact</td>
                          <td style={{ color: "#10B981", fontWeight: "bold" }}>Verified</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  <div style={{ flex: 1 }}>
                    <h3 style={{ marginBottom: "15px", color: "#0F172A" }}>Style Configuration</h3>
                    
                    <div style={{ display: 'flex', flexDirection: "column", gap: '10px', marginBottom: '30px' }}>
                      <div style={{ display: "flex", gap: "10px" }}>
                        <button onClick={() => setNewCustomTab('fonts')} style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_custom_tab === 'fonts' ? '#0284C7' : '#FFFFFF', color: new_custom_tab === 'fonts' ? '#FFF' : '#0F172A', fontWeight: 'bold' }}>Typography</button>
                        <button onClick={() => setNewCustomTab('graphs')} style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_custom_tab === 'graphs' ? '#0284C7' : '#FFFFFF', color: new_custom_tab === 'graphs' ? '#FFF' : '#0F172A', fontWeight: 'bold' }}>Visuals</button>
                        <button onClick={() => setNewCustomTab('tables')} style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_custom_tab === 'tables' ? '#0284C7' : '#FFFFFF', color: new_custom_tab === 'tables' ? '#FFF' : '#0F172A', fontWeight: 'bold' }}>Data Grids</button>
                      </div>

                      <div style={{ background: "#FFFFFF", border: "1px solid #E2E8F0", padding: "20px", borderRadius: "8px", display: "flex", flexDirection: "column", gap: "10px" }}>
                        {new_custom_tab === 'fonts' && (new_active_template_obj?.fonts || []).map((new_f) => <button key={new_f.id} onClick={() => setNewFontStyle(new_f.id)} style={{ padding: '12px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_font_style === new_f.id ? '#F1F5F9' : '#FFFFFF', color: '#0F172A', fontWeight: 'bold', textAlign: "left", display: "flex", justifyContent: "space-between" }}>{new_f.name} {new_font_style === new_f.id && <span style={{ color: "#0284C7" }}>✓</span>}</button>)}
                        
                        {new_custom_tab === 'graphs' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                                <div style={{ fontWeight: 'bold', color: '#0F172A', fontSize: '13px', borderBottom: '1px solid #E2E8F0', paddingBottom: '5px' }}>1. Base Palette Style</div>
                                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                                    {(new_active_template_obj?.graphs || []).map((new_g) => (
                                        <button key={new_g.id} onClick={() => setNewGraphStyle(new_g.id)} style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_graph_style === new_g.id ? '#F1F5F9' : '#FFFFFF', color: '#0F172A', fontWeight: 'bold', display: "flex", justifyContent: "space-between", alignItems: "center" }}>{new_g.name} {new_graph_style === new_g.id && <span style={{ color: "#0284C7" }}>✓</span>}</button>
                                    ))}
                                </div>
                                <div style={{ fontWeight: 'bold', color: '#0F172A', fontSize: '13px', borderBottom: '1px solid #E2E8F0', paddingBottom: '5px', marginTop: '5px', display: 'flex', justifyContent: 'space-between' }}>
                                    <span>2. Include Charts (Min 1, Max 5)</span>
                                    <span style={{ color: "#64748B" }}>{new_selected_graphs.length} / 5</span>
                                </div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                                    {new_available_graphs.map((new_g) => {
                                        const new_is_sel = new_selected_graphs.includes(new_g.id);
                                        return (
                                            <div key={new_g.id} onClick={() => new_toggle_graph(new_g.id)} style={{ padding: '10px', borderRadius: '6px', border: `1px solid ${new_is_sel ? '#0284C7' : '#E2E8F0'}`, cursor: 'pointer', background: new_is_sel ? '#F0F9FF' : '#F8FAFC', color: '#0F172A', fontSize: '12px', fontWeight: 'bold', display: "flex", alignItems: "center", gap: "8px", transition: '0.1s' }}>
                                                <div style={{ width: '16px', height: '16px', borderRadius: '4px', border: '1px solid #0284C7', background: new_is_sel ? '#0284C7' : '#FFF', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                                    {new_is_sel && <span style={{ color: '#FFF', fontSize: '10px' }}>✓</span>}
                                                </div>
                                                {new_g.name}
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}

                        {new_custom_tab === 'tables' && (new_active_template_obj?.tables || []).map((new_tb) => <button key={new_tb.id} onClick={() => setNewTableStyle(new_tb.id)} style={{ padding: '12px', borderRadius: '6px', border: '1px solid #CBD5E1', cursor: 'pointer', background: new_table_style === new_tb.id ? '#F1F5F9' : '#FFFFFF', color: '#0F172A', fontWeight: 'bold', textAlign: "left", display: "flex", justifyContent: "space-between" }}>{new_tb.name} {new_table_style === new_tb.id && <span style={{ color: "#0284C7" }}>✓</span>}</button>)}
                      </div>
                    </div>

                  </div>
                </div>
              </div>
            )}

            {(new_phase === 'writing' || (new_phase === 'done' && new_view_mode === 'html')) && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '30px', alignItems: 'center', paddingBottom: "40px" }}>
                
                {new_cover_img && (
                  <div style={{ width: '800px', height: '1130px', background: '#FFFFFF', padding: '20px', borderRadius: '4px', boxShadow: '0 10px 30px rgba(0,0,0,0.1)', border: "1px solid #CBD5E1", animation: "new_fadein 0.5s", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <img src={new_cover_img} alt="Cover Page" style={{ width: "100%", height: "100%", objectFit: "contain", borderRadius: "4px" }} />
                  </div>
                )}

                {new_display_pages.map((new_page, new_page_index) => {
                  const hasVisibleBlocks = new_stream_blocks.some(b => b.new_page_index === new_page_index && new_stream_blocks.indexOf(b) <= new_stream_index);
                  if (!hasVisibleBlocks && new_phase !== 'done') return null;

                  return (
                    <div key={new_page_index} style={{ width: '800px', minHeight: '1050px', background: '#FFFFFF', color: '#0F172A', padding: '60px', borderRadius: '4px', boxShadow: '0 10px 30px rgba(0,0,0,0.1)', fontFamily: new_font_family, border: "1px solid #CBD5E1", animation: "new_fadein 0.5s" }}>
                      
                      <div style={{ borderBottom: "1px solid #E2E8F0", paddingBottom: "10px", marginBottom: "30px", fontSize: "11px", color: "#64748B", display: "flex", justifyContent: "space-between", textTransform: "uppercase", letterSpacing: "1px", fontFamily: "Arial, sans-serif" }}>
                          <span>DYNAMITE DYNASTY ENGINE</span>
                          <span>RESTRICTED ACCESS</span>
                      </div>

                      {new_stream_blocks.map((new_block, new_block_index) => ({ ...new_block, new_block_index })).filter((new_block) => new_block.new_page_index === new_page_index).map((new_block) => {
                          const new_is_past = new_block.new_block_index < new_stream_index || new_phase === 'done';
                          const new_is_current = new_block.new_block_index === new_stream_index && new_phase !== 'done';
                          const new_is_visible = new_is_past || new_is_current;
                          if (!new_is_visible) return null;

                          if (new_block.new_type === 'title') {
                            const new_text = new_is_past ? new_block.new_text : (new_block.new_text || '').slice(0, new_stream_char);
                            return <h2 key={new_block.new_block_index} id={new_is_current ? "active-typing-block" : undefined} style={{ fontSize: '26px', marginBottom: '24px', lineHeight: '1.3', color: "#0F172A", borderBottom: "2px solid #F1F5F9", paddingBottom: "10px" }}>{new_text}{new_is_current ? <span style={{ animation: 'new_blink 0.8s infinite', borderRight: "2px solid #0284C7" }}></span> : null}</h2>;
                          }

                          if (new_block.new_type === 'paragraph') {
                            const new_text = new_is_past ? new_block.new_text : (new_block.new_text || '').slice(0, new_stream_char);
                            return <p key={new_block.new_block_index} id={new_is_current ? "active-typing-block" : undefined} style={{ lineHeight: '1.8', marginBottom: '16px', fontSize: '14px', textAlign: 'justify', color: "#334155" }}>{new_text}{new_is_current ? <span style={{ animation: 'new_blink 0.8s infinite', borderRight: "2px solid #0284C7" }}></span> : null}</p>;
                          }

                          if (new_block.new_type === 'chart') {
                            const new_chartData = new_block.new_chart;
                            if (!new_chartData) return null;
                            const new_isRecharts = new_chartData.data && new_chartData.data.length > 0;
                            const new_colors = new_mock_palette.colors;

                            return (
                              <div key={new_block.new_block_index} id={new_is_current ? "active-typing-block" : undefined} style={{ border: "1px solid #E2E8F0", padding: "20px", borderRadius: "8px", margin: "25px 0", background: new_mock_palette.bg, animation: "new_fadein 0.5s", height: "400px", width: "100%" }}>
                                {new_isRecharts ? (
                                  <ResponsiveContainer width="100%" height="100%">
                                    {new_chartData.type === 'pie' ? (
                                      (() => {
                                        const new_proc = [...(new_chartData.data || [])].sort((a, b) => b.value - a.value);
                                        const new_oth_idx = new_proc.findIndex(d => String(d.name).toLowerCase() === 'other');
                                        if (new_oth_idx !== -1) {
                                            new_proc.push(new_proc.splice(new_oth_idx, 1)[ 0 ]);
                                        }
                                        const new_total = new_proc.reduce((sum, item) => sum + item.value, 0) || 1;
                                        return (
                                          <PieChart>
                                            <Tooltip contentStyle={{ backgroundColor: new_mock_palette.bg, color: new_mock_palette.text, borderRadius: "8px", border: `1px solid ${new_mock_palette.grid}` }} formatter={(value, name) => [`${value} (${((Number(value) / new_total) * 100).toFixed(1)}%)`, name]} />
                                            <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: '12px', fontWeight: 'bold', color: new_mock_palette.text }} iconType="circle" />
                                            <Pie 
                                                data={new_proc} 
                                                dataKey="value" 
                                                nameKey="name" 
                                                cx="50%" 
                                                cy="50%" 
                                                outerRadius={140}
                                                startAngle={220}
                                                endAngle={-140} 
                                                stroke={new_mock_palette.bg} 
                                                strokeWidth={2}
                                                labelLine={false}
                                                label={new_render_custom_label}
                                                {...({
                                                    activeIndex: new_pie_active_idx,
                                                    activeShape: new_render_active_shape,
                                                    onMouseEnter: (_: any, index: number) => setNewPieActiveIndex(index),
                                                    onMouseLeave: () => setNewPieActiveIndex(undefined)
                                                } as any)}
                                            >
                                              {new_proc.map((entry, index) => <Cell key={`cell-${index}`} fill={new_colors[ index % new_colors.length ]} style={{ outline: 'none', cursor: 'pointer' }} />)}
                                            </Pie>
                                          </PieChart>
                                        );
                                      })()
                                    ) : new_chartData.type === 'line' ? (
                                      <LineChart data={new_chartData.data}>
                                        <CartesianGrid strokeDasharray="3 3" stroke={new_mock_palette.grid} />
                                        <XAxis dataKey="name" stroke="#64748B" fontSize={12} />
                                        <YAxis stroke="#64748B" fontSize={12} />
                                        <Tooltip contentStyle={{ backgroundColor: new_mock_palette.bg, color: new_mock_palette.text, borderRadius: "8px", border: `1px solid ${new_mock_palette.grid}` }} />
                                        <Line type="monotone" dataKey="value" stroke={new_colors[ 0 ]} strokeWidth={3} dot={{ r: 4 }} activeDot={{ r: 8 }} />
                                      </LineChart>
                                    ) : new_chartData.type === 'horizontal_bar' ? (
                                      <BarChart data={new_chartData.data} layout="vertical">
                                        <CartesianGrid strokeDasharray="3 3" stroke={new_mock_palette.grid} horizontal={true} vertical={false} />
                                        <XAxis type="number" stroke="#64748B" fontSize={12} />
                                        <YAxis dataKey="name" type="category" stroke="#64748B" fontSize={10} width={120} />
                                        <Tooltip cursor={{ fill: 'rgba(0,0,0,0.05)' }} contentStyle={{ backgroundColor: new_mock_palette.bg, color: new_mock_palette.text, borderRadius: "8px", border: `1px solid ${new_mock_palette.grid}` }} />
                                        <Bar dataKey="value" fill={new_colors[ 1 ]} radius={[0, 4, 4, 0]}>
                                          {new_chartData.data?.map((entry, index) => <Cell key={`cell-${index}`} fill={new_colors[ index % new_colors.length ]} />)}
                                        </Bar>
                                      </BarChart>
                                    ) : (
                                      <BarChart data={new_chartData.data}>
                                        <CartesianGrid strokeDasharray="3 3" stroke={new_mock_palette.grid} vertical={false} />
                                        <XAxis dataKey="name" stroke="#64748B" fontSize={10} angle={-35} textAnchor="end" height={60} />
                                        <YAxis stroke="#64748B" fontSize={12} />
                                        <Tooltip cursor={{ fill: 'rgba(0,0,0,0.05)' }} contentStyle={{ backgroundColor: new_mock_palette.bg, color: new_mock_palette.text, borderRadius: "8px", border: `1px solid ${new_mock_palette.grid}` }} />
                                        <Bar dataKey="value" fill={new_colors[ 0 ]} radius={[4, 4, 0, 0]}>
                                          {new_chartData.data?.map((entry, index) => <Cell key={`cell-${index}`} fill={new_colors[ index % new_colors.length ]} />)}
                                        </Bar>
                                      </BarChart>
                                    )}
                                  </ResponsiveContainer>
                                ) : (
                                  <img className="generated-chart-img" src={`data:image/png;base64,${new_chartData.b64}`} alt="chart" title="AI-Generated Matplotlib Data Snapshot" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
                                )}
                              </div>
                            );
                          }

                          if (new_block.new_type === 'table') {
                            const new_tb = new_block.new_table;
                            return (
                              <div key={new_block.new_block_index} id={new_is_current ? "active-typing-block" : undefined} style={{ margin: '25px 0', overflowX: 'auto', animation: "new_fadein 0.5s" }}>
                                <div style={{ fontWeight: 'bold', marginBottom: '12px', color: "#0F172A", fontSize: "15px" }}>{new_tb?.title}</div>
                                <table className={`table-${new_table_style}`}>
                                  <thead><tr>{(new_tb?.columns || []).map((new_col, new_k) => <th key={new_k}>{new_col}</th>)}</tr></thead>
                                  <tbody>
                                    {(new_tb?.rows || []).map((new_row, new_k) => (
                                      <tr key={new_k} title={`Entity Data for: ${new_row[ 0 ]}\nThis row represents correlated telemetry extracted by the core engine.`}>
                                        {new_row.map((new_cell, new_m) => <td key={new_m}>{new_cell}</td>)}
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            );
                          }

                          if (new_block.new_type === 'list') {
                            const new_ls = new_block.new_list;
                            return (
                              <div key={new_block.new_block_index} id={new_is_current ? "active-typing-block" : undefined} style={{ margin: '20px 0', animation: "new_fadein 0.5s" }}>
                                <div style={{ fontWeight: 'bold', marginBottom: '10px', color: "#0F172A", fontSize: "15px" }}>{new_ls?.title}</div>
                                <ul style={{ paddingLeft: "20px" }}>{(new_ls?.items || []).map((new_item, new_k) => <li key={new_k} style={{ marginBottom: '8px', color: "#334155", lineHeight: "1.6" }}>{new_item}</li>)}</ul>
                              </div>
                            );
                          }
                          return null;
                        })}

                      <div style={{ borderTop: "1px solid #E2E8F0", paddingTop: "10px", marginTop: "40px", fontSize: "11px", color: "#64748B", textAlign: "center", fontFamily: "Arial, sans-serif" }}>
                          Page {new_page_index + 1}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {new_phase === 'compiling' && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", width: "100%" }}>
                <div style={{ padding: '80px', textAlign: 'center', background: '#FFFFFF', borderRadius: '12px', boxShadow: '0 10px 40px rgba(0,0,0,0.08)', border: "1px solid #E2E8F0" }}>
                  <div style={{ width: '60px', height: '60px', border: '5px solid #F1F5F9', borderTop: '5px solid #0284C7', borderRadius: '50%', margin: '0 auto 25px auto', animation: 'new_spin 1s linear infinite' }} />
                  <h2 style={{ color: '#0F172A', marginBottom: '15px', fontSize: "24px" }}>Compiling Enterprise Dossier</h2>
                  <p style={{ color: '#64748B', fontSize: '15px', fontWeight: "bold" }}>Applying visual assets, layouts, and sealing the immutable ledger.</p>
                </div>
              </div>
            )}

            {new_phase === 'done' && new_view_mode === 'pdf' && new_pdf_url && (
                <div style={{ width: "100%", maxWidth: "1000px", animation: "new_fadein 0.5s" }}>
                    <iframe src={`${new_pdf_url}#toolbar=0&navpanes=0&scrollbar=0&view=FitH`} style={{ width: '100%', height: '80vh', border: '1px solid #CBD5E1', borderRadius: '8px', background: '#F8FAFC', boxShadow: '0 10px 40px rgba(0,0,0,0.15)' }} />
                </div>
            )}

          </div>
        </div>
      </div>

      <div style={{ width: "320px", backgroundColor: "#FFFFFF", borderLeft: "1px solid #E2E8F0", display: "flex", flexDirection: "column", padding: "30px", boxShadow: "-2px 0 10px rgba(0,0,0,0.02)", zIndex: 10 }}>
        <h3 style={{ fontSize: "16px", color: "#0F172A", marginBottom: "25px", borderBottom: "1px solid #E2E8F0", paddingBottom: "15px" }}>Generation Insights</h3>
        
        <div style={{ display: "flex", flexWrap: "wrap", gap: "15px", marginBottom: "40px" }}>
            <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
                <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Word Count</div>
                <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{new_phase === 'writing' ? Math.floor(new_stream_index * 15.5) : new_phase === 'done' ? Math.floor(new_stream_blocks.length * 15.5) : 0}</div>
            </div>
            <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
                <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Pages Drafted</div>
                <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{new_phase === 'done' ? new_total_actual_pages : new_phase === 'compiling' ? Math.max(1, new_total_actual_pages - 2) : new_phase === 'writing' ? Math.min(new_total_actual_pages, Math.ceil(new_stream_index / 8)) : 0}</div>
            </div>
            <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
                <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Visuals</div>
                <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{new_stream_index > 25 ? new_selected_graphs.length : new_stream_index > 15 ? Math.min(2, new_selected_graphs.length) : 0}</div>
            </div>
            <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
                <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Sources</div>
                <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{new_phase !== 'idle' ? 19 : 0}</div>
            </div>
        </div>

        <h3 style={{ fontSize: "13px", color: "#64748B", marginBottom: "20px", textTransform: "uppercase", letterSpacing: "1px", fontWeight: "bold" }}>Live Activity Log</h3>
        <div style={{ flexGrow: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "15px", fontSize: "13px", color: "#334155", fontWeight: "bold" }}>
            {new_phase !== 'idle' && <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#0284C7" }}>•</span> Structuring Executive Summary...</div>}
            {new_stream_index > 5 && <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#0284C7" }}>•</span> Formatting Telemetry Data...</div>}
            {new_stream_index > 12 && <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Rendering Data Visualizations...</div>}
            {new_stream_index > 20 && <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Parsing Anomaly Threat Metrics...</div>}
            {new_phase === 'compiling' || new_phase === 'done' ? <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#F59E0B" }}>•</span> Compiling remaining {new_total_actual_pages > 5 ? new_total_actual_pages - 5 : 0} pages...</div> : null}
            {new_phase === 'done' && <div style={{ display: "flex", gap: "10px", animation: "new_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Official PDF payload packaged successfully.</div>}
        </div>
      </div>

    </div>
  );
}