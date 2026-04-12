import re
with open(r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace dummy template state with fetched state
target_state = \"\"\"  const [new_templates] = useState([
    {
      id: "tp1", name: "Midnight Executive", thumbnail: "/templates/template_1/thumb.png",
      covers: [{ id: "1", name: "Cover 1", image: "/templates/template_1/thumb.png" }, { id: "2", name: "Cover 2", image: "/templates/template_2/thumb.png" }],
      fonts: [{ id: "times", name: "Times New Roman" }, { id: "arial", name: "Arial Classic" }],
      graphs: [{ id: "classic", name: "Classic" }, { id: "modern", name: "Modern Dark" }],
      tables: [{ id: "clean", name: "Clean Minimal" }]
    }
  ]);
  const [new_selected_template, setNewSelectedTemplate] = useState('tp1');
  const [new_selected_cover, setNewSelectedCover] = useState('1');\"\"\"

new_state = \"\"\"  const [new_templates, setNewTemplates] = useState<any[]>([]);
  const [new_selected_template, setNewSelectedTemplate] = useState('');
  const [new_selected_cover, setNewSelectedCover] = useState('');

  useEffect(() => {
    fetch('http://localhost:8001/api/report/templates')
      .then(res => res.json())
      .then(data => {
        const list = data.templates || [];
        setNewTemplates(list);
        if (list.length > 0) {
          setNewSelectedTemplate(list[0].id);
          setNewFontStyle(list[0].fonts?.[0]?.id || 'times');
          setNewGraphStyle(list[0].graphs?.[0]?.id || 'classic');
          setNewTableStyle(list[0].tables?.[0]?.id || 'clean');
        }
      })
      .catch(console.error);
  }, []);

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

  const new_active_template_obj = useMemo(() => new_templates.find(t => t.id === new_selected_template), [new_templates, new_selected_template]);
\"\"\"
text = text.replace(target_state, new_state)

with open(r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx', 'w', encoding='utf-8') as f:
    f.write(text)
