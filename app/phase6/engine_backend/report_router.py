import os
import uuid
from typing import Any, Dict, Optional, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .forensic_engine import build_report_preview, generate_forensic_report
from .template_config import TEMPLATES

router = APIRouter(prefix="/api/report", tags=["report"])

BASE_DIR = os.path.dirname(__file__)
GEN_DIR = os.path.join(BASE_DIR, "generated_reports")
os.makedirs(GEN_DIR, exist_ok=True)

class ReportRequest(BaseModel):
    payload: Dict[str, Any]
    template_id: str = "template_1"
    cover_id: Optional[str] = None
    report_title: Optional[str] = None
    font_style: Optional[str] = "times"
    graph_style: Optional[str] = "classic"
    table_style: Optional[str] = "clean"
    selected_graphs: Optional[List[str]] = None  # <--- THE MSQ INJECTION

@router.get("/templates")
def get_templates():
    return {"templates": list(TEMPLATES.values())}

@router.post("/preview")
def preview_report(data: ReportRequest):
    raw = data.payload if isinstance(data.payload, dict) else {}
    template = TEMPLATES.get(data.template_id, TEMPLATES["template_1"])
    preview = build_report_preview(raw, new_gstyle=data.graph_style, selected_graphs=data.selected_graphs)

    return {
        "ok": True,
        "template": template,
        "selected": {
            "font_style": data.font_style,
            "graph_style": data.graph_style,
            "table_style": data.table_style,
            "selected_graphs": data.selected_graphs
        },
        "preview": preview,
    }

@router.post("/generate")
def generate_report(data: ReportRequest):
    raw = data.payload if isinstance(data.payload, dict) else {}
    template = TEMPLATES.get(data.template_id, TEMPLATES["template_1"])

    cover_path = None
    if data.cover_id:
        for c in template.get("covers", []):
            if c["id"] == data.cover_id:
                img_suffix = c["image"].lstrip("/")
                possible_dirs = [
                    os.path.abspath(os.path.join(BASE_DIR, "..", "engine_frontend", "public")),
                    os.path.abspath(os.path.join(BASE_DIR, "..", "public")),
                    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "engine_frontend", "public")),
                ]
                for d in possible_dirs:
                    p = os.path.join(d, img_suffix)
                    if os.path.exists(p):
                        cover_path = p
                        break
                break

    case_id = raw.get("case_id", "CASE-UNKNOWN")
    safe_case_id = "".join(c for c in str(case_id) if c.isalnum() or c in ("-", "_"))
    file_id = uuid.uuid4().hex[:8]
    filename = f"FULL_REPORT_{safe_case_id}_{file_id}.pdf"
    output_path = os.path.join(GEN_DIR, filename)

    try:
        generate_forensic_report(
            raw_data_object=raw,
            custom_color=template.get("color", "#003366"),
            output_path=output_path,
            cover_path=cover_path,
            new_gstyle=data.graph_style,
            selected_graphs=data.selected_graphs  # <--- WIRING IT IN
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "ok": True,
        "filename": filename,
        "pdf_url": f"/api/report/files/{filename}",
    }

@router.get("/files/{filename}")
def get_report_file(filename: str, download: bool = False):
    file_path = os.path.join(GEN_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    disp = "attachment" if download else "inline"
    return FileResponse(
        file_path,
        media_type="application/pdf",
        headers={"Content-Disposition": f"{disp}; filename={filename}"}
    )