import json
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="IDS Dashboard")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
ALERTS_FILE = os.path.join(PROJECT_ROOT, "ids_alerts.json")

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    alerts = load_alerts()

    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("score", 0) >= 70)
    inbound = sum(1 for a in alerts if a.get("direction") == "INBOUND")
    outbound = sum(1 for a in alerts if a.get("direction") == "OUTBOUND")

    return templates.TemplateResponse(
        "overview.html",
        {
            "request": request,
            "total": total,
            "critical": critical,
            "inbound": inbound,
            "outbound": outbound,
        },
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    alerts = load_alerts()
    alerts = sorted(alerts, key=lambda a: a.get("timestamp", 0), reverse=True)

    return templates.TemplateResponse(
        "alerts.html",
        {"request": request, "alerts": alerts},
    )


@app.get("/alerts/{idx}", response_class=HTMLResponse)
def alert_detail(request: Request, idx: int):
    alerts = load_alerts()
    alerts = sorted(alerts, key=lambda a: a.get("timestamp", 0), reverse=True)

    if idx < 0 or idx >= len(alerts):
        return HTMLResponse("Alert not found", status_code=404)

    return templates.TemplateResponse(
        "alert_detail.html",
        {
            "request": request,
            "alert": alerts[idx],
            "idx": idx,
        },
    )
from fastapi.responses import JSONResponse

@app.get("/api/alerts")
def api_alerts():
    alerts = load_alerts()
    alerts = sorted(alerts, key=lambda a: a.get("timestamp", 0), reverse=True)
    return JSONResponse(alerts)

