from __future__ import annotations
from pathlib import Path
import html, re, shutil, subprocess, sys

repo = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
poster = repo / "poster"
brief = poster / "01_research_brief.md"
metrics_path = poster / "03_verified_metrics.md"
text = brief.read_text(encoding="utf-8", errors="replace")
metrics_text = metrics_path.read_text(encoding="utf-8", errors="replace") if metrics_path.exists() else ""

def clean(s: str) -> str:
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = s.replace("**","").replace("`","").replace("\u2014","-").replace("\u2013","-").replace("\u2192","->")
    return re.sub(r"\s+", " ", s).strip()

def sec(*names: str) -> str:
    for name in names:
        m = re.search(r"(?ms)^##+\s+" + re.escape(name) + r"\s*$\n(.*?)(?=^##+\s+|\Z)", text)
        if m:
            return m.group(1).strip()
    return ""

def items(block: str) -> list[str]:
    out=[]
    for line in block.splitlines():
        m=re.match(r"^\s*(?:[-*]|\d+\.)\s+(.*)", line)
        if m:
            v=clean(m.group(1))
            if v:
                out.append(v)
    return out

def reproducibility_text(s: str) -> str:
    blocks = re.findall(r"(?ms)```(?:[A-Za-z0-9_-]+)?\n(.*?)```", s)
    outside = re.sub(r"(?ms)```.*?```", "", s)
    parts = []
    if blocks:
        parts.append("\n".join(line.rstrip() for line in blocks[0].strip().splitlines()))
    prose = clean(outside)
    if prose:
        parts.append(prose)
    return "\n\n".join(parts).strip()

title = clean(sec("Academic Project Title","Project Title")) or repo.name.replace("-"," ").title()
subtitle = clean(sec("Subtitle"))
contribution = clean(sec("One-Sentence Contribution","Contribution","Research Contribution"))
methods = items(sec("Method","Methodology"))[:6]
evidence = items(sec("Current Verified Evidence","Verified Evidence","Evidence at Poster Snapshot + Claim Ledger"))[:7]
limits = items(sec("Honest Boundaries","Limitations","Limitations & Residual Risk"))[:6]
repro = reproducibility_text(sec("Reproducibility"))[:900]
repository = clean(sec("Repository")) or f"github.com/poojakira/{repo.name}"

metrics=[]
headline_match=re.search(r"(?ms)^##+\s+Headline cards\s*$\n(.*?)(?=^##+\s+|\Z)", metrics_text)
if headline_match:
    for line in headline_match.group(1).splitlines():
        m=re.match(r"^\s*[-*]\s+(.+?)\s+(?:\u2014|\u2013|-)\s+(.+?)\s*$", line)
        if m:
            value,label=clean(m.group(1)),clean(m.group(2))
            if value and label:
                metrics.append((label,value))
for line in metrics_text.splitlines():
    if not line.strip().startswith("|") or "---" in line:
        continue
    cells=[clean(c) for c in line.strip().strip("|").split("|")]
    if len(cells)<2:
        continue
    k,v=cells[0],cells[1]
    if k.lower() in {"metric","current value","value","item","claim"}:
        continue
    if not k or not v or (k,v) in metrics:
        continue
    metrics.append((k,v))
primary_metrics=metrics[:4]
extra_metrics=metrics[4:]
if extra_metrics:
    evidence=(evidence[:5] + [f"{k}: {v}" for k,v in extra_metrics[:3]])[:8]

if not methods:
    methods=["Inspect the trust boundary","Apply repository-specific security checks","Record reproducible evidence"]
if not evidence:
    evidence=["See README, verified metrics, tests, and CI for the current evidence snapshot."]
if not limits:
    limits=["No additional limitations section is present in the research brief; consult the README before generalizing results."]
if not repro:
    repro="Clone the repository, check out the evidence snapshot, install documented dependencies, and run the repository test commands from the README."

def esc(s: str) -> str:
    return html.escape(s, quote=True)

def bullets(xs: list[str]) -> str:
    return "<ul>" + "".join("<li>"+esc(x)+"</li>" for x in xs) + "</ul>"

metric_cards="".join(
    '<div class="metric"><div class="mv">'+esc(v)+'</div><div class="ml">'+esc(k)+'</div></div>'
    for k,v in primary_metrics
)
if not metric_cards:
    metric_cards='<div class="metric"><div class="mv">Verified</div><div class="ml">Repository evidence</div></div>'

flow_html=""
for i,m in enumerate(methods,1):
    flow_html += f'<div class="flow-node"><div class="step">{i:02d}</div><div class="flow-text">{esc(m)}</div></div>'

css = r"""
@page { size: 36in 48in; margin: 0; }
* { box-sizing: border-box; }
html, body { margin: 0; width: 36in; height: 48in; font-family: "Segoe UI", Arial, sans-serif; background: #eef3f7; color: #11263d; }
.poster { width: 36in; height: 48in; overflow: hidden; background: #eef3f7; }
.hero {
  height: 5.6in; padding: .72in 1.15in .62in 1.15in; color: #fff;
  background: linear-gradient(118deg,#07182f 0%,#0a3558 58%,#0b6281 100%);
  border-bottom: .10in solid #23a2c4;
}
.kicker { font-size: 17pt; letter-spacing: 2.4px; text-transform: uppercase; color: #86e5f8; font-weight: 800; }
h1 { font-size: 46pt; line-height: 1.04; margin: .12in 0 .12in; max-width: 33in; font-weight: 750; text-wrap: balance; overflow-wrap: anywhere; hyphens: auto; }
.sub { font-size: 24pt; line-height: 1.2; color: #d8f0f6; max-width: 32.5in; }
.repo { font-size: 14.5pt; color: #93def0; margin-top: .22in; white-space: normal; }

.metrics {
  height: 3.7in; padding: .45in 1.15in; display: grid;
  grid-template-columns: repeat(4, 1fr); gap: .28in; background: #f8fbfd;
  border-bottom: 2px solid #d2e0e9;
}
.metric {
  background: #fff; border: 2px solid #cddde8; border-top: 9px solid #1683aa;
  border-radius: .15in; display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: .20in;
}
.mv { font-size: 28pt; font-weight: 800; color: #0d446f; text-align: center; line-height: 1.1; }
.ml { font-size: 13pt; font-weight: 700; color: #556a7f; text-align: center; margin-top: .09in; line-height: 1.2; }

.top {
  height: 8.4in; padding: .50in 1.15in .40in; display: grid; grid-template-columns: 1.05fr 1.7fr; gap: .42in;
}
.arch {
  height: 10in; padding: .50in 1.15in .55in; background: #0b2239; color: #fff;
  border-top: .06in solid #22a3c5; border-bottom: .06in solid #22a3c5;
}
.lower {
  height: 16.7in; padding: .55in 1.15in; display: grid; grid-template-columns: 1.35fr .85fr; gap: .42in;
}
.footer {
  height: 3.6in; padding: .60in 1.15in; background: #07182f; color: #d9e7ef;
  display: grid; grid-template-columns: 2.5fr 1fr; gap: .5in; align-items: center;
}

.card {
  height: 100%; background: #fff; border: 2px solid #d3e0e9; border-radius: .16in; padding: .36in .42in;
  box-shadow: 0 5px 18px rgba(6,34,56,.06);
}
.card h2, .arch h2 {
  font-size: 23pt; margin: 0 0 .16in; color: #0b547f; padding-bottom: .08in;
  border-bottom: 4px solid #35a8c6;
}
.arch h2 { color: #8ce9fa; border-bottom-color: #2d93b1; }
.contrib { background: #eaf8fb; border-color: #96d9e8; }
.contrib p { font-size: 21pt; line-height: 1.34; font-weight: 600; margin: .08in 0 0; }
.card p, .card li { font-size: 19pt; line-height: 1.30; }
.card ul { margin: .04in 0 0 .28in; padding: 0; }
.card li { margin: .08in 0; }
.evidence { border-left: 10px solid #178e75; }
.limits { border-left: 10px solid #bd7a35; }
.method { border-left: 10px solid #1683aa; }

.flow-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); grid-auto-rows: minmax(2.15in, auto);
  gap: .30in .34in; margin-top: .30in;
}
.flow-node {
  position: relative; border: 2px solid #2c7899; background: linear-gradient(145deg,#102d48,#123b59);
  border-radius: .16in; padding: .27in .30in .25in .84in; min-height: 2.15in; display: flex; align-items: center;
}
.step {
  position: absolute; left: .24in; top: .25in; width: .46in; height: .46in; border-radius: 50%;
  background: #28a6c7; color: #061a2b; font-size: 14pt; font-weight: 900; display:flex; align-items:center; justify-content:center;
}
.flow-text { font-size: 18pt; line-height: 1.28; font-weight: 650; color: #eef9fc; }
.flow-node::after { content: "\2192"; position:absolute; right:-.30in; top:50%; transform:translateY(-50%); color:#6fd2e9; font-size:24pt; font-weight:900; z-index:4; }
.flow-node:nth-child(3n)::after { content:""; }
.flow-node:nth-child(3)::after { content:"\2193"; right:50%; top:auto; bottom:-.43in; transform:translateX(50%); }
.arch-note { font-size: 13.5pt; color: #a9dcea; margin-top: .30in; }

.method-list { display: grid; grid-template-columns: 1fr 1fr; gap: .20in .28in; margin-top: .10in; }
.method-chip { background:#f3f8fb; border:2px solid #d2e2eb; border-radius:.12in; padding:.20in .22in; font-size:18pt; line-height:1.28; font-weight:650; }
.right-stack { display:grid; grid-template-rows: 1.05fr .95fr; gap:.40in; height:100%; }
.repro { background:#f8fbfd; }
.repro p { font-family: "Cascadia Mono","Consolas",monospace; font-size: 16.5pt; line-height: 1.30; color:#22384d; word-break: break-word; white-space: pre-wrap; }

.footer h3 { font-size: 19pt; color: #86e5f8; margin: 0 0 .08in; }
.footer p { font-size: 13.5pt; line-height: 1.36; margin: 0; }
.badge { justify-self: end; border: 2px solid #4aa9c6; border-radius: .14in; padding: .22in .28in; text-align:center; font-size:13pt; font-weight:800; color:#fff; }
"""

method_chips="".join('<div class="method-chip">'+esc(m)+'</div>' for m in methods)

doc='<!doctype html><html><head><meta charset="utf-8"><style>'+css+'</style></head><body><div class="poster">'
doc+='<section class="hero"><div class="kicker">Security Engineering Research Poster</div><h1>'+esc(title)+'</h1><div class="sub">'+esc(subtitle)+'</div><div class="repo">'+esc(repository)+'</div></section>'
doc+='<section class="metrics">'+metric_cards+'</section>'
doc+='<section class="top"><div class="card contrib"><h2>Contribution</h2><p>'+esc(contribution or "Repository contribution documented in the research brief.")+'</p></div><div class="card evidence"><h2>Verified Evidence</h2>'+bullets(evidence)+'</div></section>'
doc+='<section class="arch"><h2>Architecture / Threat Flow</h2><div class="flow-grid">'+flow_html+'</div><div class="arch-note">Flow labels come directly from the repository research brief. They describe the tested control path, not a universal security guarantee.</div></section>'
doc+='<section class="lower"><div class="card method"><h2>Methodology and Control Path</h2><div class="method-list">'+method_chips+'</div></div><div class="right-stack"><div class="card limits"><h2>Limitations and Residual Risk</h2>'+bullets(limits)+'</div><div class="card repro"><h2>Reproducibility</h2><p>'+esc(repro)+'</p></div></div></section>'
doc+='<footer class="footer"><div><h3>Evidence-backed security engineering</h3><p>Poster claims are constrained to the repository evidence snapshot. README, verified metrics, tests, CI, and committed artifacts remain authoritative.</p></div><div class="badge">36 x 48 in<br>Full-page PDF + PNG</div></footer>'
doc+='</div></body></html>'

html_path=poster/"_poster_render.html"
html_path.write_text(doc,encoding="utf-8")
browsers=[
 Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
 Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
 Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
]
browser=next((p for p in browsers if p.exists()),None)
if browser is None:
    raise SystemExit("browser not found")

pdf=poster/"poster_36x48.pdf"
png=poster/"poster.png"
profile=poster/"_poster_profile"
shutil.rmtree(profile,ignore_errors=True)
uri=html_path.resolve().as_uri()
subprocess.run([
 str(browser),"--headless=new","--disable-gpu",f"--user-data-dir={profile}",
 "--no-pdf-header-footer",f"--print-to-pdf={pdf}",uri
],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

try:
    import fitz
except Exception as exc:
    raise SystemExit(f"PyMuPDF is required for full-page PNG parity: {exc}")

doc_pdf=fitz.open(pdf)
page=doc_pdf[0]
target_w=1800
scale=target_w/page.rect.width
pix=page.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
pix.save(png)
doc_pdf.close()

html_path.unlink(missing_ok=True)
shutil.rmtree(profile,ignore_errors=True)
if repo.name=="mcp-agent-security-gateway":
    shutil.copy2(pdf,repo/"MCP_Gateway_Poster.pdf")
print(repo.name, "pdf_bytes=",pdf.stat().st_size,"png_bytes=",png.stat().st_size)
