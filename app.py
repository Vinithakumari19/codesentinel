
import streamlit as st
import ast
import io
import re
import json
import zipfile
import requests
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse

st.set_page_config(
    page_title="CodeSentinel | Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- BRANDING ----------------

LOGO = """
<svg width="48" height="48" viewBox="0 0 100 100"
 xmlns="http://www.w3.org/2000/svg">
 <defs>
  <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
   <stop offset="0%" stop-color="#20D9FF"/>
   <stop offset="55%" stop-color="#536DFF"/>
   <stop offset="100%" stop-color="#B45CFF"/>
  </linearGradient>
 </defs>
 <path d="M50 5 L88 25 L88 57 Q80 82 50 95
          Q20 82 12 57 L12 25 Z"
       fill="none" stroke="url(#g)" stroke-width="6"/>
 <path d="M18 50 Q50 17 82 50 Q50 83 18 50Z"
       fill="none" stroke="url(#g)" stroke-width="5"/>
 <circle cx="50" cy="50" r="14"
         fill="none" stroke="#22D9FF" stroke-width="5"/>
 <circle cx="50" cy="50" r="5" fill="#FFFFFF"/>
</svg>
"""

st.markdown("""
<style>
.stApp {
    background: #050B18;
    color: #EAF2FF;
}
[data-testid="stSidebar"] {
    background: #081326;
    border-right: 1px solid #172B50;
}
h1, h2, h3 {
    color: #F2F6FF !important;
}
p, label, li {
    color: #B8C8E5;
}
div.stButton > button {
    background: linear-gradient(100deg,#743DFF,#078CFF);
    color: white;
    border: 0;
    border-radius: 9px;
    font-weight: 700;
    min-height: 42px;
}
div.stButton > button:hover {
    border: 1px solid #39D9FF;
    color: white;
}
div[data-testid="stMetric"] {
    background: #0D1B34;
    border: 1px solid #1D3763;
    padding: 17px;
    border-radius: 12px;
}
div[data-testid="stFileUploader"] {
    background: #0B1830;
    border: 1px dashed #3978D8;
    border-radius: 12px;
    padding: 12px;
}
.cs-card {
    background: linear-gradient(145deg,#101E3A,#091329);
    border: 1px solid #203D70;
    border-radius: 15px;
    padding: 22px;
    margin-bottom: 15px;
}
.cs-muted { color: #9CB0D1; }
.cs-gradient {
    background: linear-gradient(90deg,#20D9FF,#7880FF,#B45CFF);
    -webkit-background-clip: text;
    color: transparent;
}
</style>
""", unsafe_allow_html=True)


def brand():
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:12px;">'
        f'{LOGO}<span style="font-size:27px;font-weight:800;">'
        f'Code<span class="cs-gradient">Sentinel</span></span></div>',
        unsafe_allow_html=True
    )


def card(title, description):
    st.markdown(
        f'<div class="cs-card"><h3>{title}</h3>'
        f'<p class="cs-muted">{description}</p></div>',
        unsafe_allow_html=True
    )


# ---------------- CODE ANALYSIS ----------------

def analyze_code(filename, source):
    findings = []
    score = 0
    metrics = Counter()

    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return {
            "score": 0,
            "findings": [{
                "severity": "INFO",
                "title": "Could not parse this file",
                "detail": f"Python syntax error near line {error.lineno}.",
                "fix": "Check the Python syntax and scan again."
            }],
            "metrics": {},
            "lines": len(source.splitlines()),
            "functions": 0
        }

    lines = source.splitlines()

    # Broad exception handling and empty handlers
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                metrics["Broad exception handling"] += 1
                score += 8
                findings.append({
                    "severity": "HIGH",
                    "title": "Bare exception handler",
                    "detail": f"An exception is caught without specifying its type in {filename}, line {node.lineno}.",
                    "fix": "Catch specific exception types instead of catching every exception."
                })

            if isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
                metrics["Broad exception handling"] += 1
                score += 6
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Broad exception handling",
                    "detail": f"A broad exception type is used in {filename}, line {node.lineno}.",
                    "fix": "Catch only the exceptions that the code is expected to handle."
                })

            if any(isinstance(item, ast.Pass) for item in node.body):
                metrics["Empty exception handlers"] += 1
                score += 10
                findings.append({
                    "severity": "HIGH",
                    "title": "Empty exception handler",
                    "detail": f"An exception is silently ignored in {filename}, line {node.lineno}.",
                    "fix": "Log the error or handle it explicitly."
                })

        # Dangerous dynamic execution
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                metrics["Dynamic execution"] += 1
                score += 15
                findings.append({
                    "severity": "HIGH",
                    "title": f"Use of {node.func.id}()",
                    "detail": f"Dynamic code execution was found in {filename}, line {node.lineno}.",
                    "fix": "Avoid executing dynamic strings. Use safer alternatives."
                })

    # Long functions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            length = end - node.lineno + 1
            if length > 50:
                metrics["Long functions"] += 1
                score += 5
                findings.append({
                    "severity": "LOW",
                    "title": "Long function",
                    "detail": f"{node.name} contains approximately {length} lines.",
                    "fix": "Consider splitting this function into smaller reusable functions."
                })

    
    
    # Repeated non-empty lines
    normalized = [
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]

    repeated_lines = {
        line: count
        for line, count in Counter(normalized).items()
        if count >= 2 and len(line) >= 5
    }

    repeated = sum(count - 1 for count in repeated_lines.values())

    if repeated > 0:
        metrics["Repeated code lines"] = repeated
        score += min(15, repeated * 3)

        examples = list(repeated_lines.keys())[:3]

        findings.append({
            "severity": "MEDIUM",
            "title": "Repeated code patterns",
            "detail": (
                f"Found {repeated} repeated line occurrence(s) "
                f"in {filename}. Examples: "
                + "; ".join(examples)
            ),
            "fix": (
                "Consider extracting repeated logic into reusable "
                "functions to improve maintainability."
            )
        })

    # Input validation heuristic
    if re.search(r"\binput\s*\(", source):
        if not re.search(r"\b(validate|isinstance|isdigit|isalpha|fullmatch)\b", source):
            metrics["Possible input validation gaps"] += 1
            score += 8
            findings.append({
                "severity": "MEDIUM",
                "title": "Possible input validation gap",
                "detail": f"User input is present in {filename}, but common validation patterns were not detected.",
                "fix": "Validate input type, length, and allowed values before processing."
            })

    return {
        "score": min(score, 100),
        "findings": findings,
        "metrics": dict(metrics),
        "lines": len(lines),
        "functions": sum(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            for n in ast.walk(tree)
        )
    }


def scan_sources(files):
    all_findings = []
    all_metrics = Counter()
    total_lines = 0
    total_functions = 0
    file_count = 0
    total_score = 0

    for filename, source in files:
        result = analyze_code(filename, source)
        file_count += 1
        total_score += result["score"]
        total_lines += result["lines"]
        total_functions += result["functions"]
        all_findings.extend(result["findings"])
        all_metrics.update(result["metrics"])

    average_score = round(total_score / max(file_count, 1))
    return {
        "score": min(average_score, 100),
        "findings": all_findings,
        "metrics": dict(all_metrics),
        "lines": total_lines,
        "functions": total_functions,
        "files": file_count
    }


# ---------------- GITHUB REPOSITORY ----------------


def get_github_files(repo_url):
    match = re.match(
        r"https?://github\.com/([^/]+)/([^/#?]+)",
        repo_url.strip()
    )

    if not match:
        raise ValueError("Enter a valid public GitHub repository URL.")

    owner, repo = match.groups()
    repo = repo.removesuffix(".git")

    headers = {"Accept": "application/vnd.github+json"}

    # Get repository information
    response = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers=headers,
        timeout=20
    )
    response.raise_for_status()

    branch = response.json()["default_branch"]

    # Get the repository file list
    tree_response = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}",
        params={"recursive": "1"},
        headers=headers,
        timeout=30
    )
    tree_response.raise_for_status()

    tree_data = tree_response.json()

    if tree_data.get("truncated"):
        raise ValueError(
            "This repository is too large for the current prototype scanner."
        )

    python_files = [
        item for item in tree_data.get("tree", [])
        if item.get("type") == "blob"
        and item.get("path", "").endswith(".py")
        and item.get("size", 0) <= 500_000
    ]

    if not python_files:
        raise ValueError("No supported Python files were found.")

    files = []

    # Download a maximum of 20 Python files
    
    files = []

    for item in python_files[:20]:
        path = item["path"]

        raw_url = (
            f"https://raw.githubusercontent.com/"
            f"{owner}/{repo}/{branch}/"
            f"{requests.utils.quote(path, safe='/')}"
        )

        try:
            file_response = requests.get(
                raw_url,
                timeout=(10, 30)
            )
            file_response.raise_for_status()

            files.append((
                path,
                file_response.content.decode(
                    "utf-8", errors="replace"
                )
            ))

        except requests.exceptions.RequestException:
            continue

    if not files:
        raise ValueError(
            "Could not download any Python files. "
            "Check your internet connection or try another repository."
        )

    return files

# ---------------- SESSION STATE ----------------

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "history" not in st.session_state:
    st.session_state.history = []
if "latest" not in st.session_state:
    st.session_state.latest = None


# ---------------- SIDEBAR ----------------

with st.sidebar:
    brand()
    st.markdown("---")
    page = st.radio(
        "NAVIGATION",
        ["Home", "Login", "Dashboard", "Scan Results", "Pricing"],
        index=0
    )
    st.markdown("---")
    st.markdown("**SECURITY INTELLIGENCE**")
    st.caption("Scan. Analyze. Secure.")
    if st.session_state.logged_in:
        st.success("Demo session active")
    else:
        st.caption("Guest access")


# ---------------- HOME ----------------

if page == "Home":
    brand()
    st.write("")
    st.markdown(
        '<h1 style="font-size:48px;">Find Hidden Security Debt '
        '<span class="cs-gradient">in Your Code</span></h1>',
        unsafe_allow_html=True
    )
    st.markdown(
        "CodeSentinel analyzes Python codebases for architectural "
        "patterns that may create future security and maintenance risks."
    )
    if st.button("Start Scanning →", key="home_scan"):
        st.session_state.go_scan = True
        st.rerun()

    st.write("")
    col1, col2 = st.columns(2)
    with col1:
        card("01 · Pattern Detection",
             "Identify broad exception handling, repeated code and other risky patterns.")
        card("02 · Explainable Results",
             "Understand why a pattern was detected and where it appears.")
    with col2:
        card("03 · Security Debt Score",
             "Get an indicative score based on detected patterns.")
        card("04 · Actionable Recommendations",
             "See practical suggestions to improve your codebase.")

    st.markdown("---")
    st.subheader("Built for safer AI-assisted development")
    st.info("CodeSentinel uses code-pattern heuristics in this prototype. It does not prove whether code was written by AI.")


# ---------------- LOGIN ----------------

elif page == "Login":
    brand()
    st.title("Welcome Back")
    st.write("Enter a name and email to start a demonstration session.")

    with st.form("login_form"):
        name = st.text_input("Your name")
        email = st.text_input("Email address")
        submitted = st.form_submit_button("Continue")

    if submitted:
        if name.strip() and "@" in email:
            st.session_state.logged_in = True
            st.session_state.username = name.strip()
            st.success("Demo session started!")
            st.rerun()
        else:
            st.error("Enter your name and a valid email address.")

    st.caption("Demo login only. No password or permanent account is created.")


# ---------------- DASHBOARD ----------------

elif page == "Dashboard":
    brand()
    st.title("Security Dashboard")
    st.write("Analyze a public GitHub repository or upload your Python code.")

    if not st.session_state.logged_in:
        st.info("You are using guest mode. You can still run scans.")

    source_type = st.radio(
        "Choose your source",
        ["GitHub Repository", "Upload Code"],
        horizontal=True
    )

    if source_type == "GitHub Repository":
        repo_url = st.text_input(
            "Public GitHub repository URL",
            placeholder="https://github.com/username/repository"
        )
        st.caption("For this prototype, public repositories containing Python files are supported.")
    else:
        uploads = st.file_uploader(
            "Upload Python files or a ZIP archive",
            type=["py", "zip", "txt"],
            accept_multiple_files=True
        )
        st.caption("You can upload multiple files or ZIP archives.")

    if st.button("🔍 Analyze Codebase", use_container_width=True):
        try:
            with st.spinner("Analyzing your codebase..."):
                if source_type == "GitHub Repository":
                    if not repo_url.strip():
                        st.error("Please enter a repository URL.")
                        st.stop()
                    source_files = get_github_files(repo_url)
                    project_name = repo_url.rstrip("/").split("/")[-1]

                else:
                    source_files = []
                    if not uploads:
                        st.error("Please upload at least one file.")
                        st.stop()

                    project_name = "Uploaded project"

                    for upload in uploads:
                        data = upload.getvalue()
                        if upload.name.lower().endswith(".zip"):
                            with zipfile.ZipFile(io.BytesIO(data)) as z:
                                for item in z.infolist():
                                    if item.filename.endswith(".py") and not item.is_dir():
                                        if item.file_size > 1_000_000:
                                            continue
                                        if len(source_files) >= 50:
                                            break
                                        content = z.read(item).decode("utf-8", errors="replace")
                                        source_files.append((item.filename, content))
                        else:
                            source_files.append((
                                upload.name,
                                data.decode("utf-8", errors="replace")
                            ))

                if not source_files:
                    st.error("No supported Python files found.")
                    st.stop()

                result = scan_sources(source_files)
                result["project"] = project_name
                result["date"] = datetime.now().strftime("%d %b %Y, %I:%M %p")

                st.session_state.latest = result
                st.session_state.history.insert(0, result)
                st.success("Analysis completed!")

        except requests.exceptions.HTTPError as error:
            st.error(f"GitHub could not provide this repository: {error}")
        except requests.exceptions.RequestException as error:
            st.error(f"Network error: {error}")
        except zipfile.BadZipFile:
            st.error("The uploaded ZIP file is invalid.")
        except Exception as error:
            st.error(f"Something went wrong: {error}")

    if st.session_state.latest:
        st.markdown("---")
        st.subheader("Latest Scan")
        result = st.session_state.latest
        c1, c2, c3 = st.columns(3)
        c1.metric("Security Debt Score", f'{result["score"]}/100')
        c2.metric("Files Analyzed", result["files"])
        c3.metric("Lines of Code", result["lines"])
        st.caption("Higher score means more detected debt patterns. This is a prototype heuristic, not a certified security rating.")
        if st.button("View Detailed Results"):
            st.session_state.show_results = True
            st.rerun()


# ---------------- SCAN RESULTS ----------------

elif page == "Scan Results":
    brand()
    st.title("Scan Results")

    result = st.session_state.latest
    if not result:
        st.info("No scan results yet. Open Dashboard and run a scan first.")
    else:
        score = result["score"]
        st.markdown(f'<div class="cs-card"><h2>{result["project"]}</h2>'
                    f'<h1 class="cs-gradient" style="font-size:64px;">{score}/100</h1>'
                    f'<p>Indicative Security Debt Score</p></div>',
                    unsafe_allow_html=True)

        if score >= 50:
            st.error("Higher detected security debt")
        elif score >= 20:
            st.warning("Moderate detected security debt")
        else:
            st.success("Lower detected security debt")

        a, b, c = st.columns(3)
        a.metric("Files", result["files"])
        b.metric("Lines", result["lines"])
        c.metric("Functions", result["functions"])

        st.subheader("Risk Breakdown")
        if result["metrics"]:
            for name, count in result["metrics"].items():
                st.write(f"**{name}** — {count} occurrence(s)")
        else:
            st.success("No patterns from the current rule set were detected.")

        st.subheader("Detected Patterns & Recommendations")
        if result["findings"]:
            for finding in result["findings"]:
                with st.expander(
                    f'{finding["severity"]} · {finding["title"]}'
                ):
                    st.write(finding["detail"])
                    st.markdown("**Recommended action**")
                    st.write(finding["fix"])
        else:
            st.success("No findings from the current rule set.")

        report = {
            "project": result["project"],
            "date": result["date"],
            "score": result["score"],
            "metrics": result["metrics"],
            "findings": result["findings"]
        }
        st.download_button(
            "Download Scan Report (JSON)",
            data=json.dumps(report, indent=2),
            file_name="codesentinel_report.json",
            mime="application/json"
        )

    st.markdown("---")
    st.subheader("Scan History")
    if st.session_state.history:
        for item in st.session_state.history:
            st.write(
                f'**{item["project"]}** · '
                f'{item["score"]}/100 · {item["date"]}'
            )
    else:
        st.caption("Your scans will appear here during this session.")


# ---------------- PRICING ----------------

elif page == "Pricing":
    brand()
    st.title("Simple, Transparent Pricing")
    st.write("Start free. Upgrade when you need deeper code analysis.")

    free, premium = st.columns(2)
    with free:
        card("FREE PLAN", "₹0 / month")
        st.write("✓ Basic Python code scanning")
        st.write("✓ Security Debt Score")
        st.write("✓ Basic recommendations")
        st.write("✓ Manual uploads")
        st.button("Current Plan", disabled=True)

    with premium:
        card("PREMIUM PLAN", "₹499 / month · Proposed")
        st.write("✓ Everything in Free")
        st.write("✓ Advanced analysis")
        st.write("✓ Extended scan history")
        st.write("✓ Multiple project monitoring")
        st.button("Upgrade to Premium", key="upgrade")
        st.info("Payment integration is not active in this prototype.")

    st.caption("Prices are demonstration pricing, not active offers.")
