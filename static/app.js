function esc(value) { return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;", "'":"&#39;"}[ch])); }

const scanForm = document.querySelector("#website-scan-form");
const scanStatus = document.querySelector("#scan-status");
const scanHistory = document.querySelector("#scan-history");
const activeProbeToggle=document.querySelector("#enable-active");
const authorizationToggle=document.querySelector("#scan-authorized");
const probeAuthorizationHint=document.querySelector("#probe-authorization-hint");
function updateProbeAuthorizationHint(){
  const required=activeProbeToggle.checked&&!authorizationToggle.checked;
  probeAuthorizationHint.hidden=!required;
  probeAuthorizationHint.textContent=required?"To run these probes, confirm the site is yours or you have permission. Other selected checks can run after you confirm.":"";
}
activeProbeToggle.addEventListener("change",updateProbeAuthorizationHint);
authorizationToggle.addEventListener("change",updateProbeAuthorizationHint);

function setMetric(id, value) { document.querySelector(id).textContent = String(value ?? 0); }
function compactUrl(url) { try { const parsed = new URL(url); return parsed.host + parsed.pathname; } catch { return url; } }

function normalizeAiReport(value, fallbackText="") {
  if (value && typeof value === "object") return value;
  if (typeof value === "string") {
    try { const parsed=JSON.parse(value); if(parsed && typeof parsed==="object") return parsed; } catch {}
    return {executive_summary:value, risk_level:"REVIEW", http_summary:fallbackText, key_findings:[], priority_actions:[], limitations:["This is an older plain-text scan summary; detailed tool results are shown below."], check_results:[], contract_result:null};
  }
  return {executive_summary:fallbackText || "No AI report was returned.", risk_level:"UNKNOWN", http_summary:"", key_findings:[], priority_actions:[], limitations:[], check_results:[], contract_result:null};
}
function renderAiReport(report) {
  const ai=normalizeAiReport(report.ai_summary,report.summary);
  const findings=(ai.key_findings||[]).map(item=>`<article class="ai-finding"><div class="ai-finding-heading"><strong>${esc(item.title||"Finding")}</strong><span class="severity ${esc(String(item.severity||"review").toLowerCase())}">${esc(item.severity||"Review")}</span></div><p>${esc(item.detail||"")}</p>${item.source?`<small>Source: ${esc(item.source)}</small>`:""}${item.recommended_fix?`<p class="ai-fix"><strong>Recommended fix:</strong> ${esc(item.recommended_fix)}</p>`:""}</article>`).join("")||'<p class="empty-state">No potential findings were reported by the selected checks.</p>';
  const actions=(ai.priority_actions||[]).map(item=>`<li>${esc(item)}</li>`).join("")||"<li>Continue with manual review of the target site.</li>";
  const checkResults=(ai.check_results||report.test_groups||[]).map(item=>`<article class="ai-check-row"><div><strong>${esc(item.name||item.title||"Check")}</strong>${item.evidence?`<small>${esc(item.evidence)}</small>`:""}</div><span class="badge ${esc(String(item.status||"UNKNOWN").toLowerCase())}">${esc(String(item.status||"UNKNOWN").replaceAll("_"," "))}</span></article>`).join("");
  const contract=ai.contract_result||report.contract||{};
  const limitations=(ai.limitations||[]).map(item=>`<li>${esc(item)}</li>`).join("");
  const risk=String(ai.risk_level||"UNKNOWN").toUpperCase();
  return `<div class="result-heading"><div><p class="eyebrow">Complete target scan · ${esc(new Date(report.created_at).toLocaleString())}</p><h2>${esc(report.url)}</h2></div><span class="badge ${esc(String(report.status).toLowerCase())}">${esc(String(report.status).replaceAll("_"," "))}</span></div><section class="ai-overview"><div class="ai-section-heading"><h3>Gemma assessment</h3><span class="risk-badge risk-${esc(risk.toLowerCase())}">${esc(risk)} RISK</span></div><p class="ai-executive">${esc(ai.executive_summary||report.summary||"No summary available.")}</p><p class="ai-http-summary">${esc(ai.http_summary||"")}</p><small class="hint">Summary source: ${esc(ai.source||report.ai_summary_source||"Built-in report")}</small></section><section class="ai-report-section"><h3>Key findings (${(ai.key_findings||[]).length})</h3><div class="ai-findings">${findings}</div></section><section class="ai-report-section"><h3>Recommended next steps</h3><ol class="ai-actions">${actions}</ol></section><details class="ai-report-details" open><summary>All check results (${(ai.check_results||report.test_groups||[]).length} groups)</summary><div class="ai-checks">${checkResults}</div><div class="ai-contract"><strong>Schemathesis API contract · ${esc(String(contract.status||"NOT_RUN").replaceAll("_"," "))}</strong><p>${esc(contract.summary||"Not run.")}</p></div></details>${limitations?`<section class="ai-report-section"><h3>Coverage notes</h3><ul class="ai-limitations">${limitations}</ul></section>`:""}`;
}

function statusForGroups(items) {
  if (!items.length) return "NOT_RUN";
  const statuses=items.map(item=>item.status);
  if(statuses.includes("ERROR")) return "ERROR";
  if(statuses.includes("ISSUES_FOUND")) return "ISSUES_FOUND";
  if(statuses.includes("FAILED")) return "FAILED";
  if(statuses.includes("REVIEW")) return "REVIEW";
  if(statuses.includes("DEGRADED")) return "DEGRADED";
  if(statuses.every(status=>status==="PASSED"||status==="SKIPPED")) return statuses.includes("SKIPPED")?"REVIEW":"PASSED";
  return "NOT_RUN";
}
function renderQualityTools(report, running=false) {
  const groups=report.test_groups||[];
  const byId=id=>groups.find(item=>item.id===id);
  const httpGroups=groups.filter(item=>["status_200","response_header_present","response_time_under_5s","body_not_empty"].includes(item.id));
  const securityGroups=groups.filter(item=>["security_headers","cookie_security","exposed_resources"].includes(item.id));
  const browser=byId("browser_accessibility");
  const contract=report.contract||{};
  const securityChecks=report.security_checks||[];
  const active=securityChecks.some(item=>String(item.title||"").startsWith("Reflected input")||String(item.title||"").startsWith("Access-control route"));
  const tools=[
    {name:"HTTPX live endpoint checks",status:running?"RUNNING":statusForGroups(httpGroups),detail:running?"Checking status, headers, timing, and response body.":`${httpGroups.filter(item=>item.status==="PASSED").length}/${httpGroups.length} response checks passed.` ,icon:"⌁"},
    {name:"Security scan",status:running?"RUNNING":(statusForGroups(securityGroups)==="FAILED"?"REVIEW":statusForGroups(securityGroups)),detail:running?"Checking headers, cookies, and exposed resources.":`${(report.security||[]).length} potential finding(s) · ${active?"authorized inert probes ran":"active probes off"}. Review items in Vulnerabilities Found.`,icon:"⬡"},
    {name:"Playwright + axe WCAG",status:running?"RUNNING":((browser?.status==="FAILED"||(report.accessibility?.violations||[]).length)?"ISSUES_FOUND":(browser?.status||"NOT_RUN")),detail:running?"Opening the submitted target and checking browser accessibility.":`${report.accessibility?.violations?.length||0} axe violation(s) · ${report.accessibility?.checks_passed||0} rules passed. Review items in Vulnerabilities Found.`,icon:"♿"},
    {name:"Schemathesis API contract",status:running?"WAITING":(contract.status||"NOT_RUN"),detail:running?"Waiting for authorization and same-origin API schema discovery.":(contract.summary||"Not run."),icon:"〈〉"}
  ];
  document.querySelector("#quality-results").innerHTML=tools.map(item=>{
    const badge=`<span class="badge ${esc(String(item.status).toLowerCase().replaceAll(" ","_"))}">${esc(String(item.status).replaceAll("_"," "))}</span>`;
    const detail=item.name==="Schemathesis API contract"?`<div id="contract-report" class="tool-card-detail"><p>${esc(item.detail)}</p>${contract.schema_url?`<small>Schema: ${esc(contract.schema_url)}</small>`:""}${contract.operations_tested?`<small>${Number(contract.operations_tested)} GET operation(s) tested</small>`:""}</div>`:`<p>${esc(item.detail)}</p>`;
    return `<article class="tool-card"><div class="tool-card-head"><span class="tool-icon" aria-hidden="true">${esc(item.icon)}</span>${badge}</div><h3>${esc(item.name)}</h3>${detail}</article>`;
  }).join("");
}
function renderScanProgress() {
  const placeholder={test_groups:[],security:[],security_checks:[],accessibility:{},contract:{},ai_summary:{source:"Gemma AI"}};
  renderQualityTools(placeholder,true);
  document.querySelector("#test-results").innerHTML='<p class="empty-state">The scan is running. Results will appear here when each tool completes.</p>';
}
function renderScan(report, addHistory=true) {
  const httpx = report.httpx || {};
  const httpxChecks = httpx.checks || [];
  const security = report.security || [];
  const securityChecks = report.security_checks || [];
  const a11y = report.accessibility || {};
  const violations = a11y.violations || [];
  document.querySelector("#httpx-report").innerHTML = `<p><strong>HTTP ${esc(httpx.status_code ?? "—")}</strong> · ${esc(httpx.content_type || "Content-Type missing")}</p><p class="hint">${Number(httpx.header_count || 0)} headers · ${esc(httpx.elapsed_seconds ?? "—")} seconds</p>` + (httpxChecks.length ? httpxChecks.map(item => `<article class="finding-row"><div><strong>${esc(String(item.id || "HTTPX check").replaceAll("_"," "))}</strong><small>${esc(item.actual || "")}</small></div><span class="badge ${esc(String(item.status||"").toLowerCase())}">${esc(item.status)}</span></article>`).join("") : '<p class="empty-state">HTTPX checks were not run.</p>');
  const securityHeaderTitles=new Set(["Content-Security-Policy","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","Clickjacking protection","Strict-Transport-Security"]);
  const sections=[
    {title:"Security headers",description:"Browser security policy, HTTPS, content type, referrer, permissions, and framing protections.",checks:securityChecks.filter(item=>securityHeaderTitles.has(item.title)),findings:security.filter(item=>item.category==="Security header")},
    {title:"Cookie security",description:"Secure, HttpOnly, and SameSite flags; cookie values are not stored.",checks:securityChecks.filter(item=>item.title==="Cookie flags"),findings:security.filter(item=>item.category==="Cookie security")},
    {title:"Exposed resources",description:"HEAD-only checks for public environment files, Git metadata, and backup archives.",checks:securityChecks.filter(item=>String(item.title||"").startsWith("Exposure probe:")),findings:security.filter(item=>item.category==="Exposed resource")},
    {title:"Active XSS and access-control probes",description:report.active_probes_run?"Authorized inert canary and bounded unauthenticated route checks.":"Not run. Enable these optional probes and confirm authorization in Advanced scan options.",checks:securityChecks.filter(item=>item.title==="Reflected input canary"||String(item.title||"").startsWith("Access-control route")),findings:security.filter(item=>item.category==="XSS reflection"||item.category==="Access control"),notRun:!report.active_probes_run},
  ];
  const usedChecks=new Set(sections.flatMap(section=>section.checks));
  const usedFindings=new Set(sections.flatMap(section=>section.findings));
  const extraChecks=securityChecks.filter(item=>!usedChecks.has(item));
  const extraFindings=security.filter(item=>!usedFindings.has(item));
  if(extraChecks.length||extraFindings.length)sections.push({title:"Other security results",description:"Additional scanner diagnostics.",checks:extraChecks,findings:extraFindings});
  const statusForSection=section=>{
    const states=section.checks.map(item=>item.status);
    if(section.notRun||!report.security_scan_enabled&&states.length===0)return "NOT_RUN";
    if(states.includes("ERROR"))return "ERROR";
    if(states.includes("FLAGGED")||section.findings.length)return "REVIEW";
    if(!states.length||states.every(item=>item==="SKIPPED"))return "SKIPPED";
    return "PASSED";
  };
  const renderSecurityCheck=item=>{const flagged=item.status==="FLAGGED";const visibleStatus=flagged?"REVIEW":String(item.status||"UNKNOWN").replaceAll("_"," ");return `<article class="security-check-row"><div><strong>${esc(item.title||"Security check")}</strong><small>${esc(item.evidence||"")}</small></div><span class="badge ${esc(flagged?"review":String(item.status||"UNKNOWN").toLowerCase())}">${esc(visibleStatus)}</span></article>`;};
  const renderSecurityFinding=item=>`<article class="security-finding-row"><div><strong>${esc(item.title||"Potential finding")}</strong><small>${esc(item.evidence||"Requires manual review.")}</small>${item.recommendation?`<p>${esc(item.recommendation)}</p>`:""}</div><span class="severity ${esc(String(item.severity||"review").toLowerCase())}">${esc(item.severity||"Review")}</span></article>`;
  const sectionTargets={"Security headers":"#security-headers-report","Cookie security":"#cookie-security-report","Exposed resources":"#exposure-report","Active XSS and access-control probes":"#active-probes-report","Other security results":"#security-headers-report"};
  sections.forEach(section=>{
    const target=document.querySelector(sectionTargets[section.title]);
    if(!target)return;
    const details=section.checks.length?section.checks.map(renderSecurityCheck).join(""):(section.notRun||!report.security_scan_enabled?'<p class="empty-state">Not run for this scan.</p>':'<p class="empty-state">No checks in this category.</p>');
    if(section.title==="Other security results"){
      target.insertAdjacentHTML("beforeend",`<h3 class="other-checks-heading">Other security results</h3>${details}`);
      return;
    }
    target.innerHTML=`<div class="security-category-summary"><span>${section.checks.length} check(s) · ${section.findings.length} potential finding(s)</span><span class="badge ${esc(statusForSection(section).toLowerCase())}">${esc(statusForSection(section).replaceAll("_"," "))}</span></div><p class="security-type-description">${esc(section.description)}</p>${details}`;
  });
  const vulnerabilityItems=[
    ...security.map(item=>({title:item.title||"Potential security finding",source:item.category||"Security scan",severity:item.severity||"Review",detail:item.evidence||"Requires manual review.",fix:item.recommendation||"Review the affected security control and apply an appropriate fix."})),
    ...violations.map(item=>({title:item.help||item.id||"Accessibility violation",source:`axe-core · ${item.id||"WCAG"}`,severity:item.impact||"Review",detail:`${item.description||"Accessibility rule violation."}${item.node_count?` ${Number(item.node_count)} affected node(s).`:""}`,fix:item.help_url?`Review the rule guidance: ${item.help_url}`:"Fix the affected elements and verify with keyboard and assistive-technology testing."}))
  ];
  document.querySelector("#vulnerability-count").textContent=`${vulnerabilityItems.length} item${vulnerabilityItems.length===1?"":"s"}`;
  document.querySelector("#vulnerabilities-list").innerHTML=vulnerabilityItems.length?vulnerabilityItems.map(item=>`<article class="vulnerability-card"><div class="vulnerability-card-heading"><span class="vulnerability-source">${esc(item.source)}</span><span class="severity ${esc(String(item.severity).toLowerCase())}">${esc(item.severity)}</span></div><h3>${esc(item.title)}</h3><p>${esc(item.detail)}</p><p class="vulnerability-fix"><strong>Suggested fix</strong><br>${esc(item.fix)}</p></article>`).join(""):'<p class="empty-state">No vulnerabilities or accessibility violations were reported by the selected checks.</p>';
  const a11yPassed = Number(a11y.checks_passed ?? (a11y.checks || []).filter(item => !item.impact).length);
  document.querySelector("#accessibility-report").innerHTML = `<div><strong class="a11y-count">${violations.length}</strong><span class="a11y-engine">violation(s) · ${esc(a11y.engine || "Not run")}</span><p class="hint">${a11yPassed} rules passed${a11y.incomplete ? ` · ${Number(a11y.incomplete)} need manual review` : ""}</p></div>` + (violations.length ? violations.slice(0, 8).map(item => `<article class="finding-row"><div><strong>${esc(item.help || item.id || "Accessibility issue")}</strong><small>${esc(item.impact || "Review")} · ${esc(item.description || "")} · ${Number(item.node_count || 0)} affected node(s)</small></div><span class="severity moderate">WCAG</span></article>`).join("") : `<p class="empty-state">${esc(a11y.warning || "No accessibility violations reported.")}</p>`);
  const browserChecks = a11y.browser_checks || [];
  const browserHtml = browserChecks.map(item => `<article class="finding-row"><div><strong>${esc(item.title)}</strong><small>${esc(item.evidence || "")}</small></div><span class="badge ${esc(String(item.status||"").toLowerCase())}">${esc(item.status)}</span></article>`).join("");
  document.querySelector("#accessibility-report").insertAdjacentHTML("beforeend", browserHtml);
  const testGroups=report.test_groups||[];
  document.querySelector("#test-group-count").textContent=`${testGroups.length} target groups`;
  document.querySelector("#test-results").innerHTML=testGroups.map(item=>{const status=item.status==="FAILED"&&["security_headers","cookie_security","exposed_resources"].includes(item.id)?"REVIEW":item.id==="browser_accessibility"&&item.status==="FAILED"?"ISSUES_FOUND":String(item.status||"NOT_RUN").replaceAll("_"," ");return `<article class="test-result-row"><div><strong>${esc(item.title)}</strong><small>${esc(item.evidence||"")}</small></div><span class="badge ${esc(status.toLowerCase().replaceAll(" ","_"))}">${esc(status.replaceAll("_"," "))}</span></article>`;}).join("") + `<article class="test-result-row"><div><strong>Schemathesis API contract</strong><small>${esc((report.contract||{}).summary||"Not run.")}</small></div><span class="badge ${esc(String((report.contract||{}).status||"NOT_RUN").toLowerCase())}">${esc(String((report.contract||{}).status||"NOT_RUN").replaceAll("_"," "))}</span></article>`;
  renderQualityTools(report);
  if(addHistory){
    const totalFindings = testGroups.filter(item=>item.status==="FAILED").length + security.length + violations.length;
    const row = document.createElement("tr");
    row.dataset.searchText = `${report.url} ${security.map(x=>x.title).join(" ")} ${violations.map(x=>x.help).join(" ")}`.toLowerCase();
    row.innerHTML = `<td>${Number(report.id)}</td><td class="url-cell" title="${esc(report.url)}">${esc(compactUrl(report.url))}</td><td>HTTPX + Security + Browser</td><td>${esc(new Date(report.created_at).toLocaleString())}</td><td>${totalFindings} issue${totalFindings===1?"":"s"}</td><td><span class="badge ${esc(String(report.status).toLowerCase())}">${esc(String(report.status).replaceAll("_"," "))}</span></td><td><button type="button" class="history-view" data-scan-id="${Number(report.id)}">View</button></td>`;
    const empty = scanHistory.querySelector(".empty-state"); if (empty) scanHistory.replaceChildren();
    scanHistory.prepend(row);
  }
  const resultPanel=document.querySelector("#website-scan-result");
  resultPanel.innerHTML=renderAiReport(report);
  resultPanel.classList.remove("hidden");
  resultPanel.scrollIntoView({behavior:"smooth", block:"start"});
  loadDashboardStats();
}
async function loadDashboardStats() {
  try {
    const [statsResponse, reportsResponse] = await Promise.all([fetch("/api/dashboard"), fetch("/api/scan-reports?limit=10")]);
    if (!statsResponse.ok || !reportsResponse.ok) throw new Error("Dashboard data unavailable");
    const stats=await statsResponse.json(), reports=await reportsResponse.json();
    setMetric("#metric-total", stats.total_scans); setMetric("#metric-vulnerabilities", stats.vulnerabilities);
    setMetric("#metric-security", stats.security_issues); setMetric("#metric-a11y", stats.accessibility_issues);
    if (reports.length) {
      scanHistory.innerHTML=reports.map(report=>{
        const findings=(report.security||[]).length+(report.accessibility?.violations||[]).length;
        return `<tr data-search-text="${esc(`${report.url} ${(report.security||[]).map(x=>x.title).join(" ")}`).toLowerCase()}"><td>${Number(report.id)}</td><td class="url-cell" title="${esc(report.url)}">${esc(compactUrl(report.url))}</td><td>HTTPX + Security + Browser</td><td>${esc(new Date(report.created_at).toLocaleString())}</td><td>${findings} issue${findings===1?"":"s"}</td><td><span class="badge ${esc(String(report.status).toLowerCase())}">${esc(String(report.status).replaceAll("_"," "))}</span></td><td><button type="button" class="history-view" data-scan-id="${Number(report.id)}">View</button></td></tr>`;
      }).join("");
    }
  } catch { /* Dashboard history may be temporarily unavailable. */ }
}
scanForm.addEventListener("submit", async event=>{
  event.preventDefault();
  const activeRequested=activeProbeToggle.checked;
  const authorized=authorizationToggle.checked;
  const active=activeRequested&&authorized;
  const start=document.querySelector("#start-scan");start.disabled=true;start.textContent="Scanning…";renderScanProgress();scanStatus.textContent=activeRequested&&!authorized?"Running the regular checks. Active probes will be skipped until you confirm permission.":"Checking the target. This can take up to a minute for browser accessibility scanning.";
  try {
    const response=await fetch("/api/scans",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:document.querySelector("#scan-url").value,security_scan:document.querySelector("#enable-security").checked,accessibility_scan:document.querySelector("#enable-a11y").checked,active_security_probes:active,api_contract_scan:document.querySelector("#enable-contract").checked,authorized})});
    const report=await response.json();if(!response.ok)throw new Error(report.detail||"Scan failed.");
    renderScan(report);scanStatus.textContent=report.summary+(activeRequested&&!authorized?" Active XSS/access-control probes were skipped because permission was not confirmed; the other selected scans completed.":"");await loadDashboardStats();
  } catch(error) { scanStatus.textContent=error.message; }
  finally {start.disabled=false;start.innerHTML='<span aria-hidden="true">▷</span> Start Scan';}
});
scanHistory.addEventListener("click",async event=>{
  const button=event.target.closest("[data-scan-id]");
  if(!button)return;
  button.disabled=true;
  try{const response=await fetch(`/api/scans/${Number(button.dataset.scanId)}`);if(!response.ok)throw new Error("Saved report could not be loaded.");renderScan(await response.json(),false);document.querySelector("#website-scan-result").scrollIntoView({behavior:"smooth",block:"start"});}
  catch(error){scanStatus.textContent=error.message;}
  finally{button.disabled=false;}
});
document.querySelector("#refresh-scans").addEventListener("click",loadDashboardStats);
document.querySelector("#today-label").textContent=new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short"}).format(new Date());
loadDashboardStats();
