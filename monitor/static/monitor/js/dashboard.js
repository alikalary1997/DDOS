(() => {
    "use strict";
    const byId = id => document.getElementById(id);
    const csrf = document.querySelector('[name="csrfmiddlewaretoken"]')?.value || "";
    const search = byId("dashboardSearch");
    const refreshButton = byId("dashboardRefresh");
    let reading = false, latest = null, eventFilter = "all";
    const statuses = {Normal:"normal", Warning:"warning", "Under Attack":"under-attack", Unknown:"unknown"};
    const metricLabels = {total_pps:"Total PPS", bandwidth_mbps:"Bandwidth", syn_pps:"TCP SYN PPS", udp_pps:"UDP PPS"};
    const numeric = value => typeof value === "number" && Number.isFinite(value) && value >= 0;
    const number = (value, places=2) => numeric(value) ? value.toLocaleString(undefined, {maximumFractionDigits:places}) : "\u2014";
    const time = value => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString(undefined, {month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",timeZoneName:"short"}) : "\u2014";
    const duration = value => numeric(value) ? [Math.floor(value/3600),Math.floor(value/60)%60,Math.floor(value)%60].map(n=>String(n).padStart(2,"0")).join(":") : "\u2014";
    const metrics = items => Array.isArray(items) ? items.map(item=>metricLabels[item.metric]).filter(Boolean).join(", ") : "";
    function text(id, value) { const element=byId(id); if (element) element.textContent = value; }
    function element(tag, content, className) { const node=document.createElement(tag); if(content!==undefined) node.textContent=content; if(className) node.className=className; return node; }
    function link(label, href, className) { const node=element("a",label,className); node.href=typeof href === "string" && /^\/(?!\/)/.test(href) ? href : "#"; return node; }
    function cell(row, label) { const node=row.insertCell(); node.dataset.label=label; return node; }
    function lines(root, primary, secondary) { root.append(element("strong", primary)); if(secondary) root.append(element("small",secondary)); }
    function badge(status) { const safe=Object.hasOwn(statuses,status) ? status : "Unknown"; const node=element("span",safe,"detection-badge"); node.dataset.state=statuses[safe]; node.setAttribute("data-ddos-status",""); return node; }
    function empty(table, columns, title, detail) { const target=table.insertRow().insertCell(); target.colSpan=columns; target.className="overview-empty"; target.append(element("strong",title)); if(detail) target.append(element("span",detail)); }
    function liveStatus(item) { return item.monitoring_health === "Active" && Object.hasOwn(statuses,item.ddos_status) ? item.ddos_status : "Unknown"; }
    function renderIPs() {
        const table=byId("rulesTable"); table.replaceChildren();
        if(!latest) { empty(table,5,"Current data unavailable"); return; }
        const term=(search?.value || "").trim().toLowerCase();
        const items=latest.rules.filter(item=>(item.address+" "+item.device_name).toLowerCase().includes(term));
        text("ipResults",items.length+" of "+latest.rules.length+" saved IPs");
        if(!items.length) empty(table,5,latest.rules.length ? "No matching IPs" : latest.empty_message || "No public IPs configured",latest.rules.length ? "Try another IP or device name." : "Add an assignment to begin.");
        items.forEach(item=>{
            const row=table.insertRow(), identity=cell(row,"Public IP");
            identity.append(link(item.address,item.inspect_url),element("small",item.device_name));
            if(item.retry_url && item.provisioning_status!=="verified") {
                const form=element("form"); form.method="POST"; form.action=item.retry_url;
                const token=element("input"); token.type="hidden"; token.name="csrfmiddlewaretoken"; token.value=csrf;
                const button=element("button","Retry Provisioning","overview-inspect"); button.type="submit";
                form.append(token,button); identity.append(form);
            }
            const fresh=item.monitoring_health === "Active";
            cell(row,"UDP PPS").textContent=number(fresh?item.udp_pps:null);
            cell(row,"TCP SYN PPS").textContent=number(fresh?item.syn_pps:null);
            cell(row,"Mbps").textContent=number(fresh?item.mbps:null,6);
            const state=cell(row,"Status"); state.append(badge(liveStatus(item)),element("small",item.monitoring_health || "Not Monitored"));
        });
    }
    function renderIncidents(data) {
        const table=byId("incidentsTable"); table.replaceChildren();
        const incidents=(data.incidents || []).filter(item=>["Warning","Under Attack"].includes(liveStatus(item)));
        if(!incidents.length) empty(table,6,"No active detections","Only fresh, confirmed Warning and Under Attack samples appear here.");
        incidents.forEach(item=>{
            const row=table.insertRow(); lines(cell(row,"Target"),item.address,item.device_name);
            cell(row,"Triggers").textContent=metrics(item.ddos_metrics) || "Threshold crossing";
            lines(cell(row,"Current traffic"),number(item.mbps,6)+" Mbps",number(item.pps)+" PPS");
            lines(cell(row,"Started / elapsed"),time(item.started_at),duration(item.duration_seconds));
            cell(row,"Severity").append(badge(item.ddos_status));
            cell(row,"Inspect").append(link("Inspect \u2192",item.inspect_url,"overview-inspect"));
        });
        byId("incidentPanel").dataset.state=incidents.some(item=>item.ddos_status==="Under Attack") ? "under-attack" : incidents.length ? "warning" : "quiet";
    }
    function renderFleet(data) {
        const table=byId("savedDevices"); table.replaceChildren();
        if(!data.devices.length) empty(table,3,data.empty_message || "No devices configured");
        data.devices.forEach(device=>{
            const row=table.insertRow(), identity=cell(row,"Device"); lines(identity,device.name,device.management_ip);
            identity.append(element("small",device.last_connection_test ? "Last API test: "+time(device.last_connection_test)+" / "+(device.last_connection_test_succeeded ? "passed" : "failed") : "API connection not tested"));
            lines(cell(row,"Observed traffic"),number(device.mbps,6)+" Mbps",number(device.monitored_ips,0)+" / "+number(device.assigned_ips,0)+" IPs sampled");
            const health=element("span",device.monitoring_health || "Not Monitored","overview-chip"); health.dataset.state=(device.monitoring_health || "Not Monitored").toLowerCase().replaceAll(" ","-"); cell(row,"Sampling").append(health);
        });
    }
    function renderEvents() {
        const root=byId("recentEvents"); root.replaceChildren();
        if(!latest) { root.append(element("div","Event history unavailable","overview-empty")); return; }
        const items=(latest.recent_events || []).filter(item=>eventFilter==="all" || item.severity===eventFilter);
        if(!items.length) root.append(element("div",eventFilter==="all" ? "No detection events recorded" : "No attack events in the latest incidents","overview-empty"));
        items.forEach(item=>{
            const article=element("article",undefined,"overview-event"); article.dataset.state=item.status==="Recovered" ? "recovered" : statuses[item.severity] || "unknown";
            const heading=element("div"); const stamp=element("time",time(item.started_at)); if(item.started_at) stamp.dateTime=item.started_at;
            heading.append(badge(item.severity),stamp);
            article.append(heading,link(item.address+" / "+item.device_name,item.history_url),element("p",item.status+" / "+metrics(item.metrics)),
                element("small","Peak "+number(item.peak_pps)+" PPS / "+number(item.peak_mbps,6)+" Mbps / "+duration(item.duration_seconds)));
            root.append(article);
        });
    }
    function health(id, label, active) { text(id,label); byId(id).dataset.state=active ? "active" : "unknown"; }
    function render(data) {
        latest=data;
        const live=data.monitoring;
        text("status",live ? "MONITORING" : "NOT MONITORED"); byId("status").dataset.state=live?"live":"stopped";
        ["statusDot","routerDot"].forEach(id=>{if(byId(id)) byId(id).dataset.state=live?"live":"stopped";});
        text("routerStatus",live?"Receiving assigned IP counters":"No fresh monitoring samples"); text("lastUpdate",time(data.last_update));
        Object.entries(data.summary || {}).forEach(([key,value])=>text("summary-"+key,number(value,0)));
        Object.entries(data.overview || {}).forEach(([key,value])=>text("overview-"+key,number(value,key==="total_mbps"?6:2)));
        document.querySelectorAll("[data-polling-interval]").forEach(node=>node.textContent=data.polling_interval);
        const system=data.system || {};
        text("detectionMode",system.detection_enabled?"Passive detection enabled":"Detection disabled");
        health("healthWorker",system.worker_running?"Running":"No active app worker",system.worker_running);
        health("healthDetection",system.detection_enabled?"Enabled":"Disabled",system.detection_enabled);
        health("healthRouter",system.sampled_devices ? "Receiving data":"No fresh data",system.sampled_devices>0);
        health("healthDashboard","Available",true);
        renderIncidents(data); renderFleet(data); renderIPs(); renderEvents();
    }
    function unavailable() {
        latest=null; text("error","Dashboard data unavailable. Check your connection or sign in again. Displayed live statuses have been cleared.");
        text("status","DATA UNAVAILABLE"); byId("status").dataset.state="error"; text("lastUpdate","\u2014");
        text("routerStatus","Current data unavailable"); ["statusDot","routerDot"].forEach(id=>{if(byId(id)) byId(id).dataset.state="error";});
        ["devices","monitored_devices","public_ips"].forEach(key=>text("summary-"+key,"\u2014"));
        ["total_mbps","total_pps","active_detections","monitored_ips","attack_ips","warning_ips","unknown_ips"].forEach(key=>text("overview-"+key,"\u2014"));
        ["healthWorker","healthDetection","healthRouter","healthDashboard"].forEach(id=>health(id,"Unknown",false));
        text("detectionMode","Detection status unavailable"); text("ipResults","Current data unavailable"); byId("incidentPanel").dataset.state="unknown";
        byId("incidentsTable").replaceChildren(); empty(byId("incidentsTable"),6,"Detection data unavailable");
        byId("savedDevices").replaceChildren(); empty(byId("savedDevices"),3,"Device data unavailable");
        renderIPs(); renderEvents();
    }
    async function refresh() {
        if(reading) return; reading=true; if(refreshButton) refreshButton.disabled=true;
        const controller=new AbortController(); const timeout=window.setTimeout(()=>controller.abort(),15000);
        try {
            const response=await fetch(document.body.dataset.monitoringUrl,{signal:controller.signal,cache:"no-store",credentials:"same-origin"});
            if(!response.ok || response.redirected) throw new Error("request");
            const data=await response.json(); if(!Array.isArray(data.rules)||!Array.isArray(data.devices)) throw new Error("payload");
            render(data); text("error","");
        } catch (_) { unavailable(); }
        finally { window.clearTimeout(timeout); reading=false; if(refreshButton) refreshButton.disabled=false; }
    }
    search?.addEventListener("input",renderIPs);
    document.querySelectorAll("[data-event-filter]").forEach(button=>button.addEventListener("click",()=>{
        eventFilter=button.dataset.eventFilter;
        document.querySelectorAll("[data-event-filter]").forEach(item=>item.setAttribute("aria-pressed",String(item===button)));
        renderEvents();
    }));
    refreshButton?.addEventListener("click",refresh);
    refresh(); window.setInterval(refresh,2000);
})();
