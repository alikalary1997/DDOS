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
    function emptyCard(title, detail) {
        const box=element("div",undefined,"overview-empty");
        box.append(element("strong",title)); if(detail) box.append(element("span",detail)); return box;
    }
    const SVGNS="http://www.w3.org/2000/svg";
    function svgNode(tag, attrs) { const node=document.createElementNS(SVGNS,tag); Object.entries(attrs||{}).forEach(([k,v])=>node.setAttribute(k,v)); return node; }
    function niceMax(value) { const mag=Math.pow(10,Math.floor(Math.log10(value))); return [1,2,5,10].map(f=>f*mag).find(v=>v>=value); }
    function smoothPath(pts) {
        if(pts.length===1) return "M"+pts[0][0]+" "+pts[0][1];
        let d="M"+pts[0][0]+" "+pts[0][1];
        for(let i=1;i<pts.length;i++) { const mx=(pts[i-1][0]+pts[i][0])/2; d+=" C"+mx+" "+pts[i-1][1]+" "+mx+" "+pts[i][1]+" "+pts[i][0]+" "+pts[i][1]; }
        return d;
    }
    function renderTraffic(history) {
        const root=byId("trafficChart"); if(!root) return; root.replaceChildren();
        const stat=(id,value)=>text(id,numeric(value)?number(value,3):"—");
        const ok=history && history.available && Array.isArray(history.points) && history.points.length;
        stat("trafficCurrentIn",ok?history.current_in:null); stat("trafficCurrentOut",ok?history.current_out:null);
        stat("trafficAverage",ok?(history.average_in+history.average_out)/2:null);
        stat("trafficPeak",ok?Math.max(history.peak_in,history.peak_out):null);
        if(!ok) { root.append(emptyCard("No sensor history",history ? "Enable an SNMP traffic sensor to chart inbound and outbound." : "Sensor history unavailable.")); return; }
        const W=720,H=220,L=44,R=10,T=10,B=24, pts=history.points, step=history.bucket_seconds;
        const t1=pts[pts.length-1].t, t0=t1-86400, max=niceMax(Math.max(...pts.map(p=>Math.max(p.in,p.out)),1e-6));
        const x=t=>L+(t-t0)/86400*(W-L-R), y=v=>T+(1-v/max)*(H-T-B);
        const svg=svgNode("svg",{viewBox:"0 0 "+W+" "+H,preserveAspectRatio:"none"});
        [0,.5,1].forEach(f=>{ const yy=y(max*f); svg.append(svgNode("line",{class:"grid",x1:L,x2:W-R,y1:yy,y2:yy}));
            const label=svgNode("text",{class:"axis",x:L-6,y:yy+3,"text-anchor":"end"}); label.textContent=number(max*f,2); svg.append(label); });
        [t0,t0+43200,t1].forEach((t,i)=>{ const label=svgNode("text",{class:"axis",x:x(t),y:H-6,"text-anchor":i===0?"start":i===2?"end":"middle"});
            label.textContent=new Date(t*1000).toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"}); svg.append(label); });
        [["in","var(--ov-in)"],["out","var(--ov-out)"]].forEach(([key,color])=>{
            const segments=[]; let current=[];
            pts.forEach((p,i)=>{ if(i && p.t-pts[i-1].t>step*2) { segments.push(current); current=[]; } current.push([x(p.t),y(p[key])]); }); segments.push(current);
            segments.forEach(seg=>{
                if(seg.length>1) { const base=y(0), d=smoothPath(seg);
                    svg.append(svgNode("path",{d:d+" L"+seg[seg.length-1][0]+" "+base+" L"+seg[0][0]+" "+base+" Z",fill:color,"fill-opacity":".12"})); }
                svg.append(svgNode(seg.length>1?"path":"circle",seg.length>1?{d:smoothPath(seg),fill:"none",stroke:color,"stroke-width":"1.8"}:{cx:seg[0][0],cy:seg[0][1],r:2.5,fill:color}));
            });
        });
        root.append(svg);
    }
    function liveStatus(item) { return item.monitoring_health === "Active" && Object.hasOwn(statuses,item.ddos_status) ? item.ddos_status : "Unknown"; }
    const sortRank = {"Under Attack":0, Warning:1, Unknown:2, Normal:3};
    function renderIPs() {
        const table=byId("rulesTable"); table.replaceChildren();
        if(!latest) { empty(table,6,"Current data unavailable"); return; }
        const term=(search?.value || "").trim().toLowerCase(), wanted=byId("ipFilter")?.value || "", order=byId("ipSort")?.value || "address";
        const items=latest.rules.filter(item=>(item.address+" "+item.device_name).toLowerCase().includes(term) && (!wanted || liveStatus(item)===wanted));
        if(order==="mbps") items.sort((a,b)=>(numeric(b.mbps)&&b.monitoring_health==="Active"?b.mbps:-1)-(numeric(a.mbps)&&a.monitoring_health==="Active"?a.mbps:-1));
        else if(order==="status") items.sort((a,b)=>sortRank[liveStatus(a)]-sortRank[liveStatus(b)]);
        text("ipResults",items.length+" of "+latest.rules.length+" saved IPs");
        if(!items.length) empty(table,6,latest.rules.length ? "No matching IPs" : latest.empty_message || "No public IPs configured",latest.rules.length ? "Try another IP or device name." : "Add an assignment to begin.");
        items.forEach(item=>{
            const row=table.insertRow(), identity=cell(row,"Public IP");
            identity.append(link(item.address,item.inspect_url,"mono"));
            if(item.retry_url && item.provisioning_status!=="verified") {
                const form=element("form"); form.method="POST"; form.action=item.retry_url;
                const token=element("input"); token.type="hidden"; token.name="csrfmiddlewaretoken"; token.value=csrf;
                const button=element("button","Retry Provisioning","overview-inspect"); button.type="submit";
                form.append(token,button); identity.append(form);
            }
            cell(row,"Device").textContent=item.device_name;
            const fresh=item.monitoring_health === "Active";
            const udp=cell(row,"UDP PPS"); udp.className="mono"; udp.textContent=number(fresh?item.udp_pps:null);
            const syn=cell(row,"TCP SYN PPS"); syn.className="mono"; syn.textContent=number(fresh?item.syn_pps:null);
            const mbps=cell(row,"Mbps"); mbps.className="mono"; mbps.textContent=number(fresh?item.mbps:null,6);
            const state=cell(row,"Status"); state.append(badge(liveStatus(item)),element("small",item.monitoring_health || "Not Monitored"));
        });
    }
    function renderIncidents(data) {
        const table=byId("incidentsTable"); table.replaceChildren();
        const incidents=(data.incidents || []).filter(item=>["Warning","Under Attack"].includes(liveStatus(item)));
        if(!incidents.length) empty(table,5,"No active detections","Only fresh, confirmed Warning and Under Attack samples appear here.");
        incidents.forEach(item=>{
            const row=table.insertRow(); row.dataset.state=statuses[item.ddos_status] || "unknown";
            const target=cell(row,"Target Public IP"); target.append(link(item.address,item.inspect_url,"mono"),element("small",item.device_name));
            cell(row,"Triggering Metrics").textContent=metrics(item.ddos_metrics) || "Threshold crossing";
            const traffic=cell(row,"Current Traffic"); traffic.className="mono"; traffic.append(element("span",number(item.mbps,6)+" Mbps"),element("small",number(item.pps)+" PPS"));
            const started=cell(row,"Started / Elapsed"); started.className="mono"; started.append(element("span",time(item.started_at)),element("small",duration(item.duration_seconds)));
            cell(row,"Severity").append(badge(item.ddos_status));
        });
        byId("incidentPanel").dataset.state=incidents.some(item=>item.ddos_status==="Under Attack") ? "under-attack" : incidents.length ? "warning" : "quiet";
    }
    function renderFleet(data) {
        const table=byId("savedDevices"); table.replaceChildren();
        if(!data.devices.length) empty(table,5,data.empty_message || "No devices configured");
        const pill=(label,state)=>{ const node=element("span",label,"status-pill"); node.dataset.state=state; return node; };
        data.devices.forEach(device=>{
            const row=table.insertRow(), identity=cell(row,"Device"); identity.append(link(device.name,"/devices/"),element("small",device.management_ip,"mono"));
            const conn=cell(row,"Connection"), tested=Boolean(device.last_connection_test);
            conn.append(!tested ? pill("Not tested","not-tested") : device.last_connection_test_succeeded ? pill("Online","receiving-samples") : pill("Connection Error","connection-failed"),
                element("small",tested ? "Last API check "+time(device.last_connection_test) : "No API check yet"));
            const traffic=cell(row,"Traffic"); traffic.append(element("strong",numeric(device.mbps)?number(device.mbps,6)+" Mbps":"\u2014","mono"),element("small",number(device.monitored_ips,0)+" / "+number(device.assigned_ips,0)+" IPs sampled"));
            const cpu=cell(row,"CPU / Memory"); cpu.append(element("span",numeric(device.cpu)?Math.min(100,Math.round(device.cpu))+"%":"N/A","mono"),element("small","Memory N/A"));
            const health=device.monitoring_health || "Not Monitored";
            cell(row,"Sampling").append(pill(health==="Receiving samples"?"Receiving Samples":["Not Monitored","Stale"].includes(health)?"No Samples":health,health.toLowerCase().replaceAll(" ","-")));
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
        text("detectionMode",system.detection_enabled?"Passive Detection Enabled":"Detection disabled");
        health("healthWorker",system.worker_running?"Running":"No active app worker",system.worker_running);
        health("healthDetection",system.detection_enabled?"Enabled":"Disabled",system.detection_enabled);
        health("healthRouter",system.sampled_devices ? "Receiving data":"No fresh data",system.sampled_devices>0);
        health("healthDashboard","Available",true);
        text("overview-monitored_ips_2",number((data.overview||{}).monitored_ips,0));
        renderIncidents(data); renderFleet(data); renderIPs(); renderEvents(); renderTraffic(data.traffic_history);
    }
    function unavailable() {
        latest=null; text("error","Dashboard data unavailable. Check your connection or sign in again. Displayed live statuses have been cleared.");
        text("status","DATA UNAVAILABLE"); byId("status").dataset.state="error"; text("lastUpdate","\u2014");
        text("routerStatus","Current data unavailable"); ["statusDot","routerDot"].forEach(id=>{if(byId(id)) byId(id).dataset.state="error";});
        ["devices","monitored_devices","public_ips"].forEach(key=>text("summary-"+key,"\u2014"));
        ["total_mbps","total_pps","active_detections","monitored_ips","attack_ips","warning_ips","unknown_ips"].forEach(key=>text("overview-"+key,"\u2014"));
        ["healthWorker","healthDetection","healthRouter","healthDashboard"].forEach(id=>health(id,"Unknown",false));
        text("detectionMode","Detection status unavailable"); text("ipResults","Current data unavailable"); byId("incidentPanel").dataset.state="unknown";
        ["overview-monitored_ips_2","overview-total_syn_pps","overview-total_udp_pps"].forEach(id=>text(id,"—"));
        byId("incidentsTable").replaceChildren(); empty(byId("incidentsTable"),5,"Detection data unavailable");
        byId("savedDevices").replaceChildren(); empty(byId("savedDevices"),5,"Device data unavailable");
        renderTraffic(null); renderIPs(); renderEvents();
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
    ["dashboardSearch","ipFilter","ipSort"].forEach(id=>byId(id)?.addEventListener(id==="dashboardSearch"?"input":"change",renderIPs));
    document.querySelectorAll("[data-event-filter]").forEach(button=>button.addEventListener("click",()=>{
        eventFilter=button.dataset.eventFilter;
        document.querySelectorAll("[data-event-filter]").forEach(item=>item.setAttribute("aria-pressed",String(item===button)));
        renderEvents();
    }));
    refreshButton?.addEventListener("click",refresh);
    refresh(); window.setInterval(refresh,2000);
})();
