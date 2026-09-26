"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const node = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
  const link = (text, href, download=false) => { const a=node("a",text); a.href=href; if(download)a.setAttribute("download",""); return a; };
  const button = (text, action) => { const b=node("button",text); b.addEventListener("click", action); return b; };
  const sizes = n => n < 1024 ? n+" B" : n < 1048576 ? (n/1024).toFixed(1)+" KiB" : n < 1073741824 ? (n/1048576).toFixed(1)+" MiB" : (n/1073741824).toFixed(2)+" GiB";
  const labels = {allocated:"Available",deleted:"Deleted",reallocated:"Reallocated",unknown:"Unknown / carved"};
  let page=0, items=[], viewIndex=0, generation=0;
  const perPage=48;
  function pagination(render) {
    const total=Math.max(1,Math.ceil(items.length/perPage)); page=Math.min(page,total-1);
    const prev=button("Previous page",()=>{page--;render();}), next=button("Next page",()=>{page++;render();});
    prev.disabled=page===0; next.disabled=page>=total-1;
    $("pagination").replaceChildren(prev,node("span",`Page ${page+1} of ${total} · ${items.length.toLocaleString()} results`),next);
  }
  function evidence() {
    const data=window.DA_EVIDENCE;
    $("tier").value=location.pathname.endsWith("evidence.html")?"all":"attention";
    function render() {
      const q=$("search").value.toLowerCase(), tier=$("tier").value;
      items=data.findings.filter(f=>(tier==="all"||f.triage.tier===tier)&&JSON.stringify(f).toLowerCase().includes(q));
      pagination(render); $("results").replaceChildren();
      $("summary").textContent=`${items.length.toLocaleString()} ${tier==='all'?'observations':tier==='attention'?'items needing attention':tier==='lead'?'unconfirmed leads':'background observations'}.`;
      if(!items.length) $("results").append(node("p","No items in this view. Other tiers remain available in the filter.","muted"));
      for(const f of items.slice(page*perPage,(page+1)*perPage)) {
        const card=node("article",undefined,"lead");card.id=f.id;
        card.append(node("h2",f.title),node("p",f.triage.reason),node("small",`${f.id} · ${f.kind} · ${f.sources.length} source(s)`));
        const validation=f.automatic_validation||{};
        if(validation.status) card.append(node("p",`Automatic validation: ${validation.status}. ${validation.summary||''}`));
        if(validation.scope) card.append(node("p",validation.scope,"muted"));
        if(validation.addresses?.length) {
          const details=node("details"),list=node("div");details.append(node("summary",`${validation.addresses.length} public address derivations and balance checks`));
          for(const a of validation.addresses) {
            const row=node("div",undefined,"address");row.append(node("strong",a.chain),node("code",a.address),node("small",`${a.path||'Observed'} · ${a.linkage}`));
            const checks=data.balances.filter(b=>b.chain===a.chain&&(a.chain==='ethereum'?b.address.toLowerCase()===a.address.toLowerCase():b.address===a.address));
            if(!checks.length)row.append(node("p","Balance: not checked","muted"));
            for(const b of checks) {
              row.append(node("p",b.status==='ok'?`Balance: ${b.data.balance_display} · ${b.data.activity||'activity unknown'} · ${b.checked_at}`:`Balance: lookup failed (${b.status}); no zero balance inferred`));
              row.append(node("small",`Source: ${b.provider}. ${b.data.scope||''}`));
            }
            list.append(row);
          }
          details.append(list);card.append(details);
        }
        const details=node("details");details.append(node("summary","Evidence and source locations"));
        for(const s of f.sources) {
          const p=node("p",s.path||s.method||"Source");
          if(s.file_id)p.append(document.createTextNode(" · "),link("Find file",`files.html#file=${encodeURIComponent(s.file_id)}`));
          details.append(p,node("pre",JSON.stringify(s,null,2)));
        }
        card.append(details);$("results").append(card);
      }
    }
    const fragment=decodeURIComponent(location.hash.slice(1));
    if(fragment==='lead')$("tier").value='lead';
    else if(fragment.startsWith('F')) { $("tier").value='all';$("search").value=fragment; }
    for(const id of ['search','tier'])$(id).addEventListener('input',()=>{page=0;render();});
    render();
  }
  if(window.DA_EVIDENCE)evidence();
})();
