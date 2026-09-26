"use strict";
(() => {
  const data = window.DA_MEDIA || [], access = window.DA_ACCESS;
  const $ = id => document.getElementById(id);
  const node = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
  const button = (text, action, cls) => { const b = node('button', text, cls); b.type = 'button'; b.onclick = action; return b; };
  const count = n => Number(n || 0).toLocaleString();
  const size = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KiB` : n < 1073741824 ? `${(n/1048576).toFixed(1)} MiB` : `${(n/1073741824).toFixed(2)} GiB`;
  const labels = {allocated: 'Existing', deleted: 'Deleted', reallocated: 'Reallocated', unknown: 'Carved / unknown'};
  const duration = n => n > 0 && Number.isFinite(n) ? `${Math.floor(n/60)}:${String(Math.floor(n%60)).padStart(2,'0')}` : 'Video';
  const date = n => n > 0 && Number.isFinite(n) && !Number.isNaN(new Date(n*1000).getTime()) ? new Date(n*1000).toISOString().slice(0,10) : 'Unknown';
  const manifest = window.DA_MEDIA_FOLDERS;
  const folders = manifest.folders;
  const defaults = {type: 'all', state: 'all', availability: 'all', sort: 'name', album: '', scope: 'subtree', q: '', copies: false, page: 0, limit: 96, tile: 200};
  function readView() {
    const params = new URLSearchParams(location.hash.slice(1)), value = {...defaults};
    for (const key of Object.keys(defaults)) if (params.has(key)) value[key] = params.get(key);
    for (const [key, allowed] of Object.entries({type:['all','image','video'], state:['all',...Object.keys(labels)], availability:['all','exported','image','partial'], sort:['name','newest','oldest','largest','smallest'], scope:['folder','subtree']})) if (!allowed.includes(value[key])) value[key] = defaults[key];
    value.copies = value.copies === true || value.copies === 'true'; value.limit = [48,96,192].includes(Number(value.limit)) ? Number(value.limit) : 96;
    value.page = Math.max(0, Math.min(1000000, Math.floor(Number(value.page) || 0))); value.tile = Math.min(300, Math.max(150, Number(value.tile) || 200));
    if (!Object.hasOwn(folders, value.album) || value.album === 'root') value.album = '';
    return value;
  }
  const view = readView(), expanded = new Set(['root']), treeLimits = new Map(), trails = new Map();
  let items = [], index = 0, request = null, generation = 0, searchTimer, activeResult = null, folderLimit = 12, skipCloseRender = false;
  let conversionAttempted = false;
  let folderCounts = new Map(), cardFolders = [];
  const historyKey = history.state?.gallery || Math.random().toString(36).slice(2);
  let historyIndex = history.state?.gallery === historyKey ? history.state.index : 0, historyMax = historyIndex;
  try { historyMax = Math.max(historyIndex, Number(sessionStorage.getItem('gallery-history-' + historyKey)) || 0); } catch {}
  history.replaceState({gallery:historyKey,index:historyIndex}, '', location.href);
  function trail(id) {
    if (!trails.has(id)) {
      const result = [];
      for (let current = id; current; current = folders[current].parent) result.unshift(current);
      trails.set(id, result);
    }
    return trails.get(id);
  }
  function folderName(id) {
    const f = folders[id];
    if (id === 'root') return 'All folders';
    if (f.parent === 'root') return manifest.volumes[f.name]?.name || (f.name === 'Unknown origin / carved' ? 'Carved / unknown origin' : f.name);
    return f.name;
  }
  const folderPath = id => trail(id).slice(1).map(folderName).join(' / ') || 'All folders';
  function revealFolder() {
    for (const id of trail(view.album || 'root').slice(0,-1)) expanded.add(id);
  }
  revealFolder();
  function url(openId) {
    const p = new URLSearchParams();
    for (const key of Object.keys(defaults)) if (view[key] !== defaults[key]) p.set(key, view[key]);
    if (openId) p.set('media', openId);
    return '#' + p.toString();
  }
  function save(openId) { history.replaceState({gallery:historyKey,index:historyIndex}, '', url(openId)); }
  function change(patch) {
    clearTimeout(searchTimer);
    Object.assign(view, {page:0}, patch);
    if (url() !== location.hash) {
      historyIndex++; historyMax = historyIndex;
      try { sessionStorage.setItem('gallery-history-' + historyKey, historyMax); } catch {}
      history.pushState({gallery:historyKey,index:historyIndex}, '', url());
    }
    if (Object.hasOwn(patch, 'album')) { folderLimit = 12; $('album-search').value = ''; revealFolder(); }
    $('media-library').classList.remove('folders-open'); $('toggle-media-folders').setAttribute('aria-expanded','false');
    render(); $('gallery-scroll').scrollTop = 0;
  }
  function navigate(id) { change({album:id === 'root' ? '' : id}); }
  function up() { if (view.album) navigate(folders[view.album].parent); }
  function focusFolder(id) {
    const item = [...$('albums').querySelectorAll('.media-tree-item')].find(n => n.dataset.folder === id);
    if (item) {
      for (const n of $('albums').querySelectorAll('.media-tree-item')) n.tabIndex = n === item ? 0 : -1;
      item.focus({preventScroll:true}); item.scrollIntoView({block:'nearest'});
    }
  }
  function renderAlbums() {
    const query = $('album-search').value.trim().toLowerCase(), visible = new Set(['root']);
    const focused = document.activeElement.closest('.media-tree-item')?.dataset.folder;
    if (query) for (const id of Object.keys(folders)) {
      if (folderPath(id).toLowerCase().includes(query)) for (const ancestor of trail(id)) visible.add(ancestor);
    }
    $('albums').replaceChildren();
    const stack = [{id:'root',container:$('albums'),level:1,position:1,siblings:1}];
    while (stack.length) {
      const {id,container,level,position,siblings} = stack.pop(), f = folders[id];
      const children = f.children.filter(child => !query || visible.has(child));
      const isOpen = id === 'root' || !!query || expanded.has(id);
      const item = node('div',undefined,'media-tree-item'), row = node('div',undefined,'media-tree-row');
      item.dataset.folder=id; item.setAttribute('role','treeitem'); item.tabIndex=id===(focused || view.album || 'root')?0:-1;
      item.setAttribute('aria-level',level); item.setAttribute('aria-posinset',position); item.setAttribute('aria-setsize',siblings);
      item.setAttribute('aria-selected',String(id === (view.album || 'root')));
      item.setAttribute('aria-label',`${folderName(id)}, ${count(folderCounts.get(id) || 0)} media files`);
      row.style.paddingLeft = `${8+(level-1)*16}px`;
      const toggle = button(children.length && id!=='root' ? (isOpen?'⌄':'›') : '', () => {
        if (isOpen) expanded.delete(id); else expanded.add(id);
        renderAlbums(); focusFolder(id);
      }, 'media-tree-toggle');
      toggle.tabIndex=-1; toggle.disabled=!children.length || id==='root' || !!query;
      toggle.setAttribute('aria-label',`${isOpen?'Collapse':'Expand'} ${folderName(id)}`);
      if (children.length) item.setAttribute('aria-expanded',String(isOpen));
      const b = button('',()=>{navigate(id);focusFolder(id);},'media-folder-name'); b.tabIndex=-1; b.title=folderPath(id);
      b.append(node('span',id==='root'?'▦':f.parent==='root'?'▤':'▱','folder-symbol'),node('span',folderName(id),'album-name'),node('span',count(folderCounts.get(id) || 0),'album-count'));
      row.append(toggle,b); item.append(row); container.append(item);
      if (children.length && isOpen) {
        const group=node('div'); group.setAttribute('role','group'); item.append(group);
        const limit=treeLimits.get(id)||60, shown=children.slice(0,limit);
        const selectedChild=trail(view.album || 'root').find(child=>folders[child].parent===id);
        if (children.includes(selectedChild) && !shown.includes(selectedChild)) shown.push(selectedChild);
        // A branch is rendered only when expanded, and large sibling lists are bounded.
        for (let n=shown.length-1;n>=0;n--) stack.push({id:shown[n],container:group,level:level+1,position:children.indexOf(shown[n])+1,siblings:children.length});
        if (children.length>limit) {
          const more=button(`Show ${Math.min(60,children.length-limit)} more folders`,()=>{treeLimits.set(id,limit+60);renderAlbums();},'more-tree-folders');
          more.style.marginLeft=`${24+level*16}px`; item.append(more);
        }
      }
    }
    if (query && visible.size===1) $('albums').append(node('p','No matching folders.','folder-search-empty'));
    if (!$('albums').querySelector('.media-tree-item[tabindex="0"]')) $('albums').querySelector('.media-tree-item').tabIndex=0;
    if (focused) focusFolder(focused);
  }
  function renderLocation() {
    const id=view.album || 'root', path=trail(id), crumbs=$('media-breadcrumbs'); crumbs.replaceChildren();
    for (const part of path) {
      if (part!=='root') crumbs.append(node('span','/','breadcrumb-separator'));
      const b=button(folderName(part),()=>navigate(part)); b.title=folderPath(part);
      if(part===id)b.setAttribute('aria-current','location'); crumbs.append(b);
    }
    crumbs.scrollLeft=crumbs.scrollWidth;
    $('media-up').disabled=!view.album; $('media-back').disabled=historyIndex===0; $('media-forward').disabled=historyIndex>=historyMax;
    $('media-file-browser').href=`files.html#folder=${encodeURIComponent(id)}&scope=folder`;
    $('media-scope').value=view.scope; $('media-scope').disabled=!view.album;
    $('media-scope-note').textContent=!view.album?'Across all folders':view.scope==='subtree'?'In this folder and all subfolders':'Directly in this folder';
    $('search').placeholder=view.album?'Search within '+folderName(id)+'…':'Search all photos and videos…';
    cardFolders=folders[id].children;
    $('media-subfolders').hidden=!cardFolders.length;
    $('subfolders-title').textContent=view.album?'Subfolders':'Locations';
    $('subfolders-count').textContent=`${count(cardFolders.length)} ${view.album?'folders':'locations'}`;
    $('media-folder-cards').replaceChildren();
    for (const child of cardFolders.slice(0,folderLimit)) {
      const b=button('',()=>navigate(child),'media-folder-card'); b.dataset.folder=child; b.title=folderPath(child);
      const text=node('span',undefined,'folder-card-text'); text.append(node('strong',folderName(child)),node('span',`${count(folderCounts.get(child) || 0)} matching media · includes subfolders`));
      b.append(node('span',folders[child].parent==='root'?'▤':'▱','folder-card-symbol'),text,node('span','›','folder-card-arrow'));
      $('media-folder-cards').append(b);
    }
    $('more-media-folders').hidden=cardFolders.length<=folderLimit;
    $('more-media-folders').textContent=`Show more folders (${count(Math.max(0,cardFolders.length-folderLimit))} remaining)`;
  }
  function fallback(f, small=false) {
    const box = node('div',undefined,'fallback');
    box.append(node('span',f.type==='video'?'▷':'▧'));
    if (!small) box.append(node('span',f.artifact?'Open to preview':f.on_demand?'On image · open to load':'No saved content'));
    return box;
  }
  function preview(f, small=false) {
    const box = node('div',undefined,'tile-preview'); box.style.height='100%';
    const poster = access.poster(f), raw = f.artifact || access.cached.get(f.id)?.url;
    if (poster || (f.type==='image' && raw)) {
      const img = node('img'); img.alt=f.name; img.loading='lazy'; img.decoding='async'; img.src=poster || raw;
      let triedOriginal = !poster;
      img.onerror = () => {
        if (!triedOriginal && f.type==='image' && raw) { triedOriginal=true; img.src=raw; }
        else box.replaceChildren(fallback(f,small));
      }; box.append(img);
    } else if (f.type==='video' && raw && !small) {
      const video=node('video'); video.src=raw; video.preload='metadata'; video.muted=true; video.playsInline=true;
      video.onerror=()=>box.replaceChildren(fallback(f,small)); box.append(video);
    } else box.append(fallback(f,small));
    return box;
  }
  function render() {
    const q=view.q.trim().toLowerCase(), current=view.album || 'root';
    const inFolder=f=>!view.album || (view.scope==='folder' ? f.folder===current : trail(f.folder).includes(current));
    const available=data.filter(f=>(view.state==='all'||f.state===view.state)&&
      (!q||`${f.name} ${f.path} ${f.id}`.toLowerCase().includes(q))&&
      (view.availability==='all'||(view.availability==='exported'&&f.artifact)||(view.availability==='image'&&!f.artifact)||(view.availability==='partial'&&f.artifact&&f.status==='partial')));
    const filtered=available.filter(f=>view.type==='all'||f.type===view.type);
    folderCounts=new Map();
    for (const f of filtered) for (const id of trail(f.folder)) folderCounts.set(id,(folderCounts.get(id)||0)+1);
    $('library-types').replaceChildren();
    for (const [type,label,symbol] of [['all','All media','▦'],['image','Photos','▧'],['video','Videos','▷']]) {
      const b = button('',()=>change({type})); b.dataset.type=type; b.setAttribute('aria-pressed',String(view.type===type));
      b.append(node('span',symbol,'type-symbol'),node('span',label),node('span',count(available.filter(f=>inFolder(f)&&(type==='all'||f.type===type)).length))); $('library-types').append(b);
    }
    renderAlbums(); renderLocation();
    const found = filtered.filter(inFolder);
    found.sort((a,b)=> {
      let result=0;
      if (['newest','oldest'].includes(view.sort)) {
        if (!a.modified || !b.modified) result = !a.modified ? (!b.modified ? 0 : 1) : -1;
        else result=(a.modified-b.modified)*(view.sort==='newest'?-1:1);
      } else if (['largest','smallest'].includes(view.sort)) result=(a.size-b.size)*(view.sort==='largest'?-1:1);
      return result || a.name.localeCompare(b.name,undefined,{numeric:true}) || a.id.localeCompare(b.id);
    });
    const groups = new Map(); items=[];
    for (const f of found) {
      const key = view.copies && f.sha256 && f.artifact ? f.sha256 : f.id;
      if (!groups.has(key)) { const item={file:f,copies:[]}; groups.set(key,item); items.push(item); }
      groups.get(key).copies.push(f);
    }
    const pages=Math.max(1,Math.ceil(items.length/view.limit)); view.page=Math.min(Math.floor(view.page),pages-1);
    $('state').value=view.state; $('availability').value=view.availability; $('media-sort').value=view.sort;
    $('search').value=view.q; $('group-copies').checked=view.copies; $('tile-size').value=view.tile;
    $('media-library').style.setProperty('--tile',view.tile+'px'); $('media-page-size').value=view.limit;
    $('album-title').textContent=view.album?folderName(view.album):view.type==='image'?'Photos':view.type==='video'?'Videos':'All media';
    $('summary').textContent=`${count(items.length)} ${view.copies?'content groups':'items'} · ${count(found.filter(f=>f.type==='image').length)} photos, ${count(found.filter(f=>f.type==='video').length)} videos · ${count(found.filter(f=>!f.artifact).length)} not exported`;
    $('reset-media').hidden=!(view.q||view.type!=='all'||view.state!=='all'||view.availability!=='all'||view.copies);
    const start=view.page*view.limit; $('results').replaceChildren();
    for (let i=start;i<Math.min(start+view.limit,items.length);i++) {
      const item=items[i],f=item.file,figure=node('figure',undefined,'media-tile'),b=button('',()=>open(i),'media-button'); b.setAttribute('aria-label',`Open ${f.name}`);
      b.append(preview(f),node('span',labels[f.state],'tile-state '+f.state),node('span',f.type==='video'?duration(f.duration):f.name.split('.').at(-1).toUpperCase(),'tile-format'));
      if (item.copies.length>1) b.append(node('span',`${count(item.copies.length)} copies`,'tile-copies'));
      const caption=node('figcaption'),meta=node('div',undefined,'tile-meta'); caption.append(node('strong',f.name)); caption.title=f.path;
      const location=button(folderPath(f.folder),()=>navigate(f.folder),'tile-folder'); location.title=folderPath(f.folder); location.setAttribute('aria-label',`Open folder ${folderPath(f.folder)}`);
      meta.append(node('span',access.label(f)),node('span',f.width&&f.height?`${f.width} × ${f.height}`:size(f.size))); caption.append(location,meta); figure.append(b,caption); $('results').append(figure);
    }
    $('media-empty').hidden=items.length>0;
    $('media-empty').replaceChildren(node('h3','No media in this view'),node('p',view.album&&view.scope==='folder'&&cardFolders.length?'Open a subfolder above, or include subfolders to see their photos and videos.':'Try another folder or clear the filters. Only files present in the saved inventory can appear here.'));
    if(view.album&&view.scope==='folder'&&cardFolders.length)$('media-empty').append(button('Include subfolders',()=>change({scope:'subtree'})));
    if(!$('reset-media').hidden)$('media-empty').append(button('Clear filters',reset));
    $('page-range').textContent=items.length?`${count(start+1)}–${count(Math.min(start+view.limit,items.length))} of ${count(items.length)}`:'0 items';
    $('media-page').value=view.page+1; $('media-page').max=pages; $('media-pages').textContent=`of ${count(pages)}`;
    $('previous-page').disabled=view.page===0; $('next-page').disabled=view.page===pages-1; save();
  }
  function reset() { change({type:'all',state:'all',availability:'all',q:'',copies:false}); }
  function info(item) {
    const f=item.file, pane=$('viewer-info'); pane.replaceChildren(node('h3',f.name));
    const dl=node('dl');
    for (const [label,value] of [['Original path',f.path],['Volume',f.volume||'Unknown origin'],['File state',labels[f.state]],['Content',activeResult?.source==='preview'?'Converted MP4 playback preview':activeResult?.source==='image'?'Read from image (temporary cache)':access.label(f)],['Original size',size(f.size)],['Modified (UTC, filesystem)',date(f.modified)],['Dimensions',f.width&&f.height?`${f.width} × ${f.height}`:null],['Duration',f.duration?duration(f.duration):null]]) {
      if (value) dl.append(node('dt',label),node('dd',value));
    }
    pane.append(dl);
    if (f.status==='partial'||activeResult?.partial) pane.append(node('p','Only part of this file is available. It may be damaged or fail to play.','viewer-warning'));
    if (f.state==='reallocated') pane.append(node('p','These blocks were reused. The content may belong to a different file.','viewer-warning'));
    const source=node('a','Show in file browser'); source.href=`files.html#file=${encodeURIComponent(f.id)}`; pane.append(source);
    pane.append(button('Open media folder',()=>{
      $('viewer').addEventListener('close',()=>navigate(f.folder),{once:true}); $('viewer').close();
    },'viewer-folder-link'));
    if(f.type==='video' && access.session.video_previews && !conversionAttempted) {
      pane.append(button('Create playable preview',()=>convertVideo(generation),'viewer-folder-link'));
      pane.append(node('p','Use this if the original video has playback or audio problems. The download remains the original file.'));
    }
    if(activeResult?.source==='preview')pane.append(node('p','This is a converted viewing copy, up to 720p, with the first audio track. Download original keeps the recovered video unchanged.'));
    if (item.copies.length>1) {
      pane.append(node('h3',`${count(item.copies.length)} identical copies`));
      let limit=0;
      const locations=node('div');
      function more() {
        for (const copy of item.copies.slice(limit,limit+30)) {
          const a=node('a',`${labels[copy.state]} · ${copy.path}`); a.href=`files.html#file=${encodeURIComponent(copy.id)}`; locations.append(a);
        }
        limit+=30; next.hidden=limit>=item.copies.length;
      }
      const next=button('More locations',more); pane.append(locations,next); more();
    }
  }
  function viewerMessage(text, retry=false) {
    $('viewer-message').hidden=false; $('viewer-message').replaceChildren(node('p',text));
    if (retry) $('viewer-message').append(button('Retry opening',()=>open(index)));
  }
  function displayMedia(f, result, token) {
    activeResult=result; $('viewer-message').hidden=true;
    const media=node(f.type==='video'?'video':'img');
    if(f.type==='video'){media.controls=true;media.preload='metadata';media.playsInline=true;const poster=access.poster(f);if(poster)media.poster=poster;}
    else {media.alt=f.name;media.ondblclick=zoom;}
    media.onerror=()=>{
      if(token!==generation)return;
      if(f.type==='video' && result.source!=='preview' && access.session.video_previews && !conversionAttempted)convertVideo(token);
      else viewerMessage(f.type==='video' && result.source!=='preview'
        ? (access.session.enabled?'This browser cannot play the original. Install FFmpeg on the local browser host to create a compatible preview, or download the original.'
          :'This browser cannot play the original. Open the case through cold-digger serve to create a compatible preview, or download the original.')
        : 'This browser cannot display this format, or the file is damaged. Download the original to open it locally.');
    };
    media.src=result.url; $('viewer-media').replaceChildren(media);
    $('viewer-caption').textContent=`${index+1} / ${count(items.length)} · ${f.path} · ${labels[f.state]} · ${result.source==='preview'?'Converted MP4 preview'+(result.partial?' · Partial source':''):result.partial?'Partial content':result.source==='image'?'Read from image':access.label(f)}`;
    info(items[index]);
  }
  async function convertVideo(token) {
    if(token!==generation || conversionAttempted || !items[index])return;
    conversionAttempted=true;
    const f=items[index].file;
    $('viewer-media').querySelector('video')?.pause(); $('viewer-media').replaceChildren();
    viewerMessage('Preparing a playable video preview locally…'); info(items[index]);
    try {
      const result=await access.video(f,status=>{
        if(token===generation)viewerMessage(status.status==='queued'?'Waiting to prepare this video…':`Preparing playable preview · ${size(status.bytes||0)} created`);
      },request.signal);
      if(token===generation)displayMedia(f,result,token);
    } catch(error) {if(token===generation && error.name!=='AbortError')viewerMessage(error.message,true);}
  }
  async function open(nextIndex) {
    if (!items[nextIndex]) return;
    index=nextIndex; const item=items[index],f=item.file, token=++generation;
    request?.abort(); request=new AbortController(); activeResult=null; conversionAttempted=false;
    $('viewer-media').replaceChildren(); $('viewer-media').classList.remove('actual-size'); $('zoom-media').textContent='Actual size';
    $('zoom-media').disabled=f.type!=='image'; $('download-media').hidden=true; $('viewer-message').hidden=true;
    $('viewer-name').textContent=f.name; $('viewer-position').textContent=`${index+1} / ${count(items.length)}`;
    $('viewer-caption').textContent=`${index+1} / ${count(items.length)} · ${f.path} · ${labels[f.state]} · ${access.label(f)}`;
    $('previous-media').disabled=index===0; $('next-media').disabled=index===items.length-1; info(item);
    $('filmstrip').replaceChildren();
    for(let n=Math.max(0,index-5);n<Math.min(items.length,index+6);n++) {
      const b=button('',()=>open(n)); b.setAttribute('aria-label',`View ${items[n].file.name}`); b.title=items[n].file.name;
      if(n===index)b.setAttribute('aria-current','true'); b.append(preview(items[n].file,true)); $('filmstrip').append(b);
    }
    if(!$('viewer').open)$('viewer').showModal(); save(f.id);
    if(!f.artifact)viewerMessage('Opening this file from the image…');
    try {
      const result=await access.open(f,status=>viewerMessage(`${status.status==='queued'?'Waiting to read':'Reading from image'} · ${size(status.bytes||0)} of ${size(f.size)}`),request.signal);
      if(token!==generation)return;
      $('download-media').href=result.url; $('download-media').download=f.name; $('download-media').hidden=false;
      displayMedia(f,result,token);
    } catch(error) { if(token===generation && error.name!=='AbortError')viewerMessage(error.message,true); }
  }
  function zoom() {
    if(!items[index]||items[index].file.type!=='image')return;
    const actual=$('viewer-media').classList.toggle('actual-size'); $('zoom-media').textContent=actual?'Fit to screen':'Actual size';
  }
  $('close-viewer').onclick=()=>$('viewer').close();
  $('viewer').addEventListener('close',()=>{generation++;request?.abort();$('viewer-media').replaceChildren();$('viewer-message').hidden=true;if(skipCloseRender){skipCloseRender=false;return;}view.page=Math.floor(index/view.limit);render();});
  $('previous-media').onclick=()=>open(index-1);$('next-media').onclick=()=>open(index+1);$('zoom-media').onclick=zoom;
  $('info-media').onclick=()=>{const hidden=$('viewer-info').hidden; $('viewer-info').hidden=!hidden;$('info-media').setAttribute('aria-expanded',String(hidden));};
  $('fullscreen-media').onclick=()=>{const task=document.fullscreenElement?document.exitFullscreen():$('viewer').requestFullscreen?.();task?.catch(()=>{});};
  document.addEventListener('keydown',event=>{
    if(!$('viewer').open){
      if(event.altKey&&['ArrowLeft','ArrowRight','ArrowUp'].includes(event.key)){
        event.preventDefault();
        if(event.key==='ArrowUp')up();
        if(event.key==='ArrowLeft'&&historyIndex>0)history.back();
        if(event.key==='ArrowRight'&&historyIndex<historyMax)history.forward();
      }
      if(event.key==='Escape'){$('media-library').classList.remove('folders-open');$('toggle-media-folders').setAttribute('aria-expanded','false');}
      return;
    }
    if(['INPUT','SELECT','TEXTAREA'].includes(event.target.tagName))return;
    // Let native video controls handle their own seek/volume keys when focused.
    if(event.target.tagName==='VIDEO')return;
    if(event.key==='ArrowLeft'&&index>0){event.preventDefault();open(index-1);}
    if(event.key==='ArrowRight'&&index<items.length-1){event.preventDefault();open(index+1);}
    if(event.key===' '){const video=$('viewer-media').querySelector('video');if(video){event.preventDefault();if(video.paused)video.play().catch(()=>{});else video.pause();}}
    if(event.key==='z')zoom();
  });
  for(const [id,key] of [['state','state'],['availability','availability'],['media-sort','sort']])$(id).onchange=()=>change({[key]:$(id).value});
  $('search').oninput=()=>{clearTimeout(searchTimer);const q=$('search').value;searchTimer=setTimeout(()=>change({q}),180);};
  $('album-search').oninput=()=>renderAlbums();
  $('albums').onkeydown=event=>{
    if(event.altKey)return;
    const item=event.target.closest('.media-tree-item');
    if(!item || event.target.closest('button'))return;
    const id=item.dataset.folder, visible=[...$('albums').querySelectorAll('.media-tree-item')], position=visible.indexOf(item);
    if(!['ArrowDown','ArrowUp','ArrowLeft','ArrowRight','Home','End','Enter',' '].includes(event.key))return;
    event.preventDefault();
    if(event.key==='ArrowDown')focusFolder(visible[Math.min(position+1,visible.length-1)].dataset.folder);
    if(event.key==='ArrowUp')focusFolder(visible[Math.max(0,position-1)].dataset.folder);
    if(event.key==='Home')focusFolder('root');
    if(event.key==='End')focusFolder(visible.at(-1).dataset.folder);
    if(event.key==='Enter'||event.key===' ')navigate(id);
    if(event.key==='ArrowRight' && folders[id].children.length){
      if(item.getAttribute('aria-expanded')==='true'){
        const child=item.querySelector('.media-tree-item'); if(child)focusFolder(child.dataset.folder);
      }else{expanded.add(id);renderAlbums();focusFolder(id);}
    }
    if(event.key==='ArrowLeft'){
      if(id!=='root'&&expanded.has(id)&&!$('album-search').value){expanded.delete(id);renderAlbums();focusFolder(id);}
      else if(folders[id].parent)focusFolder(folders[id].parent);
    }
  };
  $('collapse-media-tree').onclick=()=>{expanded.clear();expanded.add('root');$('album-search').value='';renderAlbums();focusFolder('root');};
  $('more-media-folders').onclick=()=>{folderLimit+=12;renderLocation();};
  $('media-up').onclick=up; $('media-back').onclick=()=>history.back(); $('media-forward').onclick=()=>history.forward();
  $('media-scope').onchange=()=>change({scope:$('media-scope').value});
  $('group-copies').onchange=()=>change({copies:$('group-copies').checked});
  $('tile-size').oninput=()=>{view.tile=Number($('tile-size').value);$('media-library').style.setProperty('--tile',view.tile+'px');save();};
  $('toggle-media-folders').onclick=()=>{const open=$('media-library').classList.toggle('folders-open');$('toggle-media-folders').setAttribute('aria-expanded',String(open));};
  $('reset-media').onclick=reset;
  $('media-page-size').onchange=()=>change({limit:Number($('media-page-size').value)});
  function page(number){change({page:Math.max(0,Number(number)||0)});}
  $('previous-page').onclick=()=>page(view.page-1);$('next-page').onclick=()=>page(view.page+1);$('media-page').onchange=()=>page(Math.floor(Number($('media-page').value))-1);
  function restore() {
    clearTimeout(searchTimer);
    if(history.state?.gallery===historyKey)historyIndex=history.state.index;
    else {historyIndex++;historyMax=historyIndex;}
    const id=new URLSearchParams(location.hash.slice(1)).get('media');
    const restoreView=()=>{
      Object.assign(view,readView());folderLimit=12;$('album-search').value='';revealFolder();render();
      const next=items.findIndex(item=>item.copies.some(f=>f.id===id));if(next>=0)open(next);
    };
    if($('viewer').open){skipCloseRender=true;$('viewer').addEventListener('close',restoreView,{once:true});$('viewer').close();}
    else restoreView();
  }
  window.addEventListener('popstate',restore);
  access.ready.then(session=>{
    $('access-note').textContent=session.image?'● Local browser connected · Open a file to read it from the image. No full scan is started.':session.enabled?'● Local browser · Saved exports are available. Start with --image to open unexported files.':'Static report · Saved exports open here. Use “cold-digger serve CASE --image IMAGE” to open files that are still on the image.';
    const id=new URLSearchParams(location.hash.slice(1)).get('media');render();
    const next=items.findIndex(item=>item.copies.some(f=>f.id===id));if(next>=0)open(next);
  });
})();
