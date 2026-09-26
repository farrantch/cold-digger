"use strict";
(() => {
  let session = {enabled: false, image: false};
  const cached = new Map();
  const ready = location.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(location.hostname)
    ? fetch('api/session', {credentials: 'same-origin'}).then(r => r.ok ? r.json() : session).then(value => (session = value)).catch(() => session)
    : Promise.resolve(session);
  async function open(file, progress = () => {}, signal) {
    if (file.artifact) return {url: file.artifact, partial: file.status === 'partial', source: 'export'};
    await ready;
    if (!session.image) throw new Error('Start the local browser with cold-digger serve CASE --image IMAGE to open this file on demand.');
    if (!file.on_demand) throw new Error('This entry has no readable filesystem record. Its original content is not currently available.');
    let response = await fetch(`api/open/${encodeURIComponent(file.id)}`, {method: 'POST', headers: {'X-Disk-Analyzer': 'open'}, signal});
    let status = await response.json();
    if (!response.ok) throw new Error(status.error || 'Could not open file');
    while (['queued', 'reading'].includes(status.status)) {
      progress(status);
      await new Promise(resolve => setTimeout(resolve, 350));
      if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
      response = await fetch(`api/status/${encodeURIComponent(file.id)}`, {signal});
      status = await response.json();
      if (!response.ok) throw new Error(status.error || 'Read failed');
    }
    if (status.status !== 'ready') throw new Error(status.error || 'The file cache expired. Open the file again.');
    const value = {...status, url: `api/content/${encodeURIComponent(file.id)}`};
    cached.set(file.id, value); return value;
  }
  async function video(file, progress = () => {}, signal) {
    await ready;
    if (!session.enabled) throw new Error('Open this case through the local browser to create a playable video preview, or download the original.');
    if (!session.video_previews) throw new Error('Install FFmpeg on the local browser host to create playable video previews.');
    let response = await fetch(`api/video/${encodeURIComponent(file.id)}`, {method:'POST', headers:{'X-Disk-Analyzer':'open'}, signal});
    let status = await response.json();
    if (!response.ok) throw new Error(status.error || 'Could not prepare video');
    while (['queued','converting'].includes(status.status)) {
      progress(status);
      await new Promise(resolve => setTimeout(resolve, 350));
      if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
      response = await fetch(`api/video-status/${encodeURIComponent(file.id)}`, {signal});
      status = await response.json();
      if (!response.ok) throw new Error(status.error || 'Video conversion failed');
    }
    if (status.status !== 'ready') throw new Error(status.error || 'The video preview expired; retry opening it.');
    return {...status, url:`api/video-content/${encodeURIComponent(file.id)}`};
  }
  window.DA_ACCESS = {
    ready, open, video, cached,
    get session() { return session; },
    poster(file) { return file.thumbnail || (session.enabled && (file.artifact || cached.has(file.id)) ? `api/thumbnail/${encodeURIComponent(file.id)}` : null); },
    label(file) {
      if (file.artifact) return file.status === 'partial' ? 'Partial export' : 'Exported';
      if (cached.has(file.id)) return cached.get(file.id).partial ? 'Partial read' : 'Opened from image';
      return file.on_demand && session.image ? 'On image' : 'Not exported';
    }
  };
})();
