# Cold Digger reference

This document covers the knobs, caveats, and implementation details that do
not belong on the project landing page.

[Back to the short README](../README.md)

## Quick start on Ubuntu

From this directory, install the recovery tools and optional content readers:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pil python3-libmsiecf python3-libesedb sleuthkit testdisk e2fsprogs poppler-utils tesseract-ocr ffmpeg
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -m pip install -e .
cold-digger doctor
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc
```

Open `/mnt/recovery/old-pc/report.html` locally. No web server or external assets are required. The overview highlights prioritized leads; `crypto.html`, `files.html`, and `media.html` provide drill-down views. The media gallery is **unredacted** and includes photo viewing and inline video playback for browser-supported codecs.

Use Python 3.11–3.13 (Ubuntu 24.04's Python 3.12 is tested). The project installs `bip-utils` for crypto validation and address derivation. The virtual environment above retains access to Ubuntu's Pillow and IE-reader packages. Python 3.14 is currently excluded because a crypto dependency fails to build there. `testdisk` supplies PhotoRec. **Scans stop before hashing or scanning if required recovery tools are missing.** This includes the crypto library, Sleuth Kit, PhotoRec (unless `--carve off`), and both Internet Explorer readers. Explicitly requested OCR/bulk extraction also requires its tool. Restart checks dependencies before archiving the old case. The error lists missing tools and installation instructions. `bulk_extractor` is optional, not included in the container, and is not available from every Ubuntu release's repositories.

`--allow-partial` deliberately permits missing tools for that invocation and prints a warning before scanning. It is never remembered as a resume default. If an earlier run finished with unavailable recovery stages, install the listed packages and run the same command with **`--resume`**: completed raw scanning is retained, and unavailable recovery stages are retried.

## Container execution

Copy `.env.example` to `.env`, set the **existing absolute directories** for your images and results, and set your numeric UID/GID (`id -u`, `id -g`). The output directory must be writable by that user.

```bash
docker build -t cold-digger:local .
cp .env.example .env
# Edit .env before starting containers.
docker compose run --rm analyzer doctor
docker compose run --rm analyzer scan /images/old-pc.img --output /cases/old-pc
```

The direct `docker build` command does not require `IMAGE_DIR` or `CASE_DIR`. Compose validates these variables even for `docker compose build`, so use the direct command when rebuilding before configuring mounts.

Image building needs network access; scans run with `network_mode: none`, no Linux capabilities, a read-only application filesystem, and a read-only `/images` mount. No privileged container, loop device, filesystem mount, or root user is needed to read ordinary image files. The base image/tag and Ubuntu package versions are not locked to immutable digests; tool versions are recorded per case.

## What runs

1. Check required recovery dependencies, then record source size, timestamps and file identity using the default quick check. `--hash-mode full` adds a complete SHA-256 pass before analysis.
2. Discover MBR primary/logical partitions or GPT partitions, validate GPT CRCs, and identify inter-partition gaps. GPT can establish 512/4096-byte sectors automatically. For MBR/unknown raw images, 512 is an explicit reported assumption unless you specify `--sector-size 4096`.
3. Scan raw bytes across the **entire image**, including all partitions, gaps, metadata, free space, and slack. Text candidates are detected in ASCII and UTF-16. Raw hits are not automatically called deleted.
4. Use Sleuth Kit to inventory each readable filesystem and export selected files, prioritizing wallet paths, browser databases/sidecars, media, deleted records, and personal documents. Deleted regular files are selected regardless of extension, including files over the generic 2 MiB threshold, subject to the configured recovery limits. Filesystem exports allow crypto detection in fragmented files that survive as readable file records. Publish recovered browser history before starting the longer carving pass.
5. Use PhotoRec to carve the entire image independently of the current partition table. Recovered names are synthetic; deletion state is unknown. Where present, PhotoRec's XML byte extents are retained rather than guessed from filenames.
6. Extract Chromium/Firefox/Internet Explorer browser-history records, rescan exported/carved files, inspect bounded ZIP members, extract PDF text, and generate image previews/selected EXIF metadata when tools are available. `--ocr` enables local Tesseract processing.
7. Write HTML, JSON and CSV reports with per-stage/per-volume coverage and source references. Optional local AI can be run later, using the saved case.

## Crypto detection in this version

Detection retains observations; automatic validation and ranking decide what appears on the dashboard. Broad filename/keyword matches, help-index fragments, code constants and known test material go to supporting evidence. No observations are deleted. A valid checksum does not alone promote a wallet to the attention list: overlapping seed candidates and suspicious context are also considered. The raw image is read in bounded windows during validation when supplied, not rescanned end to end.

- WIF private keys: Base58Check, supported version/length, compression marker, and secp256k1 scalar bounds.
- Common extended private/public keys: Base58Check, supported payload structure, curve-point validation and child-address derivation through `bip-utils`.
- English BIP39 phrases of 12/15/18/21/24 words: checksum validation. A checksum match can still be an example, an unrelated phrase, or an accidental match.
- Bitcoin Base58/Bech32/Bech32m addresses; EIP-55 checksum validation for mixed-case Ethereum addresses. Lowercase/uppercase-only Ethereum values remain unchecksummed candidates.
- Hexadecimal private-key candidates only when paired with a key label.
- Ethereum V3 keystore, Electrum JSON wallet and generic encrypted-vault schema indicators in small exported files.
- Wallet filenames, selected browser-extension paths, Bitcoin database record markers, mining references, backup clues and private-key container headers.

WIF and labeled hexadecimal keys receive scalar checks and local public-address derivation. BIP39 candidates derive Bitcoin BIP44/49/84/86 receive/change addresses and Ethereum BIP44 addresses, with an empty passphrase, account 0 and the first 20 indices by default. Extended keys derive the stored node plus direct and receive/change children relative to that node; the original path is not assumed. Each assessment records its exact scope. Ethereum V3 keystores receive parameter/length checks and expose any public address metadata, explicitly labeled unauthenticated until decryption/MAC verification. Electrum JSON wallets expose supported stored public keys. Supported PEM containers are parsed locally; an RSA key is not presented as a Bitcoin/Ethereum key.

Findings do **not** establish ownership or spendability. This version does not decrypt password-protected wallets, validate Electrum-native/legacy seed phrases, non-English raw BIP39 detection, SLIP39, arbitrary binary private keys, or every wallet format. It does not reconstruct Berkeley DB records or parse LevelDB/browser vault databases comprehensively. Unsupported/damaged material and derivation bounds stay visible in assessments. Other passphrases, accounts, paths and chains are not ruled out by an empty lookup.

### Refresh an existing case without restarting recovery

Install the updated dependencies (or rebuild the container), then run whichever steps you want:

```bash
# Rebuild the dashboard from saved results; no image required:
cold-digger report /mnt/recovery/old-pc

# Validate saved candidates; the image enables small reads of legacy raw hits/context:
cold-digger validate /mnt/recovery/old-pc --image /mnt/images/old-pc.img

# Derive a wider address range for supported wallets:
cold-digger validate /mnt/recovery/old-pc --address-count 100

# Generate missing photo thumbnails from files already recovered:
cold-digger media /mnt/recovery/old-pc
```

The image option checks saved identity metadata first. These commands do not start a scan, restore additional files or run PhotoRec. Refreshing without the source retains previous validation results for legacy raw hits whose bytes are unavailable. Scans also perform validation automatically. Private keys and phrases never appear in the dashboard's public-address lists.

### Explicit balance checks

Scans, report generation and validation stay offline. The separate command below sends only public addresses to the operator-selected endpoint, including addresses derived locally from supported keys. There is no default provider and no automatic network access. Providers learn the queried addresses. Background/example candidates are excluded unless you supply `--include-background`.

```bash
cold-digger balances /mnt/recovery/old-pc --allow-network \
  --bitcoin-api https://YOUR-ESPLORA-SERVER/api \
  --ethereum-rpc https://YOUR-ETHEREUM-RPC-ENDPOINT
```

Either endpoint may be omitted. Local/private-IP HTTP endpoints are supported for your own nodes/services; public endpoints require HTTPS. Bitcoin uses the [Esplora address API](https://github.com/Blockstream/esplora/blob/master/API.md), separating confirmed satoshis, pending changes and transaction counts. Ethereum verifies chain ID 1 and queries [native ETH balance and outgoing transaction count](https://ethereum.org/en/developers/docs/apis/json-rpc/); ERC-20/NFT holdings, other EVM networks and incoming history are not queried. Results show provider, time and scope. Failures remain unknown, and **zero at the checked addresses does not establish an empty wallet**. Positive reported balances are promoted to the attention list without claiming key ownership. Existing offline scan containers cannot access providers; run this explicit command natively in your prepared environment.

### Dashboard and file navigation

`report.html` summarizes attention items, unconfirmed leads, deleted exports, media and browser history. `evidence.html` retains every observation with pagination.

`files.html` is an offline file explorer with a persistent folder sidebar, separate file-state views and counts, breadcrumbs, back/forward/up navigation, and a compact sortable list. Double-click a folder to open it; click a file for its preview, download, original path, timestamps and recovery details. Search names, paths or evidence IDs in the current folder, its subfolders, or all volumes. Filter by file type or whether content was recovered; selecting either filter includes subfolders automatically, with the scope shown beside search. Fully exported and partial files have separate filters. “Show in folder” returns a search result to its original location and selects its page.

Folders and files share pages of 50, 100 or 250 items, with a page-number control. Large sidebar branches expand incrementally; inventory chunks load on demand with a bounded cache. Search, filters, folder, sort and page are preserved in the URL for reloads and browser navigation. Arrow keys move through rows, Enter opens folders or file details, Alt+Up goes to the parent, and `/` focuses search. The folder sidebar and details pane can be toggled; narrow screens use drawers.

Surviving paths reconstruct a navigable deleted-file tree, including empty directory records; carved files with missing paths stay under unknown origin. Reallocated blocks can contain replacement content. File counts exclude directory records. Exported status describes recovery output, not proof that a file is intact. Recovered HTML and other active documents are download-only; supported images, audio and videos can preview locally. Unsupported formats show a download fallback.

After updating the project, regenerate the dashboard from the saved case without rescanning the image:

```bash
cold-digger report /mnt/recovery/old-pc
# Then reopen files.html or refresh the browser.
```

`media.html` is a media library with an expandable folder tree: volume → original folders → subfolders. Parent folders remain navigable even when their media lives further down. Click a folder name to open it, its chevron to expand it, or a folder card above the photos to go deeper. Breadcrumbs and Back/Forward/Up controls keep your location visible; Alt+Left/Right/Up provides keyboard navigation. Folder search keeps matching paths in their hierarchy, and large branches expand incrementally. Carved files with no known volume have a separate origin branch.

Folder views include subfolders by default; choose **This folder only** to view direct contents. Photo/video, file-state and export filters, search, date/size/name sorting, adjustable tile sizes and pages of 48/96/192 items work within that scope. Folder counts include matching media in descendants. Clearing filters keeps the current folder. Folder, scope, filters and page survive reloads and browser Back/Forward. Each tile links to its media folder, and “Open file browser” opens the current location in the file explorer.

The optional “Group identical files” view uses export SHA-256 values and retains links to every matching source location. A full-window viewer provides a filmstrip, keyboard navigation, actual-size photo viewing, video controls, downloads and file details. Closing the viewer returns to the page containing the current item. Missing/partial content stays labeled; the library includes media in the inventory even when it has no export yet.

Browser-supported originals open directly. With the local server, videos the browser cannot decode (including many MOV/AVI files) automatically get a compatible MP4 viewing copy when opened. FFmpeg converts video to H.264 up to 720p and the first audio track to stereo AAC; silent videos remain silent. **Download original** always downloads the recovered file. The viewer labels converted and partial content. If a video opens with playback or audio problems, choose **Details → Create playable preview**.

Conversion requires FFmpeg/ffprobe on the server host. One video converts at a time, with up to four queued/running jobs. Copies share `--cache-bytes` with temporary image reads and are removed when the server stops. Each copy is limited to 512 MiB (or `--max-file-bytes`, if smaller), with the same timeout as `--read-timeout` (15 minutes by default). Failed, oversized or timed-out copies are discarded and the original remains downloadable. A file that is still on the disk image must first finish its on-demand read. No bulk video conversion or additional recovery scan is started.

The local server also creates photo thumbnails and video posters from exports as needed. `cold-digger media CASE` prepares permanent thumbnails/posters for a static report, without reopening the image; it does not convert videos. Video posters need FFmpeg/ffprobe; photo thumbnails need Pillow. Static `file://` reports rely on native browser playback and offer original downloads for unsupported formats. Use `serve` for compatible video previews, with `--exports-only` when all needed files have already been recovered.

### Open files from the image on demand

“Not exported” means that the case has a filesystem record but no saved copy of that file's contents. It does **not** establish that the contents are unreadable. Other statuses distinguish a pending export, a skipped limit, and a failed recovery attempt.

```bash
cold-digger serve /mnt/recovery/old-pc --image /mnt/images/old-pc.img
```

Open the private loopback URL printed by the command. `serve` regenerates the report from the saved case, then waits for browser requests; it does not start a recovery scan. In the file browser, select **Open from image** or double-click a file. In the gallery, opening an unexported tile starts the same read automatically. If `--image` is omitted, the saved source path is used. Use `--exports-only` to browse without the source image.

The server uses [Sleuth Kit's `icat`](https://www.sleuthkit.org/sleuthkit/man/icat.html) with the saved partition offset and filesystem record, including recovery mode for deleted files. The first open extracts that individual file into a temporary cache; a large file can take time to open. HTTP byte ranges then allow video seeking without repeatedly extracting it. The source remains read-only, with quick identity checks before/after extraction. Deleted or reused blocks may yield incomplete or replacement content. Records without an inode/partition mapping cannot be reconstructed this way.

Defaults are **4 GiB per file**, **8 GiB of temporary content cache**, two concurrent reads, and a 15-minute timeout per read. Adjust them with `--max-file-bytes`, `--cache-bytes`, and `--read-timeout` (seconds). The cache lives under the case's private directory, evicts older unused entries, and is removed on normal shutdown/Ctrl-C. It is separate from permanent recovery exports; browsing does not mark a file recovered, run crypto analysis on it, or advance scan stages. An interrupted process killed without cleanup may leave a `private/browser-cache-*` directory. Permanent exports continue to be managed by `scan --resume`.

The browser server binds only to `127.0.0.1`, uses a per-session URL token, rejects foreign Host/Origin requests, and serves an explicit list of report assets. Private files, logs, and the case database are not exposed. Recovered active documents remain download-only. Keep the printed URL private. The static `file://` report still works for exports, but cannot launch filesystem tools itself.

For the Ubuntu Docker setup, rebuild the image once after updating the code. The optional browser service uses host networking so its loopback listener is reachable; the scan service retains `network_mode: none`. The browser service makes no external API calls, but host networking does not provide the scan container's network isolation. FFmpeg preview inputs restrict [protocols](https://ffmpeg.org/ffmpeg-protocols.html#Protocol-Options) and [formats](https://ffmpeg.org/ffmpeg-formats.html) to supported local media, excluding playlists.

```bash
docker build -t cold-digger:local .
# Supply the mount paths here, or set them in .env as in the scan setup:
IMAGE_DIR=/mnt/disk-images CASE_DIR=/mnt/recovery \
  docker compose run --rm browser serve /cases/old-pc --image /images/old-pc.img
```

If `CASE_DIR` points directly at an existing case instead of its parent directory, pass `/cases` to `serve`.

The cache uses the writable case mount, not the container's small `/tmp` filesystem. Installations that already need an AppArmor override for Docker also need that existing override for the browser service.

## Resume, restart, limits and exit codes

```bash
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc --resume
cold-digger status /mnt/recovery/old-pc
cold-digger report /mnt/recovery/old-pc

# Increase export limits and retry files that exceeded them:
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc \
  --resume --max-file-bytes 8GiB --max-output-bytes 500GiB
```

Ctrl-C saves findings and a report. Raw scanning resumes at a committed byte checkpoint; filesystem inventory resumes per volume and recovery per file. Quick mode checks saved source metadata on resume, avoiding a separate full-image hash pass. **An interrupted PhotoRec pass restarts from the beginning**, preserving and importing prior outputs; it does not resume its exact carving position. Identical exports retain all source records.

To start the entire analysis over at the **same output path**, use `--restart`:

```bash
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc --restart
```

The previous case contents move to a private sibling folder such as `old-pc.backup-20260910T120000Z-abcd1234`, and a fresh case starts at `old-pc`. Its path is printed before scanning. Restart uses current defaults (quick source checks and 4 GiB per file) plus options supplied on that command; previous settings and checkpoints are not reused. Recovered files and reports stay in the backup. Moving them does not copy their bytes, but the fresh scan will consume additional output space. The output's parent directory must be writable for the backup; for containers, use a case subdirectory under the results mount.

`--restart` and `--resume` are mutually exclusive. Restart requires an existing case and refuses to proceed while another CLI process holds its lock. Stop an active scan with Ctrl-C first. Ordinary move failures or Ctrl-C during archiving trigger an attempt to restore moved entries before returning an error.

### Source verification and read-only shares

New cases default to `--hash-mode quick`, suitable when you trust the source to stay unchanged, such as an image on your controlled read-only share. It compares size, modification/change timestamps, inode and device identity when available, and checks metadata again after scanning. It cannot detect every content change that preserves metadata. Older cases initially have only size and modification time available for comparison. A replaced file or remounted share can fail the identity check even when its bytes are unchanged.

```bash
# Optional complete SHA-256 verification before a new scan:
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc --hash-mode full

# Resume an existing case with quick checks, including after interrupting an initial hash:
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc --resume --hash-mode quick

# Add OCR later using quick source checks:
cold-digger scan /mnt/images/old-pc.img --output /mnt/recovery/old-pc --resume --hash-mode quick --ocr
```

Cases remember the selected hash mode. Cases created before this option default to quick mode unless you explicitly choose full. Full mode recomputes SHA-256 on each resume and compares it with a saved digest, when one exists. Switching a quick case to full establishes its first content hash after the metadata check; it cannot retrospectively prove that earlier quick scans saw identical bytes. A full-mode case can verify an identical relocated image using its digest. Without a saved digest, changed metadata requires a new case.

Reports label image hashes as not computed, computed, verified, or previously recorded. A historical hash retained during a quick resume is not presented as newly verified. Recovered files still receive content hashes for deduplication. Actual raw scanning and recovery still read the image; quick mode removes the preliminary hashing pass. The original image is still required for `scan --resume`, including when enabling OCR later.

Defaults are 4 GiB per exported file, 50 GiB of exported artifacts, **no file-count cap**, and a 24-hour timeout per long-running external tool. Resuming also removes old saved file-count caps and retries inventories previously stopped by them. `--max-files N` is an optional cap for that invocation; `0` means unlimited. Other saved limits persist on resume; add `--max-file-bytes 4GiB` to raise an older case to that default. Larger media may require higher limits. Unclassified allocated files over 2 MiB are inventoried but not exported; deleted files and recognized browser databases are exempt from that generic threshold. ZIP inspection is limited to 200 entries, 8 MiB per member, 32 MiB per archive, and one level. PDF/OCR outputs are limited to 8 MiB. Other archive formats are not unpacked.

The artifact budget is **not a filesystem quota**: private snippets, indexes, logs, text extractions, and native tool output require additional space. PhotoRec's total output is checked periodically and can briefly overshoot the budget. A dedicated output filesystem/quota is appropriate for long unattended runs. Low free space stops PhotoRec. No image-size-based storage estimate is guaranteed.

- `0`: requested core recovery stages completed; format/algorithm limitations still apply.
- `2`: report produced, with disabled/unavailable/incomplete recovery stages or export limits.
- `1`: invalid invocation or failed run. Inspect the saved report/logs when available.
- `130`: interrupted; resume is available.

`--carve off` intentionally leaves carving coverage incomplete (exit 2). `--bulk` runs an installed `bulk_extractor` and preserves its native outputs privately; these outputs are not merged into normalized crypto findings yet. `--ocr` enables slower local image text extraction. Tools that fail to decode content are recorded as incomplete.

## Browser history

History extraction runs automatically after filesystem recovery and again after carving, so recovered history can be reviewed while carving continues. Allocated and recovered deleted databases are both inspected. It supports Chromium-family browsers (including Chrome, Edge, Brave, Opera and Vivaldi), Firefox-family browsers and Internet Explorer. Browser branding inferred from a source path is only a hint; carved databases with no original path retain a family label. Missing or incomplete filesystem recovery also marks overall history coverage incomplete; an empty report is not evidence that no history existed.

| Browser storage | Reader and scope |
| --- | --- |
| Chromium `History` / Firefox `places.sqlite` | Live SQLite rows and matching committed WAL snapshot |
| IE 4–9 `index.dat` (formats 4.7/5.2) | `pymsiecf`: URL records and recoverable remnants exposed by the library |
| IE 10/11 `WebCacheV01.dat` / `WebCacheV24.dat` | `pyesedb`: `History` / `MSHist*` containers from the base ESE database |

IE readers are included in the container. For native execution, Ubuntu's `python3-libmsiecf` and `python3-libesedb` packages provide them; `doctor` checks availability. The scanner tries its Python interpreter, then `/usr/bin/python3` for Ubuntu system packages. Missing readers and unreadable databases appear as coverage gaps. Known IE database names and WebCache log/checkpoint files are selected for recovery above the generic 2 MiB threshold. Exported files with recognizable index.dat/ESE signatures are also inspected when their original names are missing.

`browser-history.html` provides a searchable list of pages, titles, UTC timestamps, browser/profile paths and source record IDs, plus domain counts and per-database coverage. The CSV and JSON exports contain every extracted record up to the configured limit. Full original URLs remain in the private case database; report URLs omit credentials, query values and fragments and apply the usual secret-pattern masking. URLs are displayed as text, never opened or fetched.

```bash
# Analyze browser databases already exported into an existing case, without the disk image:
cold-digger history /mnt/recovery/old-pc

# Increase the default 100,000-record limit per database:
cold-digger history /mnt/recovery/old-pc --max-rows 500000
# For a new scan, the equivalent option is --max-browser-rows 500000.
```

Extensionless `History` files and their sidecars are explicitly selected for recovery even when larger than the generic 2 MiB threshold. If an earlier case skipped one, `scan ... --resume` retries its export. `history CASE` alone cannot recover files that were never exported.

When a complete allocated database and its complete `-wal` file have matching original paths on the same volume, extraction uses disposable copies together. The original recovered files remain unchanged. Ambiguous/missing exports of a known WAL, corrupt databases, unsupported schemas and row limits appear in coverage. Rollback journals are retained but not replayed. Carved/deleted databases are inspected without guessing a matching WAL.

Individual visits are distinguished from URL-level last-visit summaries in older/partial schemas. Firefox bookmark-only entries are not treated as visits. IE history entries are last-visit/access summaries; counts do not reconstruct individual visits. IE cache/cookie/redirect URL references remain labeled as references without a visit timestamp, and non-history WebCache containers are skipped. Titles are currently unavailable for IE rows. Original integer timestamps and their epochs are preserved alongside UTC conversions, including FILETIME's 100-nanosecond precision. Weekly index.dat timestamps with an unknown local timezone receive no invented UTC time. A visit may have arrived through sync/import, and a deleted database does not imply its individual history entries were deleted. Duplicate database copies can repeat visits. Domain matches flag crypto-related leads, not proof of account ownership, wallet use or funds.

For index.dat, recovered remnants are labeled as candidates; they do not establish that someone deliberately cleared history. WebCache parsing does not replay ESE transaction logs or carve deleted ESE pages. A database without a clean-shutdown header is reported as partial because recent changes may exist only in logs. WebCache may also contain activity from Windows applications; browser attribution is not guaranteed. Native readers run in a separate process with a five-minute timeout, 2 GiB address-space limit and 128 MiB private output limit per source, alongside the history row limit.

SQLite parsing does not carve cleared cells or old WAL frames. Private-browsing recovery is not promised. Safari, EdgeHTML's separate history store, IE 3 `mm*.dat` files, downloads and bookmarks are not yet parsed. See [IE validation fixtures](ie-testing.md) for the real-format tests.

## Offline AI, independently of scanning

Install a local Ollama model before disconnecting from the network. Configure Ollama with `OLLAMA_NO_CLOUD=1` and restart its server; keep outbound traffic blocked if strict offline operation is required. The scanner does not install, download, or select a model automatically.

Run this command **natively on the same Ubuntu host as Ollama** (the scan container has no network and cannot reach the host's loopback):

```bash
cold-digger analyze /mnt/recovery/old-pc --model YOUR_INSTALLED_LOCAL_MODEL
```

The client accepts only literal loopback or `localhost` endpoints, disables HTTP proxies and redirects, requires a locally listed model, and rejects cloud model names/remote model metadata. Ollama's own cloud-disable setting and network isolation are still necessary to prevent server-side remote routing.

The initial AI integration analyzes up to 100 finding groups (bounded to 60 KB) using **redacted metadata only**. It does not yet read arbitrary documents, images, raw keys or seed values, and does not perform semantic search over the whole disk. It returns observations, inferences and leads with evidence IDs. Claims with nonexistent citations are rejected; valid citations do not make a claim true. Raw model responses are not printed or published. Models can be changed later without rescanning the image.

## Private case contents

```text
case/
  report.html          # Prioritized overview and drill-down links
  crypto.html          # Automatic validation, public derivations, balance snapshots
  files.html           # Folder navigation, deleted/allocated/carved states
  evidence.html        # All observations, including background matches
  details.html         # Coverage, source identity and detailed provenance
  dashboard-data/      # Local scripts and chunked redacted inventory data
  findings.json        # Structured findings, sources, coverage, tool versions
  inventory.csv        # Full redacted filesystem/carving inventory
  browser-history.html # Searchable local history report
  browser-history.csv  # All extracted records, with report URL masking
  browser-history.json # Structured history, provenance and source coverage
  media.html           # Unredacted photo/video gallery and viewer
  case.sqlite          # Full internal inventory and findings
  artifacts/           # Recovered files, content-addressed
  private/             # Secret hits, bodyfiles, extracted text, native tool outputs
  thumbnails/          # Unredacted image previews
  logs/                # Tool diagnostics; may contain original filenames
```

Case directories use mode `0700`; files created by the CLI use a restrictive umask. **These are access controls, not encryption.** Store cases on an encrypted filesystem if encryption at rest is needed. Recovered files, database contents, thumbnails, OCR text and logs may contain plaintext secrets. Redaction is pattern-based and cannot guarantee that every possible secret format is masked. Do not commit real case data or publish the report/gallery. No recovered executable is launched; exported files use generated names, and ZIP member paths are never used as extraction destinations.

## Validation and demo

```bash
python3 -m unittest discover -v
python3 scripts/make_demo.py /tmp/cold-digger-demo
cold-digger scan /tmp/cold-digger-demo/demo.img \
  --output /tmp/cold-digger-demo/case --max-output-bytes 100MiB
```

The synthetic disk has two ext2 partitions, a deleted public-test WIF key, a public-test BIP39 phrase, duplicate PNGs, Chromium/Firefox history databases and a key in the gap outside the partitions. **Never use its keys or phrases for real funds.** Integration tests run real Sleuth Kit and PhotoRec when installed; otherwise those tests explicitly skip. Tests cover GPT/MBR layouts, 4K sectors, backup GPT fallback, checksums, UTF-16/chunk boundaries, checkpoint replay, quick/full source identity checks, interrupted initial hashing, redaction, report escaping, local AI citation handling, browser timestamp conversions, WAL-only visits, row-limit retries and immutable recovered artifacts.

See [architecture and extension points](architecture.md) and [third-party notices](../THIRD_PARTY_NOTICES.md).

A dashboard-only synthetic example requires no source image:

```bash
python -m scripts.make_report_demo /tmp/cold-digger-dashboard-demo
# Optional browser smoke tests, in a development environment with Playwright:
python -m scripts.check_dashboard_browser /tmp/cold-digger-dashboard-demo
```
