#!/usr/bin/env python3
"""
HaNe IPTV - HTTPS->HTTP bridge proxy
====================================
Browsers block "mixed content": an https page (e.g. the Firebase-hosted app)
may not load anything from an http-only Xtream panel. This proxy fixes that by
fetching from the panel SERVER-SIDE and re-serving it to the browser:

    browser (https) --> this proxy --> http://panel:8080

Endpoints:
    GET /p?u=<urlencoded target url>   proxy any http(s) resource (API, video)
    GET /fix?src=<url>[&t=<seconds>]   audio-fix: video copied 1:1, AC3/EAC3/DTS
                                       audio transcoded to AAC (needs ffmpeg)
    GET /health                        "ok"

Features:
    * streams video with Range support (seeking works)
    * rewrites HLS playlists (.m3u8) so every segment/key URI also goes
    * ffmpeg audio transcode for browser-silent MKV/MP4 movies
      through the proxy
    * CORS enabled, zero dependencies (Python 3.8+ stdlib only)

Run:
    python proxy.py [port]             # default 8899

IMPORTANT - the hosted app needs this proxy to be permanently reachable over
HTTPS. Deploy server.py to a service such as Render/Railway or behind a named
Cloudflare Tunnel, then put that stable HTTPS hostname in js/config.js. Do not
use a trycloudflare.com quick-tunnel in production: those URLs expire.
"""
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8899))
CHUNK = 64 * 1024
# IPTV panels commonly gate streams by their User-Agent. Do not forward the
# browser's Chrome/Render signature; use a configurable media-player signature
# instead. Providers that require a specific value can override this safely in
# Render with UPSTREAM_USER_AGENT (no credentials are stored in the app).
FORWARD_REQ_HEADERS = ("range", "accept", "accept-language")
UPSTREAM_USER_AGENT = os.environ.get(
    "UPSTREAM_USER_AGENT", "VLC/3.0.20 LibVLC/3.0.20"
).strip() or "VLC/3.0.20 LibVLC/3.0.20"
FORWARD_RES_HEADERS = ("content-type", "content-length", "content-range",
                       "accept-ranges", "last-modified", "etag")


def find_ffmpeg():
    """ffmpeg from PATH, FFMPEG_PATH env var, or the winget install dir."""
    p = os.environ.get("FFMPEG_PATH") or shutil.which("ffmpeg")
    if p and os.path.isfile(p):
        return p
    pattern = os.path.expandvars(
        r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\Gyan.FFmpeg*\**\bin\ffmpeg.exe")
    hits = glob.glob(pattern, recursive=True)
    return hits[0] if hits else None


FFMPEG = find_ffmpeg()


def find_ffprobe():
    """ffprobe lives next to ffmpeg."""
    p = os.environ.get("FFPROBE_PATH") or shutil.which("ffprobe")
    if p and os.path.isfile(p):
        return p
    if FFMPEG:
        for name in ("ffprobe.exe", "ffprobe"):
            cand = os.path.join(os.path.dirname(FFMPEG), name)
            if os.path.isfile(cand):
                return cand
    return None


FFPROBE = find_ffprobe()

# Optional automatic subtitle catalog. Keep the provider key server-side.
# Provider credentials must be injected by the host (Render/Railway/local env),
# never committed as a fallback value in the bridge source.
SUBDL_API_KEY = os.environ.get("SUBDL_API_KEY", "").strip()
SUBDL_API_BASE = os.environ.get("SUBDL_API_BASE", "https://api.subdl.com/api/v2").rstrip("/")
SUBTITLE_RATE_LIMIT = max(10, int(os.environ.get("SUBTITLE_RATE_LIMIT", "120")))
SUBTITLE_MAX_BYTES = 4 * 1024 * 1024
_subtitle_hits = {}
_subtitle_lock = threading.Lock()


def _subdl_request(path, params=None, expect_json=True):
    """Fixed-host authenticated request; the key never reaches the browser."""
    if not SUBDL_API_KEY:
        raise RuntimeError("subtitle provider is not configured")
    url = SUBDL_API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + SUBDL_API_KEY,
        "Accept": "application/json" if expect_json else "text/plain, application/zip, */*",
        "User-Agent": "HaNeIPTV/2.0",
    })
    response = urllib.request.urlopen(req, timeout=18)
    if expect_json:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("provider response is too large")
        return json.loads(raw.decode("utf-8", "replace") or "{}")
    return response


def _subtitle_language(value):
    raw = str(value or "").strip().lower()
    aliases = {"dutch": "nl", "nederlands": "nl", "english": "en", "eng": "en", "dut": "nl", "nld": "nl"}
    return aliases.get(raw, raw[:3])


def _decode_subtitle(data):
    for encoding in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            pass
    return data.decode("utf-8", "replace")


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ── helpers ──────────────────────────────────────────────────────────
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type")
        self.send_header("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges")

    def _fail(self, code, msg):
        try:
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            body = msg.encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _subtitle_rate_ok(self):
        forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        client = forwarded or (self.client_address[0] if self.client_address else "unknown")
        now = time.time()
        with _subtitle_lock:
            recent = [stamp for stamp in _subtitle_hits.get(client, []) if now - stamp < 3600]
            if len(recent) >= SUBTITLE_RATE_LIMIT:
                _subtitle_hits[client] = recent
                return False
            recent.append(now)
            _subtitle_hits[client] = recent
        return True

    @staticmethod
    def _provider_records(payload):
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []
        for key in ("results", "data", "movies", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = Proxy._provider_records(value)
                if nested:
                    return nested
        return []

    @staticmethod
    def _pick_provider_title(payload, title, year):
        records = Proxy._provider_records(payload)
        if not records:
            return {}
        wanted = re.sub(r"[^a-z0-9]+", "", (title or "").lower())
        best, best_score = records[0], -1
        for record in records[:12]:
            if not isinstance(record, dict):
                continue
            name = record.get("name") or record.get("title") or record.get("film_name") or ""
            normalized = re.sub(r"[^a-z0-9]+", "", str(name).lower())
            score = 3 if normalized == wanted and wanted else (2 if wanted and (wanted in normalized or normalized in wanted) else 0)
            record_year = str(record.get("year") or record.get("release_year") or "")[:4]
            if year and record_year == str(year)[:4]:
                score += 2
            if score > best_score:
                best, best_score = record, score
        return best if isinstance(best, dict) else {}

    @staticmethod
    def _collect_subtitle_candidates(payload, wanted_languages):
        found = []

        def walk(node, inherited_lang="", inherited_release="", file_context=False):
            if isinstance(node, list):
                for item in node:
                    walk(item, inherited_lang, inherited_release, file_context)
                return
            if not isinstance(node, dict):
                return
            lang = _subtitle_language(node.get("language") or node.get("lang") or node.get("language_code") or inherited_lang)
            release = str(node.get("release_name") or node.get("release") or node.get("filename") or node.get("file_name") or inherited_release or "").strip()
            fmt = str(node.get("format") or os.path.splitext(release)[1].lstrip(".") or "srt").lower()
            file_id = node.get("file_n_id") or node.get("n_id") or node.get("subtitle_id")
            if not file_id and file_context and lang:
                file_id = node.get("id")
            if file_id and lang and fmt in ("srt", "vtt"):
                found.append({
                    "id": str(file_id),
                    "lang": lang,
                    "label": release or (lang.upper() + " subtitle"),
                    "release": release,
                    "format": fmt,
                })
            for key, value in node.items():
                if key in ("files", "subtitles", "results", "data", "items"):
                    walk(value, lang, release, file_context or key == "files")

        walk(payload)
        ranked = []
        seen = set()
        for wanted in wanted_languages:
            for candidate in found:
                if candidate["lang"] == wanted and wanted not in seen:
                    ranked.append(candidate)
                    seen.add(wanted)
                    break
        for candidate in found:
            if candidate["lang"] not in seen and len(ranked) < 6:
                ranked.append(candidate)
                seen.add(candidate["lang"])
        return ranked

    def _proxy_prefix(self):
        # absolute prefix pointing back at this proxy (works behind tunnels)
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ("localhost:%d" % PORT)
        scheme = self.headers.get("X-Forwarded-Proto") or "http"
        return "%s://%s/p?u=" % (scheme, host)

    def _rewrite_m3u8(self, text, base_url):
        """Make every URI in an HLS playlist absolute.
        Strategy: upgrade http:// segment URLs to https:// so browsers can load
        them directly (panel sends Access-Control-Allow-Origin: * so CORS is fine).
        Only wrap through the proxy if the source URL has an unusual port that
        the browser might not accept over plain HTTPS (e.g. :8080 with a bad cert).
        """
        # Detect if the base URL uses a non-standard port with http://
        m = re.match(r"(https?://)([^/:]+)(?::(\d+))?", base_url, re.I)
        src_scheme = (m.group(1) if m else "http://").lower()
        src_host   = m.group(2) if m else ""
        src_port   = m.group(3) if m else None

        # If the panel is already HTTPS or on standard 80/443, do a direct
        # absolute rewrite (no proxy wrapping needed).
        # Otherwise wrap only the .m3u8 sub-playlists through the proxy; 
        # leave .ts segments as https:// direct (panel CORS allows it).
        use_direct_https = True  # upgrade http → https for all URIs

        def make_absolute(u):
            return urllib.parse.urljoin(base_url, u.strip())

        def wrap_or_upgrade(u):
            absolute = make_absolute(u)
            if use_direct_https and absolute.startswith("http://"):
                # Upgrade to https:// – browser loads segment directly, no proxy
                return proxy_wrap(u)
            # Already https or we chose to proxy it
            return proxy_wrap(u)

        def proxy_wrap(u):
            absolute = make_absolute(u)
            return self._proxy_prefix() + urllib.parse.quote(absolute, safe="")

        out = []
        for line in text.splitlines():
            s = line.strip()
            if not s:
                out.append(line)
            elif s.startswith("#"):
                # Sub-playlist refs in URI="..." attributes: proxy-wrap so they
                # come through this server (for further rewriting).
                out.append(re.sub(r'URI="([^"]+)"', lambda m2: 'URI="%s"' % proxy_wrap(m2.group(1)), line))
            else:
                # Segment lines: direct HTTPS upgrade (no proxy hop)
                out.append(wrap_or_upgrade(s))
        return "\n".join(out) + "\n"

    # ── HTTP methods ─────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        # Render performs HEAD health checks. Reply successfully instead of
        # reporting an unsupported-method error in every deployment log.
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/health"):
            self.send_response(200)
            self._cors()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()
    def _do_probe(self, parsed):
        """List embedded audio + subtitle tracks of a stream (ffprobe JSON)."""
        if not FFPROBE:
            return self._fail(501, "ffprobe not found")
        q = urllib.parse.parse_qs(parsed.query)
        src = q.get("src", [""])[0]
        if not re.match(r"^https?://", src, re.I):
            return self._fail(400, "src must be an http(s) URL")
        try:
            res = subprocess.run(
                [FFPROBE, "-v", "quiet", "-print_format", "json", "-show_streams",
                 "-analyzeduration", "10000000", "-probesize", "10000000", src],
                capture_output=True, timeout=30)
            data = json.loads(res.stdout.decode("utf-8", "replace") or "{}")
        except Exception as e:
            return self._fail(502, "probe failed: %s" % e)
        audio, subs = [], []
        for s in data.get("streams", []):
            tags = s.get("tags") or {}
            entry = {
                "lang": tags.get("language") or "",
                "title": tags.get("title") or "",
                "codec": s.get("codec_name") or "",
            }
            if s.get("codec_type") == "audio":
                entry["index"] = len(audio)
                audio.append(entry)
            elif s.get("codec_type") == "subtitle":
                entry["index"] = len(subs)
                subs.append(entry)
        body = json.dumps({"audio": audio, "subs": subs}).encode("utf-8")
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _do_subs(self, parsed):
        """Extract an embedded subtitle track as WebVTT.
        Buffers the first chunk so we can return 404 if ffmpeg produces nothing."""
        if not FFMPEG:
            return self._fail(501, "ffmpeg not found")
        q = urllib.parse.parse_qs(parsed.query)
        src = q.get("src", [""])[0]
        idx = max(0, int(q.get("index", ["0"])[0] or 0))
        if not re.match(r"^https?://", src, re.I):
            return self._fail(400, "src must be an http(s) URL")
        args = [FFMPEG, "-hide_banner", "-loglevel", "error",
                "-i", src, "-map", "0:s:%d" % idx, "-f", "webvtt", "pipe:1"]
        try:
            ff = subprocess.Popen(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        except Exception as e:
            return self._fail(500, "ffmpeg failed to start: %s" % e)
        out = ff.stdout
        if out is None:
            return self._fail(500, "ffmpeg gave no output pipe")
        # Buffer the first chunk – if empty, ffmpeg found no subtitle stream
        first = out.read(256)
        if not first:
            try:
                ff.kill()
            except Exception:
                pass
            err = ff.stderr.read(300).decode("utf-8", "replace") if ff.stderr else ""
            return self._fail(404, "No subtitle stream at index %d%s" % (
                idx, (": " + err.strip()) if err.strip() else ""))
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/vtt; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(first)
            while True:
                chunk = out.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            try:
                ff.kill()
            except Exception:
                pass

    def _do_subtitle_status(self):
        self._json(200, {
            "provider": "subdl",
            "configured": bool(SUBDL_API_KEY),
            "rate_limit_per_hour": SUBTITLE_RATE_LIMIT,
        })

    def _do_subtitle_search(self, parsed):
        if not self._subtitle_rate_ok():
            return self._json(429, {"error": "rate_limited", "candidates": []})
        if not SUBDL_API_KEY:
            return self._json(503, {"error": "not_configured", "unavailable": True, "candidates": []})
        query = urllib.parse.parse_qs(parsed.query)
        kind = query.get("type", ["movie"])[0].lower()
        if kind not in ("movie", "tv"):
            kind = "movie"
        title = query.get("title", [""])[0].strip()[:160]
        year = re.sub(r"\D", "", query.get("year", [""])[0])[:4]
        imdb_id = query.get("imdb_id", [""])[0].strip()[:24]
        tmdb_id = re.sub(r"\D", "", query.get("tmdb_id", [""])[0])[:20]
        season = re.sub(r"\D", "", query.get("season", [""])[0])[:4]
        episode = re.sub(r"\D", "", query.get("episode", [""])[0])[:4]
        if imdb_id and not re.match(r"^tt\d+$", imdb_id, re.I):
            imdb_id = ""
        languages = []
        for value in query.get("languages", ["nl,en"])[0].split(","):
            lang = _subtitle_language(value)
            if re.match(r"^[a-z]{2,3}$", lang) and lang not in languages:
                languages.append(lang)
        if not languages:
            languages = ["nl", "en"]
        if not title and not imdb_id and not tmdb_id:
            return self._json(400, {"error": "title_or_id_required", "candidates": []})

        try:
            sd_id = ""
            if not imdb_id and not tmdb_id and title:
                resolved = _subdl_request("/movies/search", {
                    "q": title,
                    "type": kind,
                    "limit": 5,
                })
                match = self._pick_provider_title(resolved, title, year)
                imdb_id = str(match.get("imdb_id") or match.get("imdb") or "")
                tmdb_id = str(match.get("tmdb_id") or match.get("tmdb") or "")
                sd_id = str(match.get("sd_id") or match.get("subdl_id") or "")

            params = {"languages": ",".join(languages), "unpack": 1, "type": kind}
            if imdb_id:
                params["imdb_id"] = imdb_id
            elif tmdb_id:
                params["tmdb_id"] = tmdb_id
            elif sd_id:
                params["sd_id"] = sd_id
            else:
                params["film_name"] = title
            if season:
                params["season"] = season
            if episode:
                params["episode"] = episode
            payload = _subdl_request("/subtitles/search", params)
            candidates = self._collect_subtitle_candidates(payload, languages)
            return self._json(200, {
                "provider": "subdl",
                "candidates": candidates,
                "matched": {"imdb_id": imdb_id, "tmdb_id": tmdb_id, "sd_id": sd_id},
            })
        except urllib.error.HTTPError as exc:
            return self._json(502, {"error": "provider_http_%d" % exc.code, "candidates": []})
        except Exception as exc:
            return self._json(502, {"error": "provider_failed", "message": str(exc)[:160], "candidates": []})

    def _do_subtitle_file(self, parsed):
        if not self._subtitle_rate_ok():
            return self._fail(429, "subtitle rate limit reached")
        if not SUBDL_API_KEY:
            return self._fail(503, "subtitle provider is not configured")
        file_id = urllib.parse.parse_qs(parsed.query).get("id", [""])[0].strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,80}$", file_id):
            return self._fail(400, "invalid subtitle id")
        try:
            upstream = _subdl_request("/subtitles/%s/download" % urllib.parse.quote(file_id, safe=""), {"format": "file"}, expect_json=False)
            data = upstream.read(SUBTITLE_MAX_BYTES + 1)
            content_type = (upstream.headers.get("Content-Type") or "").lower()
            upstream.close()
            if len(data) > SUBTITLE_MAX_BYTES:
                return self._fail(413, "subtitle file is too large")

            if "json" in content_type or data.lstrip().startswith(b"{"):
                descriptor = json.loads(data.decode("utf-8", "replace") or "{}")
                download_url = descriptor.get("download_url") or descriptor.get("url") or descriptor.get("file_url")
                parsed_url = urllib.parse.urlparse(download_url or "")
                host = (parsed_url.hostname or "").lower()
                if not download_url or not (host == "subdl.com" or host.endswith(".subdl.com")):
                    return self._fail(502, "provider returned no safe subtitle file")
                direct = urllib.request.urlopen(urllib.request.Request(download_url, headers={"User-Agent": "HaNeIPTV/2.0"}), timeout=18)
                data = direct.read(SUBTITLE_MAX_BYTES + 1)
                direct.close()
                if len(data) > SUBTITLE_MAX_BYTES:
                    return self._fail(413, "subtitle file is too large")

            if data.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    names = [name for name in archive.namelist() if name.lower().endswith((".srt", ".vtt"))]
                    if not names:
                        return self._fail(415, "archive contains no SRT or VTT subtitle")
                    info = archive.getinfo(names[0])
                    if info.file_size > SUBTITLE_MAX_BYTES:
                        return self._fail(413, "subtitle file is too large")
                    data = archive.read(names[0])

            text = _decode_subtitle(data).replace("\x00", "")
            if "-->" not in text:
                return self._fail(422, "downloaded file has no subtitle cues")
            body = text.encode("utf-8")
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            return self._fail(502, "subtitle provider HTTP %d" % exc.code)
        except Exception as exc:
            return self._fail(502, "subtitle download failed: %s" % str(exc)[:160])

    def _do_fix(self, parsed):
        """Audio-fix / enhancement: audio -> AAC; optionally denoise+sharpen video
        (enhance=1, ideas borrowed from AI enhancers, done in realtime ffmpeg)."""
        if not FFMPEG:
            return self._fail(501, "ffmpeg not found - install it (winget install Gyan.FFmpeg)")
        q = urllib.parse.parse_qs(parsed.query)
        src = q.get("src", [""])[0]
        start = max(0, int(q.get("t", ["0"])[0] or 0))
        enhance = q.get("enhance", ["0"])[0] == "1"
        audio = max(0, int(q.get("audio", ["0"])[0] or 0))  # audio track index
        if not re.match(r"^https?://", src, re.I):
            return self._fail(400, "src must be an http(s) URL")

        args = [FFMPEG, "-hide_banner", "-loglevel", "error"]
        if start > 0:
            args += ["-ss", str(start)]
        args += ["-i", src, "-map", "0:v:0?", "-map", "0:a:%d?" % audio]
        if enhance:
            # light denoise + unsharp mask - visibly crisper without a GPU
            args += ["-vf", "hqdn3d=1.5:1.5:6:6,unsharp=5:5:0.6:5:5:0.0",
                     "-c:v", "libx264", "-preset", "veryfast", "-crf", "21"]
        else:
            args += ["-c:v", "copy"]                     # video untouched
        args += [
            "-c:a", "aac", "-b:a", "192k", "-ac", "2",  # audio -> AAC stereo
            "-f", "mp4",
            "-movflags", "frag_keyframe+empty_moov+default_base_moof",
            "pipe:1",
        ]
        try:
            ff = subprocess.Popen(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except Exception as e:
            return self._fail(500, "ffmpeg failed to start: %s" % e)
        out = ff.stdout
        if out is None:
            return self._fail(500, "ffmpeg gave no output pipe")

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                chunk = out.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # player stopped / seeked - normal
        finally:
            try:
                ff.kill()
            except Exception:
                pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/health":
            return self._fail(200, "ok" + ("" if FFMPEG else " (no ffmpeg - /fix disabled)"))

        if parsed.path == "/subtitle-status":
            return self._do_subtitle_status()

        if parsed.path == "/subtitle-search":
            return self._do_subtitle_search(parsed)

        if parsed.path == "/subtitle-file":
            return self._do_subtitle_file(parsed)

        if parsed.path == "/fix":
            return self._do_fix(parsed)

        if parsed.path == "/probe":
            return self._do_probe(parsed)

        if parsed.path == "/subs":
            return self._do_subs(parsed)

        if parsed.path == "/apk":
            # serve the signed Android APK (Firebase's free plan forbids hosting it)
            apk = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "..", "hane-iptv-apk", "app-release-signed.apk")
            apk = os.path.normpath(apk)
            if not os.path.isfile(apk):
                return self._fail(404, "APK not built yet")
            try:
                size = os.path.getsize(apk)
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Disposition", 'attachment; filename="HaNeIPTV.apk"')
                self.send_header("Content-Length", str(size))
                self.end_headers()
                with open(apk, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return

        if parsed.path != "/p":
            return self._fail(404, "Use /p, /fix, /probe, /subs, /subtitle-search or /subtitle-file")

        target = urllib.parse.parse_qs(parsed.query).get("u", [""])[0]
        if not re.match(r"^https?://", target, re.I):
            return self._fail(400, "u must be an http(s) URL")

        req = urllib.request.Request(target)
        for h in FORWARD_REQ_HEADERS:
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)
        req.add_header("User-Agent", UPSTREAM_USER_AGENT)

        try:
            upstream = urllib.request.urlopen(req, timeout=20)
        except urllib.error.HTTPError as e:
            # 456 is returned by some IPTV panels for account/IP/device limits.
            # Keep the upstream code for the player, but log the sanitized
            # reason and hostname so Render diagnostics identify the real side
            # that rejected the request without leaking playlist credentials.
            try:
                detail = e.read(280).decode("utf-8", "replace").replace("\n", " ").strip()
                host = urllib.parse.urlparse(target).hostname or "unknown"
                sys.stderr.write("Upstream %s rejected request (%d): %s\n" % (host, e.code, detail[:220]))
            except Exception:
                pass
            return self._fail(e.code, "Upstream error %d" % e.code)
        except Exception as e:
            return self._fail(502, "Cannot reach panel: %s" % e)

        ctype = upstream.headers.get("Content-Type", "")
        is_m3u8 = ("mpegurl" in ctype.lower()) or target.split("?")[0].lower().endswith(".m3u8")

        try:
            if is_m3u8:
                # playlists are small: read, rewrite, serve
                body = self._rewrite_m3u8(
                    upstream.read().decode("utf-8", "replace"), upstream.geturl()
                ).encode("utf-8")
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/vnd.apple.mpegurl")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            else:
                # stream everything else (API JSON, video files, TS segments)
                self.send_response(upstream.status)
                self._cors()
                for h in FORWARD_RES_HEADERS:
                    v = upstream.headers.get(h)
                    if v:
                        self.send_header(h, v)
                if not upstream.headers.get("Content-Length"):
                    self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = upstream.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # player stopped / seeked - normal
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    def log_message(self, fmt, *args):
        # quiet: only log errors (4xx/5xx)
        if args and str(args[-2] if len(args) > 1 else "").startswith(("4", "5")):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print("HaNe HTTPS->HTTP bridge listening on http://0.0.0.0:%d" % PORT)
    print("  proxy endpoint : /p?u=<urlencoded url>")
    print("  audio-fix      : /fix?src=<url>&t=<sec>  (ffmpeg: %s)" % (FFMPEG or "NOT FOUND"))
    print("  subtitles      : /subtitle-search (SubDL: %s)" % ("configured" if SUBDL_API_KEY else "set SUBDL_API_KEY"))
    print("  expose as https: cloudflared tunnel --url http://localhost:%d" % PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Proxy).serve_forever()
