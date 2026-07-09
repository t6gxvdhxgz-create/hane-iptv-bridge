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

IMPORTANT - to help the HOSTED (https) app, the proxy itself must be reachable
over https. Easiest free way (no VPS, no certificates):
    cloudflared tunnel --url http://localhost:8899
...then put the printed https://xxxx.trycloudflare.com URL into HTTP_PROXY in
js/config.js. For local/TV use (http) you don't need this proxy at all.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8899))
CHUNK = 64 * 1024
FORWARD_REQ_HEADERS = ("range", "user-agent", "accept")
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

    def _proxy_prefix(self):
        # absolute prefix pointing back at this proxy (works behind tunnels)
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ("localhost:%d" % PORT)
        scheme = self.headers.get("X-Forwarded-Proto") or "http"
        return "%s://%s/p?u=" % (scheme, host)

    def _rewrite_m3u8(self, text, base_url):
        """Make every URI in an HLS playlist absolute and proxy-wrapped."""
        prefix = self._proxy_prefix()

        def wrap(u):
            absolute = urllib.parse.urljoin(base_url, u.strip())
            return prefix + urllib.parse.quote(absolute, safe="")

        out = []
        for line in text.splitlines():
            s = line.strip()
            if not s:
                out.append(line)
            elif s.startswith("#"):
                # rewrite URI="..." attributes (keys, maps, media renditions)
                out.append(re.sub(r'URI="([^"]+)"', lambda m: 'URI="%s"' % wrap(m.group(1)), line))
            else:
                out.append(wrap(s))
        return "\n".join(out) + "\n"

    # ── HTTP methods ─────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
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
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            try:
                ff.kill()
            except Exception:
                pass
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
            return self._fail(404, "Use /p?u=<url>, /fix?src=<url>, /probe?src=<url> or /subs?src=<url>&index=N")

        target = urllib.parse.parse_qs(parsed.query).get("u", [""])[0]
        if not re.match(r"^https?://", target, re.I):
            return self._fail(400, "u must be an http(s) URL")

        req = urllib.request.Request(target)
        for h in FORWARD_REQ_HEADERS:
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)
        if not req.has_header("User-agent"):
            req.add_header("User-Agent", "HaNeIPTV/1.0")

        try:
            upstream = urllib.request.urlopen(req, timeout=20)
        except urllib.error.HTTPError as e:
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
    print("  expose as https: cloudflared tunnel --url http://localhost:%d" % PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Proxy).serve_forever()
