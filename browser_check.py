"""Serve the static site in Edge, use real viewport emulation, and capture screenshots."""
import base64
import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
from threading import Thread
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).parent.resolve()
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
if not EDGE.exists():
    EDGE = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
if not EDGE.exists():
    raise SystemExit("No Chromium browser found")


class QuietHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def handle_error(self, request, client_address):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


class DevTools:
    def __init__(self, url):
        target = urlparse(url)
        self.sock = socket.create_connection((target.hostname, target.port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {target.path} HTTP/1.1\r\nHost: {target.hostname}:{target.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        self.buffer = b""
        while b"\r\n\r\n" not in self.buffer:
            self.buffer += self.sock.recv(4096)
        self.buffer = self.buffer.split(b"\r\n\r\n", 1)[1]
        self.sock.settimeout(5)
        self.serial = 0
        self.errors = []

    def send_frame(self, payload):
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x81, 0x80 | length])
        elif length < 65536:
            header = bytes([0x81, 0xFE]) + struct.pack("!H", length)
        else:
            header = bytes([0x81, 0xFF]) + struct.pack("!Q", length)
        self.sock.sendall(header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))

    def receive(self):
        while len(self.buffer) < 2:
            self.buffer += self.sock.recv(65536)
        first, second = self.buffer[0], self.buffer[1]
        size, offset = second & 127, 2
        if size == 126:
            while len(self.buffer) < 4: self.buffer += self.sock.recv(65536)
            size, offset = struct.unpack("!H", self.buffer[2:4])[0], 4
        elif size == 127:
            while len(self.buffer) < 10: self.buffer += self.sock.recv(65536)
            size, offset = struct.unpack("!Q", self.buffer[2:10])[0], 10
        mask = b""
        if second & 128:
            while len(self.buffer) < offset + 4: self.buffer += self.sock.recv(65536)
            mask, offset = self.buffer[offset:offset + 4], offset + 4
        while len(self.buffer) < offset + size:
            self.buffer += self.sock.recv(65536)
        data, self.buffer = self.buffer[offset:offset + size], self.buffer[offset + size:]
        if mask:
            data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
        if first & 15 == 8:
            raise ConnectionError("DevTools WebSocket closed")
        return json.loads(data.decode())

    def command(self, method, params=None):
        self.serial += 1
        ident = self.serial
        self.send_frame(json.dumps({"id": ident, "method": method, "params": params or {}}).encode())
        while True:
            message = self.receive()
            if message.get("method") in ("Runtime.exceptionThrown", "Log.entryAdded"):
                self.errors.append(message)
            if message.get("id") == ident:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message.get("result", {})


KAZAKH_GLYPHS = "ӘәҒғҚқҢңӨөҰұҮүҺһІі"


def audit_glyphs(cdp, families):
    specs = []
    for family in families:
        for weight, style in ((400, "normal"), (500, "normal"), (700, "normal"), (400, "italic"), (700, "italic")):
            specs.append({"family": family, "weight": weight, "style": style})
    script = """(()=>{const chars=__CHARS__,specs=__SPECS__,root=document.createElement('div');root.id='glyph-audit';root.style.cssText='position:fixed;left:-10000px;top:0;opacity:.01;white-space:nowrap';for(let s=0;s<specs.length;s++)for(let i=0;i<chars.length;i++){const el=document.createElement('span');el.dataset.index=String(s*chars.length+i);el.textContent=chars[i];el.style.cssText=`font-family:'${specs[s].family}';font-size:32px;font-weight:${specs[s].weight};font-style:${specs[s].style}`;root.appendChild(el)}document.body.appendChild(root);return root.children.length})()""".replace("__CHARS__", json.dumps(list(KAZAKH_GLYPHS), ensure_ascii=False)).replace("__SPECS__", json.dumps(specs))
    cdp.command("Runtime.evaluate", {"expression": script, "returnByValue": True})
    cdp.command("Runtime.evaluate", {"expression": "document.fonts.ready.then(()=>true)", "awaitPromise": True, "returnByValue": True})
    doc = cdp.command("DOM.getDocument", {"depth": 1}).get("root", {})
    nodes = cdp.command("DOM.querySelectorAll", {"nodeId": doc["nodeId"], "selector": "#glyph-audit span"}).get("nodeIds", [])
    issues = []
    for index, node_id in enumerate(nodes):
        spec_index, char_index = divmod(index, len(KAZAKH_GLYPHS))
        spec = specs[spec_index]
        rendered = cdp.command("CSS.getPlatformFontsForNode", {"nodeId": node_id}).get("fonts", [])
        actual = [font.get("familyName", "") for font in rendered]
        if spec["family"] not in actual or any(name != spec["family"] for name in actual):
            issues.append({"family": spec["family"], "weight": spec["weight"], "style": spec["style"], "char": KAZAKH_GLYPHS[char_index], "renderedBy": actual})
    cdp.command("Runtime.evaluate", {"expression": "document.querySelector('#glyph-audit')?.remove()"})
    return issues


server = QuietServer(("127.0.0.1", 0), QuietHandler)
Thread(target=server.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{server.server_port}/"
profile = tempfile.TemporaryDirectory(prefix="legal-site-edge-")
browser = subprocess.Popen(
    [str(EDGE), "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-extensions",
     "--remote-debugging-port=0", f"--user-data-dir={profile.name}", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
)

try:
    active_port = Path(profile.name) / "DevToolsActivePort"
    deadline = time.time() + 20
    while not active_port.exists() and time.time() < deadline:
        time.sleep(.1)
    if not active_port.exists():
        raise RuntimeError("Edge did not start its DevTools endpoint")
    port = active_port.read_text().splitlines()[0]
    request = Request(f"http://127.0.0.1:{port}/json/new?{base}", method="PUT")
    target = json.load(urlopen(request, timeout=5))
    cdp = DevTools(target["webSocketDebuggerUrl"])
    cdp.command("Page.enable")
    cdp.command("Runtime.enable")
    cdp.command("Log.enable")
    cdp.command("DOM.enable")
    cdp.command("CSS.enable")

    for name, width, height, mobile in (("preview-desktop.png", 1440, 1000, False), ("preview-mobile.png", 390, 844, True)):
        cdp.command("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile})
        cdp.command("Page.navigate", {"url": base})
        time.sleep(2)
        metrics = cdp.command("Runtime.evaluate", {
            "expression": "JSON.stringify({viewport:innerWidth,document:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,height:document.documentElement.scrollHeight,hero:document.querySelector('.hero').getBoundingClientRect().width,heading:document.querySelector('h1').getBoundingClientRect().width,headingScroll:document.querySelector('h1').scrollWidth,font:getComputedStyle(document.querySelector('h1')).fontSize,image:document.querySelector('.hero-photo').complete})",
            "returnByValue": True,
        }).get("result", {}).get("value", "{}")
        shot = cdp.command("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        (ROOT / name).write_bytes(base64.b64decode(shot["data"]))
        print(f"{name}: {metrics}")
        if not mobile:
            height = json.loads(metrics).get("height", 0)
            full = cdp.command("Page.captureScreenshot", {
                "format": "png", "captureBeyondViewport": True,
                "clip": {"x": 0, "y": 0, "width": width, "height": height, "scale": 1},
            })
            (ROOT / "preview-full.png").write_bytes(base64.b64decode(full["data"]))

    baseline = audit_glyphs(cdp, ["DM Sans", "Playfair Display"])
    old_summary = {}
    for issue in baseline:
        old_summary.setdefault(issue["family"], set()).add(issue["char"])
    print("CURRENT FONT FALLBACKS:", json.dumps({family: "".join(sorted(chars)) for family, chars in old_summary.items()}, ensure_ascii=False))

    ready = cdp.command("Runtime.evaluate", {
        "expression": "document.querySelector('[data-lang=kk]').click();document.fonts.ready.then(()=>true)",
        "awaitPromise": True, "returnByValue": True,
    })
    time.sleep(.5)
    kaz_metrics = cdp.command("Runtime.evaluate", {
        "expression": "JSON.stringify({lang:document.documentElement.lang,hero:document.querySelector('h1').getBoundingClientRect().height,document:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,height:document.documentElement.scrollHeight})",
        "returnByValue": True,
    }).get("result", {}).get("value", "{}")
    kaz_height = json.loads(kaz_metrics).get("height", 0)
    full_kaz = cdp.command("Page.captureScreenshot", {
        "format": "png", "captureBeyondViewport": True,
        "clip": {"x": 0, "y": 0, "width": 390, "height": kaz_height, "scale": 1},
    })
    (ROOT / "preview-kazakh-full.png").write_bytes(base64.b64decode(full_kaz["data"]))
    mobile_kaz = cdp.command("Page.captureScreenshot", {"format": "png", "fromSurface": True})
    (ROOT / "preview-kazakh-mobile.png").write_bytes(base64.b64decode(mobile_kaz["data"]))
    cdp.command("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
    time.sleep(.25)
    desktop_kaz = cdp.command("Runtime.evaluate", {
        "expression": "JSON.stringify({lang:document.documentElement.lang,document:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,height:document.documentElement.scrollHeight})",
        "returnByValue": True,
    }).get("result", {}).get("value", "{}")
    desktop_kaz_height = json.loads(desktop_kaz).get("height", 0)
    kaz_full_desktop = cdp.command("Page.captureScreenshot", {
        "format": "png", "captureBeyondViewport": True,
        "clip": {"x": 0, "y": 0, "width": 1440, "height": desktop_kaz_height, "scale": 1},
    })
    (ROOT / "preview-kazakh-desktop.png").write_bytes(base64.b64decode(kaz_full_desktop["data"]))
    noto_issues = audit_glyphs(cdp, ["Noto Sans", "Noto Serif"])
    print("KAZAKH MOBILE:", kaz_metrics)
    print("KAZAKH DESKTOP:", desktop_kaz)
    print("NOTO FALLBACKS:", json.dumps(noto_issues, ensure_ascii=False))

    cdp.command("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
    interaction = cdp.command("Runtime.evaluate", {
        "expression": "(()=>{const menu=document.querySelector('.menu-toggle'),nav=document.querySelector('.nav');menu.click();const menuOpens=nav.classList.contains('open')&&menu.getAttribute('aria-expanded')==='true';nav.querySelector('a[href=\\\"#about\\\"]').click();const anchorWorks=location.hash==='#about'&&!nav.classList.contains('open');document.querySelector('[data-lang=kk]').click();const kazakh=document.documentElement.lang==='kk';document.querySelector('[data-lang=ru]').click();const f=document.querySelector('#contact-form');f.elements.name.value='QA Test';f.elements.phone.value='+77000000000';f.elements.message.value='Локальная проверка формы';f.elements.consent.checked=true;let opened=0;window.open=()=>{opened++;return null};f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));return JSON.stringify({menuOpens,anchorWorks,kazakh,preview:!document.querySelector('.message-preview').hidden,externalWindowsOpened:opened})})()",
        "returnByValue": True,
    }).get("result", {}).get("value", "{}")
    print("SAFE INTERACTION CHECK:", interaction)

    cdp.command("Page.navigate", {"url": (ROOT / "index.html").as_uri()})
    time.sleep(2)
    file_metrics = cdp.command("Runtime.evaluate", {
        "expression": "JSON.stringify({title:document.title,bodyBackground:getComputedStyle(document.body).backgroundColor,heroBackgroundImage:getComputedStyle(document.querySelector('.hero')).backgroundImage,imageLoaded:document.querySelector('.hero-photo').naturalWidth>0,stylesheets:document.querySelectorAll('link[rel=stylesheet]').length,documentWidth:document.documentElement.scrollWidth})",
        "returnByValue": True,
    }).get("result", {}).get("value", "{}")
    print("FILE URL CHECK:", file_metrics)

    print("Console/runtime errors:", len(cdp.errors))
    for error in cdp.errors:
        print(json.dumps(error, ensure_ascii=False)[:500])
    cdp.sock.close()
finally:
    browser.terminate()
    try:
        browser.wait(timeout=5)
    except subprocess.TimeoutExpired:
        browser.kill()
    profile.cleanup()
    server.shutdown()
    server.server_close()
