"""Dependency-free structural checks for the static site."""
from html.parser import HTMLParser
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).parent


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs, self.ids, self.anchors = [], set(), []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for attr in ("src", "href"):
            value = attrs.get(attr, "")
            if value and not value.startswith(("http:", "https:", "mailto:", "tel:", "#", "data:")):
                self.refs.append(value)
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.append(attrs["href"][1:])


errors = []
for filename in ("index.html", "privacy.html", "consent.html"):
    content = (ROOT / filename).read_bytes().decode("utf-8")
    page = Page()
    page.feed(content)
    missing = [ref for ref in page.refs if not (ROOT / ref.lstrip("/")).exists()]
    broken = [anchor for anchor in page.anchors if anchor not in page.ids]
    print(f"{filename}: UTF-8 OK; missing files={missing}; broken anchors={broken}")
    errors.extend(f"{filename}: missing {x}" for x in missing)
    errors.extend(f"{filename}: broken #{x}" for x in broken)

ET.parse(ROOT / "sitemap.xml")
print("sitemap.xml: valid XML")

html = (ROOT / "index.html").read_text(encoding="utf-8")
script = (ROOT / "script.js").read_text(encoding="utf-8")
ru = script.split("ru:{", 1)[1].split("},\nkk:{", 1)[0]
kk = script.split("kk:{", 1)[1].split("}\n};", 1)[0]
keys = lambda text: set(re.findall(r"(?:^|,)\s*([A-Za-z][A-Za-z0-9]*):", text))
markers = set(re.findall(r'data-i="([^"]+)"', html))
missing_ru, missing_kk = markers - keys(ru), markers - keys(kk)
print(f"translation markers={len(markers)}; missing RU={sorted(missing_ru)}; missing KK={sorted(missing_kk)}")
errors.extend(f"Missing Russian translation: {x}" for x in missing_ru)
errors.extend(f"Missing Kazakh translation: {x}" for x in missing_kk)

if errors:
    raise SystemExit("\n".join(errors))
print("Structural checks passed.")
