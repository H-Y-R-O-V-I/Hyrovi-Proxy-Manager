"""Safe, coarse per-request Smart analytics. NEVER exports raw source IP or User-Agent."""
import re

BOT=re.compile(r"googlebot|bingbot|duckduckbot|yandexbot|baiduspider|slurp|applebot|facebookexternalhit|bytespider|petalbot|crawler|spider|(?:^|[\s;/])bot(?:[\s;/]|$)|curl/|wget/|python-requests|python-urllib|scrapy|headlesschrome|playwright|puppeteer|selenium|aiohttp|httpx/|go-http-client|java/|libwww|okhttp|postmanruntime", re.I)
LOCALE=re.compile(r"^[a-z]{2,3}(?:-[A-Z]{2})?$")
SENSITIVE={"admin","account","login","logout","auth","signin","password","oauth",
  "token","secret","vault","payment","checkout","billing","profile","user","users","private",
  "identity","session","api"}
PATH=re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,35}$")

def classify(request):
    ua=str(request.get("user_agent") or "")[:512]
    ch=str(request.get("sec_ch_ua_platform") or "").replace('"',"")[:50]
    lang=str(request.get("accept_language") or "").split(",")[0].split(";")[0].strip()
    region=lang if LOCALE.fullmatch(lang) else "Unbekannt"
    bot=bool(BOT.search(ua))
    browser="Unbekannt"
    if re.search(r"Edg(?:e|A|iOS)?/",ua,re.I):browser="Edge"
    elif re.search(r"OPR/|Opera/",ua,re.I):browser="Opera"
    elif "SamsungBrowser/" in ua:browser="Samsung Internet"
    elif re.search(r"Firefox/|FxiOS/",ua,re.I):browser="Firefox"
    elif re.search(r"Chrome/|CriOS/",ua,re.I):browser="Chrome"
    elif "Safari/" in ua and "Version/" in ua:browser="Safari"
    if re.search("Android",ua+ch,re.I):platform="Android"
    elif re.search("iPad|iPhone|iPod",ua,re.I) or "iOS" in ch:platform="iOS/iPadOS"
    elif "Windows" in ua+ch:platform="Windows"
    elif re.search("Macintosh|Mac OS X|macOS",ua+ch,re.I):platform="macOS"
    elif re.search("Linux|X11",ua+ch,re.I):platform="Linux"
    else: platform="Unbekannt"
    if re.search("iPad|Tablet|Android(?!.*Mobile)",ua,re.I):device="Tablet"
    elif re.search("iPhone|iPod|Mobile|Android.*Mobile",ua,re.I) or str(request.get("sec_ch_ua_mobile") or "")=="?1":device="Smartphone"
    elif browser!="Unbekannt":device="Desktop/Unbekannt"
    else:device="Unbekannt"
    return {"classification":"bot" if bot else "unknown",
      "browser":browser,"platform":platform,"device":device,
      "languageRegion":region,"reason":"Automations-User-Agent" if bot else "Kein eindeutiges Automationsmerkmal"}

def safe_event(request, desc, host, when, safe_section):
    time=when.replace(second=0,microsecond=0).isoformat()
    return {"source":"VPS","host":host,"origin":"proxy","type":"request",
      "time":time,"section":safe_section(request.get("path")), "method":str(request.get("method") or "")[:8],
      "status":int(request.get("status") or 0), **desc}

def new_breakdown():
    return {"botRequests":0,"unknownRequests":0,"devices":{},
      "browsers":{},"platforms":{},"languageRegions":{},"botDevices":{},
      "botBrowsers":{},"botPlatforms":{},"botLanguageRegions":{}}

def tally(b, desc):
    b["botRequests" if desc["classification"]=="bot" else "unknownRequests"]+=1
    for key,field in (("devices","device"),("browsers","browser"),
                      ("platforms","platform"),("languageRegions","languageRegion")):
        label=desc[field]
        b[key][label]=b[key].get(label,0)+1
        if desc["classification"]=="bot":
            botkey="bot"+key[:1].upper()+key[1:]
            b[botkey][label]=b[botkey].get(label,0)+1
