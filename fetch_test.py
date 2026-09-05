#!/usr/bin/env python3
# SS44 v4 — REAL traffic verification with sing-box
# Round1: DNS+TCP (prefilter) | Round2: real HTTP via proxy (generate_204 must come back)
# GOLD = ترافیک واقعی رد کرده | همه پورت‌ها و همه پروتکل‌ها (بدون تبعیض 443)

import re, socket, ssl, time, base64, json, ipaddress, urllib.request, urllib.parse
import concurrent.futures, subprocess, tempfile, os, queue
from datetime import datetime, timezone

SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/tuic.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/HighSpeed.txt",
]

REPO_URL = "https://github.com/ZendanTeam/SS44-sub"
MAX_TEST = 900          # سقف تست TCP
MAX_TRAFFIC = 600       # سقف تست ترافیک واقعی
TIMEOUT = 4
THREADS = 50
TRAFFIC_WORKERS = 25
TRAFFIC_TIMEOUT = 10    # تایماوت هر تست ترافیک
TEST_URLS = ["https://cp.cloudflare.com/generate_204",
             "https://www.gstatic.com/generate_204"]
SINGBOX = os.environ.get("SINGBOX", "./sing-box")

LINK_RE = re.compile(r'^(vless|vmess|trojan|ss|hy2|hysteria2|tuic)://\S+', re.I)


def extract_links(text):
    lines = [l.strip() for l in text.splitlines() if LINK_RE.match(l.strip())]
    if lines:
        return lines
    try:
        decoded = base64.b64decode(text.strip()).decode("utf-8", "ignore")
        lines = [l.strip() for l in decoded.splitlines() if LINK_RE.match(l.strip())]
        if lines:
            print("  (base64 decoded)")
            return lines
    except Exception:
        pass
    return []


def fetch_all():
    all_links = []
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SS44/4.0"})
            data = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "ignore")
            lines = extract_links(data)
            print(f"OK .../{url.rsplit('/',1)[1]} -> {len(lines)}")
            all_links.extend(lines)
        except Exception as e:
            print(f"FAIL .../{url.rsplit('/',1)[1]}: {e}")
    return all_links


def decode_vmess(link):
    try:
        b64 = link[8:].split("#")[0].strip()
        b64 += "=" * (-len(b64) % 4)
        return json.loads(base64.b64decode(b64).decode("utf-8", "ignore"))
    except Exception:
        return None


def port_digits(s):
    m = re.match(r'\d+', s)
    return m.group(0) if m else "0"


def parse_host_port(link):
    try:
        scheme = link.lower().split("://", 1)[0]
        if scheme == "vmess":
            d = decode_vmess(link)
            if not d:
                return None
            host, port = str(d.get("add", "")).strip(), int(str(d.get("port", 0)))
        elif scheme == "ss":
            body = link.split("://", 1)[1].split("#")[0].split("?")[0].split("/")[0]
            try:
                if "@" not in body:
                    body += "=" * (-len(body) % 4)
                    body = base64.b64decode(body).decode("utf-8", "ignore")
                _, hp = body.rsplit("@", 1)
            except Exception:
                return None
            host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
        else:
            body = link.split("://", 1)[1]
            hp = body.split("@", 1)[1] if "@" in body else body
            hp = re.split(r'[/?#]', hp, maxsplit=1)[0]
            if ":" not in hp:
                return None
            host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
        if not host or not (1 <= port <= 65535):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            pass
        return (host, port)
    except Exception:
        return None


def dedupe(links):
    seen, uniq = set(), []
    for l in links:
        scheme = l.lower().split("://", 1)[0]
        hp = parse_host_port(l)
        ident = l.split("://", 1)[1].split("@", 1)[0][:64] if "@" in l else ""
        key = (scheme, hp, ident)
        if hp is None or key in seen:
            continue
        seen.add(key)
        uniq.append(l)
    return uniq


def query_of(link):
    try:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
    except Exception:
        return {}


def q(p, k, d=""):
    v = p.get(k, [d])
    return urllib.parse.unquote(v[0] if isinstance(v, list) else v)


def tcp_ping(link):
    hp = parse_host_port(link)
    if hp is None:
        return (link, False, 9999)
    t0 = time.time()
    try:
        socket.create_connection(hp, timeout=TIMEOUT).close()
        return (link, True, (time.time() - t0) * 1000)
    except Exception:
        return (link, False, 9999)


def rename(link, idx, prefix="SS44"):
    return link.split("#", 1)[0] + f"#{prefix}-{idx:03d}"


# ================= sing-box outbound converters =================
def fp_map(fp):
    fp = (fp or "").lower()
    return fp if fp in ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq") else "chrome"


def tls_block(p, host, Reality=False):
    sni = q(p, "sni") or q(p, "serverName") or q(p, "peer") or host
    t = {"enabled": True, "server_name": sni}
    if q(p, "fp"):
        t["utls"] = {"enabled": True, "fingerprint": fp_map(q(p, "fp"))}
    if Reality or q(p, "security", "").lower() == "reality":
        t["reality"] = {"enabled": True, "public_key": q(p, "pbk"), "short_id": q(p, "sid", "")}
    return t


def transport_block(p):
    net = q(p, "type", "tcp").lower()
    if net == "ws":
        return {"type": "ws", "path": q(p, "path", "/") or "/",
                "headers": {"Host": q(p, "host", "") or q(p, "sni", "")}}
    if net == "grpc":
        return {"type": "grpc", "service_name": q(p, "serviceName", "") or q(p, "service_name", "")}
    return None


def to_outbound(link):
    """URI -> sing-box outbound dict (یا None اگه پشتیبانی نشه)"""
    scheme = link.lower().split("://", 1)[0]
    if scheme == "vmess":
        d = decode_vmess(link)
        if not d:
            return None
        ob = {"type": "vmess", "server": str(d.get("add", "")), "server_port": int(str(d.get("port", 0))),
              "uuid": str(d.get("id", "")), "security": str(d.get("scy", "auto") or "auto"),
              "alter_id": int(str(d.get("aid", 0)))}
        net = str(d.get("net", "tcp") or "tcp").lower()
        if str(d.get("tls", "")).lower() == "tls":
            t = {"enabled": True, "server_name": str(d.get("sni") or d.get("host") or d.get("add", ""))}
            if d.get("fp"):
                t["utls"] = {"enabled": True, "fingerprint": fp_map(str(d.get("fp")))}
            ob["tls"] = t
        if net == "ws":
            ob["transport"] = {"type": "ws", "path": str(d.get("path", "/") or "/"),
                               "headers": {"Host": str(d.get("host", "") or "")}}
        elif net == "grpc":
            ob["transport"] = {"type": "grpc", "service_name": str(d.get("path", "") or "")}
        return ob
    if scheme == "vless":
        u = urllib.parse.urlsplit(link)
        p = urllib.parse.parse_qs(u.query)
        ob = {"type": "vless", "server": u.hostname, "server_port": u.port,
              "uuid": urllib.parse.unquote(u.username or "")}
        if q(p, "flow"):
            ob["flow"] = q(p, "flow")
        if q(p, "security", "none").lower() in ("tls", "reality"):
            ob["tls"] = tls_block(p, u.hostname)
        tr = transport_block(p)
        if tr:
            ob["transport"] = tr
        return ob
    if scheme == "trojan":
        u = urllib.parse.urlsplit(link)
        p = urllib.parse.parse_qs(u.query)
        ob = {"type": "trojan", "server": u.hostname, "server_port": u.port,
              "password": urllib.parse.unquote(u.username or ""),
              "tls": tls_block(p, u.hostname)}
        tr = transport_block(p)
        if tr:
            ob["transport"] = tr
        return ob
    if scheme == "ss":
        body = link.split("://", 1)[1].split("#")[0].split("?")[0].split("/")[0]
        if "@" not in body:
            body += "=" * (-len(body) % 4)
            body = base64.b64decode(body).decode("utf-8", "ignore")
        userinfo, hp = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo += "=" * (-len(userinfo) % 4)
            userinfo = base64.b64decode(userinfo).decode("utf-8", "ignore")
        method, password = userinfo.split(":", 1)
        host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
        return {"type": "shadowsocks", "server": host, "server_port": port,
                "method": method, "password": password}
    if scheme in ("hy2", "hysteria2"):
        u = urllib.parse.urlsplit(link)
        p = urllib.parse.parse_qs(u.query)
        ob = {"type": "hysteria2", "server": u.hostname, "server_port": u.port,
              "password": urllib.parse.unquote(u.username or "") or q(p, "auth", ""),
              "tls": {"enabled": True, "server_name": q(p, "sni") or q(p, "peer") or u.hostname,
                      "insecure": True}}
        if q(p, "obfs") not in ("", "none") and q(p, "obfs-password"):
            ob["obfs"] = {"type": "salamander", "password": q(p, "obfs-password")}
        return ob
    if scheme == "tuic":
        u = urllib.parse.urlsplit(link)
        p = urllib.parse.parse_qs(u.query)
        user = urllib.parse.unquote(u.username or "")
        pwd = urllib.parse.unquote(u.password or "")
        return {"type": "tuic", "server": u.hostname, "server_port": u.port,
                "uuid": user, "password": pwd or user,
                "congestion_control": "bbr",
                "tls": {"enabled": True, "server_name": q(p, "sni") or u.hostname, "insecure": True}}
    return None


PORTS = queue.Queue()
for _port in range(22000, 22400):
    PORTS.put(_port)


def traffic_test(link):
    """تست واقعی: رد کردن HTTP از داخل تونل — 204 برگشت = واقعاً سالمه. خروجی: (ok, ms)"""
    try:
        ob = to_outbound(link)
    except Exception:
        return (False, 9999)
    if not ob:
        return (False, 9999)
    port = PORTS.get()
    try:
        cfg = {"log": {"level": "error"},
               "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
               "outbounds": [dict(ob, tag="out"), {"type": "direct", "tag": "direct"}],
               "route": {"final": "out"}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        proc = subprocess.Popen([SINGBOX, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            t0 = time.time()
            for _ in range(30):  # صبر تا پورت بالا بیاد
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                    break
                except Exception:
                    time.sleep(0.15)
            else:
                return (False, 9999)
            for url in TEST_URLS:
                try:
                    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                                        "-x", f"http://127.0.0.1:{port}", "--max-time", str(TRAFFIC_TIMEOUT), url],
                                       capture_output=True, text=True, timeout=TRAFFIC_TIMEOUT + 3)
                    code, t = (r.stdout.strip().split() + ["0", "0"])[:2]
                    if code in ("200", "204"):
                        return (True, float(t) * 1000)
                except Exception:
                    continue
            return (False, 9999)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            try:
                os.unlink(path)
            except Exception:
                pass
    except Exception:
        return (False, 9999)
    finally:
        PORTS.put(port)


# ---------- clash converter (for output file) ----------
def to_clash(link, name):
    try:
        scheme = link.lower().split("://", 1)[0]
        if scheme == "vless":
            return clash_vless(link, name)
        if scheme == "vmess":
            return clash_vmess(link, name)
        if scheme == "trojan":
            return clash_trojan(link, name)
        if scheme == "ss":
            return clash_ss(link, name)
        if scheme in ("hy2", "hysteria2"):
            return clash_hy2(link, name)
        if scheme == "tuic":
            return clash_tuic(link, name)
    except Exception:
        return None
    return None


def clash_vless(link, name):
    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    net = q(p, "type", "tcp")
    sec = q(p, "security", "none")
    proxy = {"name": name, "type": "vless", "server": u.hostname, "port": u.port,
             "uuid": urllib.parse.unquote(u.username or ""), "udp": True, "network": net}
    if sec in ("tls", "reality"):
        proxy["tls"] = True
        if q(p, "sni"):
            proxy["servername"] = q(p, "sni")
        if q(p, "fp"):
            proxy["client-fingerprint"] = q(p, "fp")
    if q(p, "flow"):
        proxy["flow"] = q(p, "flow")
    if sec == "reality":
        proxy["reality-opts"] = {"public-key": q(p, "pbk"), "short-id": q(p, "sid", "")}
    if net == "ws":
        proxy["ws-opts"] = {"path": q(p, "path", "/"), "headers": {"Host": q(p, "host", q(p, "sni", u.hostname))}}
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q(p, "serviceName", "")}
    return proxy


def clash_vmess(link, name):
    d = decode_vmess(link)
    if not d:
        return None
    proxy = {"name": name, "type": "vmess", "server": str(d.get("add", "")),
             "port": int(str(d.get("port", 0))), "uuid": str(d.get("id", "")),
             "alterId": int(str(d.get("aid", 0))), "cipher": str(d.get("scy", "auto") or "auto"),
             "udp": True, "network": str(d.get("net", "tcp") or "tcp")}
    if str(d.get("tls", "")) == "tls":
        proxy["tls"] = True
        if d.get("sni"):
            proxy["servername"] = str(d["sni"])
    net = proxy["network"]
    if net == "ws":
        proxy["ws-opts"] = {"path": str(d.get("path", "/") or "/"),
                            "headers": {"Host": str(d.get("host", "") or d.get("add", ""))}}
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": str(d.get("path", "") or "")}
    return proxy


def clash_trojan(link, name):
    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    net = q(p, "type", "tcp")
    proxy = {"name": name, "type": "trojan", "server": u.hostname, "port": u.port,
             "password": urllib.parse.unquote(u.username or ""), "udp": True, "network": net}
    if q(p, "sni"):
        proxy["sni"] = q(p, "sni")
    if net == "ws":
        proxy["ws-opts"] = {"path": q(p, "path", "/")}
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q(p, "serviceName", "")}
    return proxy


def clash_ss(link, name):
    body = link.split("://", 1)[1].split("#")[0].split("?")[0].split("/")[0]
    if "@" not in body:
        body += "=" * (-len(body) % 4)
        body = base64.b64decode(body).decode("utf-8", "ignore")
    userinfo, hp = body.rsplit("@", 1)
    if ":" not in userinfo:
        userinfo += "=" * (-len(userinfo) % 4)
        userinfo = base64.b64decode(userinfo).decode("utf-8", "ignore")
    method, password = userinfo.split(":", 1)
    host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
    return {"name": name, "type": "ss", "server": host, "port": port,
            "cipher": method, "password": password, "udp": True}


def clash_hy2(link, name):
    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    proxy = {"name": name, "type": "hysteria2", "server": u.hostname, "port": u.port,
             "password": urllib.parse.unquote(u.username or q(p, "auth", "")),
             "skip-cert-verify": True, "udp": True}
    if q(p, "sni") or q(p, "peer"):
        proxy["sni"] = q(p, "sni", q(p, "peer"))
    return proxy


def clash_tuic(link, name):
    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    user = urllib.parse.unquote(u.username or "")
    pwd = urllib.parse.unquote(u.password or "")
    proxy = {"name": name, "type": "tuic", "server": u.hostname, "port": u.port,
             "uuid": user, "password": pwd or user,
             "skip-cert-verify": True, "udp": True, "congestion-controller": "bbr"}
    if q(p, "sni"):
        proxy["sni"] = q(p, "sni")
    return proxy


def yaml_emit(proxies):
    out = ["# SS44 clash subscription — auto-generated (traffic-verified first)", "proxies:"]
    for pr in proxies:
        out.append(f"  - {{name: {pr['name']}, type: {pr['type']}, server: {pr['server']}, port: {pr['port']}}}")
        for k, v in pr.items():
            if k in ("name", "type", "server", "port"):
                continue
            out.append(f"    {k}: {json.dumps(v, ensure_ascii=False)}")
    return "\n".join(out) + "\n"


def main():
    import random
    t_start = time.time()
    raw = fetch_all()
    print(f"RAW total: {len(raw)}", flush=True)
    uniq = dedupe(raw)
    print(f"UNIQUE valid: {len(uniq)}", flush=True)

    # قاطی کردن تا همه پورت‌ها/پروتکل‌ها شانس تست داشته باشن (بدون تبعیض 443)
    random.seed(int(time.time()) // 1800)
    random.shuffle(uniq)
    candidates = uniq[:MAX_TEST]
    print(f"Round1 TCP testing {len(candidates)} ...", flush=True)
    opened = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for link, good, ms in ex.map(tcp_ping, candidates):
            if good:
                opened.append(link)
    print(f"Round1 OPEN: {len(opened)} / {len(candidates)}", flush=True)

    use_traffic = os.path.exists(SINGBOX) and os.access(SINGBOX, os.X_OK)
    print(f"sing-box traffic test: {'ON' if use_traffic else 'OFF (fallback: TCP only)'}", flush=True)
    gold, silver = [], []
    if use_traffic:
        traffic_cands = opened[:MAX_TRAFFIC]
        print(f"Round2 TRAFFIC testing {len(traffic_cands)} ...", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=TRAFFIC_WORKERS) as ex:
            for link, (ok, ms) in zip(traffic_cands, ex.map(traffic_test, traffic_cands)):
                (gold if ok else silver).append((ms if ok else 9999, link))
        gold.sort(key=lambda x: x[0])
        print(f"GOLD (real traffic OK): {len(gold)} / {len(traffic_cands)}", flush=True)
        if gold:
            ms_sorted = sorted(m for m, _ in gold)
            print(f"  latency p50={ms_sorted[len(ms_sorted)//2]:.0f}ms", flush=True)
    else:
        silver = [(9999, l) for l in opened]

    # تنوع پروتکل: اول ۱۵۰ تای سریع‌تر، بعد اگه پروتکل سالمی جا مونده بود اضافه کن
    final = sorted(gold, key=lambda x: x[0])[:150]
    have = {l.split("://", 1)[0].lower() for _, l in final}
    for _, link in sorted(gold, key=lambda x: x[0]):
        proto = link.split("://", 1)[0].lower()
        if proto not in have:
            have.add(proto)
            final.append((9999, link))

    links = [rename(l, i + 1) for i, (_, l) in enumerate(final)]
    udp_links = [l for _, l in final if l.split("://", 1)[0].lower() in ("hy2", "hysteria2", "tuic")]
    udp_out = [rename(l, i + 1, prefix="SS44-U") for i, l in enumerate(udp_links[:60])]

    title_b64 = base64.b64encode("🚀 SS44 VERIFIED | Iran".encode()).decode()
    header = [f"#profile-title: base64:{title_b64}", "#profile-update-interval: 1",
              f"#support-url: {REPO_URL}", f"#profile-web-page-url: {REPO_URL}"]
    with open("SS44-gold.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header + links) + "\n")
    with open("SS44.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header + links) + "\n")
    with open("SS44-base64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    with open("SS44-udp.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(udp_out) + ("\n" if udp_out else ""))

    clash_proxies, proto_count = [], {}
    for i, l in enumerate(links, 1):
        scheme = l.split("://", 1)[0].lower()
        proto_count[scheme] = proto_count.get(scheme, 0) + 1
        cp = to_clash(l, f"SS44-{i:03d}")
        if cp:
            clash_proxies.append(cp)
    with open("SS44-clash.yaml", "w", encoding="utf-8") as f:
        f.write(yaml_emit(clash_proxies))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open("STATS.md", "w", encoding="utf-8") as f:
        f.write(f"# 📊 SS44 Stats\n\n- Last update: **{now}**\n- Fetched: **{len(raw)}**\n"
                f"- Unique valid: **{len(uniq)}**\n- Round1 TCP: **{len(candidates)}** → open **{len(opened)}**\n"
                f"- Round2 TRAFFIC: **{min(len(opened), MAX_TRAFFIC)}** → 🥇 GOLD **{len(gold)}**\n"
                f"- Published: **{len(links)}** (UDP extra **{len(udp_out)}**, clash **{len(clash_proxies)}**)\n\n"
                f"| Protocol | Count |\n|---|---|\n")
        for k, v in sorted(proto_count.items()):
            f.write(f"| {k} | {v} |\n")
    print(f"DONE in {time.time()-t_start:.0f}s — gold {len(gold)}, published {len(links)}, clash {len(clash_proxies)}",
          flush=True)


if __name__ == "__main__":
    main()
