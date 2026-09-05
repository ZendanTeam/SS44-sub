#!/usr/bin/env python3
# SS44 v2 — Irancell-first smart subscription builder
# فچ از چند ساب -> دیکد vmess -> حذف تکراری/خصوصی -> تست TCP
# -> رتبه‌بندی Reality/443 -> خروجی txt + base64 + clash + stats

import re, socket, time, base64, json, ipaddress, urllib.request, urllib.parse
import concurrent.futures
from datetime import datetime, timezone

SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/HighSpeed.txt",
]

REPO_URL = "https://github.com/ZendanTeam/SS44-sub"
MAX_TEST = 500
TIMEOUT = 4
THREADS = 50
TOP_N = 120

LINK_RE = re.compile(r'^(vless|vmess|trojan|ss)://\S+', re.I)


def extract_links(text):
    lines = [l.strip() for l in text.splitlines() if LINK_RE.match(l.strip())]
    if lines:
        return lines
    try:  # بعضی ساب‌ها کل فایل base64 است
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
            req = urllib.request.Request(url, headers={"User-Agent": "SS44/2.0"})
            data = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "ignore")
            lines = extract_links(data)
            print(f"OK {url[:70]}... -> {len(lines)}")
            all_links.extend(lines)
        except Exception as e:
            print(f"FAIL {url[:70]}: {e}")
    return all_links


def decode_vmess(link):
    try:
        b64 = link[8:].split("#")[0].strip()
        b64 += "=" * (-len(b64) % 4)
        return json.loads(base64.b64decode(b64).decode("utf-8", "ignore"))
    except Exception:
        return None


def parse_host_port(link):
    """(host, port) یا None — آی‌پی خصوصی/لوپ‌بک حذف می‌شود"""
    try:
        low = link.lower()
        if low.startswith("vmess://"):
            d = decode_vmess(link)
            if not d:
                return None
            host, port = str(d.get("add", "")).strip(), int(str(d.get("port", 0)))
        elif low.startswith("ss://"):
            body = link[5:].split("#")[0].split("?")[0].split("/")[0]
            try:
                if "@" not in body:
                    body += "=" * (-len(body) % 4)
                    body = base64.b64decode(body).decode("utf-8", "ignore")
                userinfo, hp = body.rsplit("@", 1)
            except Exception:
                return None
            host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
        else:  # vless / trojan
            body = link.split("://", 1)[1]
            hp = body.split("@", 1)[1] if "@" in body else body
            hp = re.split(r'[/?#]', hp, maxsplit=1)[0]
            if ":" not in hp:
                return None
            host, port = hp.rsplit(":", 1)[0].strip("[]"), int(port_digits(hp.rsplit(":", 1)[1]))
        if not host or not (1 <= port <= 65535):
            return None
        try:  # حذف آی‌پی خصوصی، لوپ‌بک، رزرو شده
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                return None
        except ValueError:
            pass  # دامنه است، قبول
        return (host, port)
    except Exception:
        return None


def port_digits(s):
    m = re.match(r'\d+', s)
    return m.group(0) if m else "0"


def dedupe(links):
    seen, uniq = set(), []
    for l in links:
        low = l.lower()
        scheme = low.split("://", 1)[0]
        hp = parse_host_port(l)
        ident = l.split("://", 1)[1].split("@", 1)[0][:64] if "@" in l else ""
        key = (scheme, hp, ident)
        if hp is None or key in seen:
            continue
        seen.add(key)
        uniq.append(l)
    return uniq


def score(link):
    ll = link.lower()
    s = 0
    if "reality" in ll:
        s -= 10
    if ":443" in ll or "%3a443" in ll:
        s -= 5
    if "security=tls" in ll:
        s -= 2
    if "flow=xtls" in ll:
        s -= 1
    return s


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


def rename(link, idx):
    return link.split("#", 1)[0] + f"#SS44-{idx:03d}"


# ---------- clash.yaml converter ----------
def to_clash(link, name):
    try:
        low = link.lower()
        if low.startswith("vless://"):
            return clash_vless(link, name)
        if low.startswith("vmess://"):
            return clash_vmess(link, name)
        if low.startswith("trojan://"):
            return clash_trojan(link, name)
        if low.startswith("ss://"):
            return clash_ss(link, name)
    except Exception:
        return None
    return None


def q(p, k, d=""):
    v = p.get(k, [d])
    return urllib.parse.unquote(v[0] if isinstance(v, list) else v)


def clash_vless(link, name):
    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    net = q(p, "type", "tcp")
    sec = q(p, "security", "none")
    proxy = {"name": name, "type": "vless", "server": u.hostname, "port": u.port,
             "uuid": urllib.parse.unquote(u.username or ""), "udp": True, "network": net}
    if sec in ("tls", "reality"):
        proxy["tls"] = True
        if q(p, "sni"): proxy["servername"] = q(p, "sni")
        if q(p, "fp"): proxy["client-fingerprint"] = q(p, "fp")
    if q(p, "flow"): proxy["flow"] = q(p, "flow")
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
        if d.get("sni"): proxy["servername"] = str(d["sni"])
        elif d.get("host"): proxy["servername"] = str(d["host"])
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
    if q(p, "sni"): proxy["sni"] = q(p, "sni")
    if net == "ws":
        proxy["ws-opts"] = {"path": q(p, "path", "/")}
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q(p, "serviceName", "")}
    return proxy


def clash_ss(link, name):
    body = link[5:].split("#")[0].split("?")[0].split("/")[0]
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


def yaml_emit(proxies):
    out = ["# SS44 clash subscription — auto-generated", "proxies:"]
    for pr in proxies:
        out.append(f"  - {{name: {pr['name']}, type: {pr['type']}, server: {pr['server']}, port: {pr['port']}}}")
        for k, v in pr.items():
            if k in ("name", "type", "server", "port"):
                continue
            out.append(f"    {k}: {json.dumps(v, ensure_ascii=False)}")
    return "\n".join(out) + "\n"


def main():
    t_start = time.time()
    raw = fetch_all()
    print(f"RAW total: {len(raw)}")
    uniq = dedupe(raw)
    print(f"UNIQUE (valid endpoint): {len(uniq)}")
    uniq.sort(key=score)
    candidates = uniq[:MAX_TEST]
    print(f"Testing {len(candidates)} ...")
    ok = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for link, good, ms in ex.map(tcp_ping, candidates):
            if good:
                ok.append((ms, link))
    ok.sort(key=lambda x: x[0])
    print(f"OPEN: {len(ok)} / {len(candidates)}")
    top = ok[:TOP_N]

    links, clash_proxies, proto_count = [], [], {}
    for i, (ms, link) in enumerate(top, 1):
        scheme = link.split("://", 1)[0].lower()
        proto_count[scheme] = proto_count.get(scheme, 0) + 1
        links.append(rename(link, i))
        cp = to_clash(link, f"SS44-{i:03d}")
        if cp:
            clash_proxies.append(cp)

    title_b64 = base64.b64encode("🚀 SS44 | Iran Irancell".encode()).decode()
    header = [f"#profile-title: base64:{title_b64}",
              "#profile-update-interval: 1",
              f"#support-url: {REPO_URL}",
              f"#profile-web-page-url: {REPO_URL}"]
    with open("SS44.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header + links) + "\n")
    with open("SS44-base64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    with open("SS44-clash.yaml", "w", encoding="utf-8") as f:
        f.write(yaml_emit(clash_proxies))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open("STATS.md", "w", encoding="utf-8") as f:
        f.write(f"# 📊 SS44 Stats\n\n- Last update: **{now}**\n- Fetched: **{len(raw)}**\n"
                f"- Unique valid: **{len(uniq)}**\n- Tested: **{len(candidates)}**\n"
                f"- Online: **{len(ok)}**\n- Published: **{len(links)}** (clash: {len(clash_proxies)})\n\n"
                f"| Protocol | Count |\n|---|---|\n")
        for k, v in sorted(proto_count.items()):
            f.write(f"| {k} | {v} |\n")
    print(f"DONE in {time.time()-t_start:.0f}s — published {len(links)}, clash {len(clash_proxies)}, stats written")


if __name__ == "__main__":
    main()
