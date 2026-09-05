#!/usr/bin/env python3
# SS44 v3 — 3-round verification for Iran
# Round1: DNS+TCP | Round2: real TLS handshake with config SNI (+expired-cert filter)
# Round3: Iran SNI scoring (non-Google first) | + Hysteria2/TUIC UDP collection
# Outputs: SS44-gold.txt (TLS-verified) / SS44.txt (all) / SS44-udp.txt / clash / stats

import re, socket, ssl, time, base64, json, ipaddress, urllib.request, urllib.parse
import concurrent.futures
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
MAX_TEST = 500
MAX_TLS_PROBE = 250
TIMEOUT = 4
TLS_TIMEOUT = 6
THREADS = 50
TOP_N = 120

LINK_RE = re.compile(r'^(vless|vmess|trojan|ss|hy2|hysteria2|tuic)://\S+', re.I)
UDP_SCHEMES = {"hy2", "hysteria2", "tuic"}


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
            req = urllib.request.Request(url, headers={"User-Agent": "SS44/3.0"})
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
        low = link.lower()
        scheme = low.split("://", 1)[0]
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
        else:  # vless / trojan / hy2 / hysteria2 / tuic
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


def needs_tls(link):
    low = link.lower()
    scheme = low.split("://", 1)[0]
    if scheme == "vmess":
        d = decode_vmess(link)
        return bool(d) and str(d.get("tls", "")).lower() == "tls"
    p = query_of(link)
    return q(p, "security", "").lower() in ("tls", "reality")


def get_sni(link, host):
    scheme = link.lower().split("://", 1)[0]
    if scheme == "vmess":
        d = decode_vmess(link) or {}
        return str(d.get("sni") or d.get("host") or host)
    p = query_of(link)
    return q(p, "sni") or q(p, "serverName") or q(p, "peer") or q(p, "host") or host


# SNI هایی که تو ایران اختلال دارن (گوگل و...) آخر صف؛ مایکروسافت/اپل/آمازون اول
BAD_SNI = ("google", "gstatic", "youtube", "gmail", "blogger", "googlevideo")
GOOD_SNI = ("microsoft", "apple", "amazon", "cloudflare", "azure", "yahoo")


def sni_adjust(link):
    sni = get_sni(link, "").lower()
    if any(b in sni for b in BAD_SNI):
        return 4
    if any(g in sni for g in GOOD_SNI):
        return -2
    return 0


def score(link):
    ll = link.lower()
    s = sni_adjust(link)
    if "reality" in ll:
        s -= 10
    if ":443" in ll:
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


def dns_ok(link):
    hp = parse_host_port(link)
    if hp is None:
        return False
    try:
        socket.getaddrinfo(hp[0], hp[1], timeout=TIMEOUT)
        return True
    except Exception:
        try:
            socket.getaddrinfo(hp[0], hp[1])
            return True
        except Exception:
            return False


def tls_probe(host, port, sni):
    """هندشیک واقعی TLS با SNI کانفیگ — سرتیفیکیت منقضی = مرده"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT")
        t0 = time.time()
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
                cert = tls.getpeercert()
                ms = (time.time() - t0) * 1000
                info = {"ms": ms, "version": tls.version() or "?", "cipher": (tls.cipher() or ["?"])[0]}
                if cert and "notAfter" in cert:
                    try:
                        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        if exp < datetime.now(timezone.utc):
                            return None  # منقضی
                        info["exp"] = exp.strftime("%Y-%m-%d")
                    except Exception:
                        pass
                return info
    except Exception:
        return None


def rename(link, idx, prefix="SS44"):
    return link.split("#", 1)[0] + f"#{prefix}-{idx:03d}"


# ---------- clash converter ----------
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
    if q(p, "obfs") and q(p, "obfs") != "none":
        proxy["obfs"] = q(p, "obfs")
        if q(p, "obfs-password"):
            proxy["obfs-password"] = q(p, "obfs-password")
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
    print(f"UNIQUE valid: {len(uniq)}")

    tcp_links = [l for l in uniq if l.lower().split("://", 1)[0] not in UDP_SCHEMES]
    udp_links = [l for l in uniq if l.lower().split("://", 1)[0] in UDP_SCHEMES]
    print(f"TCP-family: {len(tcp_links)} | UDP-family (hy2/tuic): {len(udp_links)}")

    tcp_links.sort(key=score)
    candidates = tcp_links[:MAX_TEST]
    print(f"Round1 TCP testing {len(candidates)} ...")
    opened = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for link, good, ms in ex.map(tcp_ping, candidates):
            if good:
                opened.append((ms, link))
    opened.sort(key=lambda x: x[0])
    print(f"Round1 OPEN: {len(opened)} / {len(candidates)}")

    # Round2: TLS handshake واقعی فقط برای کانفیگ‌های tls/reality
    tls_cands = [(ms, l) for ms, l in opened if needs_tls(l)][:MAX_TLS_PROBE]
    print(f"Round2 TLS probing {len(tls_cands)} ...")

    def probe(item):
        ms, link = item
        hp = parse_host_port(link)
        info = tls_probe(hp[0], hp[1], get_sni(link, hp[0])) if hp else None
        return (link, ms, info)

    gold, silver = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        results = list(ex.map(probe, tls_cands))
    tls_ok_hosts = set()
    for link, ms, info in results:
        if info:
            gold.append((ms, link, info))
            hp = parse_host_port(link)
            if hp:
                tls_ok_hosts.add(hp)
    for ms, link in opened:
        if not needs_tls(link):
            silver.append((ms, link))  # بدون tls (مثل ss/shadowsocks) — هندشیک نداره
        elif link not in [g[1] for g in gold]:
            hp = parse_host_port(link)
            if hp and hp in tls_ok_hosts:
                silver.append((ms, link))  # هاست سالمه ولی این کانفیگ خاص نه
    gold.sort(key=lambda x: x[0])
    silver.sort(key=lambda x: x[0])
    print(f"GOLD (TLS-verified): {len(gold)} | SILVER (TCP-open): {len(silver)}")

    # UDP family: فقط DNS
    udp_ok = [l for l in udp_links if dns_ok(l)]
    print(f"UDP DNS-ok: {len(udp_ok)} / {len(udp_links)}")

    # خروجی‌ها
    gold_links = [rename(l, i + 1) for i, (_, l, _) in enumerate(gold)]
    silver_sorted = sorted(silver, key=lambda x: (score(x[1]), x[0]))
    all_links = gold_links + [rename(l, i + 1 + len(gold_links)) for i, (_, l) in
                              enumerate(silver_sorted)]
    all_links = all_links[:150]  # سقف: گوشی کند نشه
    udp_out = [rename(l, i + 1, prefix="SS44-U") for i, l in enumerate(udp_ok[:60])]

    title_b64 = base64.b64encode("🚀 SS44 GOLD | Iran Irancell".encode()).decode()
    header = [f"#profile-title: base64:{title_b64}", "#profile-update-interval: 1",
              f"#support-url: {REPO_URL}", f"#profile-web-page-url: {REPO_URL}"]
    with open("SS44-gold.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header + gold_links) + "\n")
    with open("SS44.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header + all_links) + "\n")
    with open("SS44-base64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(all_links).encode()).decode())
    with open("SS44-udp.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(udp_out) + ("\n" if udp_out else ""))

    clash_proxies, proto_count = [], {}
    for i, l in enumerate(all_links, 1):
        scheme = l.split("://", 1)[0].lower()
        proto_count[scheme] = proto_count.get(scheme, 0) + 1
        cp = to_clash(l, f"SS44-{i:03d}")
        if cp:
            clash_proxies.append(cp)
    for i, l in enumerate(udp_out, 1):
        scheme = l.split("://", 1)[0].lower()
        proto_count[scheme] = proto_count.get(scheme, 0) + 1
        cp = to_clash(l, f"SS44-U{i:03d}")
        if cp:
            clash_proxies.append(cp)
    with open("SS44-clash.yaml", "w", encoding="utf-8") as f:
        f.write(yaml_emit(clash_proxies))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open("STATS.md", "w", encoding="utf-8") as f:
        f.write(f"# 📊 SS44 Stats\n\n- Last update: **{now}**\n- Fetched: **{len(raw)}**\n"
                f"- Unique valid: **{len(uniq)}**\n- Round1 TCP tested: **{len(candidates)}** → open **{len(opened)}**\n"
                f"- Round2 TLS probed: **{len(tls_cands)}** → 🥇 GOLD **{len(gold)}**\n"
                f"- Published: **{len(all_links)}** (+UDP **{len(udp_out)}**, clash **{len(clash_proxies)}**)\n\n"
                f"| Protocol | Count |\n|---|---|\n")
        for k, v in sorted(proto_count.items()):
            f.write(f"| {k} | {v} |\n")
    print(f"DONE in {time.time()-t_start:.0f}s — gold {len(gold)}, total {len(all_links)}, udp {len(udp_out)}, clash {len(clash_proxies)}")


if __name__ == "__main__":
    main()
