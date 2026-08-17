#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources_sg.txt"
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

XRAY = os.environ.get("XRAY_PATH", "xray")
UA = "FreeForYoung-SG-Ultra"

FETCH_TIMEOUT = 15
TCP_TIMEOUT = 3.0
REAL_TIMEOUT = 10
TCP_ATTEMPTS = 2
REAL_ATTEMPTS = 2

TCP_WORKERS = 60
REAL_WORKERS = 8

MAX_PER_SOURCE = 2000
MAX_TOTAL = 8000
MAX_REAL_TEST = 120
MAX_PUBLISHED = 60
MAX_PER_IP = 2

SOCKS_BASE = 24000
SOCKS_SPAN = 5000

EXCLUDED_WORDS = (
    "cloudflare", "fastly", "akamai", "cloudfront",
    "vercel", "netlify", "gcore", "bunny",
    "stackpath", "imperva", "incapsula", "cdn77",
    "edgecast", "limelight"
)

URI_RE = re.compile(
    r'''(?:vless|vmess|trojan|ss)://[^\s<>'"`]+''',
    re.IGNORECASE,
)

TEST_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)


def log(*a):
    print(*a, flush=True)


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read().decode("utf-8", "ignore")


def maybe_b64(text: str) -> str | None:
    s = re.sub(r"\s+", "", text)
    if len(s) < 24 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    try:
        out = base64.urlsafe_b64decode(
            s + "=" * (-len(s) % 4)
        ).decode("utf-8", "ignore")
        return out if "://" in out else None
    except Exception:
        return None


def extract(text: str) -> list[str]:
    d = maybe_b64(text)
    if d:
        text = d
    out, seen = [], set()
    for m in URI_RE.finditer(text):
        u = m.group(0).rstrip("),;")
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= MAX_PER_SOURCE:
            break
    return out


def ep(uri):
    try:
        p = urlsplit(uri)
        if not p.hostname:
            return None
        return p.hostname, p.port or 443
    except Exception:
        return None


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def geo_batch(ips):
    out = {}
    for start in range(0, len(ips), 100):
        chunk = ips[start:start + 100]
        payload = json.dumps([
            {"query": ip, "fields": "query,status,countryCode,city,isp,org,as"}
            for ip in chunk
        ]).encode()
        req = Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": UA,
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=20) as r:
                rows = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            log("GEO_FAIL", e)
            continue
        for row in rows:
            if row.get("status") == "success" and row.get("query"):
                out[row["query"]] = row
    return out


def excluded(info):
    s = " ".join(
        str(info.get(k, ""))
        for k in ("isp", "org", "as")
    ).lower()
    return any(x in s for x in EXCLUDED_WORDS)


def tcp(uri):
    x = ep(uri)
    if not x:
        return None, None
    host, port = x
    ip = resolve(host)
    if not ip:
        return None, None
    vals = []
    for _ in range(TCP_ATTEMPTS):
        t = time.perf_counter()
        try:
            with socket.create_connection(
                (ip, port),
                timeout=TCP_TIMEOUT,
            ):
                vals.append(
                    round(
                        (time.perf_counter() - t) * 1000,
                        1,
                    )
                )
        except Exception:
            pass
    if not vals:
        return None, ip
    vals.sort()
    return vals[len(vals) // 2], ip


def qdict(uri):
    p = urlsplit(uri)
    out = {}
    for k, vals in parse_qs(
        p.query,
        keep_blank_values=True,
    ).items():
        if vals:
            out[k.lower()] = vals[-1]
    return out


def stream_settings(q):
    network = q.get("type") or q.get("network") or "tcp"
    stream = {"network": network}
    sec = q.get("security", "").lower()

    if sec == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": q.get("sni") or q.get("host") or "",
            "allowInsecure": q.get(
                "allowinsecure",
                q.get("insecure", "0"),
            ).lower() in ("1", "true", "yes"),
        }
        if q.get("fp"):
            stream["tlsSettings"]["fingerprint"] = q["fp"]

    elif sec == "reality":
        if not q.get("sni") or not q.get("pbk"):
            raise ValueError("Reality missing sni/pbk")
        reality = {
            "show": False,
            "fingerprint": q.get("fp", "chrome"),
            "serverName": q["sni"],
            "publicKey": q["pbk"],
        }
        if q.get("sid"):
            reality["shortId"] = q["sid"]
        stream["security"] = "reality"
        stream["realitySettings"] = reality

    if network == "ws":
        ws = {"path": unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": q.get("servicename", "")
        }

    return stream


def vless(uri):
    p = urlsplit(uri)
    q = qdict(uri)
    uid = unquote(p.username or "")
    if not p.hostname or not p.port or not uid:
        raise ValueError("bad VLESS")
    user = {
        "id": uid,
        "encryption": "none",
    }
    if q.get("flow"):
        user["flow"] = q["flow"]
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p.hostname,
                "port": p.port,
                "users": [user],
            }]
        },
        "streamSettings": stream_settings(q),
    }


def trojan(uri):
    p = urlsplit(uri)
    q = qdict(uri)
    pw = unquote(p.username or "")
    if not p.hostname or not p.port or not pw:
        raise ValueError("bad Trojan")
    stream = stream_settings(q)
    if "security" not in stream:
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": q.get("sni") or p.hostname,
            "allowInsecure": q.get(
                "allowinsecure",
                q.get("insecure", "0"),
            ).lower() in ("1", "true", "yes"),
        }
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": p.hostname,
                "port": p.port,
                "password": pw,
            }]
        },
        "streamSettings": stream,
    }


def vmess(uri):
    raw = uri[len("vmess://"):]
    d = maybe_b64(raw)
    if not d:
        raise ValueError("bad VMess")
    o = json.loads(d)
    address = o.get("add") or o.get("address")
    port = int(o.get("port", 443))
    uid = o.get("id")
    if not address or not uid:
        raise ValueError("bad VMess fields")
    q = {
        "type": o.get("net") or o.get("type") or "tcp",
        "host": o.get("host", ""),
        "path": o.get("path", "/"),
        "sni": o.get("sni") or o.get("host", ""),
        "fp": o.get("fp", ""),
    }
    if str(o.get("tls", "")).lower() in ("tls", "1"):
        q["security"] = "tls"
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": uid,
                    "alterId": int(o.get("aid", 0)),
                    "security": o.get("scy", "auto"),
                }],
            }]
        },
        "streamSettings": stream_settings(q),
    }


def shadowsocks(uri):
    p = urlsplit(uri)
    user = unquote(p.username or "")
    if not p.hostname or not p.port or ":" not in user:
        raise ValueError("bad SS")
    method, password = user.split(":", 1)
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": p.hostname,
                "port": p.port,
                "method": method,
                "password": password,
            }]
        },
    }


def outbound(uri):
    low = uri.lower()
    if low.startswith("vless://"):
        return vless(uri)
    if low.startswith("trojan://"):
        return trojan(uri)
    if low.startswith("vmess://"):
        return vmess(uri)
    if low.startswith("ss://"):
        return shadowsocks(uri)
    raise ValueError("unsupported protocol")


def test_port():
    for _ in range(30):
        p = random.randint(
            SOCKS_BASE,
            SOCKS_BASE + SOCKS_SPAN,
        )
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            s.close()
    raise RuntimeError("no free local port")


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=1,
            ):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def real_test(uri):
    try:
        ob = outbound(uri)
    except Exception as e:
        return {"ok": False, "stage": "parse", "error": str(e)}

    port = test_port()

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False,
            },
        }],
        "outbounds": [ob],
    }

    path = None
    proc = None

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as f:
            json.dump(
                config,
                f,
                ensure_ascii=False,
            )
            path = f.name

        proc = subprocess.Popen(
            [XRAY, "run", "-c", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        if not wait_port(
            port,
            REAL_TIMEOUT,
        ):
            err = ""
            try:
                _, err = proc.communicate(timeout=1)
            except Exception:
                pass
            return {
                "ok": False,
                "stage": "startup",
                "error": err[-1200:],
            }

        opener = build_opener(
            ProxyHandler({
                "http": f"socks5://127.0.0.1:{port}",
                "https": f"socks5://127.0.0.1:{port}",
            })
        )

        successful = 0
        latencies = []

        for url in TEST_URLS:
            passed = False
            for _ in range(REAL_ATTEMPTS):
                t = time.perf_counter()
                try:
                    req = Request(
                        url,
                        headers={"User-Agent": UA},
                    )
                    with opener.open(
                        req,
                        timeout=REAL_TIMEOUT,
                    ) as response:
                        code = getattr(response, "status", 200)
                        response.read(32)

                    if 200 <= code < 400:
                        successful += 1
                        latencies.append(
                            round(
                                (time.perf_counter() - t) * 1000,
                                1,
                            )
                        )
                        passed = True
                        break
                except Exception:
                    pass

            if not passed:
                continue

        return {
            "ok": successful >= 2,
            "successful_requests": successful,
            "latency_ms": (
                round(
                    sum(latencies) / len(latencies),
                    1,
                )
                if latencies else None
            ),
        }

    except Exception as e:
        return {
            "ok": False,
            "stage": "exception",
            "error": str(e),
        }

    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def main():
    log("=== FreeForYoung SG ULTRA ===")

    version = subprocess.run(
        [XRAY, "version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if version.returncode != 0:
        raise SystemExit(
            version.stderr or "Xray failed"
        )

    if version.stdout:
        log(version.stdout.splitlines()[0])

    all_nodes = []
    source_stats = {}

    for line in SOURCES.read_text(
        encoding="utf-8"
    ).splitlines():

        url = line.strip()

        if not url or url.startswith("#"):
            continue

        try:
            got = extract(fetch(url))
            source_stats[url] = len(got)
            all_nodes.extend(got)
            log("SOURCE", len(got), url)
        except Exception as e:
            source_stats[url] = f"ERROR: {e}"
            log("SOURCE_FAIL", url, e)

    all_nodes = list(
        dict.fromkeys(all_nodes)
    )[:MAX_TOTAL]

    log("RAW UNIQUE:", len(all_nodes))

    resolved = {}

    for uri in all_nodes:
        x = ep(uri)
        if not x:
            continue
        ip = resolve(x[0])
        if ip:
            resolved[uri] = ip

    log("RESOLVED:", len(resolved))

    geo = geo_batch(
        list(
            dict.fromkeys(
                resolved.values()
            )
        )
    )

    sg = []

    for uri, ip in resolved.items():
        g = geo.get(ip)

        if not g:
            continue

        if str(
            g.get(
                "countryCode",
                "",
            )
        ).upper() != "SG":
            continue

        if excluded(g):
            continue

        sg.append({
            "uri": uri,
            "ip": ip,
            "city": g.get("city"),
            "isp": g.get("isp"),
            "org": g.get("org"),
            "as": g.get("as"),
        })

    log(
        "SG AFTER GEO + CDN FILTER:",
        len(sg),
    )

    tcp_alive = []

    with ThreadPoolExecutor(
        max_workers=TCP_WORKERS
    ) as pool:

        futures = {
            pool.submit(
                tcp,
                item["uri"],
            ): item
            for item in sg
        }

        for future in as_completed(futures):

            item = futures[future]

            try:
                ping, ip = future.result()
            except Exception:
                ping, ip = None, item["ip"]

            if ping is None:
                continue

            copy = dict(item)
            copy["ip"] = ip or item["ip"]
            copy["tcp_ping_ms"] = ping
            tcp_alive.append(copy)

    tcp_alive.sort(
        key=lambda x: (
            x["tcp_ping_ms"],
            x["ip"],
        )
    )

    log(
        "TCP ALIVE:",
        len(tcp_alive),
    )

    real_pool = tcp_alive[
        :MAX_REAL_TEST
    ]

    log(
        "REAL XRAY TEST:",
        len(real_pool),
    )

    real_alive = []

    with ThreadPoolExecutor(
        max_workers=REAL_WORKERS
    ) as pool:

        futures = {
            pool.submit(
                real_test,
                item["uri"],
            ): item
            for item in real_pool
        }

        for future in as_completed(futures):

            item = futures[future]

            try:
                result = future.result()
            except Exception as e:
                log(
                    "REAL TEST ERROR:",
                    e,
                )
                continue

            if not result.get(
                "ok",
                False,
            ):
                continue

            copy = dict(item)
            copy["real_test"] = result
            copy["real_latency_ms"] = result.get(
                "latency_ms",
                999999,
            )
            real_alive.append(copy)

    real_alive.sort(
        key=lambda x: (
            x.get(
                "real_latency_ms",
                999999,
            ),
            x.get(
                "tcp_ping_ms",
                999999,
            ),
            x["ip"],
        )
    )

    log(
        "REAL XRAY ALIVE:",
        len(real_alive),
    )

    published = []
    ip_counts = {}

    for item in real_alive:

        ip = item["ip"]

        if ip_counts.get(
            ip,
            0,
        ) >= MAX_PER_IP:
            continue

        ip_counts[ip] = (
            ip_counts.get(ip, 0) + 1
        )

        published.append(item)

        if len(
            published
        ) >= MAX_PUBLISHED:
            break

    uris = [
        item["uri"]
        for item in published
    ]

    header = (
        "#profile-title: "
        "FreeForYoung SG ULTRA\n"
        "#announce: "
        "SG GeoIP + CDN filtered + "
        "TCP + REAL XRAY HTTP verified\n"
        "#subscription-auto-update-enable: 1\n"
        "#subscription-ping-onopen-enabled: 1\n"
        "#subscriptions-sort-type: ping\n"
        "#ping-type: proxy\n"
        "#check-url-via-proxy: "
        "https://cp.cloudflare.com/generate_204\n"
        "#ping-result: time\n"
    )

    (
        OUT / "singapore.txt"
    ).write_text(
        header
        + "\n".join(uris)
        + ("\n" if uris else ""),
        encoding="utf-8",
    )

    encoded = base64.b64encode(
        "\n".join(uris).encode()
    ).decode()

    (
        OUT / "singapore-base64.txt"
    ).write_text(
        encoded + "\n",
        encoding="utf-8",
    )

    stats = {
        "generated_at_utc": int(
            time.time()
        ),
        "raw_unique": len(all_nodes),
        "resolved": len(resolved),
        "geoip_singapore_after_cdn_filter": len(sg),
        "tcp_alive": len(tcp_alive),
        "real_xray_tested": len(real_pool),
        "real_xray_alive": len(real_alive),
        "published": len(published),
        "source_stats": source_stats,
        "servers": published,
    }

    (
        OUT / "singapore-stats.json"
    ).write_text(
        json.dumps(
            stats,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    log("=== FINAL ===")
    for key in (
        "raw_unique",
        "resolved",
        "geoip_singapore_after_cdn_filter",
        "tcp_alive",
        "real_xray_tested",
        "real_xray_alive",
        "published",
    ):
        log(
            key + ":",
            stats[key],
        )


if __name__ == "__main__":
    main()
