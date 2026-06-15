#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 三网优选筛选器（GitHub Actions / 本地通用）

做什么：
- 读取候选 Cloudflare IPv4（默认从 ip.txt / ips.txt / cfip.txt / cmcc.txt / ctcc.txt / cucc.txt 合并）
- 使用 Globalping 公共 API 从中国探针执行 TCP ping（默认 443 端口）
- 分别按综合 / 移动 / 电信 / 联通输出：cfip.txt / cmcc.txt / ctcc.txt / cucc.txt
- 严格优先：loss < 3%、avg < 150ms；不足 5 个时只取各组最优 5 个，不用重复/乱填

说明：
- GitHub Actions 本身不在大陆，不能直接代表三网；这里借 Globalping 的中国探针做外部测量。
- Globalping 中国探针不保证每次都有 CMCC/CTCC/CUCC ISP 探针，因此脚本会按 ISP magic 优先，失败时降级到 China + eyeball/datacenter 探针。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests

SESSION = requests.Session()
# GitHub Actions 正常无代理；本地 Hermes 环境可能带 SOCKS 代理但缺少 PySocks，禁用环境代理避免失败。
SESSION.trust_env = False

API_BASE = "https://api.globalping.io/v1"
ROOT = Path(__file__).resolve().parent
DEFAULT_INPUTS = ["ip.txt", "ips.txt", "cfip.txt", "cmcc.txt", "ctcc.txt", "cucc.txt", "443ip.txt", "80ip.txt"]
OUTPUTS = {
    "cfip": "cfip.txt",
    "cmcc": "cmcc.txt",
    "ctcc": "ctcc.txt",
    "cucc": "cucc.txt",
}
CARRIER_MAGIC = {
    "cmcc": ["China Mobile", "CMCC", "China + Mobile", "China"],
    "ctcc": ["China Telecom", "CTCC", "China + Telecom", "China"],
    "cucc": ["China Unicom", "CUCC", "China + Unicom", "China"],
    "cfip": ["China", "China + eyeball", "China + datacenter"],
}
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CF_NETS = [ipaddress.IPv4Network(x) for x in CF_RANGES]
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
LAT_RE = re.compile(r"(?:time|tcp_conn|rtt)[=< ]+([0-9.]+)\s*ms", re.I)
SUMMARY_RE = re.compile(r"([0-9.]+)%\s*packet loss", re.I)
RTT_RE = re.compile(r"(?:round-trip|rtt).*?=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/(?:[0-9.]+)\s*ms", re.I)


def is_cf_ipv4(ip: str) -> bool:
    try:
        obj = ipaddress.IPv4Address(ip)
        return obj.is_global and any(obj in net for net in CF_NETS)
    except Exception:
        return False


def unique(seq: Iterable[str]) -> List[str]:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


def read_candidates(paths: List[str], limit: int) -> List[str]:
    ips: List[str] = []
    for name in paths:
        p = ROOT / name
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        ips.extend(IP_RE.findall(text))
    clean = [ip for ip in unique(ips) if is_cf_ipv4(ip)]
    # 保持现有文件顺序优先，再随机少量打散避免永远只测旧前排
    head, tail = clean[: max(limit // 2, 1)], clean[max(limit // 2, 1):]
    random.seed(20260615)
    random.shuffle(tail)
    return (head + tail)[:limit]


def gp_create(target: str, magic: str, port: int, packets: int, probes: int, token: Optional[str]) -> Optional[str]:
    payload = {
        "type": "ping",
        "target": target,
        "measurementOptions": {"protocol": "TCP", "port": port, "packets": packets},
        "locations": [{"magic": magic, "limit": probes}],
    }
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Bearer " + token
    try:
        r = SESSION.post(f"{API_BASE}/measurements", json=payload, headers=headers, timeout=20)
        if r.status_code in (400, 404, 422):
            print(f"[WARN] Globalping create failed {target} magic={magic}: {r.status_code} {r.text[:180]}")
            return None
        r.raise_for_status()
        return r.json().get("id")
    except Exception as e:
        print(f"[WARN] Globalping create exception {target} magic={magic}: {e}")
        return None


def gp_wait(mid: str, token: Optional[str], timeout_s: int = 90) -> Optional[dict]:
    headers = {}
    if token:
        headers["authorization"] = "Bearer " + token
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = SESSION.get(f"{API_BASE}/measurements/{mid}", headers=headers, timeout=20)
            r.raise_for_status()
            data = r.json()
            if data.get("status") in ("finished", "failed"):
                return data
        except Exception as e:
            print(f"[WARN] Globalping wait exception {mid}: {e}")
        time.sleep(3)
    return None


def parse_result(data: dict) -> Tuple[float, float, int, List[str]]:
    vals: List[float] = []
    losses: List[float] = []
    probes: List[str] = []
    for item in data.get("results", []) or []:
        probe = item.get("probe", {}) or {}
        probes.append("/".join(str(x or "") for x in [probe.get("country"), probe.get("city"), probe.get("network")]))
        raw = ((item.get("result") or {}).get("rawOutput") or "")
        m = SUMMARY_RE.search(raw)
        if m:
            losses.append(float(m.group(1)))
        m2 = RTT_RE.search(raw)
        if m2:
            vals.append(float(m2.group(2)))
        else:
            # fallback: collect individual ms values, but ignore tcp_conn sequence numbers without ms
            for n in LAT_RE.findall(raw):
                try: vals.append(float(n))
                except Exception: pass
        # Globalping may expose structured timings in future; keep raw parser tolerant.
    avg = statistics.mean(vals) if vals else 9999.0
    loss = statistics.mean(losses) if losses else (100.0 if not vals else 0.0)
    return avg, loss, len(data.get("results", []) or []), probes


def measure_one(ip: str, group: str, args) -> dict:
    token = os.getenv("GLOBALPING_TOKEN") or os.getenv("GP_TOKEN")
    last = None
    for magic in CARRIER_MAGIC[group]:
        mid = gp_create(ip, magic, args.port, args.packets, args.probes, token)
        if not mid:
            continue
        data = gp_wait(mid, token, args.measure_timeout)
        if not data:
            continue
        avg, loss, probe_count, probes = parse_result(data)
        last = {"ip": ip, "group": group, "magic": magic, "avg": avg, "loss": loss, "probe_count": probe_count, "probes": probes, "id": mid}
        # 有有效数据就使用；如果全丢包，尝试下一个 magic
        if avg < 9999 and loss < 100:
            return last
    return last or {"ip": ip, "group": group, "magic": None, "avg": 9999.0, "loss": 100.0, "probe_count": 0, "probes": [], "id": None}


def score(row: dict) -> Tuple[float, float, str]:
    return (float(row.get("loss", 100.0)), float(row.get("avg", 9999.0)), row.get("ip", ""))


def select_ips(rows: List[dict], min_count: int, max_count: int, latency_limit: float, loss_limit: float) -> List[str]:
    ok = [r for r in rows if r["loss"] < loss_limit and r["avg"] < latency_limit]
    chosen = sorted(ok, key=score)[:max_count]
    if len(chosen) < min_count:
        # 兜底：只用本组已测的最好 IP，不跨组乱填
        chosen = sorted(rows, key=score)[:min(max_count, max(min_count, len(rows)))]
    return [r["ip"] for r in chosen[:max_count]]


def write_list(path: str, ips: List[str]) -> None:
    (ROOT / path).write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="*", default=DEFAULT_INPUTS)
    ap.add_argument("--candidate-limit", type=int, default=int(os.getenv("CANDIDATE_LIMIT", "40")))
    ap.add_argument("--per-group-limit", type=int, default=int(os.getenv("PER_GROUP_LIMIT", "18")))
    ap.add_argument("--min-count", type=int, default=int(os.getenv("MIN_COUNT", "5")))
    ap.add_argument("--max-count", type=int, default=int(os.getenv("MAX_COUNT", "15")))
    ap.add_argument("--latency-limit", type=float, default=float(os.getenv("LATENCY_LIMIT_MS", "150")))
    ap.add_argument("--loss-limit", type=float, default=float(os.getenv("LOSS_LIMIT_PCT", "3")))
    ap.add_argument("--port", type=int, default=int(os.getenv("TCP_PORT", "443")))
    ap.add_argument("--packets", type=int, default=int(os.getenv("PACKETS", "3")))
    ap.add_argument("--probes", type=int, default=int(os.getenv("PROBES", "1")))
    ap.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", "3")))
    ap.add_argument("--measure-timeout", type=int, default=int(os.getenv("MEASURE_TIMEOUT", "90")))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    candidates = read_candidates(args.inputs, args.candidate_limit)
    if not candidates:
        print("[ERROR] 没有可用 Cloudflare IPv4 候选")
        return 2
    print(f"[INFO] candidates={len(candidates)} port={args.port} packets={args.packets}")

    all_results: Dict[str, List[dict]] = {k: [] for k in OUTPUTS}
    for group in ["cfip", "cmcc", "ctcc", "cucc"]:
        group_candidates = candidates[:args.per_group_limit]
        print(f"[INFO] measuring {group}: {len(group_candidates)} IPs")
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(measure_one, ip, group, args): ip for ip in group_candidates}
            for fut in as_completed(futs):
                row = fut.result()
                all_results[group].append(row)
                print(f"[RESULT] {group} {row['ip']} avg={row['avg']:.1f}ms loss={row['loss']:.1f}% magic={row.get('magic')}")
                time.sleep(0.2)

    report = {"generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": all_results, "selected": {}}
    for group, rows in all_results.items():
        ips = select_ips(rows, args.min_count, args.max_count, args.latency_limit, args.loss_limit)
        report["selected"][OUTPUTS[group]] = ips
        if not args.dry_run:
            write_list(OUTPUTS[group], ips)
        print(f"[SELECT] {OUTPUTS[group]} {len(ips)} -> {ips}")

    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "carrier-select-latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
