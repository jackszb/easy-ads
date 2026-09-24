#!/usr/bin/env python3
"""
从 EasyList / EasyPrivacy 提取"纯域名拦截规则"，生成：
  rules/easy.json   sing-box 规则集源文件 (version 5, domain_suffix)
  rules/easy.list   Clash/Surge 风格的 DOMAIN-SUFFIX 列表

只依赖 Python 标准库。

用法：
  python scripts/build_easy.py                       # 在线下载并生成到 <repo>/rules
  python scripts/build_easy.py --easylist a.txt --easyprivacy b.txt   # 使用本地文件(调试)

======================================================================
提取原则：不扩大语义
======================================================================
只有当一条 Adblock 规则的含义"恰好等价于 DOMAIN-SUFFIX,<域名>"时才提取：

    ||example.com^            ->  DOMAIN-SUFFIX,example.com     （提取）

`||host^` 表示：任意协议、任意路径，host 本身及其所有子域名 —— 与
DOMAIN-SUFFIX 语义一致。凡是无法保证等价（转换后会拦得更多）的规则一律忽略。

【忽略清单】(脚本统计时按下列类别计数)
  1. 空行、`!` 注释、`[Adblock Plus x.x]` 文件头
  2. 元素隐藏/脚本注入等 cosmetic 规则：`##`、`#@#`、`#?#`、`#$#`、`#%#` ...
  3. 正则规则：`/.../`
  4. 例外(白名单)规则 `@@...` 本身不产出域名；其中"无条件整域名例外"
     `@@||host^` 会用来剔除与之冲突的拦截域名(见下文)
  5. 以 `|` 开头的起始锚点规则：`|http://x.com^`、`|javascript:`、`|blob:` ...
     (锚定协议/整体 URL 开头，不匹配子域名，与 DOMAIN-SUFFIX 不等价)
  6. 不以 `||` 开头的关键字/路径片段规则：`&ev=PageView&`、`-ad.jpg` ...
  7. 以 `||` 开头但不是纯 `||域名^` 形式：
       - 含路径：        ||example.com/ads/
       - 含通配符 `*`：  ||cas.*.criteo.com^ 、 ||example.com^*/ad
       - 含端口 `:`：    ||example.com:8080^
       - 末尾无 `^`：    ||example.com   (会匹配 example.com.evil.net，语义不同)
       - `^|` 结尾、`^` 后接其他内容等
  8. 带限制性选项的域名规则：`||example.com^$third-party`、`$script`、`$image`、
     `$popup`、`$document`、`$domain=...`、`$redirect` ...
     (选项把拦截限定在某类请求/某些站点，转成整域名拦截会扩大范围。
      只有不改变匹配范围的选项 SAFE_OPTIONS 才视为无限制)
  9. IP 规则：`||1.2.3.4^`、IPv6 (`[...]`)；判定依据：最后一个标签为纯数字
 10. 非法主机名：单标签(如 `||com^`)、标签含非 [a-z0-9_-] 字符、标签首尾为 `-`、
     标签超过 63 字符、非 ASCII(IDN 不做转换，直接忽略)
 11. 被 `$badfilter` 禁用的规则

【例外规则的处理】
  - `@@||host^`(无选项) 是无条件整域名白名单，会抵消同域名及其子域名的拦截。
    与其冲突的拦截域名（相同 / 位于白名单域名之下 / 是白名单域名的上级域名）
    会被剔除，避免"白名单被 DOMAIN-SUFFIX 重新拦掉"。
  - 带路径或选项的例外（`@@||host/path`、`@@||host^$domain=...`）是"某站点/某资源
    放行"，域名规则集无法表达，默认忽略。若希望更严格，把 DROP_ANY_EXCEPTED 设为
    True：凡是被任何例外规则涉及的域名都不输出（会损失 doubleclick 等核心域名）。

【合并去重】
  两份列表合并后先按完全相同去重；再合并被上级域名覆盖的子域名：
  若 example.com 已在结果中，则 a.example.com、x.y.example.com 不再输出
  (DOMAIN-SUFFIX 匹配子域名，语义不变)。最后按字符串排序。
"""

import argparse
import json
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

SOURCES = {
    "easylist": "https://easylist.to/easylist/easylist.txt",
    "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
}

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "rules"

# 提取结果少于该值视为上游异常，脚本失败（避免把空/残缺文件推上仓库）
MIN_DOMAINS = 10000

# 不改变匹配范围的选项：important 仅影响优先级；all 表示全部类型(不小于无选项)
SAFE_OPTIONS = {"important", "all"}

# 严格模式：True 时，被任何例外规则(含路径/选项)涉及的域名也一并剔除
DROP_ANY_EXCEPTED = False

# ---------------------------------------------------------------------------
# 规则匹配
# ---------------------------------------------------------------------------
# ||host^ 或 ||host^$options ；host 仅允许 ASCII 字母数字 . _ -
DOMAIN_RULE = re.compile(r"^\|\|(?P<host>[A-Za-z0-9_.\-]+)\^(?:\$(?P<opts>.*))?$")
# 例外规则中取出主机部分(host 后必须紧跟分隔符/结尾，用于严格模式)
EXC_HOST = re.compile(r"^@@\|\|(?P<host>[A-Za-z0-9_.\-]+)(?=[\^/:?$|*]|$)")
# cosmetic 规则分隔符：## #@# #?# #$# #%# #@$# #@?# ...
COSMETIC = re.compile(r"#[@$?%]*#")
LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_host(raw):
    """合法且非 IP 的主机名返回 (小写host, None)，否则返回 (None, 原因)。"""
    host = raw.lower()
    labels = host.split(".")
    if labels[-1].isdigit():
        return None, "IP 地址"
    if len(labels) < 2 or not all(LABEL.match(x) for x in labels):
        return None, "非法主机名/单标签"
    return host, None


def match_domain_rule(text):
    """
    text 为去掉 `@@` 前缀后的规则。
    返回 (host, None) 表示可等价转换；否则 (None, 忽略原因)。
    """
    m = DOMAIN_RULE.match(text)
    if not m:
        return None, "||开头但非纯 ||域名^ 形式(路径/通配符/端口等)"
    opts = m.group("opts")
    if opts is not None:
        tokens = [t.strip().lower() for t in opts.split(",")]
        if not all(t in SAFE_OPTIONS for t in tokens):
            return None, "带限制性选项($...)"
    return normalize_host(m.group("host"))


def find_badfilter_targets(lines):
    """收集被 $badfilter 禁用的规则原文。"""
    targets = set()
    for line in lines:
        if "$" not in line or "badfilter" not in line:
            continue
        rule, _, opts = line.rpartition("$")
        tokens = [t.strip() for t in opts.split(",")]
        if "badfilter" not in tokens:
            continue
        rest = [t for t in tokens if t != "badfilter"]
        targets.add(rule + ("$" + ",".join(rest) if rest else ""))
    return targets


def ancestors(host):
    """host 自身及其所有上级域名，如 a.b.com -> a.b.com, b.com, com。"""
    labels = host.split(".")
    return {".".join(labels[i:]) for i in range(len(labels))}


# ---------------------------------------------------------------------------
# 提取
# ---------------------------------------------------------------------------
def extract(sources):
    """sources: {名称: [行...]}。返回 (已排序域名列表, 统计 Counter, 被例外剔除的域名列表)。"""
    stats = Counter()
    blocked = set()
    exc_full = set()  # 无条件整域名例外
    exc_any = set()   # 任何形式例外涉及的主机(严格模式用)

    all_lines = [ln.strip() for lines in sources.values() for ln in lines]
    disabled = find_badfilter_targets(all_lines)

    for line in all_lines:
        if not line:
            stats["空行"] += 1
        elif line.startswith("!"):
            stats["注释"] += 1
        elif line.startswith("[") and line.endswith("]"):
            stats["文件头"] += 1
        elif line in disabled:
            stats["被 $badfilter 禁用"] += 1
        elif line.startswith("@@"):
            m = EXC_HOST.match(line)
            if m:
                exc_any.add(m.group("host").lower())
            host, _ = match_domain_rule(line[2:])
            if host:
                exc_full.add(host)
                stats["例外规则-无条件整域名(用于剔除冲突)"] += 1
            else:
                stats["例外规则-带路径/选项(忽略)"] += 1
        elif COSMETIC.search(line):
            stats["cosmetic 规则"] += 1
        elif line.startswith("/") and line.endswith("/") and len(line) > 1:
            stats["正则规则"] += 1
        elif line.startswith("||"):
            host, reason = match_domain_rule(line)
            if host:
                blocked.add(host)
                stats["提取(||域名^)"] += 1
            else:
                stats[reason] += 1
        elif line.startswith("|"):
            stats["|起始锚点规则"] += 1
        else:
            stats["关键字/路径片段规则"] += 1

    # 剔除与"无条件整域名例外"冲突的拦截域名
    exc_set = exc_any if DROP_ANY_EXCEPTED else exc_full
    exc_parents = set()  # 例外域名的所有"真上级域名"
    for e in exc_set:
        exc_parents |= ancestors(e) - {e}

    dropped = []
    kept = set()
    for host in blocked:
        # 相同或位于例外域名之下 / 是某例外域名的上级域名
        if (ancestors(host) & exc_set) or host in exc_parents:
            dropped.append(host)
        else:
            kept.add(host)

    # 合并：已被上级域名覆盖的子域名不再输出（DOMAIN-SUFFIX 语义完全不变）
    # 放在例外剔除之后：若上级域名因例外冲突被剔除，其子域名不受影响，仍会保留
    result = set()
    for host in kept:
        if (ancestors(host) - {host}) & kept:
            stats["合并-已被上级域名覆盖的子域名"] += 1
        else:
            result.add(host)

    return sorted(result), stats, sorted(dropped)


# ---------------------------------------------------------------------------
# 输入输出
# ---------------------------------------------------------------------------
def download(url, retries=3):
    req = urllib.request.Request(url, headers={"User-Agent": "easy-rules-builder/1.0"})
    last = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            if not text.lstrip().startswith("[Adblock"):
                raise ValueError("内容不像 Adblock 规则文件(缺少 [Adblock ...] 头)")
            return text.splitlines()
        except Exception as exc:  # noqa: BLE001
            last = exc
            print(f"下载失败({i + 1}/{retries}) {url}: {exc}", file=sys.stderr)
            time.sleep(3 * (i + 1))
    raise RuntimeError(f"无法下载 {url}: {last}")


def read_local(path):
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def write_outputs(domains, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {"version": 5, "rules": [{"domain_suffix": domains}]}
    (out_dir / "easy.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    (out_dir / "easy.list").write_text(
        "".join(f"DOMAIN-SUFFIX,{d}\n" for d in domains), encoding="utf-8", newline="\n"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--easylist", help="本地 easylist.txt（缺省则在线下载）")
    ap.add_argument("--easyprivacy", help="本地 easyprivacy.txt（缺省则在线下载）")
    ap.add_argument("--out", default=str(OUT_DIR), help="输出目录，默认 <repo>/rules")
    args = ap.parse_args()

    sources = {}
    for name, url in SOURCES.items():
        local = getattr(args, name)
        sources[name] = read_local(local) if local else download(url)
        print(f"{name}: {len(sources[name])} 行")

    domains, stats, dropped = extract(sources)

    print("\n--- 规则分类统计 ---")
    for reason, n in stats.most_common():
        print(f"{n:>8}  {reason}")
    if dropped:
        print(f"\n因无条件例外规则冲突而剔除 {len(dropped)} 个域名: {', '.join(dropped[:20])}"
              + (" ..." if len(dropped) > 20 else ""))
    print(f"\n最终输出域名数(去重后): {len(domains)}")

    if len(domains) < MIN_DOMAINS:
        sys.exit(f"提取数量({len(domains)}) 低于下限 {MIN_DOMAINS}，疑似上游异常，已中止，未写入文件")

    write_outputs(domains, Path(args.out))
    print(f"已写入 {args.out}/easy.json 与 easy.list")


if __name__ == "__main__":
    main()
