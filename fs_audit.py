#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NFS 导出安全审计脚本（单文件、仅标准库）

兼容：Python 2.7 以及 Python 3.x（含 CentOS 7 的 2.7 / 3.6）。

做什么：
    对一台或多台主机执行  showmount -e <IP>
    检查两项高危配置：
        1) 是否把目录导出给全世界（客户端是 *）
        2) 是否关闭了 root 身份压缩（no_root_squash）

重要说明（零基础也请看一眼）：
    showmount -e  一般只能看到「导出路径」和「允许哪些客户端」。
    no_root_squash 写在服务端的 /etc/exports 里，多数发行版不会通过
    showmount 回传这条选项。脚本会：
        - 如果命令输出里出现了 no_root_squash，判定为高危；
        - 如果没有出现，风险标为「未知」，并告诉你去服务端核对。

用法（python / python2 / python3 都可以）：
    python fs_audit.py --target 192.168.1.10
    python fs_audit.py --target 192.168.1.10 --timeout 15
    python fs_audit.py --target-file hosts.txt --output report.md
    python fs_audit.py --target-file hosts.txt --html report.html
    python fs_audit.py --target-file hosts.txt --output report.md --html report.html
"""

# print() 在 Python 2 里默认不是函数，这行必须放在靠前位置
from __future__ import print_function

import argparse
import errno
import io
import os
import re
import socket
import subprocess
import sys
import threading
from datetime import datetime


# 出现在 Markdown / HTML 报告页眉
TOOL_NAME = u"fs-gateway-audit"
TOOL_VERSION = u"0.2"

# showmount 默认等待秒数，避免远程主机无响应时一直卡住
DEFAULT_TIMEOUT_SECONDS = 10

# 详细结果表只要三列，修复建议单独成段，不再塞进表格
DETAIL_HEADERS = [u"检查项", u"当前配置", u"风险等级"]

# Python 2 的文字类型叫 unicode，Python 3 叫 str。后面统一用 TEXT_TYPE 判断。
if sys.version_info[0] >= 3:
    TEXT_TYPE = str
    BINARY_TYPE = bytes
else:
    TEXT_TYPE = unicode  # noqa: F821  （只有 Python 2 才有这个名字）
    BINARY_TYPE = str


class AuditError(Exception):
    """
    单个 IP 审计失败时抛出的业务异常。

    不要用 SystemExit：批量扫描时捕获这个异常就能记下原因，继续扫下一台。
    本机根本没有 showmount 这种「所有 IP 都做不了」的情况，仍用 SystemExit 直接退出。
    """

    pass


def tool_label():
    """页眉里的「审计工具」整段文字，例如 fs-gateway-audit v0.2。"""
    return u"%s v%s" % (TOOL_NAME, TOOL_VERSION)


def make_finding(title, item, current, level, problem, fix):
    """一条检查结果。标题给修复建议小节用，比「检查项」更短。"""
    return {
        u"标题": title,
        u"检查项": item,
        u"当前配置": current,
        u"风险等级": level,
        u"问题": problem,
        u"修复": fix,
        u"修复建议": u"问题：%s 修复：%s" % (problem, fix),
    }


def to_text(value):
    """
    把任意内容转成「文字」，避免 Python 2 里中文和英文混在一起时报错。

    Python 2 有两种字符串：普通 str（字节）和 unicode（文字）。
    写报告、拼表格时统一用文字。
    """
    if value is None:
        return u""
    if isinstance(value, TEXT_TYPE):
        return value
    if isinstance(value, BINARY_TYPE):
        return value.decode("utf-8", "replace")
    return TEXT_TYPE(value)


def parse_args():
    """
    解析命令行参数。

    --target 和 --target-file 二选一，必须提供其中一个（互斥）。
    --timeout、--output 可以和上面任意一种目标方式一起用。
    """
    parser = argparse.ArgumentParser(
        description="审计远程 NFS 导出：是否对 * 开放、是否出现 no_root_squash。",
        epilog=(
            "示例：\n"
            "  python fs_audit.py --target 192.168.1.10\n"
            "  python fs_audit.py --target-file hosts.txt --output report.md\n"
            "  python fs_audit.py --target-file hosts.txt --html report.html"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # mutually_exclusive_group(required=True)：两个参数不能同时出现，也不能一个都不给
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        metavar="IP",
        help="要检查的一台 NFS 服务器 IP 地址（IPv4 或 IPv6）",
    )
    target_group.add_argument(
        "--target-file",
        dest="target_file",
        metavar="FILE",
        help="从文本文件逐行读取 IP；空行和 # 开头的注释会被忽略",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SEC",
        help="每台主机 showmount 超时时间，默认 %s 秒" % DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="把 Markdown 报告写入该文件；不指定则打印到屏幕（若同时给了 --html 且未给 --output，则只写 HTML）",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="生成单文件 HTML 报告（CSS 全部内嵌，可用浏览器直接打开）",
    )
    return parser.parse_args()


def is_ipv4(text):
    """手工判断 IPv4。不用 ipaddress 模块，因为 Python 2 标准库没有它。"""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if part == "" or not part.isdigit():
            return False
        # 禁止 01 这种前导零，也禁止超长数字
        if len(part) > 1 and part[0] == "0":
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
    return True


def is_ipv6(text):
    """
    判断 IPv6。优先用系统自带的 socket.inet_pton（Linux 的 Python 2.7 一般都有）。
    没有 inet_pton 时（少数旧环境），用比较宽松的冒号格式检查。
    """
    if hasattr(socket, "inet_pton"):
        try:
            socket.inet_pton(socket.AF_INET6, text)
            return True
        except (socket.error, OSError, ValueError):
            return False

    if ":" not in text:
        return False
    # 极简兜底：只允许十六进制和冒号、以及 IPv4 内嵌写法里的点
    compact = text.strip()
    if compact.count("::") > 1:
        return False
    allowed = set("0123456789abcdefABCDEF:.")
    return all(ch in allowed for ch in compact)


def validate_ip(raw):
    """
    校验 IP 是否合法。
    不合法时抛出 AuditError，由上层决定是立刻退出还是记入报告后继续。
    """
    text = to_text(raw).strip()
    if is_ipv4(text) or is_ipv6(text):
        return text
    raise AuditError(u"不是合法的 IP 地址：%s" % text)


def load_ips_from_file(path):
    """
    从文本文件读取待扫描地址（尚未做 IP 合法性校验）。

    规则（按行处理，零基础可对照文件看）：
        - 去掉行首行尾空白
        - 空行跳过
        - 以 # 开头的行当作注释跳过
        - 行中间的 # 注释也支持，例如：  10.0.0.1  # 机房A
        - 保留文件中的原始顺序

    用 io.open 而不是内置 open：Python 2 的 open 不认识 encoding= 这个参数。
    """
    if not os.path.isfile(path):
        raise SystemExit(u"错误：找不到目标文件：%s" % to_text(path))

    try:
        handle = io.open(path, "r", encoding="utf-8", errors="replace")
    except (OSError, IOError) as exc:
        raise SystemExit(u"错误：无法读取目标文件 %s：%s" % (to_text(path), exc))

    raw_items = []
    try:
        for line in handle:
            stripped = to_text(line).strip()
            if not stripped:
                continue
            if stripped.startswith(u"#"):
                continue
            if u"#" in stripped:
                stripped = stripped.split(u"#", 1)[0].strip()
            if stripped:
                raw_items.append(stripped)
    finally:
        handle.close()

    if not raw_items:
        raise SystemExit(
            u"错误：文件 %s 里没有有效地址（全是空行或注释）。" % to_text(path)
        )
    return raw_items


def find_command(name):
    """
    在 PATH 里查找可执行文件。

    不用 shutil.which：那是 Python 3.3 才加入的。
    Windows 还会尝试 .exe 等后缀（PATHEXT）；Linux 直接找同名文件。
    """
    path_env = os.environ.get("PATH") or ""
    if os.name == "nt":
        extensions = os.environ.get("PATHEXT") or ".EXE;.BAT;.CMD"
        extra = [""] + extensions.split(os.pathsep)
    else:
        extra = [""]

    candidates = []
    # 如果用户写了带目录的路径，只检查这一个
    if os.path.dirname(name):
        candidates.append(name)
    else:
        for folder in path_env.split(os.pathsep):
            if not folder:
                continue
            for suffix in extra:
                candidates.append(os.path.join(folder, name + suffix))

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def ensure_showmount_exists():
    """本机没有 showmount 时，扫多少个 IP 都没用，直接退出并提示怎么安装。"""
    if find_command("showmount") is None:
        raise SystemExit(
            u"错误：本机找不到 showmount 命令。\n"
            u"  Debian/Ubuntu 可安装：sudo apt install nfs-common\n"
            u"  RHEL/CentOS 可安装：  sudo yum install nfs-utils\n"
            u"  Windows 一般没有此命令，请在 Linux 上运行本脚本。"
        )


def _native_cmd_arg(value):
    """Popen 在 Python 2 里要字节参数，在 Python 3 里要 str 参数。"""
    text = to_text(value)
    if sys.version_info[0] < 3:
        return text.encode("utf-8")
    return text


def _kill_process(proc):
    """超时后杀掉子进程。kill 失败就忽略，避免再抛一层异常。"""
    try:
        proc.kill()
    except (OSError, IOError):
        pass


def run_command(command, timeout):
    """
    运行外部命令，返回 (退出码, 标准输出文字, 标准错误文字)。

    不用 subprocess.run：Python 2 没有它，而且 Python 3.2 的 communicate 也没有 timeout。
    超时做法：
        - Python 3.3+ 用官方的 communicate(timeout=...)
        - 更老的版本用线程等结果，时间到了就 kill
    """
    native = [_native_cmd_arg(part) for part in command]
    try:
        proc = subprocess.Popen(
            native,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, IOError) as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            raise AuditError(u"无法启动 showmount（命令不存在）。")
        raise AuditError(u"无法执行 showmount：%s" % exc)

    # Python 3.3 起 communicate 才支持 timeout 参数
    if sys.version_info >= (3, 3):
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process(proc)
            try:
                proc.communicate()
            except Exception:
                pass
            raise AuditError(
                u"执行 %s 超过 %s 秒仍无结果。"
                u"请确认 IP 可达、NFS 端口（2049/rpcbind）未被防火墙拦截。"
                % (u" ".join([to_text(x) for x in command]), timeout)
            )
        return proc.returncode, to_text(out), to_text(err)

    # Python 2 / 3.2：自己用线程实现超时
    box = {"out": b"", "err": b""}

    def worker():
        out_err = proc.communicate()
        box["out"] = out_err[0]
        box["err"] = out_err[1]

    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        _kill_process(proc)
        thread.join()
        raise AuditError(
            u"执行 %s 超过 %s 秒仍无结果。"
            u"请确认 IP 可达、NFS 端口（2049/rpcbind）未被防火墙拦截。"
            % (u" ".join([to_text(x) for x in command]), timeout)
        )
    return proc.returncode, to_text(box["out"]), to_text(box["err"])


def run_showmount(ip, timeout):
    """
    调用系统命令：showmount -e <IP>

    成功返回标准输出文字。
    超时、命令失败、系统错误一律变成 AuditError，方便批量时「记一笔、下一台」。
    """
    command = ["showmount", "-e", ip]
    returncode, stdout, stderr = run_command(command, timeout)
    if returncode != 0:
        detail = (stderr or stdout or u"").strip()
        if detail:
            raise AuditError(
                u"showmount -e %s 失败（退出码 %s）：%s"
                % (ip, returncode, detail)
            )
        raise AuditError(
            u"showmount -e %s 失败（退出码 %s）。" % (ip, returncode)
        )
    return stdout


def parse_export_lines(showmount_output):
    """
    把 showmount 的文本拆成 [(导出路径, 客户端列表), ...]

    典型输出：
        Export list for 192.168.1.10:
        /home       *
        /data       10.0.0.0/24,192.168.1.5

    第一行是标题，从第二行开始才是真正的导出项。
    """
    exports = []
    for raw_line in to_text(showmount_output).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith(u"export list"):
            continue

        parts = line.split(None, 1)
        path = parts[0]
        clients = parts[1].strip() if len(parts) > 1 else u""
        exports.append((path, clients))
    return exports


def clients_include_wildcard(clients):
    """
    客户端字段里是否出现 *（对所有人开放）。

    常见写法：
        *
        *(rw,sync,no_root_squash)
        *,10.0.0.1
    选项括号里也有逗号，所以不能简单按逗号切开再精确匹配 "*"。
    """
    text = to_text(clients).strip()
    return re.search(r"(?:^|[\s,])\*(?=$|[\s,(])", text) is not None


def line_has_no_root_squash(text):
    """整行文本里是否出现 no_root_squash（大小写不敏感）。"""
    return u"no_root_squash" in to_text(text).lower()


def audit(exports, raw_output):
    """
    生成表格行。每一行是一个字典，键就是表头。

    检查项 1：通配符导出 *
    检查项 2：no_root_squash
    """
    rows = []

    wildcard_hits = [
        path for path, clients in exports if clients_include_wildcard(clients)
    ]
    if not exports:
        rows.append(
            {
                u"检查项": u"NFS 导出给 *（所有客户端）",
                u"当前配置": u"未解析到任何导出项",
                u"风险等级": u"信息",
                u"修复建议": u"确认目标确实开启了 NFS；或 showmount 输出格式与预期不符。",
            }
        )
    elif wildcard_hits:
        listed = u", ".join(wildcard_hits)
        rows.append(
            {
                u"检查项": u"NFS 导出给 *（所有客户端）",
                u"当前配置": u"高危：以下路径对 * 开放：%s" % listed,
                u"风险等级": u"高危",
                u"修复建议": (
                    u"在服务端 /etc/exports 中把 * 改成明确的网段或主机，"
                    u"例如 /data 10.0.0.0/24(rw,root_squash)，然后执行 exportfs -ra。"
                ),
            }
        )
    else:
        summary = u"; ".join(
            u"%s -> %s" % (path, clients) for path, clients in exports
        )
        rows.append(
            {
                u"检查项": u"NFS 导出给 *（所有客户端）",
                u"当前配置": u"未发现 *。当前导出：%s" % summary,
                u"风险等级": u"低",
                u"修复建议": u"保持仅向可信网段/主机导出；新增导出时不要使用 *。",
            }
        )

    option_hits = [
        path
        for path, clients in exports
        if line_has_no_root_squash(path) or line_has_no_root_squash(clients)
    ]
    also_in_raw = line_has_no_root_squash(raw_output)

    if option_hits or also_in_raw:
        where = u", ".join(option_hits) if option_hits else u"showmount 原始输出"
        rows.append(
            {
                u"检查项": u"开启 no_root_squash（远程 root 保持 root）",
                u"当前配置": u"高危：检测到 no_root_squash（%s）" % where,
                u"风险等级": u"高危",
                u"修复建议": (
                    u"在 /etc/exports 去掉 no_root_squash，改用默认的 root_squash，"
                    u"使客户端 root 被映射为 nfsnobody；改完后执行 exportfs -ra。"
                ),
            }
        )
    else:
        rows.append(
            {
                u"检查项": u"开启 no_root_squash（远程 root 保持 root）",
                u"当前配置": u"showmount -e 未返回该选项（多数系统都不会回传）",
                u"风险等级": u"未知",
                u"修复建议": (
                    u"请到 NFS 服务器查看 /etc/exports 或执行 exportfs -v。"
                    u"若出现 no_root_squash，请改为 root_squash 后 exportfs -ra。"
                ),
            }
        )

    return rows


def failure_rows(reason):
    """某个 IP 失败时，仍输出同一套四列表格，避免报告格式忽好忽坏。"""
    return [
        {
            u"检查项": u"扫描执行",
            u"当前配置": u"失败：%s" % to_text(reason),
            u"风险等级": u"错误",
            u"修复建议": (
                u"检查该 IP 是否可达、是否提供 NFS、防火墙是否放行 rpcbind/2049；"
                u"确认本机 showmount 可用后重试这一台。"
            ),
        }
    ]

def to_markdown(rows):
    lines = [
        u"| " + u" | ".join(DETAIL_HEADERS) + u" |",
        u"| " + u" | ".join([u"---" for _ in DETAIL_HEADERS]) + u" |",
    ]
    for row in rows:
        cells = [to_text(row[h]).replace(u"|", u"/") for h in DETAIL_HEADERS]
        lines.append(u"| " + u" | ".join(cells) + u" |")
    return u"\n".join(lines)


def render_ip_section(label, rows):
    """每个 IP 一个小节：二级标题 + 表格。label 用用户看到的地址文本。"""
    return u"## 审计结果：%s\n\n%s\n" % (to_text(label), to_markdown(rows))


def audit_one_target(raw_item, timeout):
    """
    审计一个地址，返回结构化结果（给 Markdown / HTML 两套渲染用）。

    永远不往外抛异常：失败写成 rows 里的「扫描执行」一行，调用方继续下一台。
    """
    try:
        ip = validate_ip(raw_item)
        output = run_showmount(ip, timeout)
        rows = audit(parse_export_lines(output), output)
        return {u"label": ip, u"ok": True, u"rows": rows}
    except AuditError as exc:
        return {
            u"label": to_text(raw_item).strip(),
            u"ok": False,
            u"rows": failure_rows(to_text(exc)),
        }


def render_markdown_report(results):
    """把结构化结果拼成原来的 Markdown 报告。"""
    sections = [
        render_ip_section(item[u"label"], item[u"rows"]) for item in results
    ]
    return u"# NFS 导出审计报告\n\n" + u"\n".join(sections)


def html_escape(value):
    """防止 showmount 输出里的 < > 把 HTML 页面弄坏。不用第三方库。"""
    text = to_text(value)
    return (
        text.replace(u"&", u"&amp;")
        .replace(u"<", u"&lt;")
        .replace(u">", u"&gt;")
        .replace(u'"', u"&quot;")
        .replace(u"'", u"&#39;")
    )


def risk_bucket(level):
    """
    把检查项的风险等级归到四个摘要桶：高危 / 中危 / 低危 / 未知。
    「错误」「信息」没有单独色块，归入未知（灰色）。
    """
    text = to_text(level).strip()
    if text == u"高危":
        return u"高危"
    if text == u"中危":
        return u"中危"
    if text in (u"低", u"低危"):
        return u"低危"
    return u"未知"


def count_risks(results):
    """统计所有检查项落入四个桶的数量，给顶部卡片用。"""
    counts = {u"高危": 0, u"中危": 0, u"低危": 0, u"未知": 0}
    for item in results:
        for row in item[u"rows"]:
            bucket = risk_bucket(row[u"风险等级"])
            counts[bucket] = counts.get(bucket, 0) + 1
    return counts


def html_embedded_css():
    """全部样式写在这里，报告不引用任何网上下载的 CSS/字体/图片。"""
    return u"""
:root { --bg:#f4f6f8; --card:#fff; --text:#1f2933; --muted:#52606d; --line:#d9e2ec; }
* { box-sizing: border-box; }
body { margin:0; font-family: "Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:var(--bg); color:var(--text); line-height:1.55; }
.wrap { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
header.hero { background:var(--card); border:1px solid var(--line); border-radius:12px;
              padding:20px 24px; margin-bottom:20px; }
header.hero h1 { margin:0 0 12px; font-size:22px; }
.meta { display:flex; flex-wrap:wrap; gap:8px 24px; color:var(--muted); font-size:14px; }
.meta b { color:var(--text); font-weight:600; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }
.card { flex:1 1 140px; min-width:140px; border-radius:12px; padding:14px 16px; color:#fff; }
.card .n { font-size:28px; font-weight:700; line-height:1.1; }
.card .t { opacity:.9; font-size:13px; margin-top:4px; }
.card-high { background:#c53030; }
.card-medium { background:#dd6b20; }
.card-low { background:#2f855a; }
.card-unknown { background:#718096; }
.filters { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 16px; }
.filters button { border:1px solid var(--line); background:#fff; color:var(--text);
                  border-radius:999px; padding:6px 14px; cursor:pointer; font-size:13px; }
.filters button.active { background:#2b6cb0; color:#fff; border-color:#2b6cb0; }
.host-block { background:var(--card); border:1px solid var(--line); border-radius:12px;
              padding:16px 20px; margin-bottom:16px; }
.host-block h2 { margin:0 0 12px; font-size:18px; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }
th { background:#edf2f7; font-weight:600; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff; font-size:12px; }
.badge-high { background:#c53030; }
.badge-medium { background:#dd6b20; }
.badge-low { background:#2f855a; }
.badge-unknown { background:#718096; }
.advice { margin-top:14px; padding-top:10px; border-top:1px dashed var(--line); }
.advice h3 { margin:0 0 8px; font-size:15px; }
.advice-item { margin:0 0 10px; padding:10px 12px; background:#f7fafc; border-radius:8px; }
.advice-item .who { font-size:12px; color:var(--muted); margin-bottom:4px; }
footer { color:var(--muted); font-size:12px; margin-top:8px; }
"""


def html_embedded_js():
    """原生 JS：按风险桶筛选表格行和建议段；没有可见行的主机整块隐藏。"""
    return u"""
function setFilter(level) {
  var buttons = document.querySelectorAll(".filters button");
  for (var i = 0; i < buttons.length; i++) {
    var btn = buttons[i];
    if (btn.getAttribute("data-filter") === level) {
      btn.className = "active";
    } else {
      btn.className = "";
    }
  }
  var rows = document.querySelectorAll("tbody tr");
  for (var r = 0; r < rows.length; r++) {
    var risk = rows[r].getAttribute("data-risk");
    rows[r].style.display = (level === "all" || risk === level) ? "" : "none";
  }
  var tips = document.querySelectorAll(".advice-item");
  for (var t = 0; t < tips.length; t++) {
    var tr = tips[t].getAttribute("data-risk");
    tips[t].style.display = (level === "all" || tr === level) ? "" : "none";
  }
  var hosts = document.querySelectorAll(".host-block");
  for (var h = 0; h < hosts.length; h++) {
    var visible = false;
    var hostRows = hosts[h].querySelectorAll("tbody tr");
    for (var n = 0; n < hostRows.length; n++) {
      if (hostRows[n].style.display !== "none") { visible = true; break; }
    }
    hosts[h].style.display = visible ? "" : "none";
  }
}
"""


def badge_class(bucket):
    mapping = {
        u"高危": u"badge-high",
        u"中危": u"badge-medium",
        u"低危": u"badge-low",
        u"未知": u"badge-unknown",
    }
    return mapping.get(bucket, u"badge-unknown")


def render_html_report(results, scan_time, target_desc):
    """拼一份可双击打开的 HTML：页眉、四色摘要、筛选、每台主机的表+建议。"""
    counts = count_risks(results)
    parts = []
    parts.append(u"<!DOCTYPE html>")
    parts.append(u'<html lang="zh-CN">')
    parts.append(u"<head>")
    parts.append(u'<meta charset="utf-8">')
    parts.append(u'<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(u"<title>NFS 导出审计报告</title>")
    parts.append(u"<style>%s</style>" % html_embedded_css())
    parts.append(u"</head>")
    parts.append(u"<body>")
    parts.append(u'<div class="wrap">')
    parts.append(u'<header class="hero">')
    parts.append(u"  <h1>NFS 导出审计报告</h1>")
    parts.append(u'  <div class="meta">')
    parts.append(
        u"    <div>扫描时间：<b>%s</b></div>" % html_escape(scan_time)
    )
    parts.append(
        u"    <div>目标：<b>%s</b></div>" % html_escape(target_desc)
    )
    parts.append(
        u"    <div>工具版本：<b>fs_audit %s</b></div>" % html_escape(TOOL_VERSION)
    )
    parts.append(u"  </div>")
    parts.append(u"</header>")

    parts.append(u'<section class="cards" aria-label="结论摘要">')
    parts.append(
        u'  <div class="card card-high"><div class="n">%s</div><div class="t">高危</div></div>'
        % counts[u"高危"]
    )
    parts.append(
        u'  <div class="card card-medium"><div class="n">%s</div><div class="t">中危</div></div>'
        % counts[u"中危"]
    )
    parts.append(
        u'  <div class="card card-low"><div class="n">%s</div><div class="t">低危</div></div>'
        % counts[u"低危"]
    )
    parts.append(
        u'  <div class="card card-unknown"><div class="n">%s</div><div class="t">未知</div></div>'
        % counts[u"未知"]
    )
    parts.append(u"</section>")

    parts.append(u'<div class="filters" aria-label="风险等级筛选">')
    parts.append(
        u'  <button type="button" class="active" data-filter="all" onclick="setFilter(\'all\')">全部</button>'
    )
    parts.append(
        u'  <button type="button" data-filter="高危" onclick="setFilter(\'高危\')">高危</button>'
    )
    parts.append(
        u'  <button type="button" data-filter="中危" onclick="setFilter(\'中危\')">中危</button>'
    )
    parts.append(
        u'  <button type="button" data-filter="低危" onclick="setFilter(\'低危\')">低危</button>'
    )
    parts.append(
        u'  <button type="button" data-filter="未知" onclick="setFilter(\'未知\')">未知</button>'
    )
    parts.append(u"</div>")

    if not results:
        parts.append(u"<p>没有可展示的审计结果。</p>")

    for item in results:
        label = html_escape(item[u"label"])
        parts.append(u'<section class="host-block">')
        parts.append(u"  <h2>审计结果：%s</h2>" % label)
        parts.append(u"  <table>")
        parts.append(u"    <thead><tr><th>检查项</th><th>当前配置</th><th>风险等级</th></tr></thead>")
        parts.append(u"    <tbody>")
        for row in item[u"rows"]:
            bucket = risk_bucket(row[u"风险等级"])
            parts.append(u'      <tr data-risk="%s">' % html_escape(bucket))
            parts.append(
                u"        <td>%s</td>" % html_escape(row[u"检查项"])
            )
            parts.append(
                u"        <td>%s</td>" % html_escape(row[u"当前配置"])
            )
            parts.append(
                u'        <td><span class="badge %s">%s</span></td>'
                % (badge_class(bucket), html_escape(row[u"风险等级"]))
            )
            parts.append(u"      </tr>")
        parts.append(u"    </tbody>")
        parts.append(u"  </table>")
        parts.append(u'  <div class="advice">')
        parts.append(u"    <h3>修复建议</h3>")
        for row in item[u"rows"]:
            bucket = risk_bucket(row[u"风险等级"])
            parts.append(
                u'    <div class="advice-item" data-risk="%s">' % html_escape(bucket)
            )
            parts.append(
                u'      <div class="who">%s · %s</div>'
                % (html_escape(row[u"检查项"]), html_escape(row[u"风险等级"]))
            )
            parts.append(u"      <p>%s</p>" % html_escape(row[u"修复建议"]))
            parts.append(u"    </div>")
        parts.append(u"  </div>")
        parts.append(u"</section>")

    parts.append(
        u"<footer>本报告由 fs_audit 生成，样式与脚本均内嵌于本文件，无需联网。</footer>"
    )
    parts.append(u"</div>")
    parts.append(u"<script>%s</script>" % html_embedded_js())
    parts.append(u"</body></html>")
    return u"\n".join(parts)


def write_text_file(content, output_path, empty_means_stdout):
    """
    写入 UTF-8 文本。output_path 为空且 empty_means_stdout 为真时打印到屏幕。
    HTML 路径不会走「打印到屏幕」，避免把一大页标签刷到终端。
    """
    text = to_text(content)
    if not output_path:
        if empty_means_stdout:
            print(text.rstrip(u"\n"))
        return

    parent = os.path.dirname(os.path.abspath(output_path))
    if parent and not os.path.isdir(parent):
        raise SystemExit(u"错误：输出目录不存在：%s" % to_text(parent))

    try:
        handle = io.open(output_path, "w", encoding="utf-8")
        try:
            handle.write(text)
            if not text.endswith(u"\n"):
                handle.write(u"\n")
        finally:
            handle.close()
    except (OSError, IOError) as exc:
        raise SystemExit(
            u"错误：无法写入报告文件 %s：%s" % (to_text(output_path), exc)
        )

    print(u"报告已保存：%s" % to_text(output_path))


def describe_targets(args, targets):
    """页眉「目标」那一行：单 IP 直接写；文件则写路径和数量。"""
    if args.target_file:
        return u"%s（共 %s 个地址）" % (to_text(args.target_file), len(targets))
    return to_text(targets[0]) if targets else u""


def main():
    args = parse_args()
    if args.timeout <= 0:
        raise SystemExit(u"错误：--timeout 必须是正整数。")

    # showmount 缺失是本机问题，和「某一台主机超时」不同，应在开扫前失败
    ensure_showmount_exists()

    if args.target_file:
        targets = load_ips_from_file(args.target_file)
    else:
        targets = [args.target]

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []
    for item in targets:
        # 批量时：一台失败只记入报告，绝不中断后面的 IP
        results.append(audit_one_target(item, args.timeout))

    markdown = render_markdown_report(results)
    # 只生成 HTML、不给 --output 时，不再把 Markdown 打到屏幕，避免两份报告混在一起
    print_md = (args.output is not None) or (args.html is None)
    if print_md:
        write_text_file(markdown, args.output, empty_means_stdout=True)

    if args.html:
        html = render_html_report(results, scan_time, describe_targets(args, targets))
        write_text_file(html, args.html, empty_means_stdout=False)


if __name__ == "__main__":
    main()
