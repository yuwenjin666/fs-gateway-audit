#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NFS 导出安全审计脚本（单文件、仅标准库）

做什么：
    对目标主机执行  showmount -e <IP>
    检查两项高危配置：
        1) 是否把目录导出给全世界（客户端是 *）
        2) 是否关闭了 root 身份压缩（no_root_squash）

重要说明（零基础也请看一眼）：
    showmount -e  一般只能看到「导出路径」和「允许哪些客户端」。
    no_root_squash 写在服务端的 /etc/exports 里，多数发行版不会通过
    showmount 回传这条选项。脚本会：
        - 如果命令输出里出现了 no_root_squash，判定为高危；
        - 如果没有出现，风险标为「未知」，并告诉你去服务端核对。

用法：
    python fs_audit.py --target 192.168.1.10
    python fs_audit.py --target 192.168.1.10 --timeout 15
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys


# showmount 默认等待秒数，避免远程主机无响应时一直卡住
DEFAULT_TIMEOUT_SECONDS = 10


def parse_args() -> argparse.Namespace:
    """解析命令行参数。用户必须提供 --target。"""
    parser = argparse.ArgumentParser(
        description="审计远程 NFS 导出：是否对 * 开放、是否出现 no_root_squash。",
        epilog="示例：python fs_audit.py --target 192.168.1.10",
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="IP",
        help="要检查的 NFS 服务器 IP 地址（IPv4 或 IPv6）",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="秒",
        help=f"showmount 超时时间，默认 {DEFAULT_TIMEOUT_SECONDS} 秒",
    )
    return parser.parse_args()


def validate_ip(raw: str) -> str:
    """
    校验 IP 是否合法。
    用标准库 ipaddress，避免把奇怪字符串直接丢给系统命令。
    """
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as exc:
        raise SystemExit(f"错误：--target 不是合法 IP：{raw}") from exc


def run_showmount(ip: str, timeout: int) -> str:
    """
    调用系统命令：showmount -e <IP>

    可能的异常（都会转成对用户友好的中文后退出）：
        FileNotFoundError / 命令不在 PATH  —— 本机没装 nfs-common / nfs-utils
        TimeoutExpired                     —— 对端无响应或被防火墙丢弃
        非 0 退出码                         —— RPC 失败、主机不是 NFS 服务等
    """
    # which 等价检查：命令根本不存在时，提前给出安装提示
    if shutil.which("showmount") is None:
        raise SystemExit(
            "错误：本机找不到 showmount 命令。\n"
            "  Debian/Ubuntu 可安装：sudo apt install nfs-common\n"
            "  RHEL/CentOS 可安装：  sudo yum install nfs-utils\n"
            "  Windows 一般没有此命令，请在 Linux 上运行本脚本。"
        )

    command = ["showmount", "-e", ip]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            f"错误：执行 {' '.join(command)} 超过 {timeout} 秒仍无结果。\n"
            "  请确认 IP 可达、NFS 端口（2049/rpcbind）未被防火墙拦截。"
        ) from exc
    except FileNotFoundError as exc:
        # 极少数环境下 which 通过、真正执行时文件又没了
        raise SystemExit("错误：无法启动 showmount（命令不存在）。") from exc
    except OSError as exc:
        raise SystemExit(f"错误：无法执行 showmount：{exc}") from exc

    # stderr 里常有 rpc 错误信息，失败时一并打印
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        extra = f"\n  命令输出：{detail}" if detail else ""
        raise SystemExit(
            f"错误：showmount -e {ip} 失败（退出码 {completed.returncode}）。{extra}"
        )

    return completed.stdout


def parse_export_lines(showmount_output: str) -> list[tuple[str, str]]:
    """
    把 showmount 的文本拆成 [(导出路径, 客户端列表), ...]

    典型输出：
        Export list for 192.168.1.10:
        /home       *
        /data       10.0.0.0/24,192.168.1.5

    第一行是标题，从第二行开始才是真正的导出项。
    """
    exports: list[tuple[str, str]] = []
    for raw_line in showmount_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # 跳过标题行
        if line.lower().startswith("export list"):
            continue

        # 路径和客户端之间通常是空白分隔；客户端里可能还有逗号
        parts = line.split(None, 1)
        path = parts[0]
        clients = parts[1].strip() if len(parts) > 1 else ""
        exports.append((path, clients))
    return exports


def clients_include_wildcard(clients: str) -> bool:
    """
    客户端字段里是否出现 *（对所有人开放）。

    常见写法：
        *
        *(rw,sync,no_root_squash)
        *,10.0.0.1
    选项括号里也有逗号，所以不能简单按逗号切开再精确匹配 "*"。
    """
    # 允许 * 出现在开头/逗号/空白后，后面可以是结束、逗号、空白或 (
    return re.search(r"(?:^|[\s,])\*(?=$|[\s,(])", clients.strip()) is not None


def line_has_no_root_squash(text: str) -> bool:
    """整行文本里是否出现 no_root_squash（大小写不敏感）。"""
    return "no_root_squash" in text.lower()


def audit(exports: list[tuple[str, str]], raw_output: str) -> list[dict[str, str]]:
    """
    生成表格行。每一行是一个字典，键就是表头。

    检查项 1：通配符导出 *
    检查项 2：no_root_squash
    """
    rows: list[dict[str, str]] = []

    # ---------- 检查 1：是否导出给 * ----------
    wildcard_hits = [
        path for path, clients in exports if clients_include_wildcard(clients)
    ]
    if not exports:
        rows.append(
            {
                "检查项": "NFS 导出给 *（所有客户端）",
                "当前配置": "未解析到任何导出项",
                "风险等级": "信息",
                "修复建议": "确认目标确实开启了 NFS；或 showmount 输出格式与预期不符。",
            }
        )
    elif wildcard_hits:
        listed = ", ".join(wildcard_hits)
        rows.append(
            {
                "检查项": "NFS 导出给 *（所有客户端）",
                "当前配置": f"高危：以下路径对 * 开放：{listed}",
                "风险等级": "高危",
                "修复建议": (
                    "在服务端 /etc/exports 中把 * 改成明确的网段或主机，"
                    "例如 /data 10.0.0.0/24(rw,root_squash)，然后执行 exportfs -ra。"
                ),
            }
        )
    else:
        summary = "; ".join(f"{path} -> {clients}" for path, clients in exports)
        rows.append(
            {
                "检查项": "NFS 导出给 *（所有客户端）",
                "当前配置": f"未发现 *。当前导出：{summary}",
                "风险等级": "低",
                "修复建议": "保持仅向可信网段/主机导出；新增导出时不要使用 *。",
            }
        )

    # ---------- 检查 2：no_root_squash ----------
    # showmount 默认不打印挂载选项；若输出里完全没有这个词，不能当成「已关闭」
    option_hits = [
        path
        for path, clients in exports
        if line_has_no_root_squash(path) or line_has_no_root_squash(clients)
    ]
    also_in_raw = line_has_no_root_squash(raw_output)

    if option_hits or also_in_raw:
        where = ", ".join(option_hits) if option_hits else "showmount 原始输出"
        rows.append(
            {
                "检查项": "开启 no_root_squash（远程 root 保持 root）",
                "当前配置": f"高危：检测到 no_root_squash（{where}）",
                "风险等级": "高危",
                "修复建议": (
                    "在 /etc/exports 去掉 no_root_squash，改用默认的 root_squash，"
                    "使客户端 root 被映射为 nfsnobody；改完后执行 exportfs -ra。"
                ),
            }
        )
    else:
        rows.append(
            {
                "检查项": "开启 no_root_squash（远程 root 保持 root）",
                "当前配置": "showmount -e 未返回该选项（多数系统都不会回传）",
                "风险等级": "未知",
                "修复建议": (
                    "请到 NFS 服务器查看 /etc/exports 或执行 exportfs -v。"
                    "若出现 no_root_squash，请改为 root_squash 后 exportfs -ra。"
                ),
            }
        )

    return rows


def to_markdown(rows: list[dict[str, str]]) -> str:
    """把结果拼成 Markdown 表格，方便直接贴到文档或工单里。"""
    headers = ["检查项", "当前配置", "风险等级", "修复建议"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        # 单元格里的竖线会弄坏表格，替换成斜杠
        cells = [row[h].replace("|", "/") for h in headers]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    if args.timeout <= 0:
        raise SystemExit("错误：--timeout 必须是正整数。")

    ip = validate_ip(args.target)
    output = run_showmount(ip, args.timeout)
    exports = parse_export_lines(output)
    table = to_markdown(audit(exports, output))

    print(f"# NFS 导出审计：{ip}")
    print()
    print("命令：`showmount -e " + ip + "`")
    print()
    print(table)
    print()
    print("## showmount 原始输出")
    print()
    print("```")
    print(output.rstrip() or "(空)")
    print("```")


if __name__ == "__main__":
    main()
