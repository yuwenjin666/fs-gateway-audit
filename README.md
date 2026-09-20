
```markdown
# fs-gateway-audit: 分布式存储文件网关 NFS 配置审计工具

> ⚠️ **【免责声明】**
> 本工具仅限用于**您拥有或已获得明确书面授权的**系统的安全合规审计。
> 严禁用于未授权网络探测。本工具为纯只读审计，不包含任何漏洞利用、密码爆破或数据篡改功能。使用者需自行承担因不当使用带来的法律责任。

## 📖 项目介绍
`fs-gateway-audit` 是一款专为分布式存储运维人员设计的**纯只读、低并发** NFS 配置基线审计 CLI 工具。
不同于通用漏洞扫描器，本工具**不影响生产业务**，专门解决运维改配置怕重启起不来、等保巡检缺乏标准化报告的痛点。

**本工具不是漏洞扫描器，是配置合规审计工具。** 它只做配置读取和风险判定，不攻击、不爆破、不篡改。

## ✨ 当前功能 (v0.2)
- [x] 支持单 IP（`--target`）或 IP 列表文件（`--target-file`）批量扫描
- [x] 调用只读命令 `showmount -e <IP>` 获取导出目录
- [x] **高危检测 1**：检查是否存在 `*`（任意主机）无限制导出
- [x] **高危检测 2**：检查是否开启 `no_root_squash`（客户端 root 映射为服务端 root）
- [x] 输出结构化 Markdown 报告（结论摘要 + 详细结果 + 修复建议）
- [x] 支持 `--output` 将报告保存到文件
- [x] 单个 IP 失败不中断整体任务，报告中记录失败原因
- [x] 处理超时、命令不存在等异常，友好中文提示
- [x] **兼容 Python 3**；另提供 `legacy` 分支兼容 Python 2.7 / 3.x（适用于 CentOS 7 等老系统）

> 说明：`showmount -e` 通常不会返回挂载选项，因此若输出中未出现 `no_root_squash`，脚本会标记为“未知”，并提示您到服务端 `/etc/exports` 或 `exportfs -v` 进一步核对。

## 🚀 快速上手

### 依赖
- Python 3（推荐）或 Python 2.7（需使用 `legacy` 分支）
- 系统需安装 `nfs-common` (Ubuntu/Debian) 或 `nfs-utils` (RHEL/CentOS/Rocky)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y nfs-common

# RHEL/CentOS/Rocky
sudo dnf install -y nfs-utils
```

### 安装与使用

```bash
# 克隆仓库（主分支，Python 3 版本）
git clone https://github.com/[你的用户名]/fs-gateway-audit.git
cd fs-gateway-audit

# 审计单个 IP
python3 fs_audit.py --target 192.168.1.100

# 批量审计（从文件读取 IP，输出报告到文件）
python3 fs_audit.py --target-file hosts.txt --output report.md

# 指定超时时间（默认 10 秒）
python3 fs_audit.py --target 192.168.1.100 --timeout 15
```

### 兼容老系统（CentOS 7 等）
如果你的目标机器只有 Python 2.7，请切换到 `legacy` 分支：
```bash
git checkout legacy
python fs_audit.py --target 192.168.1.100
```

## 📋 报告示例

```markdown
# NFS 导出审计报告

- **扫描时间**：2026-09-20 21:30:00
- **扫描目标**：192.168.55.129
- **审计工具**：fs-gateway-audit v0.2

## 结论摘要

| 风险等级 | 数量 |
| --- | --- |
| 高危 | 1 |
| 中危 | 0 |
| 低危 | 0 |
| 未知 | 1 |

**整体结论：发现 1 个高危配置，建议立即整改。**

## 详细结果

### 192.168.55.129

| 检查项 | 当前配置 | 风险等级 |
| --- | --- | --- |
| NFS 导出给 *（所有客户端） | 路径 /nfs 对所有客户端开放 | 高危 |
| no_root_squash 检查 | showmount 未返回该选项 | 未知 |

#### 修复建议

**1. NFS 导出给 *（高危）**
- 问题：/nfs 导出给所有客户端，任何主机都能挂载。
- 修复：在 /etc/exports 中把 * 改成明确网段，如 `/nfs 10.0.0.0/24(rw,root_squash)`，然后执行 `exportfs -ra`。

**2. no_root_squash（未知）**
- 问题：showmount 不返回挂载选项，无法远程确认。
- 修复：登录 NFS 服务端，查看 `/etc/exports` 或执行 `exportfs -v`，若出现 no_root_squash，改为 root_squash 后执行 `exportfs -ra`。
```

## 🗺️ Roadmap (后续规划)
- [ ] 增加 SMB/CIFS 协议检查（SMBv1、匿名共享、Guest账户）
- [ ] 增加 S3 对象存储检查（公开桶、未加密）
- [ ] 增加 Ceph/iSCSI 基线检查
- [ ] 生成 HTML 报告（支持风险等级筛选）
- [ ] 配置漂移检测（对比历史基线）
- [ ] 支持 `--json` 结构化输出，方便接入运维平台

## 💼 商业服务支持
本工具基础版**永久免费**。如果您需要：
1. **远程轻量巡检 (199元)**：协助环境适配、报告解读、区分告警与真实风险。
2. **深度巡检 + 等保合规整改文档 (499元)**：输出可直接交付给测评师的正式报告，包含指导修复。
3. **定制化脚本开发**：适配您公司特有的存储网关接口。

请联系：GoldY_66

## 🤝 贡献与反馈
欢迎提交 Issue 反馈 Bug 或提出新需求。如果你觉得有用，请给个 Star 支持一下！

## 📄 许可证
本项目采用 MIT 许可证。
```
