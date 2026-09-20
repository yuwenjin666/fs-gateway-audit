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
