# 适配这份新版代码的 README.md
> 重点更新：代码当前仅支持 `--target` 和 `--timeout`，**暂时没有批量 `--target-file`、`--output`**（和你上面这份代码保持一致，避免README和代码对不上，后续再加功能再改文档）

```markdown
# fs-gateway-audit
> 分布式存储文件网关 NFS 基线审计脚本 V1.0

## 简介
我是分布式存储运维工程师，日常做等保巡检、存储网关季度自查时，经常需要核查NFS导出配置。
通用扫描工具并发高，不敢直接在生产存储上跑；手动执行`showmount`效率低，缺少标准化风险定级与整改建议。

本脚本为**极简单文件Python工具**，调用系统原生`showmount -e`命令，**纯只读审计**，不会挂载、修改任何业务数据，低风险适配生产存储网关巡检场景。

> 当前版本：仅支持NFS审计，检测2项高危配置
> 1. NFS导出权限为 `*`（允许任意主机挂载）
> 2. 导出目录配置 `no_root_squash`
>
> ⚠️重要提示：`showmount -e` 默认**不会返回挂载选项**。
> 脚本仅能识别showmount输出中显式打印的`no_root_squash`；
> 如果输出没有该字段，风险标记为【未知】，需要登录存储服务端查看 `/etc/exports` / `exportfs -v` 确认。

## ✨ 特性
- 单文件脚本，仅依赖系统命令，使用Python标准库，无需额外安装Python第三方包
- 串行扫描，无并发，最大程度避免对存储网关造成业务压力
- 输出Markdown表格报告，包含：检查项、当前配置、风险等级、修复建议，可直接粘贴到工单、等保文档
- 完善异常捕获：目标不可达、nfs-utils未安装、命令超时等场景，中文友好提示

## ⚠️ 免责声明（必看）
1. 本工具**仅允许在拥有授权的资产上进行安全审计**，禁止对未授权的服务器、存储设备扫描探测。
2. 脚本仅调用`showmount`读取NFS导出配置，无任何写入、渗透、爆破功能。
3. 使用本工具产生的一切后果，由使用者自行承担。

## 📦 环境准备
推荐 Ubuntu / WSL2 Ubuntu
```bash
sudo apt update
sudo apt install -y nfs-common python3
```

## 🚀 使用方法
### 查看帮助信息
```bash
python3 fs_audit.py --help
```

### 扫描单个存储网关IP
```bash
python3 fs_audit.py --target 192.168.1.100
```

### 自定义超时时间（单位：秒）
```bash
python3 fs_audit.py --target 192.168.1.100 --timeout 15
```

## 📋 输出示例
```markdown
# NFS 导出审计：192.168.1.10
命令：`showmount -e 192.168.1.10`

| 检查项 | 当前配置 | 风险等级 | 修复建议 |
| --- | --- | --- | --- |
| NFS 导出给 *（所有客户端） | 高危：以下路径对 * 开放：/data | 高危 | 在服务端 /etc/exports 中把 * 改成明确的网段或主机，例如 /data 10.0.0.0/24(rw,root_squash)，然后执行 exportfs -ra。 |
| 开启 no_root_squash（远程 root 保持 root） | showmount -e 未返回该选项（多数系统都不会回传） | 未知 | 请到 NFS 服务器查看 /etc/exports 或执行 exportfs -v。若出现 no_root_squash，请改为 root_squash 后 exportfs -ra。 |

## showmount 原始输出
```
Export list for 192.168.1.10:
/data *
```
```

## 📌 版本规划
- V1.0：NFS基础审计（当前版本），检测`*`、`no_root_squash`，Markdown报告输出
- V1.1：计划新增：批量IP读取`--target-file`、`--output`保存报告到文件
- V2.0：后续迭代增加SMB共享审计（按需开发）

## 🤝 反馈与增值服务
脚本免费开源，欢迎下载测试，提交Issue反馈bug。

> 增值服务：存储网关远程基线巡检、等保整改方案、定制化巡检脚本开发。

⭐ 如果对你有帮助，欢迎Star，我会持续更新存储网关巡检相关能力。
```

> 后续想增加 `--target-file` 和 `--output` 功能，直接让AI扩展这份代码就行，到时候再同步更新README。

需要我顺便帮你微调**引流帖子文案**，适配当前V1.0版本的限制（暂时无批量、无文件输出）吗？
