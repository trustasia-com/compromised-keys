# 受损公钥数据工具链

[![CI](https://github.com/trustasia-com/compromised-keys/actions/workflows/ci.yml/badge.svg)](https://github.com/trustasia-com/compromised-keys/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Data: CDLA Permissive 2.0](https://img.shields.io/badge/data-CDLA--Permissive--2.0-green.svg)](DATA_NOTICE.md)

[English README](README.md)

`compromised-keys` 面向 WebPKI 场景，收集因 `reasonCode: keyCompromise` 被撤销的
证书记录，通过公开证书来源补全公钥，并导出可用于签发前风险检查和安全分析的数据。

代码、测试和发布自动化保存在 Git 仓库中；历史累积数据通过
[GitHub Releases](https://github.com/trustasia-com/compromised-keys/releases) 独立发布。

## 安全边界

本数据集是风险信号，不是密钥安全或泄露的绝对证明：

- Bloom Filter 未命中仅表示该指纹不在当前发布版本中；
- Bloom Filter 命中可能误报，必须使用同版本 CSV 或数据库精确复核；
- CRL 无法访问、上游发布延迟、证书缺失和解析限制都可能造成数据空缺；
- 当前不验证 CRL 签名或完整证书信任链；DER 身份核对不能替代来源真实性验证；
- 生产系统应记录数据版本和 SHA256，并保留独立的密钥安全控制。

将数据用于阻断策略前，请阅读 [SECURITY.md](SECURITY.md)。

## 数据流程

```text
CCADB REST API（具备 TLS 签发能力的中间证书）
  -> CA CRL
  -> reasonCode=keyCompromise 记录及 CRL AKI
  -> SQLite 历史数据库
  -> 可选、由运行方配置的 CT Provider
  -> 公开 crt.sh PostgreSQL 补全
  -> CSV + Bloom Filter + metadata + 数据库快照
  -> GitHub Releases
```

AKI 在数据库中保存为小写十六进制。日常同步只使用 CRL AKI；只有同一规范化 issuer
对应唯一一个直接 CRL AKI 时才允许传播。CCADB 范围仅用于选择 `TLS Capable=True` 的中间证书
CRL；范围变化不会删除历史记录。

每个查询源使用独立状态。HTTP 错误、超时、响应格式异常、DER 缺失和服务不可用都不会
计为有效未命中，也不会阻止其他查询源继续补全。详见
[数据源与重试规则](docs/zh-CN/sources-and-retries.md)。

## 安装

需要 Python 3.10 或更高版本，推荐使用 Python 3.14。Python 3.9 已无法安装当前包含安全
修复的 HTTP 依赖，因此不再支持。

```bash
git clone https://github.com/trustasia-com/compromised-keys.git
cd compromised-keys
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install ".[postgres,release]"
compromised-keys doctor
```

`doctor` 只检查本地环境，不会连接 CCADB、crt.sh 或 CT Provider。未找到历史数据库时会
给出警告，但不会将安装判定为失败。

开发环境：

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev,postgres,release]"
pre-commit install
```

## 选择初始数据库

本地试运行直接使用 `doctor` 提示的空数据库即可。首次同步会创建 SQLite 表，并只收集
当前上游仍然可见的数据。不安装 PostgreSQL 扩展时，可先验证 CRL 流程：

```bash
compromised-keys doctor --no-crtsh
compromised-keys crl-sync
```

生产数据库包含无法通过当前 CRL 完整重建的历史数据。项目发布首个 `data-latest` 后，
生产运行或连续更新前应先恢复该数据发布：

```bash
gh release download data-latest --dir data-release
compromised-keys restore-release \
  --asset-dir data-release \
  --output compromised_keys.db
compromised-keys doctor
```

恢复只允许写入新路径，不会覆盖已有数据库。已有运行库时，保留它并执行 `sync` 更新。

如果 GitHub CLI 返回 `release not found`，说明经过审核的初始种子尚未公开。此时只能继续
空数据库试运行，不能将其视为完整数据集，也不能据此创建生产数据发布。

## 完整同步

```bash
compromised-keys sync --report reports/sync_report.json
```

该命令通过分页 REST API 获取全部 CCADB 证书记录，校验其中 `TLS Capable=True` 的中间
证书范围、下载对应 CRL、传播 CRL AKI、执行可选 CT Provider 和公开 crt.sh 补全，
最后导出结果。CCADB 范围变化不会删除历史记录。
首次 CRL 同步可能包含数万个 URL，需要较长时间。普通日志每处理 1000 个 URL 输出一次
进度；使用 `--verbose` 才显示单个下载和中间重试。部分 CRL 无法访问属于预期情况，最终
汇总和 `crl-health` 会保留失败信息。

`sync` 在必选阶段失败或发布门禁阻断时返回退出码 1；指定的 JSON 报告会保留 CRL 和导出
阶段失败信息。可选查询源降级不影响其他数据源。重复执行时保留数据库和缓存，不要删除
数据库来“重新同步”。增量处理、断点恢复和资源调优见[运行手册](docs/zh-CN/operations.md)。

常用分阶段命令：

| 命令 | 用途 |
|:--|:--|
| `crl-sync` | 从 CCADB 选择 `TLS Capable=True` 的中间证书 CRL，下载并解析密钥泄露撤销记录。 |
| `supplement --mode postgres` | 通过公开 crt.sh PostgreSQL 服务补全缺失证书。 |
| `ct-sync` | 查询可选的兼容 CT Provider。 |
| `export` | 从 SQLite 重新生成 CSV、Bloom Filter 和 metadata。 |
| `prepare-release` | 生成经过完整性检查和摘要校验的数据发布目录。 |
| `restore-release` | 校验发布资产并原子恢复 SQLite 数据库。 |
| `check <csr>` | 使用本地 Bloom Filter 预筛一个或多个 PEM CSR。 |
| `validate-cert <cert>` | 使用已有撤销记录验证公开证书。 |
| `doctor` | 检查本地数据库、输出目录和可选同步依赖。 |
| `stats` | 输出数据库 JSON 统计。 |
| `analyze-misses` | 统计仍然缺失公钥的撤销记录。 |
| `crl-health` | 输出 CRL 下载健康报告。 |
| `exclude-record` | 预览或应用一个精确 serial+issuer 的审计排除。 |
| `clear-exclusion` | 预览或清除一个精确记录排除。 |

使用 `compromised-keys <命令> --help` 查看完整参数。

## 可选 CT Provider

只有具备兼容服务时才配置 Provider：

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync
```

请求中的 AKI 和证书序列号先从十六进制转换为二进制，再使用标准 Base64 编码。客户端
按同一 AKI 分组并按 UTC 撤销日期排序，每批最多查询 1000 个序列号，默认并发数为 5。
证书有效期范围由每批的撤销日期和 TLS BR 有效期上限推导。显式历史全量查询使用：

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync --full-history
```

全量模式忽略重试时间，对窄窗口未命中的记录再使用宽范围查询：两个起始日期均为
`2010-01-01`，`not_before_to` 为当天，`not_after_to` 为当天加一个日历年。
范围算法和历史例外见[CT 查询窗口](docs/zh-CN/sources-and-retries.md#ct-查询窗口)。
返回的 DER 证书会在本地解析，并再次核对请求
身份后才写入公钥。后续基于 DER 新增或补齐公钥时，程序根据 CA/B Forum 策略 OID 生成
`validated_type`，并仅在存在 critical CT Precertificate Poison 扩展时设置 `is_precert`。
运行方 CT 地址不会进入数据发布；报告仅使用 `operator_ct` 标识该来源。

## 配置

| 环境变量 | 默认值 | 说明 |
|:--|:--|:--|
| `COMPROMISED_KEYS_DB` | `compromised_keys.db` | SQLite 历史数据库。 |
| `COMPROMISED_KEYS_DATA_DIR` | `data/latest` | CSV、Bloom Filter 和报告目录。 |
| `COMPROMISED_KEYS_CACHE_DIR` | `cache` | CCADB 和 CRL 缓存。 |
| `CCADB_API_URL` | CCADB 生产 REST API | AllCertificateRecords API 地址。 |
| `CCADB_API_START_DECADE` | `1990` | 获取范围内最早的 `ValidFrom` 年代。 |
| `CCADB_API_END_DECADE` | `2100` | 获取范围内最晚的 `ValidFrom` 年代。 |
| `CCADB_CACHE_TTL_HOURS` | `24` | 在该时长内复用本地规范化 API 快照。 |
| `CRTSH_PG_DSN` | `postgresql://guest@crt.sh:5432/certwatch` | 公开只读 crt.sh 数据库。 |
| `CRTSH_MODE` | `postgres` | `postgres` 或受限的 `http`。 |
| `CT_SERVER_HOST` | 空 | 可选 CT Provider 基础地址或 `/search` 地址。 |
| `CT_BATCH_SIZE` | `1000` | 每次 CT 请求的序列号数量，上限 1000。 |
| `CT_CONCURRENCY` | `5` | CT 请求最大并发数。 |
| `CRL_DOWNLOAD_CONCURRENCY` | `50` | CRL 下载异步任务的并发上限。 |
| `CRL_PARSE_WORKERS` | CPU 数与 `4` 的较小值 | CRL 解析进程数。 |
| `CRL_MAX_BYTES` | `134217728` | 单个 CRL 响应上限，默认 128 MiB。 |

## 数据发布

每个不可变 `data-vYYYY.MM.DD.HHMM` 版本和滚动别名 `data-latest` 均包含：

- `compromised_keys.db.zst`
- `compromised_keys.csv`
- `compromised_keys.bf`
- `metadata.json`
- `db-manifest.json`
- `SHA256SUMS`
- CRL 健康、缺失记录和数据库统计报告

下载后使用内置 SHA256 和 SQLite 完整性校验恢复：

```bash
gh release download data-latest --dir data-release
compromised-keys restore-release \
  --asset-dir data-release \
  --output compromised_keys.db
```

生产环境应固定使用不可变版本。滚动别名更新期间可能出现资产版本暂时不一致；如果校验
失败，应重新下载，不能绕过校验继续使用。

## 项目文档

- [中文文档索引](docs/zh-CN/README.md)
- [架构](docs/zh-CN/architecture.md)
- [数据模型](docs/zh-CN/data-model.md)
- [数据源与重试规则](docs/zh-CN/sources-and-retries.md)
- [运行手册](docs/zh-CN/operations.md)
- [内部 Runner 与首个数据发布](docs/zh-CN/runner-and-bootstrap.md)
- [发布门禁](docs/zh-CN/release-process.md)
- [英文规范文档](docs/README.md)

## Docker

镜像使用 `compromised-keys` 作为 entrypoint。Python 基础镜像固定到不可变摘要，运行进程
使用非 root 用户且不具有 Linux capabilities。Compose 服务默认只同步一次并退出，不会在
空数据库上无限重启。

```bash
docker compose build
docker compose run --rm compromised-keys doctor --no-crtsh
docker compose up
```

以上命令用于空数据库试运行。连续更新历史数据时，先在宿主机下载 `data-latest`，再恢复
到命名卷：

```bash
gh release download data-latest --dir data-release
docker compose run --rm \
  -v "$PWD/data-release:/release:ro" \
  compromised-keys restore-release \
  --asset-dir /release --output /data/compromised_keys.db
docker compose run --rm compromised-keys doctor
docker compose up
```

容器使用命名卷持久化 `/data/compromised_keys.db`、`/data/latest` 和 `/cache`。只有明确
选定初始数据库后，才应使用 `docker compose run --rm compromised-keys sync --loop`。

## 公钥指纹

- RSA：移除前导零后，对无符号模数 bytes 计算 `SHA256`；
- EC：对无符号公钥点 X 坐标 bytes 计算 `SHA256`。

CSV 用于精确匹配。序列化的 `pybloom_live` Bloom Filter 目标误报率为 0.1%。
`check` 会检查全部输入：退出码 0 表示全部未列入，1 表示存在无法检查的输入，2 表示存在
可能命中（优先于 1）。命中必须精确复核，未列入不代表安全。

## 贡献与安全报告

开发和证书提交规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞应通过 GitHub
Private Vulnerability Reporting 或 `support@trustasia.com` 私密提交，不能创建公开
漏洞 Issue。

## 许可和数据条款

源代码采用 [MIT License](LICENSE)。数据发布的来源、权利和使用边界见
[DATA_NOTICE.md](DATA_NOTICE.md)。项目不保证数据覆盖率、正确性、适用性或不侵权。
