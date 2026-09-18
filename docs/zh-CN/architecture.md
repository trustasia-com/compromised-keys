# 架构

项目收集 WebPKI 中因 `reasonCode=keyCompromise` 撤销的证书记录，补全其公开公钥并发布
风险密钥数据。数据中不包含私钥；未命中不代表密钥安全。

## 数据流程

1. 通过 REST API 拉取全部 CCADB 证书记录；
2. 仅选择 `CertificateRecordType=IntermediateCertificate` 且
   `TLS Capable=True` 的记录领取 CRL；
3. 解析 CRL 中的密钥泄露撤销记录和 AKI；
4. 仅当同一规范化 issuer 对应唯一直接 CRL AKI 时，向同 issuer 记录传播 AKI；
5. 使用可选的运行方 CT 服务按 AKI+serial 补全证书；
6. 使用公开 crt.sh PostgreSQL 或 HTTP 补全；
7. 本地核对 DER 身份，提取公钥、指纹、证书策略和预证书标志；
8. 导出 CSV、Bloom Filter、metadata 和可校验 SQLite 快照。

CCADB 筛选范围只决定后续领取哪些 CRL，不删除历史记录。日常 CT 查询统一使用 CRL 来源 AKI。

根据 [CCADB Policy 6.2](https://www.ccadb.org/policy)，同一条
`JSON Array of all Full CRL URLs` 中的全部 URL 必须提供完全相同的 CRL。因此这些 URL
按顺序作为同一逻辑 CRL 的候选地址，首个成功后停止；每个 Partitioned CRL URL 仍是必须
独立下载的逻辑 CRL。报告中的 `crl_urls_found` 统计披露地址数，`crl_download_targets`
统计逻辑 CRL 数，CRL 下载成功率以后者为分母。

## 信任边界

HTTP 200 只有通过 CRL 结构解析才算成功；失败会继续尝试下一个镜像。不同 Full 组部分
重叠不会丢弃其余候选地址，分区目标保持独立。同 URL 的下载任务共享结果；来源登记批量提交。
断点检查点与批次提交见[运行手册](operations.md)。

- CCADB、CRL、SQLite 完整性和导出摘要属于必选链路，失败会阻断发布；
- CT 和 crt.sh 属于可选补全源，失败只会把运行标记为 `degraded`；
- `CT_SERVER_HOST`、凭据、缓存、日志和备份属于运行方私有信息，不进入发布；
- 代码进入 Git，无法完全重现的历史数据库通过带摘要的独立 Release 发布。

当前不做 CRL 签名与完整信任链验证，不能把结构解析、AKI 匹配或 CCADB 披露视为密码学
真实性证明。公网 CRL 的连接与重定向禁止访问非公网地址，内部 CT 仍由运行方单独配置。

## 代码结构

保留标准 `src/compromised_keys/` 包布局，确保测试与安装后的 CLI 使用相同导入路径，
避免从仓库根目录误导入代码。运行数据不属于 Python 包，也不进入 Git。

| 模块 | 职责 |
|:--|:--|
| `downloader.py`、`parser.py` | CCADB 范围、CRL 获取与解析。 |
| `data_manager.py` | 数据库初始化、事务、证书事实、检查点与查询状态。 |
| `ct_client.py`、`crt_sh_crawler.py`、`lookup.py` | 查询、身份校验与源级熔断。 |
| `crypto_utils.py` | 统一指纹、证书策略与预证书判定。 |
| `exporter.py`、`release_assets.py` | 导出、快照、摘要与恢复。 |
| `atomic_io.py`、`public_http.py` | 原子文件写入与公网 CRL 访问边界。 |
| `main.py`、`cli.py` | 流程编排、报告、命令与进程锁。 |
