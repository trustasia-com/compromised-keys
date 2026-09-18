# 运行手册

## 运行前检查与初始状态

每个新安装环境先执行：

```bash
compromised-keys doctor
```

检查失败时命令以状态码 1 退出。数据库缺失只产生警告：空数据库可用于试运行，但无法
重建历史记录。生产连续同步前必须通过 `restore-release` 恢复 `data-latest`。
如果尚未发布 `data-latest`，则暂不具备生产连续同步条件。使用 `sync --no-crtsh` 时，
对应使用 `doctor --no-crtsh`。

## 日常同步

```bash
compromised-keys sync \
  --crtsh-mode postgres \
  --crtsh-limit 5000 \
  --report reports/sync_report.json
```

检查 `release.status`、阻断原因、可选源告警、CRL 成功率、记录和公钥数量、各 outcome 以及
`missing_der` 数量。`ready` 和 `degraded` 可以进入发布准备，`blocked` 禁止发布。

首次 CRL 阶段可能处理数万个 URL。INFO 日志每完成 1000 个显示一次进度；只有排查单个
URL 时才使用 `--verbose`，因为该模式也会显示每次成功下载和中间重试。

## 增量与恢复

- 同一 Full CRL 的候选地址依次尝试；HTTP 200 但内容无法解析时继续尝试镜像。重叠地址
  在一轮下载内共享结果，分区 CRL 不会被当作可省略的镜像。
- 缓存命中不等于入库完成。`crl_status.parsed_hash` 与撤销记录在同一 SQLite 事务提交；
  下载后中断、解析失败或写库失败时，下次即使内容未变化也会重新解析。
- PostgreSQL 每批完成后保存公钥与查询状态；CT 每个管理批次结束落库。中断后重新执行
  原命令，已入库公钥不会重新查询。源熔断后本轮停止继续提交，未处理记录仍可在下轮查询。
- CLI 对同一数据库的写入任务使用进程锁。锁文件可以留在磁盘上，退出后锁自动释放；
  运行期间不能删除锁文件。不同数据库不得共用一个可写缓存或导出目录。
- 导出使用同目录临时文件和原子替换，metadata 最后写入。空数据会生成有效的空 CSV 和
  Bloom Filter，不保留上次数据。多个资产不是一个原子事务，消费端必须核对同版本摘要。

## 资源与统计

默认 CRL 下载并发 50、每主机连接上限 10、解析进程最多 4，解析排队任务最多为进程数的
两倍。内存或带宽有限时先降低 `CRL_DOWNLOAD_CONCURRENCY` 和 `CRL_PARSE_WORKERS`，不要
盲目增加 CT 或公共 crt.sh 的压力。单个 CRL 响应上限为 `CRL_MAX_BYTES`，默认 128 MiB；
超限会记录失败，不会截断后当作成功。

报告的每个阶段包含 `duration_seconds`。重点比较 `crl_parse_targets`、
`crl_unchanged_skipped`、`crl_parse_errors` 和公钥 `updated`。`total_revoked_found`
是本轮成功处理 CRL 中观察到的撤销记录数，不是数据库新增数量。CRL 解析失败会阻断发布。
CT 的 `selected`、`submitted`、`deferred` 区分选中、返回结果和本轮未处理记录。

退出码：`sync` 的 `ready`/`degraded` 为 0，`blocked` 或运行失败为 1。
使用 `--report` 留存诊断，失败时不应发布旧导出。数据库写入不是整轮事务，已经完成的批次
会保留；SIGKILL 或主机断电可能没有最终 JSON 报告，但下次可以从检查点恢复。

## 全量 CT 补全

```bash
CT_SERVER_HOST=https://ct.example.com compromised-keys ct-sync --full-history
```

此命令忽略缺失公钥记录的重试时间，先使用[撤销时间窗口](sources-and-retries.md#ct-查询窗口)，
仅对成功查询但未命中的记录再次使用宽范围：两个 `from` 均为 `2010-01-01`，
`not_before_to` 为当天，`not_after_to` 为当天加一个日历年。正常同步仅使用窄窗口。
运行方内部地址不得写入仓库、报告或 Release。

## 诊断

```bash
compromised-keys stats
compromised-keys analyze-misses
compromised-keys crl-health --out reports/crl_failures.json
```

`analyze-misses` 按数据源和 outcome 统计，并单独输出 DER 缺失。排查服务异常时应同时保留
该报告和 `sync_report.json`。
CRL 失败明细保存在本地 `reports/` 目录，不作为对外发布资产。

## 精确排除

项目不支持 issuer 子字符串排除。`exclude-record` 和 `clear-exclusion` 默认只预览，必须
增加 `--apply` 才修改数据库。排除必须提供完整 serial、完整 issuer、原因代码、说明和
操作人，可设置到期时间。

## 备份

历史库应保留独立备份。使用 SQLite 在线备份 API，或停止写入后再复制文件。替换生产数据
前执行 `PRAGMA integrity_check`，并核对记录数和公钥数。
