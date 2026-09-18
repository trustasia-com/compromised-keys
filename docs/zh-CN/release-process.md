# 发布流程与质量门禁

历史 CRL 和证书可能已经无法访问，因此累积数据库不能通过当前程序完全重建。代码和数据库
分别发布：代码进入 Git，数据库和导出物进入不可变数据 Release。

以下任一条件会将运行标记为 `blocked`：

- CCADB 拉取或筛选校验失败，或筛选范围为空；
- CRL 可用率低于 95%；
- 相比上一非阻断运行，CRL 可用率下降超过 2 个百分点；
- CRL 解析或数据库提交失败；
- SQLite 完整性检查失败；
- 活跃记录数或已有公钥数出现未解释下降；
- CSV/Bloom Filter 摘要与 metadata 不一致。

CT 或 crt.sh 失败只产生 `degraded`。`prepare-release` 强制要求同步报告，且拒绝
`blocked` 报告。

发布顺序：校验 runner 持久运行库（不存在时才恢复公开历史库）；完整同步；生成健康和缺失报告；执行发布门禁；生成并
恢复验证快照；发布不可变 `data-vYYYY.MM.DD.HHMM`；最后更新 `data-latest`。生产使用方
应固定不可变版本，并验证 `SHA256SUMS` 和数据库完整性。

对外资产包括压缩数据库、CSV、Bloom Filter、元数据、缺失公钥及数据库统计、清单和校验值。
CRL 失败报告及同步日志仅保留在 runner，不上传为 Release 资产或 Actions artifact。
公开 SQLite 快照会清除 CRL 失败状态码、计数、错误详情和失败时间，保留下载哈希与解析检查点，
原始数据库不受影响。从公开快照恢复后，CRL 失败计数重新累计；诊断历史从本地报告查阅。
历史审计 JSON 中的原始异常文本同样从公开快照移除。未审核的额外表或字段会阻止发布。

`prepare-release` 要求报告与库中已完成运行、导出版本一致，并核对数据库统计及重新生成的
CSV/Bloom Filter 内容；过期报告、不同批次混用或同步后修改数据库都会被拒绝。

自动任务只在带 `compromised-keys-sync` 标签的专用 self-hosted runner 和受保护的
`data-production` Environment 中运行。首个 `data-latest` 发布前，维护者必须按
[内部 Runner 与首个数据发布](runner-and-bootstrap.md)执行一次审核引导；定时任务绝不从
空数据库初始化生产数据。
