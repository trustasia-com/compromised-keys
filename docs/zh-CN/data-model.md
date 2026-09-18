# 数据模型

SQLite 使用 schema version 3，将证书事实与各数据源的查询状态分离。

| 表 | 用途 |
|:--|:--|
| `revoked_certs` | 序列号与 issuer、撤销时间、AKI 来源、公钥和证书元数据。 |
| `lookup_state` | 每个 `(serial_number, issuer, source)` 的结果、未命中和错误次数、下次查询时间。 |
| `record_exclusions` | 精确人工排除及原因、操作人、时间和可选到期时间。 |
| `crl_status` | CCADB 来源归属、下载健康和解析检查点。 |
| `sync_runs`、`source_runs` | 整轮与单数据源的统计和状态。 |

序列号和 AKI 保存为小写 HEX。查询 CT 时才执行 HEX -> 二进制 -> Base64 转换。
证书身份字段不得为空。验证类型和预证书标志由数据库约束其取值，未知值保留为 NULL。

`crl_status.last_hash` 表示已下载内容，`parsed_hash` 与对应撤销记录在同一事务中提交。
待补全索引仅覆盖公钥或公钥哈希缺失的活跃记录，不重复存储完整公钥。

## 记录字段

- `validated_type`：由证书策略 OID 推导的 `DV`、`OV`、`IV`、`EV` 或空值。
- `is_precert=1`：证书包含 critical CT Precertificate Poison 扩展。
- `public_key_source`、`public_key_obtained_at`：公钥来源及接受时间。
- `cleaned_at`：有值的记录处于停用状态，不参与查询和导出。
- `cleanup_reason`：停用原因。

运行状态、人工排除和证书事实分别保存。常规同步不删除历史记录。
详见[发布字段](../data-schema.md)和[重试规则](sources-and-retries.md)。
