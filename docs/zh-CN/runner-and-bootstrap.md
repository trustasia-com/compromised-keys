# 内部 Runner 与首个数据发布

每日数据工作流只允许运行在专用 self-hosted runner 上。该 runner 不得执行不受信任的 PR
代码，也不得与通用 CI 共用。

## 仓库配置

1. 注册 Linux self-hosted runner，并同时添加 `self-hosted` 和
   `compromised-keys-sync` 标签。隔离系统账号，每次任务后清理 Actions 工作目录。
   使用临时 runner 时，运行数据库和报告必须挂载在受控持久存储上。
   runner 名称不参与任务调度；已有 runner 也必须具备该自定义标签。使用组织 runner 时，
   其 runner group 必须允许当前仓库及其公开可见性，仅授权受信任的生产工作流。
2. 创建 `data-production` GitHub Environment，将部署分支限制为 `main`；首发引导和其他
   运行可配置审批人。审批规则对定时任务同样生效；需要无人值守每日更新时不要设置必需审批人。
3. 在仓库、组织或 Environment 中配置 Actions secret `CT_SERVER_HOST`。已有仓库 secret
   可直接使用，不必重复创建；组织 secret 必须授权当前仓库访问。同名 Environment secret
   优先。工作流只在同步步骤注入该值，未配置或无权访问时会停止。
4. 添加 Environment variable `INITIAL_DB_PATH`，值为 runner 受控存储中、Actions 工作
   目录之外的历史 SQLite 数据库绝对路径。该路径只用于首个数据发布。
5. 允许 Actions 使用 `GITHUB_TOKEN` 创建 Release。仓库默认工作流权限保持只读，由数据
   job 显式申请 `contents: write`。

Runner 需要访问 GitHub、CCADB、CT 和各 CRL 地址的 HTTPS，并通过 TCP 5432 连接 crt.sh
PostgreSQL。需预装 GitHub CLI，临时磁盘至少保留 5 GiB。Python 由固定版本的
`setup-python` Action 安装。

job 另有 `main` 分支限制，防止手工分派其他分支进入内部 runner。依赖安装在每次任务的
独立虚拟环境中。CRL 缓存位于 `$RUNNER_TOOL_CACHE/compromised-keys-crl-cache`，不在
checkout 清理范围内；专用 runner 应保留此目录且仅允许该服务账号写入。临时 runner
丢弃缓存只影响速度，不影响数据库检查点的正确性。公网 CRL 也可能使用 HTTP，出站策略
应允许必要的公网 80/443，同时禁止 CRL 流量访问内部地址。

同步日志与 CRL 失败报告保存在 checkout 之外的
`$RUNNER_TOOL_CACHE/compromised-keys-reports/<run-id>-<attempt>/`，仅 runner 账号可访问。
按内部策略设置保留期限；临时 runner 销毁前需将该目录保存在受控存储中。

## 首个数据发布

触发工作流前，独立备份历史库并执行：

```bash
sqlite3 /controlled/path/compromised_keys.db 'PRAGMA integrity_check;'
```

将 `INITIAL_DB_PATH` 指向审核后的数据库，然后手动触发 **Daily Data Sync**，设置
`bootstrap=true`。任务会对该历史库建立一致性快照，完整同步，执行发布门禁，生成并恢复验证候选快照，
先发布不可变 `data-v...`，成功后再创建 `data-latest`。

`data-latest` 或 runner 运行数据库已存在时，引导模式会被拒绝。运行数据库位于
`$RUNNER_TOOL_CACHE/compromised-keys-state/compromised_keys.db`，在 checkout 之外且仅
runner 账号可访问。每次任务校验并继续使用该库，保留失败或发布阻断期间已提交的增量和
失败计数。仅运行库不存在时，才从经过校验的 `data-latest` 恢复。
不要通过删除运行库重试任务；该库应另行备份。

## 运维和恢复

- `0 18 * * *` 表示 UTC 18:00，即上海时间次日 02:00。
- 工作流不使用 `pull_request_target`；专用 runner 不得分配给公开 PR。
- 不可变 Release 不允许覆盖。如果滚动别名发布失败，应先确认不可变 Release 和资产正确，
  再重新运行；新的同步会生成新的不可变版本。
- 首发成功后可删除 `INITIAL_DB_PATH`，或使其继续指向只读受控存储；只要
  `data-latest` 存在，工作流就不会使用它。
- 更新内部 CT 地址时只轮换对应作用域中的 secret，不修改源码。

发布阻断条件见[发布流程与质量门禁](release-process.md)。
