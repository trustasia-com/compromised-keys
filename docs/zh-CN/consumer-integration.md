# 数据依赖方接入指南

本文面向 CA 机构及其他风险密钥数据使用方。数据依赖方不需要运行 CRL、CT 和 crt.sh
采集流程，只需自动获取、验证并切换项目发布的数据版本，同时保留上一份可用版本。

## 推荐架构

生产 CA 应由独立更新节点访问外网：

```text
GitHub 不可变 Release
        |
        v
独立更新节点 -> 校验和及数据库校验 -> 内部制品库
                                      |
                                      v
                             签发系统及监控系统
```

更新节点只需读取公开 Release。签发系统不应持有 GitHub 凭据，也不应修改下载的数据。
多节点环境应只下载一次，经校验后同步至内部制品库，再由各签发节点消费内部分发版本。

## 版本选择

每 30 至 60 分钟检查一次最新的不可变 `data-vYYYY.MM.DD.HHMM` 标签。生产环境不要把
滚动别名 `data-latest` 作为版本标识：它的文件逐个替换，更新过程中可能暂时不一致。

可使用 GitHub CLI 获取最新不可变版本：

```bash
REPOSITORY=trustasia-com/compromised-keys
TAG="$(gh release list --repo "$REPOSITORY" --limit 30 \
  --json tagName,isDraft,isPrerelease \
  --jq '[.[] | select(.isDraft == false and .isPrerelease == false) |
    .tagName | select(test("^data-v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\\.[0-9]{4}$"))]
    | sort | last')"
test -n "$TAG"
```

每次部署和风险判定都应记录标签。除非执行有审计记录的人工回滚，否则不得用旧标签覆盖
新标签。

## 校验与原子更新

在活动数据所在文件系统创建版本化暂存目录，不能直接覆盖正在使用的文件：

```bash
BASE=/var/lib/compromised-keys
REPOSITORY=trustasia-com/compromised-keys
STAGING="$(mktemp -d "$BASE/.incoming-${TAG}.XXXXXX")"

gh release download "$TAG" --repo "$REPOSITORY" --dir "$STAGING/assets"
(
  cd "$STAGING/assets"
  sha256sum --check SHA256SUMS
)

compromised-keys restore-release \
  --asset-dir "$STAGING/assets" \
  --output "$STAGING/compromised_keys.db"
```

`restore-release` 会验证 Release 校验和、数据库清单、解压结果、SQLite 完整性和公开表
结构。只有完整执行 `SHA256SUMS` 校验且数据库恢复成功，才可使用该版本。

校验成功后，将暂存目录移动为 `releases/$TAG`，再原子替换 `current` 符号链接；仅在指针
切换后通知应用重新加载。至少保留前两个已验证版本用于回滚。任一步骤失败时，只清理暂存
目录，继续使用 last-known-good 版本并告警，不能切换到不完整、空或未校验的数据。

如需更高保证，可在完成校验后用机构内部制品签名密钥重新签名，再进行内部分发。
Release 中的校验和可以发现文件缺失和传输损坏，但校验文件与数据一同发布，并不是独立的
发布者数字签名。

## 签发前检查

建议把本项目作为签发前风险控制：

1. 根据 CSR 公钥计算项目定义的 `key_hash`。
2. 使用 `compromised_keys.bf` 快速排除未命中项。
3. Bloom Filter 命中时，必须使用同一不可变版本的 CSV 或 SQLite 数据按 `key_hash`
   精确确认。
4. 精确命中后执行 CA 的书面策略，通常拒绝签发或转安全人工审核。
5. 在签发审计日志中记录 Release 标签、Release 摘要、key hash、查询结果及策略动作。

项目指纹不是 SubjectPublicKeyInfo 的 SHA-256：

- RSA：去除前导零后的无符号模数字节 SHA-256。
- EC：无符号公钥点 X 坐标字节 SHA-256。

`compromised-keys check request.csr` 已实现项目指纹和 Bloom Filter 查询，适合接入验证及
低频调用。退出码 `0` 表示 Bloom Filter 未命中，`2` 表示可能命中，`1` 表示无法完成
检查。可能命中仍须精确确认；未收录不能证明私钥安全，不支持的密钥算法也不能当作安全。

高并发签发系统应把 CSV 的 `key_hash` 导入带索引的本地存储或查询服务。热更新期间必须
保证 Bloom Filter 和精确数据始终属于同一个 Release 标签。

## 调度与失败策略

上游当前按日发布。消费端可以更频繁轮询，因为版本检查只访问 GitHub Release 元数据，
不会增加 CRL 或 CT 数据源负载。

建议初始策略如下：

- 每 30 分钟检查一次新不可变版本，并增加少量随机延迟；
- 活动版本超过 36 小时未更新时预警，超过 48 小时时升级告警；
- 下载、校验或内部分发失败时继续使用上一份已验证版本；
- 极端陈旧时是否停止签发由 CA 单独制定，因为自动 fail-closed 可能造成签发业务中断。

监控指标至少包括：当前标签、Release 发布时间、最近成功更新时间、连续失败次数、校验和
结果、数据库校验结果和精确命中数量。告警应依据当前已验证数据的实际年龄，而不能只看
更新程序是否成功退出。

单更新节点可使用 `systemd` timer。集群或隔离 CA 环境只需让内部镜像任务访问 GitHub，
再通过现有制品管理机制分发已审核的不可变数据包。

例如，将前述完整校验更新流程封装为 `/usr/local/sbin/update-compromised-keys`，再配置：

```ini
# /etc/systemd/system/compromised-keys-update.service
[Unit]
Description=Update the verified compromised-key dataset
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=compromised-keys
ExecStart=/usr/local/sbin/update-compromised-keys
```

```ini
# /etc/systemd/system/compromised-keys-update.timer
[Unit]
Description=Check for a compromised-key data release

[Timer]
OnBootSec=5m
OnCalendar=*-*-* *:00,30:00
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
```

执行 `systemctl enable --now compromised-keys-update.timer` 启用。版本发现、下载、校验、
恢复、内部分发或应用重载任一步骤失败时，更新脚本都应非零退出，以便服务监控及时告警。
