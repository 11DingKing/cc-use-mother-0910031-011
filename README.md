# 违规线索分流处置

市级监管部门线索集中受理与分流处置服务端。市级平台统一接收**投诉、巡查、机构自报**三类线索，
解决同一事件多渠道重复登记、严重线索在普通队列延误两类痛点：系统自动提出**合并建议**与
**优先级建议**，但一律由授权人员（监管人员/复核专家）确认后生效；转派、拆分、临时措施、
延期、结案复开均有状态约束；处置权通过**租约式认领**独占，接口按角色**裁剪敏感证据**，
每次分流均记录**理由与审计轨迹**。

纯 Python 标准库实现，零第三方依赖（Python ≥ 3.11）。

## 目录

- `domain/contract.json`：领域角色、状态、约束和样例。
- `src/domain_contract/`：契约读取与确定性校验。
- `src/clueflow/`：分流处置服务端（存储、领域服务、HTTP API）。
- `tools/check_contract.py`：命令行契约摘要检查。
- `tools/run_server.py`：服务启动入口。
- `tests/`：契约回归 + 领域单元测试 + 端到端 API 测试。

## 快速开始

```bash
# 启动服务（默认 127.0.0.1:8080，SQLite 文件 clueflow.db；--db :memory: 用内存库）
python3 tools/run_server.py --port 8080 --db clueflow.db

# 查看演示账号与接口一览
curl -s http://127.0.0.1:8080/actors
curl -s http://127.0.0.1:8080/
```

演示账号（请求头 `X-Actor-Id` 携带，角色以服务端登记为准）：

| 账号 | 角色 | 说明 |
| --- | --- | --- |
| `u-heliang` | 机构合规员 | 所属机构 `org-hospital-1`，仅可登记机构自报线索 |
| `ZY-3301` | 执业人员 | 仅可见涉及本人的案件，证据裁剪最严 |
| `u-jian-guan-1` / `u-jian-guan-2` | 监管人员 | 分流、认领、处置、确认建议 |
| `u-expert-1` | 复核专家 | 结案复开、延期审批、规则集管理、全量证据 |

### 一条典型流程

```bash
H='-H Content-Type:application/json'
# 1. 登记线索（自动生成指纹、去重扫描、风险初评）
curl -s -X POST localhost:8080/clues $H -H 'X-Actor-Id: u-jian-guan-1' -d '{
  "channel":"投诉","title":"某机构涉嫌非法集资","content":"以养老名义非法集资",
  "subjects":[{"type":"机构","name":"某机构","identifier":"USCC-1"}]}'
# 2. 确认优先级建议 → 3. 分流(triage) → 4. 认领(claim 得 lease_token)
# 5. 核验(verify，需 lease_token) → 6. 决定(decide) → 7. 归档(archive)
# 每一步均可在 GET /cases/{id}/audit 查看理由与轨迹
```

## 设计要点（对应契约约束）

| 契约约束 | 实现 |
| --- | --- |
| 多源线索去重 | 来源指纹（渠道+主体+归一化内容+事发日期哈希）精确命中，或内容词元相似度+主体重合度加权 ≥0.45 时生成**待确认合并建议**；确认后来源案件的线索/主体/证据并入目标案件，来源案件以“并入”结案归档 |
| 风险优先级版本 | 风险规则集整体版本化（`PUT /risk-rules` 递增版本）；每次初评落库规则版本、得分与命中明细，确认/调整后仍可追溯；案件先按建议级别排序（严重线索不滞留），确认后转正 |
| 租约并发认领 | `claim` 发放一次性令牌 + fencing 序号，过期可重新认领；核验、决定、措施、延期申请、处置中拆分/补证据均须持有效令牌，旧持约人令牌自动失效 |
| 敏感证据裁剪 | 证据分 公开/内部/敏感/机密 四级；角色密级 执业人员1、机构合规员2、监管人员3、复核专家4：≤密级全见，密级+1 打码，更高隐藏；主体标识与反映人姓名同步裁剪，联系方式只存哈希 |

### 状态机与操作约束

```
登记 --triage--> 待核验 --verify(租约)--> 处置中 --decide(租约)--> 已决定 --archive--> 已归档
  ^--return-- 待核验                     已决定/已归档 --reopen(仅复核专家)--> 处置中
```

- **转派**：待核验/处置中；持约人本人（校验令牌）或复核专家；转派后租约释放，由接收人重新认领。
- **拆分**：登记/待核验/处置中（处置中需租约）；母案件至少保留一条线索，子案件回登记态重新初评。
- **临时措施**：仅处置中可采取；存在生效中措施时禁止归档。
- **延期**：待核验/处置中由持约人申请，复核专家审批；每周期最多 2 次、单次 ≤30 天；复开后额度重置。
- **结案复开**：仅复核专家，从已决定/已归档回到处置中，重新计时并重新初评。
- **办理时限**：按级别 低30/中15/高7/紧急3 天自周期起算，批准延期顺延；列表支持 `overdue=1` 过滤。

### 审计与分流理由

所有变更操作强制填写 `reason`（系统动作自动生成理由），与操作者、角色、前后状态、
结构化明细一并写入追加式审计表；`GET /cases/{id}/audit` 输出完整轨迹，
合并建议命中信号与初评命中规则即“自动分流的理由”。

## API 一览

认证：除 `GET /` `/health` `/meta` `/actors` 外均需 `X-Actor-Id` 头。错误格式
`{"error":{"code","message"}}`，码：`VALIDATION/UNAUTHORIZED/FORBIDDEN/NOT_FOUND/
STATE_CONFLICT/LEASE_CONFLICT/LEASE_REQUIRED/DOMAIN_VIOLATION`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/clues` | 登记线索（指纹+去重扫描+初评） |
| GET | `/clues` `/clues/{id}` | 线索查询（按可见性过滤） |
| GET | `/cases` | 案件列表（state/priority/assignee_id/overdue/q/limit/offset） |
| GET | `/cases/{id}` | 案件详情（按角色裁剪证据与字段） |
| POST | `/cases/{id}/claim` `/renew` `/release` | 租约认领/续期/释放 |
| POST | `/cases/{id}/transitions` | 状态流转（triage/return/verify/decide/archive/reopen） |
| POST | `/cases/{id}/transfer` | 转派 |
| POST | `/cases/{id}/split` | 拆分 |
| POST | `/cases/{id}/measures` `/measures/{mid}/lift` | 临时措施/解除 |
| POST | `/cases/{id}/extensions` `/extensions/{eid}/decide` | 延期申请/审批 |
| POST/GET | `/cases/{id}/evidence` | 补充证据/按角色裁剪查看 |
| GET | `/cases/{id}/audit` | 审计轨迹 |
| POST | `/cases/{id}/priority/confirm` | 确认或调整优先级建议 |
| GET/POST | `/merge-suggestions` `/merge-suggestions/{id}/confirm` `/reject` | 合并建议处理 |
| GET/PUT | `/risk-rules` | 查看/替换规则集（版本递增，仅复核专家） |
| GET/POST | `/subjects` | 涉及主体查询/登记 |

## 验证

测试命令：`python3 -m unittest discover -s tests -v`

编译命令：`python3 -m compileall -q src tools tests`

命令行检查：`python3 tools/check_contract.py domain/contract.json`
