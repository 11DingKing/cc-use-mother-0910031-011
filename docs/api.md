# HTTP 接口说明

- Base URL：`http://127.0.0.1:8080`
- 除 `GET /healthz`、`POST /api/auth/login` 外，均需请求头 `Authorization: Bearer <token>`。
- 请求/响应均为 `application/json; charset=utf-8`；时间为 ISO 8601 UTC（`...Z`）。
- 错误结构：`{"error": "<code>", "message": "...", "details": {...}}`，状态码 `400/401/403/404/409/500`。

## 认证与账号

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | - | `{username,password}` → `{token,expires_at,user}` |
| POST | `/api/auth/logout` | 已登录 | 注销当前令牌 |
| GET | `/api/me` | 已登录 | 当前账号信息 |
| GET | `/api/roles` | 已登录 | 角色清单与各角色证据敏感度上限 |
| POST | `/api/users` | 分流管理员 | `{username,password,display_name,role}` |
| GET | `/healthz` | - | 健康检查 |

## 风险规则（版本化）

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/rules?version=` | 已登录 | 读取指定版本；缺省读最新版 |
| GET | `/api/rules/versions` | 已登录 | 版本列表（发布人、时间、条数） |
| POST | `/api/rules/versions` | 分流管理员/监管人员 | 发布**新版本**（旧版本不可变） |

发布体：

```json
{
  "note": "v2 加重群体性事件",
  "rules": [
    {
      "rule_key": "group-event",
      "title": "群体性事件",
      "condition": {"field": "title_desc", "op": "contains_any", "value": ["群体性", "中毒"]},
      "add_score": 70,
      "suggest_priority": "特急"
    }
  ]
}
```

条件支持的算符：`== != > >= < <= in not_in contains_any`，并支持 `{"all":[...]}`、`{"any":[...]}`、`{"not":{...}}` 组合。
可用事实字段：`source_channel`、`title_desc`、`subject_type`、`region`、`has_sensitive_evidence`、`evidence_count`。

## 线索登记与查询

### POST `/api/clues`（机构合规员/监管人员）

```json
{
  "source_channel": "投诉",                 // 投诉 | 巡查 | 机构自报
  "source_ref": "TS-2026-0001",             // 渠道内文号
  "title": "某诊所涉嫌伪造病历骗取医保",
  "description": "……",
  "occurrence_at": "2026-10-01T09:00:00Z",
  "region": "城东区",
  "subject_type": "机构",                    // 机构 | 人员
  "subject_name": "康某诊所",
  "subject_identifier": "91330100MA0000001X",
  "reporter_contact": "138****1234",        // 选填，按敏感字段处理
  "evidences": [                            // 选填；机构端只能提交“普通”
    {"label": "投诉录音", "content_ref": "oss://bucket/a", "sensitivity": "敏感", "kind": "录音"}
  ]
}
```

响应 `201`（新登记）：

```json
{
  "duplicate": false,
  "clue_id": 12,
  "clue_no": "XS-20261004-0012",
  "risk_score": 65,
  "suggested_priority": "紧急",
  "risk_hits": [{"rule_key": "fraud-keyword", "title": "欺诈伪造关键词", "add_score": 35, "suggest_priority": "紧急"}],
  "merge_suggestions": [{"primary_id": 7, "duplicate_id": 12, "score": 0.92, "reason": "发生日期相同、标题相似度 88%"}]
}
```

同指纹重复登记返回 `200` 且 `duplicate=true`（幂等，不新建）。

### GET `/api/clues`

查询参数：`state`（逗号分隔多状态）、`priority`、`source_channel`、`subject_identifier`、`q`、`overdue=1`、`mine=1`、`include_merged=1`、`limit`、`offset`。
默认不含已合并件；排序：逾期优先 → 已确认优先级 → 时限最近。

### GET `/api/clues/{id 或 clue_no}`

线索详情，内嵌：建议/确认优先级与理由、风险命中与规则版本、时限与延期记录、当前租约、**按角色裁剪后的证据**、临时措施、延期、合并建议、母子线索、完整 `audit_trail`。

越权证据示例（机构合规员视角）：

```json
{"evidence_id": 3, "kind": "录音", "sensitivity": "敏感", "redacted": true,
 "redact_reason": "证据敏感度超出当前角色可见范围"}
```

## 合并建议（人工确认）

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/merge-suggestions?status=待确认` | 分流管理员/监管人员/复核专家 | 待确认/已确认/已驳回 |
| POST | `/api/clues/{ref}/rescan-duplicates` | 同上 | 人工触发重新查重 |
| POST | `/api/merge-suggestions/{id}/confirm` | 分流管理员/监管人员 | `{reason}`：重复件并入主件、释放其租约、状态置已归档 |
| POST | `/api/merge-suggestions/{id}/reject` | 分流管理员/监管人员 | `{reason}`：驳回，两条均保持在办 |

约束：已归档/已决定线索不能合并；已处理建议不能重复操作；合并归档件不可复开（须在主件上继续处置）。

## 优先级与时限（人工确认）

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/clues/{ref}/priority` | 分流管理员/监管人员 | `{priority,reason,deadline_hours?}` |
| POST | `/api/clues/{ref}/rescale-risk` | 分流管理员/监管人员/复核专家 | 按最新规则版本重新评分 |

- `priority`：`低/中/高/紧急/特急`；默认时限 240/120/72/48/24 小时。
- 仅 `登记/待核验` 可确认；首次确认后线索进入 `待核验` 并起算时限。

## 受理、租约与处置

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/clues/{ref}/accept` | 监管人员/复核专家 | 登记 → 待核验（仅受理，未起算时限） |
| POST | `/api/clues/{ref}/claim` | 监管人员/复核专家/分流管理员 | 租约式认领，返回 `lease_token` 与到期时间 |
| POST | `/api/clues/{ref}/renew-lease` | 持有人/分流管理员 | 续租 |
| POST | `/api/clues/{ref}/release` | 持有人/监管人员/分流管理员 | `{reason}` 释放租约 |
| POST | `/api/clues/{ref}/assign` | 分流管理员/监管人员 | `{assignee_id,reason}`：无租约为分派，有租约为**转派（理由必填）** |
| POST | `/api/clues/{ref}/verify` | 持租约的监管/复核 | 待核验 → 处置中 |
| POST | `/api/clues/{ref}/split` | 分流管理员/监管人员/复核专家 | `{children:[{title,description?,evidence_ids?}]}` |
| POST | `/api/clues/{ref}/measures` | 监管人员/复核专家/分流管理员 | `{measure_type,detail}` 采取临时措施 |
| POST | `/api/measures/{id}/lift` | 监管人员/分流管理员 | `{reason}` 解除措施（只能一次） |
| POST | `/api/clues/{ref}/extensions` | 监管人员/复核专家/分流管理员 | `{hours,reason}` 申请延期 |
| GET | `/api/extensions?status=` | 监管人员/分流管理员 | 延期申请列表 |
| POST | `/api/extensions/{id}/decision` | 监管人员/分流管理员 | `{approve:bool,comment}` 审批 |
| POST | `/api/clues/{ref}/evidence` | 机构合规员（仅普通）/监管/复核 | 补充证据并刷新建议评分 |

### 结案与归档

| 方法 | 路径 | 角色 | 迁移 |
| --- | --- | --- | --- |
| POST | `/api/clues/{ref}/close` | 监管人员/复核专家/分流管理员 | 处置中 → 已决定 |
| POST | `/api/clues/{ref}/archive` | 监管人员/分流管理员 | 已决定 → 已归档 |
| POST | `/api/clues/{ref}/reopen` | 分流管理员/监管人员 | 已归档 → 处置中（理由必填；合并归档件除外） |

结案体：`{"decision": "属实立案|不予立案|责令整改|移送司法|驳回投诉", "summary": "处置摘要"}`。
结案前置：无生效中临时措施、无待审批延期、处置中状态、租约不被他人持有（管理员除外）。

## 审计

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/audit?clue={ref}&limit=100` | 全量或单线索审计轨迹（倒序） |

每条记录：`actor/actor_role/action/from_state/to_state/reason/detail/created_at`。
主要 action：`clue.register, clue.register_duplicate, merge.suggest, merge.confirm, merge.reject,
priority.confirm, risk.rescale, rules.publish, clue.accept, clue.claim, clue.renew, clue.release,
clue.assign, clue.transfer, clue.verify, clue.split, evidence.add, measure.create, measure.lift,
extension.request, extension.approve, extension.reject, clue.close, clue.archive, clue.reopen`。
