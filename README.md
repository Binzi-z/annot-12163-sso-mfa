# SSO 验证码重放与会话固定检测

SSO 服务验证码可复用、会话 id 在 MFA 前后不轮换，审计只给结论没给复现。

```
auth/totp.py     TOTP 生成与校验
auth/session.py  会话存储
tests/           20 个用例，其中 4 个是红的
```

## Run

```bash
python -m pytest tests -q
```

## 现状

20 个用例全部通过。四类问题已修复，对应回归用例：

| 用例 | 修复 |
|---|---|
| `test_replay_is_rejected` | `verify` 记录已接受的验证码，重放即拒 |
| `test_session_id_rotates_after_mfa` | `mark_mfa` 轮换会话 id 并返回新 id |
| `test_expired_session_rejected` | `get` 强制 1 小时 TTL，过期即删并抛 `KeyError` |
| `test_compare_is_constant_time` | 新增 `compare_constant_time`（`hmac.compare_digest`），`compare` 委托给它 |

黑盒检测器：`python detector.py` —— 对 4 个攻击探针（与红色用例一一对应）给出可利用性判定与依据，并校验 16 个合法场景零误报；全部通过时退出码为 0。
