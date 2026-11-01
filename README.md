# jenkins-atom-splunk-hec

把一次构建事件发给 Splunk 的 HTTP Event Collector，并**读它的判定**。

splunk-devops 就是往 `/services/collector/event` 发一个带 `Splunk <token>` 头的请求；这里把那层信封写清楚：

```json
{"event": {"job": "acme/api", "build": "42", "result": "SUCCESS"},
 "time": "1793417238", "sourcetype": "jenkins", "source": "jenkins"}
```

**关键点：HEC 拒绝事件时也回 HTTP 200**，判定在响应体的 `code` 里（0 = 收下，其余 = 拒绝）。
只看状态码的发送器会把被丢掉的事件报成成功——这里 `code != 0` 直接失败并带上 Splunk 的原文。

- 不填 `event` 时，用 runner 给的构建事实（job / build / result / url / duration）组事件，开箱可用
- `mode=raw` 走 `/services/collector/raw`，把 `event` 当纯文本索引
- token 被拒（401/403 或 code 4）归 `USER`，其余拒绝归 `THIRD_PART`

```bash
./build.sh && ./tools/smoke.sh
```
