"""afrelay -- 审计馈送中继（audit-feed relay）

只增透明度日志的独立镜像与多租户投递服务。中继本身**从不生成任何上游
记录**：它只通过现有 DPGW 网关的只读 HTTP 接口拉取已签名 tree checkpoint
与叶记录（inclusion 文档），独立验签/折根通过后才写入自己的镜像库；
上游不可用、回退高度、坏签名或区间（证明）缺口时停在最后可信位置，恢复
后从该位置续传。

子模块::

  canonical.py  确定性 JSON / HMAC（与 dpgw 规范编码一致，便于离线互验）
  merkle.py     RFC 9162 风格 Merkle 纯函数（叶哈希/折根/包含路径）
  errors.py     稳定错误码与 HTTP 状态
  store.py      独立 SQLite 持久化（镜像、租户、连续提交屏障、窗口租约、事件）
  upstream.py   网关只读接口客户端（只 GET，验不过即抛 UpstreamError）
  relay.py      核心：同步推进、筛选、并行窗口租约/超时接管/完成、
                连续提交屏障（乱序完成补洞一次推进）、拒绝语义
  verify.py     离线投递包校验器（只需 relay 自己的 secrets.json）
  server.py     ThreadingHTTPServer JSON API（租户侧 + 管理侧）
  webui.py      零依赖运维单页（/ui）
  cli.py        命令行

威胁模型：中继是*独立*审计组件，不持有网关写能力，甚至不与网关共享
SQLite；它信任的唯一锚点是机构分发的 ``transparency_secret``（与网关
secrets.json 中同名字段一致），用它独立验证每个 checkpoint 与每片叶子。
"""

from __future__ import annotations

PACKAGE_FORMAT = "afp1"
SCHEMA_VERSION = "afr1"

__all__ = ["PACKAGE_FORMAT", "SCHEMA_VERSION"]
