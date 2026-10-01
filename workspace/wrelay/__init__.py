"""wrelay -- 并行窗口审计中继（parallel-window relay）。

同一审计租户可以**并行**持有多个互不重叠的相邻数据窗口，而不必等上一个
窗口确认后才发放下一个。中继把原序区间 ``[start_offset, end_offset)``
租给不同 worker；靠后的窗口先完成时只登记 *完成事实*，对外可见的
**连续提交屏障（commit barrier）** 必须等前面的空洞补齐后才一次推进
连续前缀。

核心不变量：

* 窗口边界是 (租户, 窗口大小, 序号) 的确定性纯函数；超时重投、进程
  重启后重新领取返回**同一 window_id 与逐字节相同的原始字节**；
* 每个窗口带单调 ``lease_epoch``（栅栏令牌）：超时被新 worker 接管后
  epoch +1，旧持有者随后的提交一律 ``stale_lease`` 拒绝；
* 重复提交幂等且不重复推进屏障；越过窗口末端、跨租户 window_id、
  租户停用、在途期间筛选规则变更都不能推进提交点；
* ``max_inflight`` 可动态收缩，但收缩**绝不抢占**仍有效的持有者，只
  阻止继续领取新窗口；
* 单个慢窗口只挡住它自己正前方的连续前缀，不挡同租户后续窗口，也不
  挡其他任何租户；
* 所有窗口区间/持有者/完成状态/连续屏障/空洞/重试次数对 HTTP、CLI
  与运维页可见；全部状态落 SQLite，重启恢复窗口边界、完成记录与提交
  顺序。

零第三方依赖，仅用 Python 3.11 标准库。

子模块::

  canonical.py  确定性 JSON / HMAC
  errors.py     稳定错误码 + HTTP 状态 + 拒绝归类
  store.py      独立 SQLite 持久化（流/租户/窗口租约/事件）
  relay.py      核心：窗口切分、租约/接管、提交、补洞推进屏障
  server.py     ThreadingHTTPServer JSON API（租户侧 + 管理侧）
  webui.py      零依赖运维单页（/ui）
  app.py        home 引导/密钥/打开 Relay
  cli.py        命令行
"""

from __future__ import annotations

PACKAGE_FORMAT = "afw1"
SCHEMA_VERSION = "wfr1"

__all__ = ["PACKAGE_FORMAT", "SCHEMA_VERSION"]
