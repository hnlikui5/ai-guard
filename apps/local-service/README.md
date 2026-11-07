# apps/local-service

本地后台守护与业务编排服务。

## 模块职责

- 作为桌面端（`apps/desktop`）与底层核心包（`packages/*`）之间的本地宿主服务层
- 暴露统一的本地 IPC / HTTP / WebSocket 控制接口（仅绑定本地回路或受控通道）
- 协调 `agent-adapters`、`security`、`session`、`backup`、`storage` 模块的生命周期
- 处理 Windows 与 WSL2 环境之间的路径映射、进程探测与事件转发
- 记录本地安全审计流水与运行日志

## 架构约束

- 默认仅监听本地受信任通道，拒绝未授权的外部网络访问。
- 保持模块化单体结构，不引入外部消息队列或重型微服务组件。
