# 验证记录 · 0.1.0rc1

日期：2026-10-08。此版本是独立 Docker 发布候选，未发布到公共仓库，未部署到真实飞书账号。

## 已执行

- Python 3.12：771 项测试通过，包含离线假数据和仅回环地址的 HTTP 子进程测试
- 实际 Uvicorn 子进程：启动后发送 SIGTERM，退出码为 0、持久化状态为 stopped；使用同一状态再次启动和停止成功
- 覆盖身份/群聊拒绝、启动前旧消息拒绝、无订阅不存储、配置变更撤权、持久化账号绑定、回调 challenge/签名/SSRF、去重、回复不确定状态、可省略 ID 的 pending getter、加密与重启恢复、私有目录权限及不安全退出锁保留
- HTTP 暴露面仅有三个 feishu_* 工具和 feishu.message.received 事件；校验授权、Host、参数边界与错误信息保密
- 新建 Python 3.12 虚拟环境，按运行时锁文件安装，构建并安装 wheel，pip check 成功，CLI --help 成功；不依赖可选飞书 Python SDK
- 官方 CLI 1.0.97 npm 完整性、Linux amd64 发布压缩包 SHA256 和 ELF 二进制摘要经过核对；安装器包含 amd64/arm64 固定压缩包摘要
- 发布文件和 Docker 构建上下文采用白名单；扫描未发现原部署账号标识、认证配置、数据库、密钥或日志

测试出现 3 项依赖警告：可选飞书 SDK 的时间/事件循环弃用提示，以及 MCP 参数类型的 Pydantic 配置提示；没有测试失败。

## 尚未验证

- 当前开发环境没有 docker/podman 命令、Docker daemon 或 socket，故没有实际构建镜像或启动容器
- Windows Docker Desktop / WSL2、Linux Docker 和 NAS 的真实部署尚未执行
- arm64 二进制未在 arm64 主机上运行
- 未连接真实飞书账号、接收真实用户消息或发送回复；未创建线上 MCP 插件/Events 订阅、Tunnel 或 TLS 入口
- GitHub Actions 工作流已提供但未运行，也未推送仓库

先在自己的 Docker 环境执行 README 的构建、自检及本地授权流程，再做真实账户验收。没有把待验证项目写成“已经通过”。
