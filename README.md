# dot2feishu

把本人拥有的飞书机器人私聊接到支持 MCP Events 的 dot。这个目录是独立的 Docker 交付候选版，默认只有一个机器人、一个用户和一个准确的私聊会话。

**Docker 只负责运行桥接服务。它不会创建 dot、登录 ChatGPT、开通 MCP Events、替你申请机器人权限或自动打通公网入口。** 真实连通还需要应用所有者完成飞书授权，以及支持该事件协议和认证方式的 dot 宿主。

## 工作方式和范围

```text
本人向指定飞书机器人发送文本
  → 固定版本的飞书官方 CLI，以 bot 身份接收
  → dot2feishu 校验身份与私聊绑定，写入本地加密状态
  → 向 dot 宿主提供的已验证 HTTPS 回调发送签名事件
  → 当前 dot 读取消息，按用户授权调用原消息回复工具
  → 机器人回复同一条原始私聊消息
```

- 事件：`feishu.message.received`
- 工具：`feishu_get_message`、`feishu_reply_to_message`、`feishu_bridge_status`
- 只接收已核验用户在已核验私聊中的新文本；群聊、其他人、其他会话、机器人消息和附件不在范围内
- 不提供任意收件人、任意 CLI 命令、任意 API 请求或通用执行工具
- MCP Events 使用协议 `2026-07-28`，Python MCP SDK 固定为 `2.3.0`
- 无需模型 API Key；模型和对话由支持事件订阅的 dot 宿主提供

## 先确认三件事

1. **飞书侧**：你拥有或有权管理该应用，已启用机器人、`im.message.receive_v1` 长连接订阅及所需的最小收发权限；权限和版本发布由所有者在飞书官方平台核对。不要为了省事授权全部权限
2. **dot 侧**：实际账号/工作区支持 MCP Events，并能连接你的私有 MCP 服务、接受这里使用的 bearer 认证。普通 MCP 工具可用，不代表事件订阅也可用；这个服务不是 OAuth 授权服务器。参见 [官方 MCP Events 文档](https://developers.openai.com/plugins/build/mcp-events)
3. **网络侧**：有经你批准的 HTTPS 入口，可转发到本机回环端口；容器能向飞书及已核验回调地址出站。入口必须兼容 MCP 请求头和认证，不能把服务裸露到公网

应预先取得并核验：应用 App ID、机器人 Open ID、本人在此应用下的 Open ID、tenant key、该用户与该机器人之间的准确 chat ID、宿主提供的回调主机名、你自己的 HTTPS MCP 域名。不能用另一个机器人的私聊 ID，也不能把用户 OAuth 身份当成机器人身份。官方 CLI 处理后的消息不携带完整 app/tenant 信封，因此 tenant key 仍是所有者需要独立核验的部署事实。

## 快速开始

以下命令在项目目录中由所有者自己的终端执行。不会在构建时使用账号信息，也不会要求把密钥交给对话。

### 1. 准备 Docker

- Windows：使用 Docker Desktop，启用 WSL 2 后端，切到 Linux containers；可在 PowerShell 或 WSL 终端运行下面相同的 `docker compose` 命令。Docker Desktop 和 WSL 应保持运行，电脑休眠或关机会中断接收
- Linux：安装官方 Docker Engine 和 Compose v2，先检查 `docker version` 与 `docker compose version`
- NAS：需要 Linux 容器及 Compose 支持；安装器提供 `linux/amd64` 和 `linux/arm64`，不支持 32 位 ARM。NAS 的可用内存、容器权限和系统限制仍需实机验证

参考：[Docker Desktop / WSL 2](https://docs.docker.com/desktop/features/wsl/)、[Docker Engine 安装](https://docs.docker.com/engine/install/)。Docker 管理权限可访问容器数据，应只交给受信任的管理员。

### 2. 构建不含凭据的镜像

```sh
docker compose build
```

构建需要访问 Docker Hub、Python 包索引、npm 官方 registry 和飞书 CLI 官方 GitHub Release。服务默认发布 `127.0.0.1:8765`。若该端口被占用，可把 `.env.example` 复制为 `.env`，仅修改 `DOT2FEISHU_PORT`；容器内部仍使用 8765。

`.env` 不用于保存任何秘密。不要把 App Secret、bearer、回调签名密钥或存储密钥写进 Dockerfile、Compose、构建参数、命令行或仓库。

### 2a. 先做完全不使用账号的容器冒烟测试

在任何输入凭据之前执行：

```sh
docker compose config --quiet
docker run --rm --network none dot2feishu:local --help
docker run --rm --network none --entrypoint /usr/local/bin/lark-cli dot2feishu:local --version
docker run --rm --network none --entrypoint /bin/sh dot2feishu:local -ec 'test "$(id -u)" = 10001; test "$(stat -c %a /data)" = 700; test "$(stat -c %u /data)" = 10001; test ! -L /usr/local/bin/lark-cli; test ! -w /usr/local/bin/lark-cli; sha256sum --check /usr/local/share/dot2feishu/lark-cli.sha256'
```

预期：Compose 校验成功、显示 setup/doctor/serve 用法、CLI 版本为 1.0.97、最后一个命令退出码为 0。这里的容器断网，不挂载已有生产卷，不登录飞书，不连接 dot，也不发送消息。这只证明镜像基本运行条件；不能代替下面的真实链路验收。

首次真实联调请使用单独的测试机器人、测试私聊和隔离的 dot 测试连接。另建项目目录及 Compose 项目名，绝不能复用已有生产数据卷或同时为同一个机器人启动第二个监听器。真实授权和测试发送由所有者明确确认后再做。

### 3. 所有者在本地授权自己的机器人

用官方 CLI 的交互式配置，把 `YOUR_APP_ID` 替换成你自己的非秘密 App ID：

```sh
docker compose run --rm --entrypoint /usr/local/bin/lark-cli bridge config init --name YOUR_APP_ID --brand feishu
```

在引导中选择已有应用，核对 App ID，再按官方提示由所有者在自己的终端输入 App Secret。不要使用 `--new` 自动创建另一个应用，不要在聊天中粘贴密钥，也不要用 `echo SECRET` 把密钥写入 shell 历史。CLI 的 profile 名称必须与 App ID 完全相同。

官方 CLI 的配置和凭据留在本项目专用数据卷，桥接代码不解析或导出它们。该容器不挂载 Windows、macOS 或 NAS 上其他应用的登录目录。本桥接只用 bot 身份，不要求 `auth login --recommend` 获取个人用户的广泛 OAuth 权限。

所有者可做以下只读身份核对，它们会访问飞书：

```sh
docker compose run --rm --entrypoint /usr/local/bin/lark-cli bridge --profile YOUR_APP_ID whoami --as bot
docker compose run --rm --entrypoint /usr/local/bin/lark-cli bridge --profile YOUR_APP_ID api GET /open-apis/bot/v3/info --as bot
```

只在本地检查输出；确认应用、profile、Feishu 品牌、bot 身份和机器人 Open ID 一致。如果 CLI 不能在目标主机保存或读取凭据，应先排查官方 CLI 的本地凭据存储，不能改成用用户令牌绕过机器人身份校验。

### 4. 初始化单用户绑定

```sh
docker compose run --rm bridge setup
docker compose run --rm bridge doctor
```

`setup` 会依次询问五个身份/私聊标识、本地所有者标签、准确的回调主机名和 HTTPS 入口主机名。主机名不含 `https://` 或路径；回调不支持通配符。CLI 路径直接回车使用 `/usr/local/bin/lark-cli`。

还需通过不回显输入交给服务一个由所有者选定的高随机性 MCP bearer，至少 32 字节。可使用自己的密码管理器生成并保管，再经宿主支持的安全配置界面录入同一个值。不要把 bearer 放入 URL 查询参数或聊天。`setup` 在本地另行生成存储加密密钥，不会显示秘密。

仅当飞书授权、身份绑定和安全入口都已确认时，对启用问题输入 `YES`。否则保持停用，待核对完毕再由所有者在服务停止时安全修改 `/data/config.json` 的 `enabled` 字段。`setup` 不覆盖已有配置或状态；不要用删卷的方式重跑它。

`doctor` 是离线检查：核对配置、权限、原生 CLI 哈希和状态存储。输出 `ok: true` **不表示**飞书授权、HTTPS、订阅或 dot 收信已经通过。

### 5. 启动与停止

```sh
docker compose up -d
docker compose logs --tail 100 bridge
docker compose stop
```

第三行用于需要停止服务时执行。容器内 Python 以前台进程运行，Docker init 负责信号与子进程回收；正常停止最多等待 60 秒。桥接先关闭 CLI 消费器 stdin，必要时再终止子进程。

Compose 默认 `restart: "no"`。这是有意的：非正常退出可能留下不确定的接收/发送状态，不能用无限重启掩盖问题。宿主重启后需要所有者核对状态并手动启动；目前不提供自动开机恢复保证。一次 `docker compose up -d` 成功也不能证明完整链路已连通。

### 6. 配置 HTTPS 并连接当前 dot

Compose 只发布回环地址。在你自己的主机上配置经批准的 TLS 反向代理或宿主支持的安全 MCP 入口，转发到 `http://127.0.0.1:8765/mcp`，对外提供 HTTPS `/mcp` 地址。默认目录不附带公网隧道，也不自动开放端口。

- 保留 `Authorization` 和 MCP 协议请求头；避免代理把 Host 改成未列入 `mcp_http_hosts` 的值
- 配置准确的 Host 允许列表，保留服务端 bearer 检查；关闭请求正文和认证头日志
- 如果代理在另一个容器里，那个容器的 `127.0.0.1` 不是本服务。应明确设计私有容器网络，不能直接把端口改成所有接口公开
- 禁止用 HTTP 公网入口、跳过证书校验或未经核验的回调域名来凑通链路

在当前 dot 使用的账号/工作区，通过实际支持的私有插件连接方式注册该 HTTPS MCP 地址和认证。检查 `server/discover`、`events/list` 与 `events` capability，再明确告诉当前 dot 监控这个私聊以及允许怎样回复。

由宿主发起 `events/subscribe`，提供回调 URL 和签名密钥；桥接会校验精确主机名并验证签名挑战。**不要自己编造 ChatGPT 回调地址、订阅、会话 ID 或签名密钥。** 若当前宿主没有提供这些能力，部署会停在这里；容器不能替宿主创建它们。

## 上线前验收

完成这些检查前，应把结果标为“未验证”，不能称为已接通：

1. 正确机器人、本人和准确私聊均已核验，CLI 明确以 bot 身份运行
2. HTTPS 入口和认证正常，未授权请求被拒绝
3. MCP Events 发现、签名挑战、有限期限订阅均成功
4. 本人发一条新文本后，当前 dot 真正收到事件并读到对应消息
5. 经授权的回复出现在该原消息下，身份是指定机器人
6. 重复事件、重复调用不产生重复回复；不确定的发送保持阻断
7. 其他用户、群聊、另一私聊、机器人和附件不进入待处理消息
8. 正常停止、重启、订阅到期、取消订阅和停用开关符合预期

`feishu_bridge_status` 可查看监听状态、订阅数、收发计数和有限的待处理元数据。工具成功响应、回调 HTTP 成功或离线测试通过，都不能单独证明“当前 dot 已收到并处理”。真实飞书发送与凭据配置不在自动测试中运行。

## 交付边界：先读这一节

- **CLI ACK 空窗**：上游可能已经确认飞书事件，而 Python 尚未提交 SQLite。此时崩溃或断管可能丢消息；不能保证端到端不丢失
- **只处理在线新消息**：订阅使用 `cursor: null`，无历史补拉承诺。停机、断网、没有有效订阅时，不能把遗漏消息当成稍后一定会补到
- **不确定回复默认阻断**：如果发送超时或进程在发送期间异常退出，即使飞书可能已发送成功，也不自动重发。先由所有者检查原始会话并核对记录；不要通过清库、换 key 或新建容器状态绕过阻断
- **不是多用户服务**：不共享数据卷，不用多个副本读取同一绑定，不从外部请求修改目标 chat ID。更换机器人、用户或绑定需要单独审查和迁移
- **入口不是 OAuth 服务**：宿主若只接受当前项目未实现的认证方式，需要先解决正式集成，不能去掉认证
- **宿主协议会变化**：本实现对已固定的协议/SDK做检查，不代表所有 MCP 客户端都支持它

## 数据与运维

专用 Docker named volume 挂载 `/data`，由 UID/GID `10001:10001` 持有；目录权限 `0700`，私有状态文件 `0600`。不需要把凭据 bind mount 到项目目录。

- `/data/config.json`：绑定、允许列表、CLI 原生哈希和启停开关
- `/data/mcp-bearer`：入口认证凭据
- `/data/config`、`/data/data`：官方 CLI 独立配置及数据
- `/data/bridge-state`：加密消息/回调状态、SQLite 和存储密钥

消息与回调秘密的落盘加密不能抵挡同时拿到数据卷和密钥的主机管理员。请限制 Docker 管理权限，按需启用宿主磁盘/备份加密；不要公开分享卷备份、数据库或日志。详见 [SECURITY.md](SECURITY.md)。

正常停止并确认没有进程写入后再做一致性卷备份；保留数据库和对应密钥，备份也按凭据保护。不要只复制正在写入的 SQLite 主文件而漏掉 WAL。恢复时保留原 UID/GID 和权限，先离线检查，再核对是否有不确定发送。`docker compose down` 保留数据卷；**`docker compose down -v` 会删除该项目数据卷，请勿把它当作普通重启步骤。**

### 常见问题

- **构建下载失败**：确认官方 registry、GitHub Release、Docker Hub 和 Python 索引可达；检查企业代理和 CA。校验和不一致必须停止，不要关闭校验或换不明二进制
- **权限检查失败**：先确认用了默认 named volume；不要使用 `chmod 777`。已有错误所有权的数据卷需由所有者离线审查修复
- **CLI 身份失败**：检查 profile 是否等于 App ID、品牌是否为 Feishu、bot 是否激活、Open ID 是否匹配及必要权限是否生效
- **回调不成功**：核对实际宿主给出的准确域名、DNS、公网 HTTPS 出站、签名挑战和订阅期限；不要放开通配域名
- **改了端口**：`.env` 只改宿主映射；代理目标相应修改，容器仍是 8765
- **CLI 更新后拒绝启动**：默认镜像禁止运行时自更新；升级需重审固定版本、发布包哈希和绑定的二进制哈希，再做离线检查与实际验收
- **异常退出后无法重启**：这是安全阻断。保留卷和记录，核对是否还有消费器或未确认发送，再决定恢复方式。此版本不提供自动清除不确定状态的捷径

## 构建与校验说明

Docker build context 采用拒绝默认、逐项允许的清单，仅含包内 Python 文件、项目元数据、运行依赖锁和构建安装器。凭据、历史状态、测试夹具和项目外文件不会进入镜像。

`@larksuite/cli@1.0.97` 的 npm 入口实际是 `scripts/run.js`；它可能自动下载二进制。镜像不运行该 launcher，而是从官方 Release 安装同一版本的原生 ELF 到 `/usr/local/bin/lark-cli`：

- npm 压缩包先与仓库固定的 SHA-512 完整性值核对
- 原生 Linux 发布包同时匹配固定 SHA-256 和该 npm 包内的官方校验清单
- 只选取预期的普通文件，不执行 npm 生命周期脚本
- 原生文件为 root 所有、只读可执行；原生哈希写入 `/usr/local/share/dot2feishu/lark-cli.sha256`
- 保留上游许可证于 `/usr/local/share/dot2feishu/lark-cli-LICENSE`

发布包 SHA-256：

```text
linux/amd64  7ce11848724f0b0bc8204012140adbf76fe7c1fc8abd41c1878bc97b7228126b
linux/arm64  2dec3e362ecce05b535854a0205035bb4ccdb72dbbed9a321890c2089da16bc5
```

来源：[官方 npm 包](https://www.npmjs.com/package/@larksuite/cli/v/1.0.97)、[官方 v1.0.97 Release](https://github.com/larksuite/cli/releases/tag/v1.0.97)、[官方安装脚本](https://github.com/larksuite/cli/blob/v1.0.97/scripts/install.js)。基础镜像使用 Python 3.12 的可更新标签；Python 运行依赖固定版本但尚未逐包加哈希，因此本候选版不是完全可复现构建，也不是已完成供应链审计的发行版。

本地开发测试：

```sh
python -m venv .venv
# 激活虚拟环境后执行：
python -m pip install -r requirements-test-lock.txt
python -m pip install --no-deps -e .
python -m pytest -q
```

GitHub Actions 工作流仅做离线测试、镜像构建和断网 smoke test，不登录飞书、不订阅真实事件、不发送消息、不发布镜像。尚未在真实 CI 中运行该工作流。

本次打包环境没有 Docker CLI、Docker daemon/socket 或 Podman，**未在此处构建、启动或实测 Docker 镜像**；Windows、NAS 和 arm64 容器尚待实机验收。已核验 Linux amd64 官方发布包及原生文件；离线应用测试结果见 [VALIDATION.md](VALIDATION.md)。

## 许可证

本项目许可证待所有者选择，目前不添加或宣称已授予某个开源许可证。随镜像分发的上游组件继续适用各自许可证；正式公开发布前还应检查其再分发义务。
