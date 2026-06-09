# 🛡️ BackdoorScan - 服务器后门扫描

批量检测 Linux 服务器后门隐患，支持 SSH 远程连接、多维度检测、实时进度和报告导出。

![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

## 功能特性

🔍 检测项目（20 项）

| 类别            | 检测项             | 说明                                                 |
| --------------- | ------------------ | ---------------------------------------------------- |
| 🌐 network       | suspicious_port    | 异常端口检测（6666/7777/8888 等常用后门端口）        |
| 🌐 network       | network_connection | 异常网络连接（TIME_WAIT/CLOSE_WAIT）                 |
| 🌐 network       | network_interface  | 异常网络接口（混杂模式网卡）                         |
| ⚙️ process       | suspicious_process | 可疑进程（nc/netcat 反弹shell）                      |
| ⚙️ process       | hidden_process     | 隐藏进程检测                                         |
| ⏰ persistence   | cron_job           | 定时任务后门检测（curl                               |
| ⏰ persistence   | ssh_key            | SSH authorized_keys 后门检测                         |
| ⏰ persistence   | sshd_config        | SSH 配置异常（ PermitRootLogin/AllowTcpForwarding ） |
| ⏰ persistence   | suid_file          | SUID 后门文件检测                                    |
| ⏰ persistence   | temp_file          | 临时目录可疑文件                                     |
| ⏰ persistence   | startup_service    | 开机启动可疑服务                                     |
| ⏰ persistence   | system_user        | 异常系统用户                                         |
| 📜 investigation | bash_history       | 历史命令异常（可疑网络行为）                         |
| 📜 investigation | env_abnormal       | 异常环境变量（LD_PRELOAD 等）                        |
| 🦠 malware       | rootkit            | Rootkit 典型特征                                     |
| 🦠 malware       | malware_file       | 恶意文件模式（eval base64 等）                       |
| 🔐 security      | selinux_status     | SELinux/AppArmor 状态                                |
| 🔐 security      | firewall_status    | 防火墙状态检测                                       |
| 📁 integrity     | file_integrity     | 系统关键文件完整性                                   |
| 📡 service       | sshd_status        | SSH 服务运行状态                                     |

✨ 核心功能

- **批量检测** - 同时检测多台服务器，支持暂停/继续/停止
- **实时进度** - 显示当前服务器、当前检测项、完成的百分比
- **SSH 连接** - 支持密码认证，自动获取系统信息
- **报告导出** - 支持 HTML / JSON / TXT 三种格式
- **数据持久化** - SQLite 数据库存储服务器列表和检测结果
- **去重解析** - 相同 IP:端口 的服务器会覆盖而非重复添加

## 项目结构

```
BackdoorScan/
├── backend/
│   ├── main.py              # aiohttp API 服务器 + CLI
│   ├── models.py            # 数据模型（Server/DetectionResult）
│   ├── detector.py          # 检测引擎
│   ├── detector_commands.py # 检测命令定义
│   ├── ssh_manager.py       # SSH 连接管理
│   ├── database.py          # SQLite 持久化
│   └── report_generator.py # 报告生成
├── frontend/
│   └── index.html           # Web界面
├── data/                    # SQLite 数据库目录
├── requirements.txt
└── README.md
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

所需依赖：

- `aiohttp` -异步 HTTP 服务器
- `asyncssh` - 异步 SSH 客户端
- `pycares` - DNS 解析器

### 2. 启动后端服务

```bash
cd backend
python main.py
```

默认监听 `http://127.0.0.1:8765`，WebSocket 端点 `ws://127.0.0.1:8765/ws`

### 3. 打开前端

直接在浏览器打开 `frontend/index.html`，修改顶部右上角的 API 地址（默认 `http://127.0.0.1:8765`），点击"连接后端"即可。

### 4. 使用流程

1. **解析服务器** - 在左侧文本框输入服务器信息，格式：

   ```
   IP,用户名,密码
   IP:端口,用户名,密码
   ```

   示例：

   ```
   192.168.1.10,root,password123
   192.168.1.11:2222,admin,secret456
   ```

2. **测试连接** - 可单独或批量测试 SSH 连接

3. **开始检测** - 选择要检测的服务器，点击开始，支持暂停/继续/停止

4. **查看结果** - 检测结果按服务器显示，分为安全/可疑/危险三档

5. **导出报告** - 选择格式导出检测报告

## API 接口

| 接口                          | 方法      | 说明               |
| ----------------------------- | --------- | ------------------ |
| `/api/parse_servers`          | POST      | 解析服务器列表     |
| `/api/test_connection`        | POST      | 测试单个服务器连接 |
| `/api/test_all_connections`   | POST      | 批量测试连接       |
| `/api/start_detection`        | POST      | 开始检测           |
| `/api/pause_detection`        | POST      | 暂停检测           |
| `/api/resume_detection`       | POST      | 继续检测           |
| `/api/stop_detection`         | POST      | 停止检测           |
| `/api/get_progress`           | POST      | 获取进度           |
| `/api/get_servers`            | POST      | 获取服务器列表     |
| `/api/get_results`            | POST      | 获取检测结果       |
| `/api/delete_servers`         | POST      | 删除服务器         |
| `/api/delete_results`         | POST      | 删除检测结果       |
| `/api/export_report`          | POST      | 导出报告           |
| `/api/rerun_detection`        | POST      | 重新检测           |
| `/api/get_detection_commands` | POST      | 获取检测命令列表   |
| `/ws`                         | WebSocket | WebSocket 实时推送 |

## CLI 模式

```bash
#解析服务器
python main.py parse --text "192.168.1.10,root,pass" --port 22

# 测试连接
python main.py test

# 执行检测
python main.py detect --servers-text "192.168.1.10,root,pass"

# 导出报告
python main.py export --format html
```

## 数据库结构

- **servers** - 服务器列表（id/ip/port/username/password/status/os_info/arch）
- **detection_results** - 检测结果（server_id/timestamp/overall_status/score/items_json）

## 注意事项

1. **只读检测** - 所有检测命令均为只读操作，不会对服务器造成修改
2. **SSH 权限** - 需要目标服务器允许 SSH 密码登录
3. **防火墙** - 确保目标服务器 SSH 端口（默认 22）可访问
4. **超时设置** - 默认 SSH 连接超时 60 秒，可通过 `ssh_manager.py` 修改
5. **批量限制** - 默认最大并发 10 个 SSH 连接，可通过 `create_ssh_manager(max_connections=N)` 调整

## 技术栈

- **后端**: Python 3.8+ / aiohttp 4.x / asyncssh
- **前端**: 原生 HTML/CSS/JavaScript（无框架依赖）
- **数据库**: SQLite
- **通信**: REST API + WebSocket

## License

MIT
