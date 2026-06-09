"""
BackdoorScan - 服务器后门扫描 - 主入口
支持HTTP API服务器模式和CLI模式
"""

import asyncio
import json
import sys
import signal
import logging
import argparse
from typing import Dict, Any, List, Optional
from datetime import datetime
from aiohttp import web
from aiohttp.web import middleware

from models import Server, ServerStatus, DetectionResult, BatchProgress
from ssh_manager import SSHConnectionManager, create_ssh_manager
from detector import BackdoorDetector, create_detector
from report_generator import ReportGenerator
from detector_commands import get_all_detection_commands, get_commands_by_category
from database import get_database

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class BackendService:
    """后端服务主类"""

    def __init__(self):
        self.ssh_manager: Optional[SSHConnectionManager] = None
        self.detector: Optional[BackdoorDetector] = None
        self.servers: Dict[str, Server] = {}
        self.results: Dict[str, DetectionResult] = {}
        self.progress = BatchProgress()
        self._running = False
        self.db = get_database()

    async def initialize(self):
        """初始化服务"""
        logger.info("初始化后端服务...")
        self.ssh_manager = await create_ssh_manager(max_connections=10)
        self.detector = await create_detector(self.ssh_manager)
        # 从数据库加载已有结果
        self._load_results_from_db()
        self._load_servers_from_db()
        logger.info("后端服务初始化完成")

    def _load_servers_from_db(self):
        """从数据库加载服务器列表"""
        try:
            db_servers = self.db.get_all_servers()
            for s in db_servers:
                server = Server(
                    id=s['id'],
                    ip=s['ip'],
                    port=s.get('port', 22),
                    username=s.get('username', ''),
                    password=s.get('password', ''),
                    status=ServerStatus(s.get('status', 'pending')) if isinstance(s.get('status'), str) else s.get('status', ServerStatus.PENDING),
                    os_info=s.get('os_info'),
                    arch=s.get('arch'),
                    last_error=s.get('last_error')
                )
                self.servers[server.id] = server
            if self.servers:
                logger.info(f"从数据库加载了 {len(self.servers)} 台服务器")
        except Exception as e:
            logger.error(f"从数据库加载服务器失败: {e}")

    def _load_results_from_db(self):
        """从数据库加载检测结果"""
        try:
            db_results = self.db.get_all_results()
            for r in db_results:
                result = DetectionResult(
                    server_id=r['server_id'],
                    server_ip=r['server_ip'],
                    timestamp=datetime.fromisoformat(r['timestamp']) if isinstance(r['timestamp'], str) else r['timestamp'],
                    overall_status=OverallStatus(r['overall_status']) if isinstance(r['overall_status'], str) else r['overall_status'],
                    score=r['score'],
                    os_info=r.get('os_info'),
                    arch=r.get('arch'),
                    error_message=r.get('error_message')
                )
                # 重建items
                from models import DetectionItem, DetectionStatus, OverallStatus
                for item_data in r.get('items', []):
                    item = DetectionItem(
                        name=item_data.get('name', ''),
                        description=item_data.get('description', ''),
                        status=DetectionStatus(item_data.get('status', 'pass')),
                        details=item_data.get('details', ''),
                        findings=item_data.get('findings', []),
                        command=item_data.get('command', ''),
                        raw_output=item_data.get('raw_output', '')
                    )
                    result.items.append(item)
                self.results[result.server_id] = result
            if self.results:
                logger.info(f"从数据库加载了 {len(self.results)} 条检测结果")
        except Exception as e:
            logger.error(f"从数据库加载结果失败: {e}")

    async def parse_servers(self, text: str, default_port: int = 22) -> List[Server]:
        """解析服务器列表"""
        servers = []
        lines = text.strip().split('\n')

        for line in lines:
            server = Server.from_line(line, default_port)
            if server:
                # 查找相同IP的服务器并更新（而不是创建新的）
                existing = None
                for sid, s in self.servers.items():
                    if s.ip == server.ip and s.port == server.port:
                        existing = s
                        break
                if existing:
                    # 覆盖已有服务器信息
                    existing.username = server.username
                    existing.password = server.password
                    existing.status = ServerStatus.PENDING
                    servers.append(existing)
                else:
                    self.servers[server.id] = server
                    servers.append(server)

        # 保存到数据库
        if servers:
            self.db.save_servers_batch([s.to_dict() for s in servers])

        return servers

    async def test_connection(self, server_id: str) -> Dict[str, Any]:
        """测试单个服务器连接"""
        if server_id not in self.servers:
            return {"success": False, "error": "服务器不存在"}

        server = self.servers[server_id]
        server.status = ServerStatus.TESTING

        result = await self.ssh_manager.test_connection(
            server.ip, server.port, server.username, server.password
        )

        if result.success:
            server.status = ServerStatus.PENDING
            server.os_info = result.os_info
            server.arch = result.arch
            return {
                "success": True,
                "data": {
                    "server_id": server_id,
                    "connected": True,
                    "os_info": result.os_info,
                    "arch": result.arch
                }
            }
        else:
            server.status = ServerStatus.FAILED
            server.last_error = result.error
            return {
                "success": False,
                "error": result.error,
                "data": {"server_id": server_id, "connected": False, "error": result.error}
            }

    async def test_all_connections(self, server_ids: List[str] = None) -> Dict[str, Any]:
        """测试所有服务器连接"""
        if server_ids is None:
            server_ids = list(self.servers.keys())

        results = []
        for server_id in server_ids:
            if server_id in self.servers:
                server = self.servers[server_id]
                server.status = ServerStatus.TESTING

                result = await self.ssh_manager.test_connection(
                    server.ip, server.port, server.username, server.password
                )

                if result.success:
                    server.status = ServerStatus.PENDING
                    server.os_info = result.os_info
                    server.arch = result.arch
                    results.append({
                        "server_id": server_id,
                        "ip": server.ip,
                        "connected": True,
                        "os_info": result.os_info,
                        "arch": result.arch
                    })
                else:
                    server.status = ServerStatus.FAILED
                    server.last_error = result.error
                    results.append({
                        "server_id": server_id,
                        "ip": server.ip,
                        "connected": False,
                        "error": result.error
                    })

        return {
            "success": True,
            "data": {
                "results": results,
                "total": len(results),
                "connected": sum(1 for r in results if r.get("connected", False))
            }
        }

    async def start_detection(self, server_ids: List[str] = None, progress_callback=None) -> Dict[str, Any]:
        """开始批量检测"""
        if server_ids is None:
            server_ids = list(self.servers.keys())

        servers = [self.servers[sid] for sid in server_ids if sid in self.servers]

        if not servers:
            return {"success": False, "error": "没有可检测的服务器"}

        self._running = True
        self.progress.total = len(servers)
        self.progress.completed = 0
        self.progress.is_running = True
        self.progress.is_paused = False

        def progress_cb(current, total, server_ip, item_name):
            self.progress.current_server = server_ip
            self.progress.current_item = item_name
            self.progress.completed = current
            if progress_callback:
                progress_callback(self.progress)

        # 包装回调，兼容 detect_server 里传 2 参数的调用方式
        def wrapped_progress_cb(*args):
            if len(args) == 2:
                # detect_server 里的调用: (server_ip, item_name)
                server_ip, item_name = args
                progress_cb(0, 0, server_ip, item_name)
            elif len(args) == 4:
                # batch_detect 里的调用: (current, total, server_ip, item_name)
                progress_cb(*args)

        asyncio.create_task(self._run_detection(servers, wrapped_progress_cb))

        return {
            "success": True,
            "data": {"started": True, "total_servers": len(servers)}
        }

    async def _run_detection(self, servers: List[Server], progress_callback):
        """运行检测任务"""
        try:
            results = await self.detector.batch_detect(servers, progress_callback)

            logger.info(f"检测完成，共 {len(results)} 个结果")
            for result in results:
                logger.info(f"  - server_id={result.server_id}, ip={result.server_ip}, items={len(result.items)}")
                result_dict = result.to_dict()
                logger.info(f"  - result_dict has items: {len(result_dict.get('items', []))}")
                self.results[result.server_id] = result

            # 保存到数据库
            try:
                dicts = [r.to_dict() for r in results]
                logger.info(f"准备保存 {len(dicts)} 个结果到数据库")
                saved = self.db.save_results_batch(dicts)
                logger.info(f"数据库保存结果: {saved}")
            except Exception as db_e:
                logger.error(f"保存数据库出错: {db_e}")
                import traceback
                traceback.print_exc()

            self.progress.is_running = False
            self.progress.current_server = ""
            self.progress.current_item = ""

            if progress_callback:
                progress_callback(self.progress)

        except Exception as e:
            logger.error(f"检测出错: {e}")
            import traceback
            traceback.print_exc()
            self.progress.is_running = False

    def pause_detection(self) -> Dict[str, Any]:
        """暂停检测"""
        if self.detector:
            self.detector.pause()
            self.progress.is_paused = True
            return {"success": True, "data": {"paused": True}}
        return {"success": False, "error": "检测器未初始化"}

    def resume_detection(self) -> Dict[str, Any]:
        """继续检测"""
        if self.detector:
            self.detector.resume()
            self.progress.is_paused = False
            return {"success": True, "data": {"resumed": True}}
        return {"success": False, "error": "检测器未初始化"}

    def stop_detection(self) -> Dict[str, Any]:
        """停止检测"""
        if self.detector:
            self.detector.stop()
            self.progress.is_running = False
            self.progress.is_paused = False
            return {"success": True, "data": {"stopped": True}}
        return {"success": False, "error": "检测器未初始化"}

    def get_progress(self) -> Dict[str, Any]:
        """获取进度"""
        return {"success": True, "data": self.progress.to_dict()}

    def get_servers(self) -> Dict[str, Any]:
        """获取服务器列表"""
        return {
            "success": True,
            "data": {
                "servers": [s.to_dict() for s in self.servers.values()],
                "count": len(self.servers)
            }
        }

    async def get_results(self, server_ids: List[str] = None) -> Dict[str, Any]:
        """获取检测结果"""
        logger.info(f"get_results called, server_ids={server_ids}, self.results count={len(self.results)}")
        if server_ids:
            results = [self.results[sid].to_dict() for sid in server_ids if sid in self.results]
        else:
            results = [r.to_dict() for r in self.results.values()]
            logger.info(f"Returning {len(results)} results, first few: {results[:2] if results else 'none'}")

        return {
            "success": True,
            "data": {"results": results, "count": len(results)}
        }

    async def export_report(self, format: str, selected_ids: List[str] = None) -> Dict[str, Any]:
        """导出报告"""
        if selected_ids:
            results = [self.results[sid] for sid in selected_ids if sid in self.results]
        else:
            results = list(self.results.values())

        if not results:
            return {"success": False, "error": "没有可导出的结果"}

        try:
            report_content = ReportGenerator.export_report(results, format, selected_ids)
            return {
                "success": True,
                "data": {
                    "format": format,
                    "content": report_content,
                    "size": len(report_content)
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_servers(self, server_ids: List[str]) -> Dict[str, Any]:
        """删除服务器列表"""
        deleted = 0
        for sid in server_ids:
            if sid in self.servers:
                del self.servers[sid]
                self.db.delete_server(sid)
                deleted += 1
        return {"success": True, "data": {"deleted": deleted}}

    def delete_results(self, server_ids: List[str]) -> Dict[str, Any]:
        """删除检测结果（不删除服务器）"""
        logger.info(f"delete_results called with server_ids={server_ids}")
        if not server_ids:
            count = len(self.results)
            self.db.clear_all()
            self.results.clear()
            return {"success": True, "data": {"deleted": count}}

        deleted = 0
        for sid in server_ids:
            if sid in self.results:
                del self.results[sid]
            self.db.delete_result(sid)
            deleted += 1
        return {"success": True, "data": {"deleted": deleted}}

    async def rerun_detection(self, server_ids: List[str]) -> Dict[str, Any]:
        """重新检测指定服务器"""
        servers = [self.servers[sid] for sid in server_ids if sid in self.servers]
        if not servers:
            return {"success": False, "error": "未找到指定的服务器"}

        # 重新执行检测
        results = await self.detector.batch_detect(servers)

        for result in results:
            self.results[result.server_id] = result

        # 保存到数据库
        self.db.save_results_batch([r.to_dict() for r in results])

        return {
            "success": True,
            "data": {"detected": len(results), "server_ids": [r.server_id for r in results]}
        }

    def get_detection_commands(self) -> Dict[str, Any]:
        """获取检测命令列表"""
        commands = get_all_detection_commands()
        categories = get_commands_by_category()

        return {
            "success": True,
            "data": {
                "commands": [cmd.to_dict() for cmd in commands],
                "categories": {cat: [cmd.name for cmd in cmds] for cat, cmds in categories.items()}
            }
        }

    async def shutdown(self):
        """关闭服务"""
        logger.info("正在关闭后端服务...")
        if self.ssh_manager:
            await self.ssh_manager.disconnect_all()
        self._running = False


# 全局服务实例
service: Optional[BackendService] = None


# ==================== HTTP API Server ====================

async def handle_parse_servers(request: web.Request) -> web.Response:
    """解析服务器列表"""
    data = await request.json()
    text = data.get("text", "")
    default_port = data.get("default_port", 22)

    servers = await service.parse_servers(text, default_port)

    return web.json_response({
        "success": True,
        "data": {
            "servers": [s.to_dict() for s in servers],
            "count": len(servers)
        }
    })


async def handle_test_connection(request: web.Request) -> web.Response:
    """测试单个服务器连接"""
    data = await request.json()
    server_id = data.get("server_id")

    result = await service.test_connection(server_id)
    return web.json_response(result)


async def handle_test_all_connections(request: web.Request) -> web.Response:
    """测试所有服务器连接"""
    data = await request.json()
    server_ids = data.get("server_ids")

    result = await service.test_all_connections(server_ids)
    return web.json_response(result)


async def handle_start_detection(request: web.Request) -> web.Response:
    """开始批量检测"""
    data = await request.json()
    server_ids = data.get("server_ids")

    # 实时推送进度
    async def progress_callback(progress):
        try:
            message = json.dumps({"type": "progress", "data": progress.to_dict()})
            await ws.send_str(message)
        except:
            pass

    result = await service.start_detection(server_ids, progress_callback)
    return web.json_response(result)


async def handle_pause_detection(request: web.Request) -> web.Response:
    """暂停检测"""
    result = service.pause_detection()
    return web.json_response(result)


async def handle_resume_detection(request: web.Request) -> web.Response:
    """继续检测"""
    result = service.resume_detection()
    return web.json_response(result)


async def handle_stop_detection(request: web.Request) -> web.Response:
    """停止检测"""
    result = service.stop_detection()
    return web.json_response(result)


async def handle_get_progress(request: web.Request) -> web.Response:
    """获取进度"""
    result = service.get_progress()
    return web.json_response(result)


async def handle_get_servers(request: web.Request) -> web.Response:
    """获取服务器列表"""
    result = service.get_servers()
    return web.json_response(result)


async def handle_get_results(request: web.Request) -> web.Response:
    """获取检测结果"""
    data = await request.json()
    server_ids = data.get("server_ids")

    result = await service.get_results(server_ids)
    return web.json_response(result)


async def handle_export_report(request: web.Request) -> web.Response:
    """导出报告"""
    data = await request.json()
    format_type = data.get("format", "json")
    selected_ids = data.get("selected_ids")

    result = await service.export_report(format_type, selected_ids)
    return web.json_response(result)


async def handle_delete_results(request: web.Request) -> web.Response:
    """删除检测结果"""
    data = await request.json()
    server_ids = data.get("server_ids", [])
    logger.info(f"handle_delete_results called, server_ids={server_ids}")

    result = service.delete_results(server_ids)
    logger.info(f"delete_results result={result}")
    return web.json_response(result)


async def handle_delete_servers(request: web.Request) -> web.Response:
    """删除服务器列表"""
    data = await request.json()
    server_ids = data.get("server_ids", [])
    logger.info(f"handle_delete_servers called, server_ids={server_ids}")

    result = service.delete_servers(server_ids)
    logger.info(f"delete_servers result={result}")
    return web.json_response(result)


async def handle_rerun_detection(request: web.Request) -> web.Response:
    """重新检测指定服务器"""
    data = await request.json()
    server_ids = data.get("server_ids", [])

    if not server_ids:
        return web.json_response({"success": False, "error": "请选择要重新检测的服务器"})

    result = await service.rerun_detection(server_ids)
    return web.json_response(result)


async def handle_get_detection_commands(request: web.Request) -> web.Response:
    """获取检测命令列表"""
    result = service.get_detection_commands()
    return web.json_response(result)


async def websocket_handler(request: web.Request) -> web.Response:
    """WebSocket处理"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            try:
                data = json.loads(msg.data)
                cmd_type = data.get("type", "")

                if cmd_type == "start_detection":
                    server_ids = data.get("server_ids")

                    async def progress_callback(progress):
                        try:
                            await ws.send_str(json.dumps({"type": "progress", "data": progress.to_dict()}))
                        except:
                            pass

                    await service.start_detection(server_ids, progress_callback)
                    await ws.send_str(json.dumps({"type": "detection_complete"}))

                elif cmd_type == "pause_detection":
                    service.pause_detection()
                    await ws.send_str(json.dumps({"type": "paused"}))

                elif cmd_type == "resume_detection":
                    service.resume_detection()
                    await ws.send_str(json.dumps({"type": "resumed"}))

                elif cmd_type == "stop_detection":
                    service.stop_detection()
                    await ws.send_str(json.dumps({"type": "stopped"}))

                elif cmd_type == "get_progress":
                    await ws.send_str(json.dumps({"type": "progress", "data": service.get_progress()["data"]}))

            except json.JSONDecodeError:
                pass

    return ws


async def cors_middleware(app, handler):
    """CORS中间件"""
    async def middleware(request):
        if request.method == 'OPTIONS':
            response = web.Response()
        else:
            response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    return middleware


def create_app() -> web.Application:
    """创建web应用"""
    app = web.Application(middlewares=[cors_middleware])

    app.router.add_post('/api/parse_servers', handle_parse_servers)
    app.router.add_post('/api/test_connection', handle_test_connection)
    app.router.add_post('/api/test_all_connections', handle_test_all_connections)
    app.router.add_post('/api/start_detection', handle_start_detection)
    app.router.add_post('/api/pause_detection', handle_pause_detection)
    app.router.add_post('/api/resume_detection', handle_resume_detection)
    app.router.add_post('/api/stop_detection', handle_stop_detection)
    app.router.add_post('/api/get_progress', handle_get_progress)
    app.router.add_post('/api/get_servers', handle_get_servers)
    app.router.add_post('/api/get_results', handle_get_results)
    app.router.add_post('/api/export_report', handle_export_report)
    app.router.add_post('/api/delete_results', handle_delete_results)
    app.router.add_post('/api/delete_servers', handle_delete_servers)
    app.router.add_post('/api/rerun_detection', handle_rerun_detection)
    app.router.add_post('/api/get_detection_commands', handle_get_detection_commands)
    app.router.add_get('/ws', websocket_handler)

    return app


# ==================== CLI Mode ====================

async def run_cli(args):
    """CLI模式"""
    global service
    service = BackendService()
    await service.initialize()

    if args.command == "parse":
        text = args.text or sys.stdin.read()
        servers = await service.parse_servers(text, args.port or 22)
        print(f"解析到 {len(servers)} 台服务器:")
        for s in servers:
            print(f"  {s.ip}:{s.port} - {s.username}")

    elif args.command == "test":
        if args.server_id:
            result = await service.test_connection(args.server_id)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            result = await service.test_all_connections()
            print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "detect":
        servers = await service.parse_servers(args.servers_text or "", args.port or 22)
        if not servers:
            print("没有服务器可检测")
            return

        def progress_callback(progress):
            print(f"\r进度: {progress.completed}/{progress.total} - {progress.current_server} - {progress.current_item}")

        result = await service.start_detection(progress_callback=progress_callback)
        print(json.dumps(result, indent=2, ensure_ascii=False))

        # 等待检测完成
        while service.progress.is_running:
            await asyncio.sleep(1)

        # 获取结果
        results = await service.get_results()
        print(json.dumps(results, indent=2, ensure_ascii=False))

    elif args.command == "export":
        format_type = args.format or "html"
        result = await service.export_report(format_type)
        if result["success"]:
            print(result["data"]["content"])
        else:
            print(f"导出失败: {result['error']}")

    elif args.command == "commands":
        result = service.get_detection_commands()
        print(json.dumps(result, indent=2, ensure_ascii=False))


async def main():
    """主入口"""
    parser = argparse.ArgumentParser(description='BackdoorScan - 服务器后门扫描工具')
    parser.add_argument('--host', default='127.0.0.1', help='API服务器地址')
    parser.add_argument('--api-port', dest='api_port', type=int, default=8765, help='API服务器端口')
    parser.add_argument('--cli', action='store_true', help='CLI模式')
    parser.add_argument('command', nargs='?', help='CLI子命令: parse, test, detect, export, commands')
    parser.add_argument('--text', help='服务器列表文本')
    parser.add_argument('--servers-text', help='服务器列表文本（用于detect命令）')
    parser.add_argument('--port', dest='port', type=int, default=22, help='默认SSH端口')
    parser.add_argument('--server-id', help='服务器ID')
    parser.add_argument('--format', help='导出格式: json, html, txt')

    args = parser.parse_args()

    global service
    service = BackendService()
    await service.initialize()

    if args.cli or args.command:
        await run_cli(args)
    else:
        # 启动HTTP服务器
        app = create_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, args.host, args.api_port)
        await site.start()

        logger.info(f"🚀 API服务器已启动: http://{args.host}:{args.api_port}")
        logger.info(f"📡 WebSocket端点: ws://{args.host}:{args.api_port}/ws")
        logger.info("按 Ctrl+C 停止服务器")

        # 处理信号
        def signal_handler(sig, frame):
            logger.info("收到退出信号...")
            asyncio.create_task(service.shutdown())
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # 保持运行
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())