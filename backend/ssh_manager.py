"""
SSH连接管理器
使用asyncssh实现异步SSH连接和命令执行
"""

import asyncio
import asyncssh
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SSHConnectionResult:
    success: bool
    output: str = ""
    error: str = ""
    os_info: Optional[str] = None
    arch: Optional[str] = None


class SSHConnectionManager:
    """SSH连接管理器"""

    def __init__(self, max_connections: int = 10, timeout: int = 60):
        self.max_connections = max_connections
        self.timeout = timeout
        self._connections: Dict[str, asyncssh.SSHClientConnection] = {}
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def initialize(self):
        """初始化管理器"""
        self._semaphore = asyncio.Semaphore(self.max_connections)

    async def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        server_id: str
    ) -> SSHConnectionResult:
        """建立SSH连接"""
        try:
            async with self._semaphore:
                conn_key = f"{server_id}:{host}:{port}"
                if conn_key in self._connections:
                    try:
                        self._connections[conn_key].close()
                    except:
                        pass

                conn = await asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    encoding='utf-8',
                    connect_timeout=self.timeout
                )

                self._connections[conn_key] = conn

                os_info, arch = await self._get_system_info(conn)

                return SSHConnectionResult(
                    success=True,
                    os_info=os_info,
                    arch=arch
                )

        except asyncssh.DisconnectError as e:
            logger.error(f"SSH DisconnectError for {host}:{port}: {e}")
            return SSHConnectionResult(success=False, error=f"连接断开: {e}")
        except asyncssh.PermissionDenied as e:
            logger.error(f"SSH PermissionDenied for {host}:{port}: {e}")
            return SSHConnectionResult(success=False, error=f"权限被拒绝: {e}")
        except asyncio.TimeoutError:
            logger.error(f"SSH TimeoutError for {host}:{port}")
            return SSHConnectionResult(success=False, error="连接超时")
        except Exception as e:
            logger.error(f"SSH Exception for {host}:{port}: {type(e).__name__}: {e}")
            return SSHConnectionResult(success=False, error=f"连接错误: {type(e).__name__}: {e}")

    async def _get_system_info(self, conn) -> Tuple[Optional[str], Optional[str]]:
        """获取系统信息"""
        try:
            result = await conn.run("uname -a", timeout=10)
            output = result.stdout.strip()

            arch = None
            if 'x86_64' in output or 'amd64' in output:
                arch = 'x86_64'
            elif 'aarch64' in output or 'arm64' in output:
                arch = 'arm64'
            elif 'armv7' in output or 'armhf' in output:
                arch = 'arm'
            elif 'mips' in output:
                arch = 'mips'
            elif 'ppc' in output:
                arch = 'ppc'

            return output, arch
        except:
            return None, None

    async def execute_command(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        command: str,
        server_id: str
    ) -> SSHConnectionResult:
        """执行SSH命令"""
        try:
            conn_key = f"{server_id}:{host}:{port}"

            if conn_key in self._connections:
                conn = self._connections[conn_key]
                if not conn.is_closed():
                    try:
                        result = await conn.run(command, timeout=self.timeout, term_type='vt100')
                        return SSHConnectionResult(
                            success=True,
                            output=result.stdout,
                            error=result.stderr if result.exit_status != 0 else ""
                        )
                    except asyncssh.DisconnectError:
                        pass

            connect_result = await self.connect(host, port, username, password, server_id)
            if not connect_result.success:
                return connect_result

            conn = self._connections[conn_key]
            result = await conn.run(command, timeout=self.timeout, term_type='vt100')

            return SSHConnectionResult(
                success=True,
                output=result.stdout,
                error=result.stderr if result.exit_status != 0 else ""
            )

        except asyncio.TimeoutError:
            return SSHConnectionResult(success=False, error=f"命令执行超时: {command[:50]}...")
        except Exception as e:
            return SSHConnectionResult(success=False, error=f"命令执行错误: {e}")

    async def disconnect(self, host: str, port: int, server_id: str):
        """断开SSH连接"""
        conn_key = f"{server_id}:{host}:{port}"
        if conn_key in self._connections:
            try:
                self._connections[conn_key].close()
            except:
                pass
            del self._connections[conn_key]

    async def disconnect_all(self):
        """断开所有SSH连接"""
        for conn_key, conn in list(self._connections.items()):
            try:
                conn.close()
            except:
                pass
        self._connections.clear()

    async def test_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: str
    ) -> SSHConnectionResult:
        """测试连接"""
        return await self.connect(host, port, username, password, "test")


async def create_ssh_manager(max_connections: int = 10) -> SSHConnectionManager:
    """创建SSH管理器"""
    manager = SSHConnectionManager(max_connections)
    await manager.initialize()
    return manager