"""
后门检测引擎
执行服务器后门检测逻辑，分析检测结果
"""

import asyncio
import re
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime

from models import (
    Server, DetectionResult, DetectionItem, DetectionStatus,
    OverallStatus, ServerStatus
)
from ssh_manager import SSHConnectionManager, SSHConnectionResult
from detector_commands import DetectionCommand, get_all_detection_commands


class BackdoorDetector:
    """服务器后门检测器"""

    def __init__(self, ssh_manager: SSHConnectionManager):
        self.ssh_manager = ssh_manager
        self.is_paused = False
        self.is_running = False
        self._stop_flag = False

    def pause(self):
        """暂停检测"""
        self.is_paused = True

    def resume(self):
        """继续检测"""
        self.is_paused = False

    def stop(self):
        """停止检测"""
        self._stop_flag = True
        self.is_paused = False

    async def detect_server(
        self,
        server: Server,
        commands: List[DetectionCommand] = None,
        progress_callback: Optional[Callable] = None,
        server_index: int = 0,
        total_servers: int = 1
    ) -> DetectionResult:
        """检测单个服务器"""
        if commands is None:
            commands = get_all_detection_commands()

        result = DetectionResult(
            server_id=server.id,
            server_ip=server.ip,
            timestamp=datetime.now()
        )

        if self._stop_flag:
            result.error_message = "检测被停止"
            return result

        while self.is_paused and not self._stop_flag:
            await asyncio.sleep(0.5)

        connect_result = await self.ssh_manager.connect(
            server.ip,
            server.port,
            server.username,
            server.password,
            server.id
        )

        if not connect_result.success:
            result.error_message = connect_result.error
            server.status = ServerStatus.FAILED
            server.last_error = connect_result.error
            return result

        result.os_info = connect_result.os_info
        result.arch = connect_result.arch
        server.os_info = connect_result.os_info
        server.arch = connect_result.arch
        server.status = ServerStatus.DETECTING

        for cmd in commands:
            if self._stop_flag:
                break

            while self.is_paused and not self._stop_flag:
                await asyncio.sleep(0.5)

            if progress_callback:
                progress_callback(server_index, total_servers, server.ip, cmd.name)

            item = await self._execute_detection(server, cmd)
            result.add_item(item)

        await self.ssh_manager.disconnect(server.ip, server.port, server.id)

        server.status = ServerStatus.COMPLETED
        return result

    async def _execute_detection(
        self,
        server: Server,
        command: DetectionCommand
    ) -> DetectionItem:
        """执行单个检测"""
        item = DetectionItem(
            name=command.name,
            description=command.description,
            status=DetectionStatus.PASS,
            command=command.command
        )

        try:
            result = await self.ssh_manager.execute_command(
                server.ip,
                server.port,
                server.username,
                server.password,
                command.command,
                server.id
            )

            item.raw_output = result.output

            if not result.success:
                item.status = DetectionStatus.ERROR
                item.details = result.error
                return item

            item = self._analyze_result(item, result.output, command)

        except Exception as e:
            item.status = DetectionStatus.ERROR
            item.details = f"检测执行失败: {str(e)}"

        return item

    def _analyze_result(
        self,
        item: DetectionItem,
        output: str,
        command: DetectionCommand
    ) -> DetectionItem:
        """分析检测结果"""
        if not output or output.strip() == "":
            item.status = DetectionStatus.PASS
            item.details = "未发现异常"
            return item

        suspicious_findings = []

        for pattern in command.patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str):
                    suspicious_findings.append(match)
                else:
                    suspicious_findings.append(str(match))

        if command.name == "suspicious_port":
            findings = self._check_suspicious_ports(output, command)
            suspicious_findings.extend(findings)
        elif command.name == "suspicious_process":
            findings = self._check_suspicious_process(output, command)
            suspicious_findings.extend(findings)
        elif command.name == "cron_job":
            findings = self._check_suspicious_cron(output, command)
            suspicious_findings.extend(findings)
        elif command.name == "suid_file":
            findings = self._check_suspicious_suid(output, command)
            suspicious_findings.extend(findings)
        elif command.name == "ssh_key":
            findings = self._check_suspicious_ssh_key(output, command)
            suspicious_findings.extend(findings)

        if suspicious_findings:
            item.findings = list(set(suspicious_findings))[:10]
            item.status = DetectionStatus.DANGER if command.severity == "danger" else DetectionStatus.WARNING
            item.details = f"发现 {len(item.findings)} 个可疑项"
        else:
            item.status = DetectionStatus.PASS
            item.details = "未发现异常"

        return item

    def _check_suspicious_ports(self, output: str, command: DetectionCommand) -> List[str]:
        """检查可疑端口"""
        findings = []
        for port in command.suspicious_ports:
            if f':{port}' in output:
                for line in output.split('\n'):
                    if f':{port}' in line:
                        findings.append(line.strip())
        return findings

    def _check_suspicious_process(self, output: str, command: DetectionCommand) -> List[str]:
        """检查可疑进程"""
        findings = []
        for line in output.split('\n'):
            if 'grep -v grep' in line:
                continue
            for pattern in command.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(line.strip())
                    break
        return findings

    def _check_suspicious_cron(self, output: str, command: DetectionCommand) -> List[str]:
        """检查可疑定时任务"""
        findings = []
        for line in output.split('\n'):
            if not line.strip() or line.strip().startswith('#') or line.startswith('---'):
                continue
            for pattern in command.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(line.strip())
                    break
        return findings

    def _check_suspicious_suid(self, output: str, command: DetectionCommand) -> List[str]:
        """检查可疑SUID文件"""
        findings = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            for pattern in command.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(line.strip())
                    break
        return findings

    def _check_suspicious_ssh_key(self, output: str, command: DetectionCommand) -> List[str]:
        """检查可疑SSH密钥"""
        findings = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            for ip_pattern in getattr(command, 'suspicious_ips', []):
                if ip_pattern in line:
                    findings.append(f"可疑来源IP: {line.strip()}")
                    break
            for pattern in command.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if line.strip() not in findings:
                        findings.append(line.strip())
                    break
        return findings

    async def batch_detect(
        self,
        servers: List[Server],
        progress_callback: Optional[Callable] = None
    ) -> List[DetectionResult]:
        """批量检测"""
        self.is_running = True
        self._stop_flag = False
        self.is_paused = False

        results = []
        commands = get_all_detection_commands()

        for i, server in enumerate(servers):
            if self._stop_flag:
                break

            server.status = ServerStatus.TESTING

            if progress_callback:
                progress_callback(i, len(servers), server.ip, "正在连接...")

            result = await self.detect_server(server, commands, progress_callback, i, len(servers))
            results.append(result)

            if progress_callback:
                progress_callback(i + 1, len(servers), server.ip, "检测完成")

        self.is_running = False
        return results


async def create_detector(ssh_manager: SSHConnectionManager) -> BackdoorDetector:
    """创建检测器"""
    return BackdoorDetector(ssh_manager)