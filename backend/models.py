"""
数据模型定义
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import uuid
import json


class ServerStatus(Enum):
    PENDING = "pending"
    TESTING = "testing"
    DETECTING = "detecting"
    COMPLETED = "completed"
    FAILED = "failed"


class DetectionStatus(Enum):
    PASS = "pass"
    WARNING = "warning"
    DANGER = "danger"
    ERROR = "error"


class OverallStatus(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    CRITICAL = "critical"


@dataclass
class Server:
    id: str
    ip: str
    port: int = 22
    username: str = ""
    password: str = ""
    status: ServerStatus = ServerStatus.PENDING
    last_error: Optional[str] = None
    os_info: Optional[str] = None
    arch: Optional[str] = None

    @staticmethod
    def from_line(line: str, default_port: int = 22) -> Optional['Server']:
        """从一行文本解析服务器信息"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        # 支持两种格式: "IP,user,pass" 或 "IP:user:pass"
        if ':' in line and ',' not in line:
            parts = line.split(':')
        else:
            parts = line.split(',')
        if len(parts) < 3:
            return None

        ip_part = parts[0].strip()
        username = parts[1].strip()
        password = parts[2].strip()

        if ':' in ip_part:
            ip, port_str = ip_part.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = default_port
        else:
            ip = ip_part
            port = default_port

        return Server(
            id=str(uuid.uuid4())[:8],
            ip=ip,
            port=port,
            username=username,
            password=password
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "port": self.port,
            "username": self.username,
            "status": self.status.value,
            "last_error": self.last_error,
            "os_info": self.os_info,
            "arch": self.arch
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class DetectionItem:
    name: str
    description: str
    status: DetectionStatus
    details: str = ""
    findings: List[str] = field(default_factory=list)
    command: str = ""
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "details": self.details,
            "findings": self.findings,
            "command": self.command,
            "raw_output": self.raw_output[:500] if self.raw_output else ""
        }


@dataclass
class DetectionResult:
    server_id: str
    server_ip: str
    timestamp: datetime
    items: List[DetectionItem] = field(default_factory=list)
    overall_status: OverallStatus = OverallStatus.CLEAN
    score: int = 100
    os_info: Optional[str] = None
    arch: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        status_val = self.overall_status.value if hasattr(self.overall_status, 'value') else self.overall_status
        return {
            "id": self.server_id,
            "server_id": self.server_id,
            "server_ip": self.server_ip,
            "timestamp": self.timestamp.isoformat() if hasattr(self.timestamp, 'isoformat') else self.timestamp,
            "items": [item.to_dict() for item in self.items],
            "overall_status": status_val,
            "score": max(0, self.score),
            "os_info": self.os_info,
            "arch": self.arch,
            "error_message": self.error_message
        }

    def add_item(self, item: DetectionItem):
        self.items.append(item)
        if item.status == DetectionStatus.DANGER:
            self.score -= 30
        elif item.status == DetectionStatus.WARNING:
            self.score -= 10

        if self.score <= 40:
            self.overall_status = OverallStatus.CRITICAL
        elif self.score <= 70:
            self.overall_status = OverallStatus.SUSPICIOUS

    def get_summary(self) -> Dict[str, int]:
        summary = {"pass": 0, "warning": 0, "danger": 0, "error": 0}
        for item in self.items:
            summary[item.status.value] += 1
        return summary


@dataclass
class BatchProgress:
    total: int = 0
    completed: int = 0
    current_server: str = ""
    current_item: str = ""
    is_paused: bool = False
    is_running: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "completed": self.completed,
            "current_server": self.current_server,
            "current_item": self.current_item,
            "is_paused": self.is_paused,
            "is_running": self.is_running,
            "percentage": (self.completed / self.total * 100) if self.total > 0 else 0
        }