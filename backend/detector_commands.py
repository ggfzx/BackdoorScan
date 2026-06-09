"""
服务器后门检测命令定义
所有命令均为只读操作，不会对服务器造成任何影响
支持多架构Linux系统（x86、ARM、MIPS等）
"""

from typing import List, Dict, Any, Optional
import re


class DetectionCommand:
    """检测命令基类"""

    def __init__(self, name: str, description: str, category: str):
        self.name = name
        self.description = description
        self.category = category
        self.command = ""
        self.patterns: List[str] = []
        self.severity = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "command": self.command,
            "patterns": self.patterns,
            "severity": self.severity
        }


class SuspiciousPortDetection(DetectionCommand):
    """检测异常监听端口"""

    def __init__(self):
        super().__init__("suspicious_port", "检测异常或可疑的监听端口", "network")
        self.command = "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"
        self.suspicious_ports = [6666, 6667, 6668, 6669, 7777, 8888, 9999, 1337, 31337, 4444, 5555]
        self.severity = "danger"


class SuspiciousProcessDetection(DetectionCommand):
    """检测可疑进程"""

    def __init__(self):
        super().__init__("suspicious_process", "检测可疑进程（如netcat后门、反弹shell等）", "process")
        self.command = "ps aux 2>/dev/null | grep -v grep"
        self.patterns = [
            r'nc\s+-[eLvp]',
            r'netcat\s+-[eLvp]',
            r'ncat\s+-[eLvp]',
            r'bash\s+-i',
            r'sh\s+-i',
            r'/dev/tcp/',
            r'python.*socket.*connect',
            r'perl.*socket',
            r'ruby.*socket',
            r'socat\s+.*connect',
        ]
        self.severity = "danger"


class CronJobDetection(DetectionCommand):
    """检测定时任务后门"""

    def __init__(self):
        super().__init__("cron_job", "检测定时任务中的可疑内容", "persistence")
        self.command = """(crontab -l 2>/dev/null; echo "---SYSTEM_CRONTAB---"; cat /etc/crontab 2>/dev/null; echo "---ANACRON---"; cat /etc/anacrontab 2>/dev/null; echo "---SYSSTAT---"; ls -la /etc/cron.d/ 2>/dev/null; echo "---USER_CRONS---"; for u in $(cut -d: -f1 /etc/passwd); do echo "=== $u ==="; crontab -l -u "$u" 2>/dev/null; done) 2>/dev/null"""
        self.patterns = [
            r'curl.*\|.*bash',
            r'wget.*\|.*bash',
            r'python.*-c.*http',
            r'nc\s+-e',
            r'bash.*-i',
            r'/dev/tcp/',
            r'lynx.*-dump',
            r'sh\s+-c',
        ]
        self.severity = "danger"


class SshKeyDetection(DetectionCommand):
    """检测SSH后门"""

    def __init__(self):
        super().__init__("ssh_key", "检测SSH authorized_keys中的异常内容", "persistence")
        self.command = """cat ~/.ssh/authorized_keys 2>/dev/null"""
        self.suspicious_ips = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        self.severity = "warning"


class SshdConfigDetection(DetectionCommand):
    """检测SSH配置异常"""

    def __init__(self):
        super().__init__("sshd_config", "检测SSH服务配置异常", "persistence")
        self.command = """grep -E '^(PermitRootLogin|PubkeyAuthentication|PasswordAuthentication|AllowTcpForwarding|GatewayPorts|AllowAgentForwarding)' /etc/ssh/sshd_config 2>/dev/null"""
        self.patterns = [
            r'PermitRootLogin\s+yes',
            r'AllowTcpForwarding\s+yes',
            r'GatewayPorts\s+yes',
            r'PasswordAuthentication\s+yes',
        ]
        self.severity = "warning"


class HiddenProcessDetection(DetectionCommand):
    """检测隐藏进程"""

    def __init__(self):
        super().__init__("hidden_process", "检测隐藏进程或异常PID", "process")
        self.command = """echo "===PROCESS_COUNT==="; ps aux | wc -l; echo "===HIDDEN_PROC==="; for pid in $(ls /proc | grep -E '^[0-9]+$'); do if [ ! -f /proc/$pid/cmdline ]; then echo "Zombie: $pid"; fi; done"""
        self.severity = "warning"


class SuidFileDetection(DetectionCommand):
    """检测SUID后门文件"""

    def __init__(self):
        super().__init__("suid_file", "检测异常的SUID文件", "persistence")
        self.command = """find / -perm -4000 -type f 2>/dev/null | head -100"""
        self.patterns = [
            r'/bin/nc',
            r'/bin/netcat',
            r'/usr/bin/nc',
            r'/usr/bin/wget',
            r'/usr/bin/curl',
            r'/tmp/',
            r'/dev/shm/',
            r'\.sh$',
            r'\.pl$',
            r'\.py$',
        ]
        self.severity = "warning"


class TempFileDetection(DetectionCommand):
    """检测临时目录可疑文件"""

    def __init__(self):
        super().__init__("temp_file", "检测临时目录中的可疑文件", "persistence")
        self.command = """find /tmp /var/tmp /dev/shm -type f 2>/dev/null | head -50"""
        self.patterns = [
            r'\.py$',
            r'\.pl$',
            r'\.sh$',
            r'\.backdoor',
            r'\.bdoor',
            r'nc',
            r'rootkit',
            r'hack',
            r'shell',
        ]
        self.severity = "warning"


class NetworkConnectionDetection(DetectionCommand):
    """检测异常网络连接"""

    def __init__(self):
        super().__init__("network_connection", "检测异常的外连行为", "network")
        self.command = """ss -tanp 2>/dev/null | grep ESTAB; echo "===LISTEN==="; ss -tlnp 2>/dev/null | grep LISTEN"""
        self.patterns = [r'TIME_WAIT', r'CLOSE_WAIT']
        self.severity = "info"


class StartupServiceDetection(DetectionCommand):
    """检测开机启动服务"""

    def __init__(self):
        super().__init__("startup_service", "检测开机启动项中的可疑服务", "persistence")
        self.command = """systemctl list-units --type=service --state=running 2>/dev/null; echo "===RC_LOCALS==="; cat /etc/rc.local 2>/dev/null; ls -la /etc/init.d/ 2>/dev/null | head -20"""
        self.patterns = [
            r'suspicious',
            r'backdoor',
            r'hack',
            r'nc\s',
            r'netcat',
        ]
        self.severity = "warning"


class BashHistoryDetection(DetectionCommand):
    """检测历史命令异常"""

    def __init__(self):
        super().__init__("bash_history", "检测bash历史中的可疑命令", "investigation")
        self.command = """tail -100 ~/.bash_history 2>/dev/null | grep -E '(wget|curl|nc|netcat|bash.*-i|/bin/bash.*i|python.*http|telnet|ssh.*-o|scp|sftp)' 2>/dev/null"""
        self.patterns = [
            r'curl.*\|.*bash',
            r'wget.*\|.*bash',
            r'nc\s+-e',
            r'bash\s+-i',
            r'python.*-m\s+http',
            r'telnet',
            r'ssh\s+-R',
        ]
        self.severity = "warning"


class SystemUserDetection(DetectionCommand):
    """检测异常系统用户"""

    def __init__(self):
        super().__init__("system_user", "检测异常的系统用户", "persistence")
        self.command = """cat /etc/passwd | grep -E '^[^:]+:[^:]+:[0-9]{1,4}:[0-9]+:' | tail -20"""
        self.patterns = [r'bash$', r'sh$']
        self.severity = "info"


class SshdStatusDetection(DetectionCommand):
    """检测SSH服务状态"""

    def __init__(self):
        super().__init__("sshd_status", "检测SSH服务状态", "service")
        self.command = """systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || service ssh status 2>/dev/null"""
        self.patterns = [r'Active:\s+active\s+\(running\)', r'Active:\s+failed']
        self.severity = "info"


class RootkitDetection(DetectionCommand):
    """检测rootkit特征"""

    def __init__(self):
        super().__init__("rootkit", "检测rootkit典型特征", "malware")
        self.command = """ls -la /lib64/security/ 2>/dev/null; ls -la /usr/lib/security/ 2>/dev/null; echo "===LD_PRELOAD==="; cat /etc/ld.so.preload 2>/dev/null || true; echo "===LSMOD==="; lsmod 2>/dev/null"""
        self.patterns = [r'\.ko$', r'virtio', r'security/']
        self.severity = "danger"


class NetworkInterfaceDetection(DetectionCommand):
    """检测异常网络接口"""

    def __init__(self):
        super().__init__("network_interface", "检测异常网络接口（如伪装网卡）", "network")
        self.command = """ip link show 2>/dev/null; echo "===IFCONFIG==="; ifconfig -a 2>/dev/null"""
        self.patterns = [r'^[0-9]+:\s+eth\d+:.*Promisc', r'Promiscuous']
        self.severity = "warning"


class FileIntegrityDetection(DetectionCommand):
    """检测系统文件完整性"""

    def __init__(self):
        super().__init__("file_integrity", "检测系统关键文件是否被修改", "integrity")
        self.command = """stat /bin/ls /bin/bash /usr/bin/ssh 2>/dev/null; echo "===CHECKSUMS==="; md5sum /bin/ls /bin/bash 2>/dev/null"""
        self.patterns = []
        self.severity = "info"


class EnvAbnormalDetection(DetectionCommand):
    """检测异常环境变量"""

    def __init__(self):
        super().__init__("env_abnormal", "检测异常的环境变量", "investigation")
        self.command = """env | grep -E '(LD_|DYLD_|JAVA_|PYTHON|PS1|SHELL)' 2>/dev/null"""
        self.patterns = [r'LD_PRELOAD', r'LD_LIBRARY_PATH=/tmp', r'DYLD_INSERT']
        self.severity = "warning"


class SelinuxStatusDetection(DetectionCommand):
    """检测SELinux状态"""

    def __init__(self):
        super().__init__("selinux_status", "检测SELinux/AppArmor状态", "security")
        self.command = """getenforce 2>/dev/null; sestatus 2>/dev/null; echo "===APPARMOR==="; aa-status 2>/dev/null"""
        self.patterns = [r'Disabled', r'Permissive']
        self.severity = "info"


class FirewallStatusDetection(DetectionCommand):
    """检测防火墙状态"""

    def __init__(self):
        super().__init__("firewall_status", "检测防火墙是否被关闭", "security")
        self.command = """iptables -L -n 2>/dev/null | head -20; echo "===UFW==="; ufw status 2>/dev/null; echo "===FIREWALLD==="; firewall-cmd --state 2>/dev/null"""
        self.patterns = [
            r'Chain\s+INPUT\s+policy\s+ACCEPT',
            r'Chain\s+FORWARD\s+policy\s+ACCEPT',
            r'Chain\s+OUTPUT\s+policy\s+ACCEPT',
        ]
        self.severity = "warning"


class MalwareFileDetection(DetectionCommand):
    """检测恶意文件特征"""

    def __init__(self):
        super().__init__("malware_file", "检测常见的恶意文件模式", "malware")
        self.command = """grep -r -l "eval.*base64" /tmp /var/tmp /dev/shm 2>/dev/null | head -10; echo "===SHELL_PATTERNS==="; find /tmp /var/tmp -name "*.php" -o -name "*.asp" -o -name "*.jsp" 2>/dev/null | head -10"""
        self.patterns = [
            r'eval\s*\(\s*base64',
            r'gzinflate\s*\(',
            r'str_rot13\s*\(',
            r'system\s*\(',
            r'exec\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
        ]
        self.severity = "danger"


def get_all_detection_commands() -> List[DetectionCommand]:
    """获取所有检测命令"""
    return [
        SuspiciousPortDetection(),
        NetworkConnectionDetection(),
        NetworkInterfaceDetection(),
        SuspiciousProcessDetection(),
        HiddenProcessDetection(),
        CronJobDetection(),
        SshKeyDetection(),
        SshdConfigDetection(),
        SuidFileDetection(),
        TempFileDetection(),
        StartupServiceDetection(),
        SystemUserDetection(),
        SshdStatusDetection(),
        RootkitDetection(),
        BashHistoryDetection(),
        EnvAbnormalDetection(),
        SelinuxStatusDetection(),
        FirewallStatusDetection(),
        FileIntegrityDetection(),
        MalwareFileDetection(),
    ]


def get_detection_command_by_name(name: str) -> Optional[DetectionCommand]:
    """根据名称获取检测命令"""
    commands = get_all_detection_commands()
    for cmd in commands:
        if cmd.name == name:
            return cmd
    return None


def get_commands_by_category() -> Dict[str, List[DetectionCommand]]:
    """按类别获取检测命令"""
    commands = get_all_detection_commands()
    categories = {}
    for cmd in commands:
        if cmd.category not in categories:
            categories[cmd.category] = []
        categories[cmd.category].append(cmd)
    return categories