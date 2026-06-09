"""
检测报告生成器
支持导出JSON、TXT、HTML格式的报告
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from models import DetectionResult, OverallStatus


class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def generate_json_report(results: List[DetectionResult]) -> str:
        """生成JSON格式报告"""
        report = {
            "report_type": "backdoor_scan",
            "generated_at": datetime.now().isoformat(),
            "total_servers": len(results),
            "summary": ReportGenerator._generate_summary(results),
            "results": [r.to_dict() for r in results]
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_txt_report(results: List[DetectionResult], selected_ids: List[str] = None) -> str:
        """生成TXT格式报告"""
        lines = []
        lines.append("=" * 80)
        lines.append("BackdoorScan 服务器后门扫描报告")
        lines.append("=" * 80)
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"检测服务器数: {len(results)}")
        lines.append("")

        summary = ReportGenerator._generate_summary(results)
        lines.append("-" * 80)
        lines.append("检测汇总")
        lines.append("-" * 80)
        lines.append(f"clean（安全）: {summary['clean']}")
        lines.append(f"suspicious（可疑）: {summary['suspicious']}")
        lines.append(f"critical（危险）: {summary['critical']}")
        lines.append("")

        if selected_ids:
            results = [r for r in results if r.server_id in selected_ids]

        for result in results:
            lines.append("=" * 80)
            lines.append(f"服务器: {result.server_ip}")
            lines.append("=" * 80)
            lines.append(f"检测时间: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

            if result.error_message:
                lines.append(f"状态: 检测失败 - {result.error_message}")
            else:
                lines.append(f"整体状态: {result.overall_status.value}")
                lines.append(f"安全评分: {max(0, result.score)}/100")
                lines.append(f"系统信息: {result.os_info or '未知'}")

                if result.items:
                    lines.append("")
                    lines.append("检测详情:")
                    for item in result.items:
                        status_icon = "✓" if item.status.value == "pass" else "⚠" if item.status.value == "warning" else "✗"
                        lines.append(f"  {status_icon} {item.name}: {item.status.value}")
                        if item.findings:
                            lines.append(f"    发现: {', '.join(item.findings[:3])}")

            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_html_report(results: List[DetectionResult], selected_ids: List[str] = None) -> str:
        """生成HTML格式报告"""
        summary = ReportGenerator._generate_summary(results)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BackdoorScan 服务器后门扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ flex: 1; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card.clean {{ background: #d4edda; }}
        .summary-card.suspicious {{ background: #fff3cd; }}
        .summary-card.critical {{ background: #f8d7da; }}
        .summary-card .number {{ font-size: 36px; font-weight: bold; }}
        .summary-card .label {{ margin-top: 5px; color: #666; }}
        .server {{ margin: 20px 0; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
        .server-header {{ background: #007bff; color: white; padding: 15px; display: flex; justify-content: space-between; }}
        .server-header.critical {{ background: #dc3545; }}
        .server-header.suspicious {{ background: #ffc107; color: #333; }}
        .server-header.clean {{ background: #28a745; }}
        .server-body {{ padding: 15px; }}
        .detection-item {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .detection-item:last-child {{ border-bottom: none; }}
        .status-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: white; }}
        .status-pass {{ background: #28a745; }}
        .status-warning {{ background: #ffc107; color: #333; }}
        .status-danger {{ background: #dc3545; }}
        .status-error {{ background: #6c757d; }}
        .finding {{ background: #fff3cd; padding: 5px 10px; margin: 5px 0; border-left: 3px solid #ffc107; font-size: 13px; }}
        .error-message {{ color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 4px; }}
        .meta {{ color: #666; font-size: 13px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ BackdoorScan 服务器后门扫描报告</h1>
        <p class="meta">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <div class="summary-card clean">
                <div class="number">{summary['clean']}</div>
                <div class="label">安全</div>
            </div>
            <div class="summary-card suspicious">
                <div class="number">{summary['suspicious']}</div>
                <div class="label">可疑</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{summary['critical']}</div>
                <div class="label">危险</div>
            </div>
        </div>
"""

        if selected_ids:
            results = [r for r in results if r.server_id in selected_ids]

        for result in results:
            status_class = result.overall_status.value
            score = max(0, result.score)

            html += f"""
        <div class="server">
            <div class="server-header {status_class}">
                <span><strong>服务器:</strong> {result.server_ip}</span>
                <span><strong>评分:</strong> {score}/100</span>
            </div>
            <div class="server-body">
"""

            if result.error_message:
                html += f'<div class="error-message">检测失败: {result.error_message}</div>'
            else:
                if result.os_info:
                    html += f'<p class="meta"><strong>系统:</strong> {result.os_info}</p>'

                html += """
                <table>
                    <tr>
                        <th style="width: 150px;">检测项</th>
                        <th>状态</th>
                        <th>发现</th>
                    </tr>
"""

                for item in result.items:
                    status_class = f'status-{item.status.value}'
                    findings_str = "<br>".join(item.findings[:5]) if item.findings else "-"

                    html += f"""
                    <tr>
                        <td><strong>{item.name}</strong><br><small>{item.description}</small></td>
                        <td><span class="status-badge {status_class}">{item.status.value}</span></td>
                        <td>{findings_str}</td>
                    </tr>
"""

                html += """
                </table>
"""

            html += """
            </div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def _generate_summary(results: List[DetectionResult]) -> Dict[str, int]:
        """生成汇总信息"""
        summary = {
            "clean": 0,
            "suspicious": 0,
            "critical": 0,
            "total_items": 0,
            "warning_items": 0,
            "danger_items": 0
        }

        for result in results:
            if result.overall_status == OverallStatus.CLEAN:
                summary["clean"] += 1
            elif result.overall_status == OverallStatus.SUSPICIOUS:
                summary["suspicious"] += 1
            else:
                summary["critical"] += 1

            for item in result.items:
                summary["total_items"] += 1
                if item.status.value == "warning":
                    summary["warning_items"] += 1
                elif item.status.value == "danger":
                    summary["danger_items"] += 1

        return summary

    @staticmethod
    def export_report(
        results: List[DetectionResult],
        format: str,
        selected_ids: List[str] = None
    ) -> str:
        """导出报告"""
        if format == "json":
            return ReportGenerator.generate_json_report(results)
        elif format == "html":
            return ReportGenerator.generate_html_report(results, selected_ids)
        elif format == "txt":
            return ReportGenerator.generate_txt_report(results, selected_ids)
        else:
            raise ValueError(f"不支持的格式: {format}")