"""
数据库管理模块 - 使用SQLite存储检测结果
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path


class Database:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'results.db')

    def __init__(self):
        self._ensure_data_dir()
        self._init_db()
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Database initialized, DB_PATH={self.DB_PATH}")

    def _ensure_data_dir(self):
        Path(os.path.dirname(self.DB_PATH)).mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            # 服务器列表表
            conn.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    id TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT,
                    password TEXT,
                    status TEXT,
                    os_info TEXT,
                    arch TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            # 检测结果表
            conn.execute('''
                CREATE TABLE IF NOT EXISTS detection_results (
                    id TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL,
                    server_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    overall_status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    os_info TEXT,
                    arch TEXT,
                    error_message TEXT,
                    items_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_server_id ON detection_results(server_id)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_server_ip ON detection_results(server_ip)
            ''')
            conn.commit()

    # ===== 服务器列表操作 =====
    def save_server(self, server: Dict[str, Any]) -> bool:
        """保存或更新服务器"""
        try:
            with self._get_conn() as conn:
                now = datetime.now().isoformat()
                conn.execute('''
                    INSERT OR REPLACE INTO servers
                    (id, ip, port, username, password, status, os_info, arch, last_error, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    server.get('id'),
                    server.get('ip'),
                    server.get('port', 22),
                    server.get('username', ''),
                    server.get('password', ''),
                    server.get('status', 'pending'),
                    server.get('os_info'),
                    server.get('arch'),
                    server.get('last_error'),
                    now,
                    now
                ))
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"保存服务器失败: {e}")
            return False

    def save_servers_batch(self, servers: List[Dict[str, Any]]) -> bool:
        """批量保存服务器"""
        try:
            with self._get_conn() as conn:
                now = datetime.now().isoformat()
                for s in servers:
                    conn.execute('''
                        INSERT OR REPLACE INTO servers
                        (id, ip, port, username, password, status, os_info, arch, last_error, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        s.get('id'),
                        s.get('ip'),
                        s.get('port', 22),
                        s.get('username', ''),
                        s.get('password', ''),
                        s.get('status', 'pending'),
                        s.get('os_info'),
                        s.get('arch'),
                        s.get('last_error'),
                        now,
                        now
                    ))
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"批量保存服务器失败: {e}")
            return False

    def get_all_servers(self) -> List[Dict[str, Any]]:
        """获取所有服务器"""
        with self._get_conn() as conn:
            rows = conn.execute('SELECT * FROM servers ORDER BY updated_at DESC').fetchall()
            return [dict(row) for row in rows]

    def delete_server(self, server_id: str) -> bool:
        """删除服务器"""
        try:
            with self._get_conn() as conn:
                conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"删除服务器失败: {e}")
            return False

    def delete_servers(self, server_ids: List[str]) -> int:
        """批量删除服务器"""
        try:
            with self._get_conn() as conn:
                placeholders = ','.join('?' * len(server_ids))
                cursor = conn.execute(
                    f'DELETE FROM servers WHERE id IN ({placeholders})',
                    server_ids
                )
                conn.commit()
            return cursor.rowcount
        except Exception as e:
            import logging
            logging.error(f"批量删除服务器失败: {e}")
            return 0

    # ===== 检测结果操作 =====
        """保存或更新检测结果"""
        try:
            with self._get_conn() as conn:
                now = datetime.now().isoformat()
                items_json = json.dumps(result.get('items', []), ensure_ascii=False)

                conn.execute('''
                    INSERT OR REPLACE INTO detection_results
                    (id, server_id, server_ip, timestamp, overall_status, score,
                     os_info, arch, error_message, items_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.get('id') or result.get('server_id'),
                    result['server_id'],
                    result['server_ip'],
                    result.get('timestamp', now),
                    result.get('overall_status', 'clean'),
                    result.get('score', 100),
                    result.get('os_info'),
                    result.get('arch'),
                    result.get('error_message'),
                    items_json,
                    now,
                    now
                ))
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"保存结果失败: {e}")
            return False

    def save_results_batch(self, results: List[Dict[str, Any]]) -> bool:
        """批量保存检测结果"""
        try:
            with self._get_conn() as conn:
                now = datetime.now().isoformat()
                for result in results:
                    items_json = json.dumps(result.get('items', []), ensure_ascii=False)
                    conn.execute('''
                        INSERT OR REPLACE INTO detection_results
                        (id, server_id, server_ip, timestamp, overall_status, score,
                         os_info, arch, error_message, items_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        result.get('id') or result.get('server_id'),
                        result['server_id'],
                        result['server_ip'],
                        result.get('timestamp', now),
                        result.get('overall_status', 'clean'),
                        result.get('score', 100),
                        result.get('os_info'),
                        result.get('arch'),
                        result.get('error_message'),
                        items_json,
                        now,
                        now
                    ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"批量保存结果失败: {e}")
            return False

    def get_all_results(self) -> List[Dict[str, Any]]:
        """获取所有检测结果"""
        with self._get_conn() as conn:
            rows = conn.execute('''
                SELECT * FROM detection_results ORDER BY updated_at DESC
            ''').fetchall()

            results = []
            for row in rows:
                r = dict(row)
                r['items'] = json.loads(r.pop('items_json'))
                r['timestamp'] = r['timestamp']
                results.append(r)
            return results

    def get_result_by_id(self, server_id: str) -> Optional[Dict[str, Any]]:
        """根据服务器ID获取检测结果"""
        with self._get_conn() as conn:
            row = conn.execute(
                'SELECT * FROM detection_results WHERE server_id = ?',
                (server_id,)
            ).fetchone()
            if row:
                r = dict(row)
                r['items'] = json.loads(r.pop('items_json'))
                return r
            return None

    def delete_result(self, server_id: str) -> bool:
        """删除单个检测结果"""
        import logging
        logger = logging.getLogger(__name__)
        try:
            with self._get_conn() as conn:
                cursor = conn.execute('DELETE FROM detection_results WHERE server_id = ?', (server_id,))
                conn.commit()
                logger.info(f"删除 server_id={server_id}, 影响行数={cursor.rowcount}")
            return True
        except Exception as e:
            logger.error(f"删除结果失败: {e}")
            return False

    def delete_results(self, server_ids: List[str]) -> int:
        """批量删除检测结果"""
        try:
            with self._get_conn() as conn:
                placeholders = ','.join('?' * len(server_ids))
                cursor = conn.execute(
                    f'DELETE FROM detection_results WHERE server_id IN ({placeholders})',
                    server_ids
                )
                conn.commit()
            return cursor.rowcount
        except Exception as e:
            import logging
            logging.error(f"批量删除结果失败: {e}")
            return 0

    def clear_all(self) -> bool:
        """清空所有检测结果（不清服务器列表）"""
        try:
            with self._get_conn() as conn:
                conn.execute('DELETE FROM detection_results')
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"清空结果失败: {e}")
            return False

    def clear_servers(self) -> bool:
        """清空所有服务器"""
        try:
            with self._get_conn() as conn:
                conn.execute('DELETE FROM servers')
                conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"清空服务器失败: {e}")
            return False

    def get_result_count(self) -> int:
        """获取结果数量"""
        with self._get_conn() as conn:
            row = conn.execute('SELECT COUNT(*) as cnt FROM detection_results').fetchone()
            return row['cnt'] if row else 0


_db_instance: Optional[Database] = None


def get_database() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance