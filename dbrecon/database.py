"""
Database manager supporting multiple database backends.

Supported drivers:
- mysql (mysql-connector-python) — MySQL / MariaDB
- mssql (pyodbc) — Microsoft SQL Server

The driver is selected automatically based on config.driver or port number.
"""

import importlib
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

from dbrecon.models import DatabaseConnection, TableInfo


class DatabaseManager:
    """Manages database connections and operations across multiple backends."""

    DRIVER_MYSQL = "mysql"
    DRIVER_MSSQL = "mssql"

    def __init__(self, config: DatabaseConnection):
        """Initialize database manager with connection configuration."""
        self.config = config
        self.connection = None
        self.driver = self._resolve_driver()

    def _resolve_driver(self) -> str:
        """Resolve which database driver to use."""
        if self.config.driver:
            return self.config.driver
        # Auto-detect: 1433 = MSSQL default, 3306 = MySQL default
        if self.config.port == 1433:
            return self.DRIVER_MSSQL
        return self.DRIVER_MYSQL

    def _load_driver_module(self):
        """Lazy-load the database driver module."""
        if self.driver == self.DRIVER_MSSQL:
            try:
                return importlib.import_module("pymssql")
            except ImportError:
                try:
                    return importlib.import_module("pyodbc")
                except ImportError:
                    raise RuntimeError(
                        "MSSQL support requires pymssql or pyodbc. "
                        "Install with: pip install pymssql"
                    )
        try:
            return importlib.import_module("mysql.connector")
        except ImportError:
            raise RuntimeError(
                "mysql-connector-python is required for MySQL support. "
                "Install with: pip install mysql-connector-python"
            )

    def connect(self) -> bool:
        """Establish database connection."""
        if self.connection and self._is_connected():
            return True

        try:
            if self.driver == self.DRIVER_MSSQL:
                return self._connect_mssql()
            return self._connect_mysql()
        except Exception:
            return False

    def _connect_mysql(self) -> bool:
        """Connect to MySQL / MariaDB."""
        mod = self._load_driver_module()
        self.connection = mod.connect(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            ssl_disabled=not self.config.ssl_enabled,
            connection_timeout=self.config.timeout,
        )
        return True

    def _connect_mssql(self) -> bool:
        """Connect to Microsoft SQL Server via pymssql or pyodbc."""
        mod = self._load_driver_module()
        if mod.__name__ == "pymssql":
            self.connection = mod.connect(
                server=f"{self.config.host}:{self.config.port}",
                user=self.config.user,
                password=self.config.password,
                database=self.config.database or "master",
                login_timeout=self.config.timeout,
                tds_version="7.4",
            )
        else:
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={self.config.host},{self.config.port};"
                f"DATABASE={self.config.database or 'master'};"
                f"UID={self.config.user};"
                f"PWD={self.config.password};"
                f"Encrypt=yes;TrustServerCertificate=yes;"
                f"Connection Timeout={self.config.timeout};"
            )
            self.connection = mod.connect(conn_str)
        return True

    def _is_connected(self) -> bool:
        """Check if the current connection is alive."""
        if self.connection is None:
            return False
        if self.driver == self.DRIVER_MSSQL:
            try:
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                return True
            except Exception:
                return False
        try:
            return self.connection.is_connected()
        except Exception:
            return False

    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None

    def execute_query(self, query: str, params: Optional[tuple] = None) -> List[tuple]:
        """Execute a SQL query and return results."""
        if not self.connection or not self._is_connected():
            raise RuntimeError("No active database connection")

        cursor = self.connection.cursor()
        try:
            if params is not None:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()
        finally:
            cursor.close()

    def get_databases(self) -> List[str]:
        """Get list of all databases."""
        if self.driver == self.DRIVER_MSSQL:
            results = self.execute_query(
                "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name"
            )
        else:
            results = self.execute_query("SHOW DATABASES")
        return [row[0] for row in results]

    def get_tables(self, database: str) -> List[str]:
        """Get list of tables in specified database."""
        if self.driver == self.DRIVER_MSSQL:
            results = self.execute_query(
                f"SELECT TABLE_NAME FROM {database}.INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME"
            )
        else:
            results = self.execute_query(f"SHOW TABLES FROM {database}")
        return [row[0] for row in results]

    def get_table_structure(self, database: str, table: str) -> List[Dict[str, Any]]:
        """Get structure information for a specific table."""
        if self.driver == self.DRIVER_MSSQL:
            return self._get_table_structure_mssql(database, table)
        return self._get_table_structure_mysql(database, table)

    def _get_table_structure_mysql(self, database: str, table: str) -> List[Dict[str, Any]]:
        """Get table structure for MySQL."""
        results = self.execute_query(f"DESCRIBE {database}.{table}")
        columns = []
        for row in results:
            columns.append({
                "name": row[0],
                "type": row[1],
                "nullable": row[2] == "YES",
                "key": row[3],
                "extra": row[5],
            })
        return columns

    def _get_table_structure_mssql(self, database: str, table: str) -> List[Dict[str, Any]]:
        """Get table structure for MSSQL."""
        results = self.execute_query(
            f"SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT "
            f"FROM {database}.INFORMATION_SCHEMA.COLUMNS "
            f"WHERE TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
            (table,),
        )
        columns = []
        for row in results:
            columns.append({
                "name": row[0],
                "type": row[1],
                "nullable": row[2] == "YES",
                "key": "",
                "extra": row[3] if row[3] else "",
            })
        return columns

    def get_server_info(self) -> Dict[str, Any]:
        """Get database server information."""
        if not self.connection:
            return {}

        if self.driver == self.DRIVER_MSSQL:
            try:
                cursor = self.connection.cursor()
                cursor.execute("SELECT @@VERSION, @@SERVERNAME")
                row = cursor.fetchone()
                cursor.close()
                if row:
                    return {
                        "version": row[0].split("\n")[0] if row[0] else "unknown",
                        "servername": row[1] if row[1] else "unknown",
                        "driver": "mssql",
                    }
            except Exception:
                pass
            return {"driver": "mssql"}

        return {
            "version": self.connection.get_server_info(),
            "charset": getattr(self.connection, "charset", None),
            "time_zone": getattr(self.connection, "time_zone", None),
            "driver": "mysql",
        }

    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor."""
        if not self.connection or not self._is_connected():
            raise RuntimeError("No active database connection")

        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()
