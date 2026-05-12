"""
Unit tests for DatabaseManager MSSQL paths (mocked pymssql).

Covers all MSSQL branches in database.py that can't be tested
without a real SQL Server instance:
- _resolve_driver (MSSQL auto-detect from port 1433)
- _load_driver_module (pymssql import, pyodbc fallback, ImportError)
- _connect_mssql (pymssql path, pyodbc path)
- _is_connected (MSSQL path)
- disconnect (exception handling)
- get_databases (MSSQL query)
- get_tables (MSSQL INFORMATION_SCHEMA query)
- get_table_structure / _get_table_structure_mssql
- get_server_info (MSSQL @@VERSION query)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call

from dbrecon.database import DatabaseManager
from dbrecon.models import DatabaseConnection


MSSQL_CONFIG = dict(
    host="127.0.0.1",
    port=1433,
    user="sa",
    password="TestPass123!",
    database="testdb",
    ssl_enabled=False,
    timeout=30,
    driver="mssql",
)

MYSQL_CONFIG = dict(
    host="localhost",
    port=3306,
    user="root",
    password="pass",
    database="testdb",
    ssl_enabled=False,
    timeout=30,
)


class TestResolveDriver:
    """Tests for _resolve_driver auto-detection."""

    def test_explicit_mysql_driver(self):
        """driver='mysql' → MYSQL."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MYSQL

    def test_explicit_mssql_driver(self):
        """driver='mssql' → MSSQL."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MSSQL

    def test_auto_detect_mysql_port(self):
        """port=3306, no driver → MYSQL."""
        cfg = dict(MYSQL_CONFIG)
        cfg.pop("driver", None)
        config = DatabaseConnection(**cfg)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MYSQL

    def test_auto_detect_mssql_port(self):
        """port=1433, no driver → MSSQL."""
        cfg = dict(MSSQL_CONFIG)
        cfg.pop("driver", None)
        config = DatabaseConnection(**cfg)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MSSQL

    def test_custom_port_defaults_to_mysql(self):
        """Custom port (not 1433) → MYSQL."""
        cfg = dict(MYSQL_CONFIG)
        cfg["port"] = 3307
        cfg.pop("driver", None)
        config = DatabaseConnection(**cfg)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MYSQL

    def test_explicit_driver_overrides_port(self):
        """driver='mssql' with port=3306 → MSSQL."""
        cfg = dict(MYSQL_CONFIG)
        cfg["driver"] = "mssql"
        config = DatabaseConnection(**cfg)
        mgr = DatabaseManager(config)
        assert mgr.driver == DatabaseManager.DRIVER_MSSQL


class TestLoadDriverModule:
    """Tests for _load_driver_module."""

    def test_load_pymssql_success(self):
        """pymssql available → returns pymssql module."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mock_mod = Mock(__name__="pymssql")
        with patch("importlib.import_module", return_value=mock_mod) as mock_import:
            result = mgr._load_driver_module()
            assert result == mock_mod
            mock_import.assert_called_once_with("pymssql")

    def test_pymssql_import_error_pyodbc_success(self):
        """pymssql fails, pyodbc available → returns pyodbc module."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mock_pyodbc = Mock(__name__="pyodbc")
        with patch("importlib.import_module", side_effect=[ImportError, mock_pyodbc]) as mock_import:
            result = mgr._load_driver_module()
            assert result == mock_pyodbc
            assert mock_import.call_count == 2

    def test_both_mssql_drivers_fail(self):
        """pymssql and pyodbc both fail → RuntimeError."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        with patch("importlib.import_module", side_effect=ImportError):
            with pytest.raises(RuntimeError, match="MSSQL support requires"):
                mgr._load_driver_module()

    def test_load_mysql_connector_success(self):
        """MySQL driver → loads mysql.connector."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mock_mod = Mock(__name__="mysql.connector")
        with patch("importlib.import_module", return_value=mock_mod) as mock_import:
            result = mgr._load_driver_module()
            assert result == mock_mod
            mock_import.assert_called_once_with("mysql.connector")

    def test_mysql_connector_import_error(self):
        """mysql.connector not installed → RuntimeError."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        with patch("importlib.import_module", side_effect=ImportError):
            with pytest.raises(RuntimeError, match="mysql-connector-python is required"):
                mgr._load_driver_module()


class TestConnectMSSQL:
    """Tests for _connect_mssql."""

    def test_connect_mssql_pymssql_path(self):
        """pymssql available → connects via pymssql API."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mock_conn = Mock()
        mock_mod = Mock(__name__="pymssql", connect=Mock(return_value=mock_conn))
        with patch.object(mgr, "_load_driver_module", return_value=mock_mod):
            result = mgr._connect_mssql()
            assert result is True
            assert mgr.connection == mock_conn
            mock_mod.connect.assert_called_once_with(
                server="127.0.0.1:1433",
                user="sa",
                password="TestPass123!",
                database="testdb",
                login_timeout=30,
                tds_version="7.4",
            )

    def test_connect_mssql_pyodbc_path(self):
        """pyodbc available → connects via ODBC connection string."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mock_conn = Mock()
        mock_mod = Mock(__name__="pyodbc", connect=Mock(return_value=mock_conn))
        with patch.object(mgr, "_load_driver_module", return_value=mock_mod):
            result = mgr._connect_mssql()
            assert result is True
            assert mgr.connection == mock_conn
            call_args = mock_mod.connect.call_args[0][0]
            assert "DRIVER={ODBC Driver 17 for SQL Server}" in call_args
            assert "SERVER=127.0.0.1,1433" in call_args
            assert "UID=sa" in call_args

    def test_connect_mssql_no_database(self):
        """No database → defaults to 'master'."""
        cfg = dict(MSSQL_CONFIG)
        cfg["database"] = None
        config = DatabaseConnection(**cfg)
        mgr = DatabaseManager(config)
        mock_conn = Mock()
        mock_mod = Mock(__name__="pymssql", connect=Mock(return_value=mock_conn))
        with patch.object(mgr, "_load_driver_module", return_value=mock_mod):
            mgr._connect_mssql()
            mock_mod.connect.assert_called_once_with(
                server="127.0.0.1:1433",
                user="sa",
                password="TestPass123!",
                database="master",
                login_timeout=30,
                tds_version="7.4",
            )


class TestIsConnected:
    """Tests for _is_connected."""

    def test_mssql_connected(self):
        """MSSQL connection alive → True."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mgr.connection.cursor.return_value = mock_cursor
        assert mgr._is_connected() is True
        mock_cursor.execute.assert_called_once_with("SELECT 1")
        mock_cursor.close.assert_called_once()

    def test_mssql_disconnected(self):
        """MSSQL connection dead → False."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("Connection lost")
        mgr.connection.cursor.return_value = mock_cursor
        assert mgr._is_connected() is False

    def test_none_connection(self):
        """connection is None → False."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = None
        assert mgr._is_connected() is False

    def test_mysql_connected(self):
        """MySQL connection alive → True."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.is_connected.return_value = True
        assert mgr._is_connected() is True

    def test_mysql_disconnected(self):
        """MySQL connection dead → False."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.is_connected.return_value = False
        assert mgr._is_connected() is False

    def test_mysql_is_connected_raises(self):
        """MySQL is_connected() raises → False."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.is_connected.side_effect = Exception("Connection broken")
        assert mgr._is_connected() is False


class TestDisconnectException:
    """Tests for disconnect exception handling."""

    def test_disconnect_close_raises(self):
        """connection.close() raises → handled gracefully."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.close.side_effect = Exception("Already closed")
        mgr.disconnect()
        assert mgr.connection is None


class TestGetDatabasesMSSQL:
    """Tests for get_databases with MSSQL."""

    def test_get_databases_mssql(self):
        """MSSQL → queries sys.databases."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            ("master",), ("tempdb",), ("testdb",)
        ]
        mgr.connection.cursor.return_value = mock_cursor
        with patch.object(mgr, "_is_connected", return_value=True):
            results = mgr.get_databases()
        assert results == ["master", "tempdb", "testdb"]
        mock_cursor.execute.assert_called_once_with(
            "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name"
        )


class TestGetTablesMSSQL:
    """Tests for get_tables with MSSQL."""

    def test_get_tables_mssql(self):
        """MSSQL → queries INFORMATION_SCHEMA.TABLES."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            ("wp_users",), ("wp_posts",)
        ]
        mgr.connection.cursor.return_value = mock_cursor
        with patch.object(mgr, "_is_connected", return_value=True):
            results = mgr.get_tables("testdb")
        assert results == ["wp_users", "wp_posts"]
        mock_cursor.execute.assert_called_once_with(
            "SELECT TABLE_NAME FROM testdb.INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_TYPE = N'BASE TABLE' ORDER BY TABLE_NAME"
        )


class TestGetTableStructureMSSQL:
    """Tests for _get_table_structure_mssql."""

    def test_get_table_structure_mssql(self):
        """MSSQL → queries INFORMATION_SCHEMA.COLUMNS."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            ("ID", "bigint", "NO", None),
            ("name", "nvarchar", "YES", None),
        ]
        mgr.connection.cursor.return_value = mock_cursor
        with patch.object(mgr, "_is_connected", return_value=True):
            results = mgr.get_table_structure("testdb", "users")
        assert len(results) == 2
        assert results[0]["name"] == "ID"
        assert results[0]["type"] == "bigint"
        assert results[0]["nullable"] is False
        assert results[1]["name"] == "name"
        assert results[1]["nullable"] is True
        mock_cursor.execute.assert_called_once_with(
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT "
            "FROM testdb.INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
            ("users",),
        )


class TestGetServerInfoMSSQL:
    """Tests for get_server_info with MSSQL."""

    def test_get_server_info_mssql(self):
        """MSSQL → queries @@VERSION, @@SERVERNAME."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            "Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)",
            "MSSQL-SERVER",
        )
        mgr.connection.cursor.return_value = mock_cursor
        info = mgr.get_server_info()
        assert "Microsoft SQL Server 2022" in info["version"]
        assert info["servername"] == "MSSQL-SERVER"
        assert info["driver"] == "mssql"

    def test_get_server_info_mssql_exception(self):
        """MSSQL query fails → returns driver-only dict."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("Query failed")
        mgr.connection.cursor.return_value = mock_cursor
        info = mgr.get_server_info()
        assert info == {"driver": "mssql"}

    def test_get_server_info_mysql(self):
        """MySQL → uses connection.get_server_info()."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.get_server_info.return_value = "8.0.30"
        mgr.connection.charset = "utf8mb4"
        mgr.connection.time_zone = "SYSTEM"
        info = mgr.get_server_info()
        assert info["version"] == "8.0.30"
        assert info["charset"] == "utf8mb4"
        assert info["time_zone"] == "SYSTEM"
        assert info["driver"] == "mysql"


class TestConnectDriverDispatch:
    """Tests for connect() driver dispatch."""

    def test_connect_dispatches_to_mssql(self):
        """driver=mssql → calls _connect_mssql."""
        config = DatabaseConnection(**MSSQL_CONFIG)
        mgr = DatabaseManager(config)
        with patch.object(mgr, "_connect_mssql", return_value=True) as mock_mssql:
            result = mgr.connect()
            assert result is True
            mock_mssql.assert_called_once()

    def test_connect_dispatches_to_mysql(self):
        """driver=mysql → calls _connect_mysql."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        with patch.object(mgr, "_connect_mysql", return_value=True) as mock_mysql:
            result = mgr.connect()
            assert result is True
            mock_mysql.assert_called_once()

    def test_connect_already_connected(self):
        """Already connected → returns True without reconnecting."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mgr.connection.is_connected.return_value = True
        result = mgr.connect()
        assert result is True

    def test_connect_failure_returns_false(self):
        """Connection failure → returns False."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        with patch("importlib.import_module", side_effect=ImportError):
            result = mgr.connect()
            assert result is False


class TestExecuteQueryParams:
    """Tests for execute_query parameter handling."""

    def test_execute_with_params(self):
        """params provided → cursor.execute(query, params)."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [("result",)]
        mgr.connection.cursor.return_value = mock_cursor
        result = mgr.execute_query("SELECT %s", ("value",))
        assert result == [("result",)]
        mock_cursor.execute.assert_called_once_with("SELECT %s", ("value",))

    def test_execute_without_params(self):
        """No params → cursor.execute(query)."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [("result",)]
        mgr.connection.cursor.return_value = mock_cursor
        result = mgr.execute_query("SELECT 1")
        assert result == [("result",)]
        mock_cursor.execute.assert_called_once_with("SELECT 1")

    def test_execute_no_connection_raises(self):
        """No connection → RuntimeError."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        with pytest.raises(RuntimeError, match="No active database connection"):
            mgr.execute_query("SELECT 1")

    def test_execute_cursor_always_closed(self):
        """Cursor closed even if execute raises."""
        config = DatabaseConnection(**MYSQL_CONFIG)
        mgr = DatabaseManager(config)
        mgr.connection = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("Query failed")
        mgr.connection.cursor.return_value = mock_cursor
        with pytest.raises(Exception):
            mgr.execute_query("INVALID SQL")
        mock_cursor.close.assert_called_once()
