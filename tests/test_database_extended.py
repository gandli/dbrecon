"""
Extended tests for DatabaseManager - covering edge cases and untested paths.

Tests focus on:
- get_server_info with no connection
- get_cursor context manager behavior
- Additional edge cases for connection handling
"""

import pytest
import mysql.connector
from unittest.mock import Mock, patch, MagicMock

from dbrecon.database import DatabaseManager
from dbrecon.models import DatabaseConnection


class TestDatabaseManagerExtended:
    """Extended test cases for DatabaseManager edge cases."""

    @pytest.fixture
    def db_config(self) -> DatabaseConnection:
        return DatabaseConnection(
            host="localhost",
            port=3306,
            user="test_user",
            password="test_password",
            database="test_db",
            ssl_enabled=False,
            timeout=30
        )

    def test_get_server_info_no_connection(self, db_config):
        """Test get_server_info returns empty dict when no connection."""
        manager = DatabaseManager(db_config)
        result = manager.get_server_info()
        assert result == {}

    def test_get_server_info_missing_attributes(self, db_config):
        """Test get_server_info with connection missing optional attributes."""
        mock_conn = Mock()
        mock_conn.is_connected.return_value = True
        mock_conn.get_server_info.return_value = "8.0.28"
        del mock_conn.charset
        del mock_conn.time_zone

        manager = DatabaseManager(db_config)
        manager.connection = mock_conn

        result = manager.get_server_info()
        assert result["version"] == "8.0.28"
        assert result["charset"] is None
        assert result["time_zone"] is None

    @patch('mysql.connector.connect')
    def test_get_cursor_success(self, mock_connect, db_config):
        """Test get_cursor context manager yields cursor."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.is_connected.return_value = True
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        manager.connect()

        with manager.get_cursor() as cursor:
            assert cursor == mock_cursor

        mock_cursor.close.assert_called_once()

    @patch('mysql.connector.connect')
    def test_get_cursor_closes_on_exception(self, mock_connect, db_config):
        """Test get_cursor closes cursor even when exception occurs."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.is_connected.return_value = True
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        manager.connect()

        with pytest.raises(ValueError):
            with manager.get_cursor() as cursor:
                raise ValueError("Test error")

        mock_cursor.close.assert_called_once()

    def test_get_cursor_no_connection(self, db_config):
        """Test get_cursor raises RuntimeError when no connection."""
        manager = DatabaseManager(db_config)

        with pytest.raises(RuntimeError, match="No active database connection"):
            with manager.get_cursor() as cursor:
                pass

    def test_get_cursor_disconnected(self, db_config):
        """Test get_cursor raises RuntimeError when connection is lost."""
        mock_conn = Mock()
        mock_conn.is_connected.return_value = False

        manager = DatabaseManager(db_config)
        manager.connection = mock_conn

        with pytest.raises(RuntimeError, match="No active database connection"):
            with manager.get_cursor() as cursor:
                pass

    @patch('mysql.connector.connect')
    def test_connect_already_connected(self, mock_connect, db_config, mock_connection):
        """Test connect() returns True when already connected."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        manager.connect()

        result = manager.connect()
        assert result is True
        mock_connect.assert_called_once()

    @patch('mysql.connector.connect')
    def test_disconnect_already_disconnected(self, mock_connect, db_config):
        """Test disconnect when already disconnected."""
        manager = DatabaseManager(db_config)
        manager.disconnect()
        assert manager.connection is None

    @patch('mysql.connector.connect')
    def test_disconnect_with_none_connection(self, mock_connect, db_config):
        """Test disconnect when connection is None."""
        manager = DatabaseManager(db_config)
        manager.connection = None
        manager.disconnect()
        assert manager.connection is None

    @patch('mysql.connector.connect')
    def test_get_table_structure_empty_result(self, mock_connect, db_config, mock_connection):
        """Test get_table_structure with empty table."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        mock_cursor.fetchall.return_value = []

        manager = DatabaseManager(db_config)
        manager.connect()

        result = manager.get_table_structure("test_db", "empty_table")
        assert result == []

    @patch('mysql.connector.connect')
    def test_get_tables_empty_database(self, mock_connect, db_config, mock_connection):
        """Test get_tables with empty database."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        mock_cursor.fetchall.return_value = []

        manager = DatabaseManager(db_config)
        manager.connect()

        result = manager.get_tables("empty_db")
        assert result == []

    @patch('mysql.connector.connect')
    def test_get_databases_empty(self, mock_connect, db_config, mock_connection):
        """Test get_databases with no databases."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        mock_cursor.fetchall.return_value = []

        manager = DatabaseManager(db_config)
        manager.connect()

        result = manager.get_databases()
        assert result == []

    @pytest.mark.parametrize("port", [3306, 3307, 5432, 8080])
    @patch('mysql.connector.connect')
    def test_connect_various_ports(self, mock_connect, db_config, mock_connection, port):
        """Test connection with various port numbers."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        db_config.port = port

        manager = DatabaseManager(db_config)
        manager.connect()

        _, call_kwargs = mock_connect.call_args
        assert call_kwargs["port"] == port

    @pytest.mark.parametrize("timeout", [5, 10, 30, 60, 120])
    @patch('mysql.connector.connect')
    def test_connect_various_timeouts(self, mock_connect, db_config, mock_connection, timeout):
        """Test connection with various timeout values."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        db_config.timeout = timeout

        manager = DatabaseManager(db_config)
        manager.connect()

        _, call_kwargs = mock_connect.call_args
        assert call_kwargs["connection_timeout"] == timeout

    @patch('mysql.connector.connect')
    def test_connect_with_database_none(self, mock_connect, db_config, mock_connection):
        """Test connection with no specific database."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        db_config.database = None

        manager = DatabaseManager(db_config)
        manager.connect()

        _, call_kwargs = mock_connect.call_args
        assert call_kwargs["database"] is None

    @patch('mysql.connector.connect')
    def test_connect_with_special_characters_password(self, mock_connect, db_config, mock_connection):
        """Test connection with special characters in password."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        db_config.password = "p@$$w0rd!#%^&*()"

        manager = DatabaseManager(db_config)
        manager.connect()

        _, call_kwargs = mock_connect.call_args
        assert call_kwargs["password"] == "p@$$w0rd!#%^&*()"

    @patch('mysql.connector.connect')
    def test_multiple_connect_disconnect_cycles(self, mock_connect, db_config, mock_connection):
        """Test multiple connect/disconnect cycles."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)

        for _ in range(3):
            result = manager.connect()
            assert result is True
            manager.disconnect()
            assert manager.connection is None
