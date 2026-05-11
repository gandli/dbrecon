import pytest
import mysql.connector
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from dbrecon.database import DatabaseManager
from dbrecon.models import DatabaseConnection


class TestDatabaseManager:
    """Test cases for DatabaseManager class."""

    @pytest.fixture
    def db_config(self) -> DatabaseConnection:
        """Fixture providing a test database configuration."""
        return DatabaseConnection(
            host="localhost",
            port=3306,
            user="test_user",
            password="test_password",
            database="test_db",
            ssl_enabled=False,
            timeout=30
        )

    @pytest.fixture
    def mock_connection(self):
        """Fixture providing a mock database connection."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.is_connected.return_value = True
        return mock_conn, mock_cursor

    def test_database_connection_initialization(self, db_config):
        """Test DatabaseManager initialization with valid config."""
        manager = DatabaseManager(db_config)
        assert manager.config == db_config
        assert manager.connection is None

    @patch('mysql.connector.connect')
    def test_connect_success(self, mock_connect, db_config, mock_connection):
        """Test successful database connection."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        result = manager.connect()

        assert result is True
        assert manager.connection == mock_conn
        mock_connect.assert_called_once_with(
            host=db_config.host,
            port=db_config.port,
            user=db_config.user,
            password=db_config.password,
            database=db_config.database,
            ssl_disabled=not db_config.ssl_enabled,
            connection_timeout=db_config.timeout
        )

    @patch('mysql.connector.connect')
    def test_connect_failure(self, mock_connect, db_config):
        """Test database connection failure."""
        mock_connect.side_effect = mysql.connector.Error("Connection failed")

        manager = DatabaseManager(db_config)
        result = manager.connect()

        assert result is False
        assert manager.connection is None

    @patch('mysql.connector.connect')
    def test_disconnect_success(self, mock_connect, db_config, mock_connection):
        """Test successful database disconnection."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        manager.connection = mock_conn
        
        manager.disconnect()
        
        mock_conn.close.assert_called_once()
        assert manager.connection is None

    def test_disconnect_no_connection(self, db_config):
        """Test disconnection when no connection exists."""
        manager = DatabaseManager(db_config)
        manager.disconnect()  # Should not raise exception
        assert manager.connection is None

    @patch('mysql.connector.connect')
    def test_execute_query_success(self, mock_connect, db_config, mock_connection):
        """Test successful query execution."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        expected_result = [("db1",), ("db2",)]
        mock_cursor.fetchall.return_value = expected_result

        manager = DatabaseManager(db_config)
        manager.connect()
        
        result = manager.execute_query("SHOW DATABASES")
        
        assert result == expected_result
        mock_cursor.execute.assert_called_once_with("SHOW DATABASES", None)
        mock_cursor.fetchall.assert_called_once()

    @patch('mysql.connector.connect')
    def test_execute_query_with_params(self, mock_connect, db_config, mock_connection):
        """Test query execution with parameters."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        expected_result = [("user1",), ("user2",)]
        mock_cursor.fetchall.return_value = expected_result

        manager = DatabaseManager(db_config)
        manager.connect()
        
        query = "SELECT * FROM users WHERE status = %s"
        params = ("active",)
        result = manager.execute_query(query, params)
        
        assert result == expected_result
        mock_cursor.execute.assert_called_once_with(query, params)

    @patch('mysql.connector.connect')
    def test_execute_query_no_connection(self, mock_connect, db_config):
        """Test query execution without active connection."""
        manager = DatabaseManager(db_config)
        
        with pytest.raises(RuntimeError, match="No active database connection"):
            manager.execute_query("SELECT 1")

    @patch('mysql.connector.connect')
    def test_execute_query_error(self, mock_connect, db_config, mock_connection):
        """Test query execution with database error."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        mock_cursor.execute.side_effect = mysql.connector.Error("Query failed")

        manager = DatabaseManager(db_config)
        manager.connect()
        
        with pytest.raises(mysql.connector.Error):
            manager.execute_query("INVALID SQL")

    @patch('mysql.connector.connect')
    def test_get_databases(self, mock_connect, db_config, mock_connection):
        """Test retrieving database list."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        expected_databases = [("information_schema",), ("mysql",), ("test_db",)]
        mock_cursor.fetchall.return_value = expected_databases

        manager = DatabaseManager(db_config)
        manager.connect()
        
        result = manager.get_databases()
        
        assert result == ["information_schema", "mysql", "test_db"]
        mock_cursor.execute.assert_called_once_with("SHOW DATABASES", None)

    @patch('mysql.connector.connect')
    def test_get_tables(self, mock_connect, db_config, mock_connection):
        """Test retrieving table list from database."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        expected_tables = [("users",), ("posts",), ("comments",)]
        mock_cursor.fetchall.return_value = expected_tables

        manager = DatabaseManager(db_config)
        manager.connect()
        
        result = manager.get_tables("test_db")
        
        assert result == ["users", "posts", "comments"]
        mock_cursor.execute.assert_called_once_with(
            "SHOW TABLES FROM test_db", None
        )

    @patch('mysql.connector.connect')
    def test_get_table_structure(self, mock_connect, db_config, mock_connection):
        """Test retrieving table structure."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        expected_structure = [
            ("id", "int(11)", "NO", "PRI", None, "auto_increment"),
            ("username", "varchar(50)", "NO", "UNI", None, ""),
            ("email", "varchar(100)", "YES", "", None, "")
        ]
        mock_cursor.fetchall.return_value = expected_structure

        manager = DatabaseManager(db_config)
        manager.connect()
        
        result = manager.get_table_structure("test_db", "users")
        
        assert len(result) == 3
        assert result[0]["name"] == "id"
        assert result[0]["type"] == "int(11)"
        assert result[1]["name"] == "username"
        assert result[2]["name"] == "email"
        
        mock_cursor.execute.assert_called_once()
        call_args = mock_cursor.execute.call_args[0][0]
        assert "DESCRIBE" in call_args or "SHOW COLUMNS" in call_args

    @patch('mysql.connector.connect')
    def test_get_server_info(self, mock_connect, db_config, mock_connection):
        """Test retrieving server information."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        mock_conn.get_server_info.return_value = "8.0.28"
        mock_conn.charset = "utf8mb4"
        mock_conn.time_zone = "SYSTEM"

        manager = DatabaseManager(db_config)
        manager.connect()
        
        result = manager.get_server_info()
        
        assert result["version"] == "8.0.28"
        assert result["charset"] == "utf8mb4"
        assert "time_zone" in result

    @patch('mysql.connector.connect')
    def test_connection_pooling(self, mock_connect, db_config, mock_connection):
        """Test connection reuse."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn

        manager = DatabaseManager(db_config)
        
        # First connection
        result1 = manager.connect()
        # Second connection should reuse existing
        result2 = manager.connect()
        
        assert result1 is True
        assert result2 is True
        assert manager.connection == mock_conn
        mock_connect.assert_called_once()  # Should only be called once

    @pytest.mark.parametrize("ssl_enabled", [True, False])
    @patch('mysql.connector.connect')
    def test_ssl_configuration(self, mock_connect, db_config, mock_connection, ssl_enabled):
        """Test SSL configuration handling."""
        mock_conn, mock_cursor = mock_connection
        mock_connect.return_value = mock_conn
        
        db_config.ssl_enabled = ssl_enabled
        
        manager = DatabaseManager(db_config)
        manager.connect()
        
        _, call_kwargs = mock_connect.call_args
        expected_ssl_disabled = not ssl_enabled
        assert call_kwargs["ssl_disabled"] == expected_ssl_disabled