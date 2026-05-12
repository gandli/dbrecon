"""
Shared test fixtures for DBRecon test suite.

Provides common fixtures used across multiple test modules to reduce
duplication and ensure consistent test setup.
"""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime

from dbrecon.models import (
    DatabaseConnection, TableInfo, FingerprintResult,
    SensitiveData, UrlInfo, ScanResult, ScanConfig
)


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def db_config() -> DatabaseConnection:
    """Standard database connection configuration for testing."""
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
def db_config_ssl() -> DatabaseConnection:
    """SSL-enabled database connection configuration."""
    return DatabaseConnection(
        host="secure-host.example.com",
        port=3306,
        user="admin",
        password="ssl_password",
        database="production_db",
        ssl_enabled=True,
        timeout=60
    )


@pytest.fixture
def mock_connection():
    """Mock database connection with cursor."""
    mock_conn = Mock()
    mock_cursor = Mock()
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.is_connected.return_value = True
    return mock_conn, mock_cursor


# =============================================================================
# Table Fixtures
# =============================================================================

@pytest.fixture
def sample_wordpress_tables():
    """Sample WordPress table structures."""
    return [
        TableInfo(
            name="wp_options",
            columns=[
                {"name": "option_id", "type": "bigint(20)", "nullable": False},
                {"name": "option_name", "type": "varchar(191)", "nullable": False},
                {"name": "option_value", "type": "longtext", "nullable": False},
                {"name": "autoload", "type": "varchar(20)", "nullable": False}
            ]
        ),
        TableInfo(
            name="wp_users",
            columns=[
                {"name": "ID", "type": "bigint(20)", "nullable": False},
                {"name": "user_login", "type": "varchar(60)", "nullable": False},
                {"name": "user_pass", "type": "varchar(255)", "nullable": False},
                {"name": "user_email", "type": "varchar(100)", "nullable": True}
            ]
        ),
        TableInfo(
            name="wp_posts",
            columns=[
                {"name": "ID", "type": "bigint(20)", "nullable": False},
                {"name": "post_title", "type": "text", "nullable": True},
                {"name": "post_content", "type": "longtext", "nullable": True}
            ]
        ),
    ]


@pytest.fixture
def sample_laravel_tables():
    """Sample Laravel table structures."""
    return [
        TableInfo(
            name="migrations",
            columns=[
                {"name": "id", "type": "int(10)", "nullable": False},
                {"name": "migration", "type": "varchar(255)", "nullable": False},
                {"name": "batch", "type": "int(11)", "nullable": False}
            ]
        ),
        TableInfo(
            name="users",
            columns=[
                {"name": "id", "type": "int(10)", "nullable": False},
                {"name": "name", "type": "varchar(255)", "nullable": False},
                {"name": "email", "type": "varchar(255)", "nullable": False},
                {"name": "password", "type": "varchar(255)", "nullable": False},
                {"name": "remember_token", "type": "varchar(100)", "nullable": True}
            ]
        ),
        TableInfo(
            name="password_resets",
            columns=[
                {"name": "email", "type": "varchar(255)", "nullable": False},
                {"name": "token", "type": "varchar(255)", "nullable": False},
                {"name": "created_at", "type": "timestamp", "nullable": True}
            ]
        ),
    ]


@pytest.fixture
def sample_user_table():
    """Sample user table with sensitive data fields."""
    return TableInfo(
        name="users",
        columns=[
            {"name": "id", "type": "int(11)", "nullable": False},
            {"name": "username", "type": "varchar(50)", "nullable": False},
            {"name": "email", "type": "varchar(100)", "nullable": True},
            {"name": "password", "type": "varchar(255)", "nullable": False},
            {"name": "phone", "type": "varchar(20)", "nullable": True},
            {"name": "api_token", "type": "varchar(255)", "nullable": True}
        ]
    )


@pytest.fixture
def sample_config_table():
    """Sample configuration table with potential secrets."""
    return TableInfo(
        name="config",
        columns=[
            {"name": "id", "type": "int(11)", "nullable": False},
            {"name": "config_key", "type": "varchar(100)", "nullable": False},
            {"name": "config_value", "type": "text", "nullable": True},
            {"name": "description", "type": "text", "nullable": True}
        ]
    )


@pytest.fixture
def empty_table():
    """Table with no columns."""
    return TableInfo(name="empty_table", columns=[])


# =============================================================================
# Result Fixtures
# =============================================================================

@pytest.fixture
def sample_fingerprint_result():
    """Sample WordPress fingerprint result."""
    return FingerprintResult(
        application="WordPress",
        confidence=0.95,
        version="5.8.1",
        evidence=[
            {"type": "table", "name": "wp_options", "match": "exact"},
            {"type": "field", "table": "wp_users", "field": "user_pass", "match": "password_hash"}
        ],
        installed_plugins=["woocommerce", "yoast-seo"]
    )


@pytest.fixture
def sample_sensitive_data():
    """Sample sensitive data findings."""
    return [
        SensitiveData(
            table="wp_users",
            field="user_pass",
            data_type="passwords",
            count=15,
            sample_values=["$2y$10$hash1", "$2y$10$hash2"]
        ),
        SensitiveData(
            table="wp_users",
            field="user_email",
            data_type="emails",
            count=15,
            sample_values=["admin@example.com", "user@test.org"]
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_fingerprint_result, sample_sensitive_data):
    """Complete sample scan result."""
    return ScanResult(
        scan_info={
            "target": "192.168.1.100:3306",
            "scan_time": datetime.now().isoformat(),
            "duration": 45,
            "database": "wordpress_db"
        },
        fingerprint_results=[sample_fingerprint_result],
        sensitive_data=sample_sensitive_data,
        urls=[
            UrlInfo(
                url="https://example.com",
                source_table="wp_options",
                source_field="option_value",
                url_type="site"
            ),
        ],
        database_structure={"wordpress_db": []},
        recommendations=[
            "Update WordPress to latest version",
            "Implement strong password policy"
        ]
    )


@pytest.fixture
def empty_scan_result():
    """Empty scan result with no findings."""
    return ScanResult(
        scan_info={
            "target": "localhost:3306",
            "scan_time": datetime.now().isoformat(),
            "duration": 5,
            "database": "empty_db"
        },
        fingerprint_results=[],
        sensitive_data=[],
        urls=[],
        database_structure={},
        recommendations=[]
    )


# =============================================================================
# Mock Manager Fixtures
# =============================================================================

@pytest.fixture
def mock_db_manager():
    """Mock database manager for testing without real connections."""
    return Mock()


@pytest.fixture
def configured_mock_manager(mock_db_manager):
    """Mock manager with common return values pre-configured."""
    mock_db_manager.get_tables.return_value = ["users", "posts", "config"]
    mock_db_manager.get_databases.return_value = ["test_db", "information_schema"]
    mock_db_manager.get_server_info.return_value = {
        "version": "8.0.30",
        "charset": "utf8mb4",
        "time_zone": "SYSTEM"
    }
    return mock_db_manager
