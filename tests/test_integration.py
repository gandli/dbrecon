"""
Integration tests against real MySQL database.

Requires Docker container 'dbrecon-mysql' running on port 3307.
Run with: pytest tests/test_integration.py -v
Skip with: pytest tests/ --ignore=tests/test_integration.py
"""

import pytest
import mysql.connector

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3307,
    "user": "root",
    "password": "testpass123",
    "database": "testdb",
}


@pytest.fixture(scope="module")
def db_conn():
    """Create a real database connection."""
    conn = mysql.connector.connect(**DB_CONFIG)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def db_cursor(db_conn):
    """Create a cursor from the connection."""
    cursor = db_conn.cursor()
    yield cursor
    cursor.close()


@pytest.fixture(autouse=True)
def _check_connection():
    """Skip all tests if MySQL is not available."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        conn.close()
    except Exception:
        pytest.skip("MySQL container not available")


class TestIntegrationDatabase:
    """Integration tests: DatabaseManager with real MySQL."""

    def test_connect_success(self):
        """真实连接应成功."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        result = manager.connect()
        assert result is True
        manager.disconnect()

    def test_connect_failure_wrong_password(self):
        """错误密码应返回 False."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(
            host="127.0.0.1", port=3307, user="root",
            password="wrong_password", database="testdb"
        )
        manager = DatabaseManager(config)
        result = manager.connect()
        assert result is False

    def test_get_databases(self):
        """应返回包含 testdb 的数据库列表."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        databases = manager.get_databases()
        manager.disconnect()

        assert "testdb" in databases

    def test_get_tables(self):
        """应返回 WordPress 表列表."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        tables = manager.get_tables("testdb")
        manager.disconnect()

        assert "wp_options" in tables
        assert "wp_users" in tables
        assert "wp_posts" in tables
        assert "wp_comments" in tables
        assert "wp_woocommerce_orders" in tables

    def test_get_table_structure(self):
        """应返回 wp_users 表结构."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        columns = manager.get_table_structure("testdb", "wp_users")
        manager.disconnect()

        col_names = [c["name"] for c in columns]
        assert "ID" in col_names
        assert "user_login" in col_names
        assert "user_pass" in col_names
        assert "user_email" in col_names

    def test_execute_query(self):
        """应正确执行查询并返回结果."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        results = manager.execute_query("SELECT user_login FROM wp_users")
        manager.disconnect()

        logins = [r[0] for r in results]
        assert "admin" in logins
        assert "editor" in logins

    def test_execute_query_with_params(self):
        """应正确执行参数化查询."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        results = manager.execute_query(
            "SELECT user_email FROM wp_users WHERE user_login = %s", ("admin",)
        )
        manager.disconnect()

        assert len(results) == 1
        assert results[0][0] == "admin@example.com"

    def test_get_server_info(self):
        """应返回服务器信息."""
        from dbrecon.database import DatabaseManager
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        info = manager.get_server_info()
        manager.disconnect()

        assert "version" in info
        assert "8.0" in info["version"]


class TestIntegrationFingerprint:
    """Integration tests: FingerprintEngine with real MySQL."""

    def test_fingerprint_wordpress_full(self):
        """真实 WordPress 数据库应被高置信度识别."""
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        engine = FingerprintEngine()
        results = engine.analyze(manager, "testdb")
        manager.disconnect()

        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert wp.confidence > 0.5

    def test_fingerprint_wordpress_version(self):
        """应检测到 WordPress 版本 5.8.1."""
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        engine = FingerprintEngine()
        results = engine.analyze(manager, "testdb")
        manager.disconnect()

        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert wp.version == "5.8.1"

    def test_fingerprint_wordpress_woocommerce_plugin(self):
        """应检测到 WooCommerce 插件."""
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        engine = FingerprintEngine()
        results = engine.analyze(manager, "testdb")
        manager.disconnect()

        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert "woocommerce" in wp.installed_plugins

    def test_fingerprint_evidence_collection(self):
        """应收集到表证据."""
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.models import DatabaseConnection

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()
        engine = FingerprintEngine()
        results = engine.analyze(manager, "testdb")
        manager.disconnect()

        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        evidence_names = [e["name"] for e in wp.evidence]
        assert "wp_options" in evidence_names
        assert "wp_users" in evidence_names


class TestIntegrationScanner:
    """Integration tests: SensitiveDataScanner with real MySQL."""

    def test_scan_finds_password_field(self):
        """应发现 user_password 密码字段."""
        from dbrecon.database import DatabaseManager
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.models import DatabaseConnection, TableInfo

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "ID", "type": "bigint(20)"},
                {"name": "user_login", "type": "varchar(60)"},
                {"name": "user_password", "type": "varchar(255)"},
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]

        scanner = SensitiveDataScanner()
        results = scanner.scan(manager, "testdb", tables)
        manager.disconnect()

        data_types = [r.data_type for r in results]
        assert "passwords" in data_types

    def test_scan_finds_email_field(self):
        """应发现 user_email 邮箱字段."""
        from dbrecon.database import DatabaseManager
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.models import DatabaseConnection, TableInfo

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]

        scanner = SensitiveDataScanner()
        results = scanner.scan(manager, "testdb", tables)
        manager.disconnect()

        assert any(r.data_type == "emails" for r in results)

    def test_scan_email_data_pattern(self):
        """应通过数据模式匹配发现邮箱数据."""
        from dbrecon.database import DatabaseManager
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.models import DatabaseConnection, TableInfo

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]

        scanner = SensitiveDataScanner()
        results = scanner.scan(manager, "testdb", tables)
        manager.disconnect()

        email_results = [r for r in results if r.data_type == "emails" and r.count > 0]
        assert len(email_results) > 0

    def test_scan_password_data_pattern(self):
        """应通过字段名匹配发现密码哈希字段."""
        from dbrecon.database import DatabaseManager
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.models import DatabaseConnection, TableInfo

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "password_hash", "type": "varchar(255)"},
            ])
        ]

        scanner = SensitiveDataScanner()
        results = scanner.scan(manager, "testdb", tables)
        manager.disconnect()

        pwd_results = [r for r in results if r.data_type == "passwords"]
        assert len(pwd_results) > 0
        assert pwd_results[0].field == "password_hash"


class TestIntegrationReporter:
    """Integration tests: ReportGenerator with real MySQL data."""

    def test_generate_json_report_from_real_data(self):
        """应从真实扫描数据生成有效 JSON 报告."""
        import json
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.reporter import ReportGenerator
        from dbrecon.models import DatabaseConnection, TableInfo, ScanResult

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        engine = FingerprintEngine()
        fp_results = engine.analyze(manager, "testdb")

        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "ID", "type": "bigint(20)"},
                {"name": "user_login", "type": "varchar(60)"},
                {"name": "user_pass", "type": "varchar(255)"},
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]
        scanner = SensitiveDataScanner()
        sd_results = scanner.scan(manager, "testdb", tables)

        scan_result = ScanResult(
            scan_info={
                "target": "127.0.0.1:3307",
                "database": "testdb",
                "duration": 10,
            },
            fingerprint_results=fp_results,
            sensitive_data=sd_results,
            urls=[],
            database_structure={},
            recommendations=["Integration test recommendation"]
        )

        generator = ReportGenerator()
        json_out = generator.generate(scan_result, "json")
        parsed = json.loads(json_out)

        assert len(parsed["fingerprint_results"]) > 0
        assert parsed["fingerprint_results"][0]["application"] == "WordPress"
        assert len(parsed["sensitive_data"]) > 0

        manager.disconnect()

    def test_generate_all_formats_from_real_data(self):
        """所有报告格式应从真实数据成功生成."""
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.reporter import ReportGenerator
        from dbrecon.models import DatabaseConnection, ScanResult

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        manager.connect()

        engine = FingerprintEngine()
        fp_results = engine.analyze(manager, "testdb")

        scan_result = ScanResult(
            scan_info={"target": "127.0.0.1:3307", "database": "testdb",
                      "duration": 5},
            fingerprint_results=fp_results,
            sensitive_data=[], urls=[], database_structure={},
            recommendations=[]
        )

        generator = ReportGenerator()

        json_out = generator.generate(scan_result, "json")
        assert "WordPress" in json_out

        csv_out = generator.generate(scan_result, "csv")
        assert "WordPress" in csv_out

        html_out = generator.generate(scan_result, "html")
        assert "WordPress" in html_out

        md_out = generator.generate(scan_result, "markdown")
        assert "WordPress" in md_out

        console_out = generator.generate(scan_result, "console")
        assert "WordPress" in console_out

        manager.disconnect()


class TestIntegrationEndToEnd:
    """Integration tests: Full E2E workflow with real MySQL."""

    def test_full_e2e_workflow(self):
        """
        完整 E2E: 连接 → 指纹 → 扫描 → 报告
        Given: WordPress 数据库
        When: 执行完整扫描流程
        Then: 识别 WordPress + WooCommerce，发现密码和邮箱，生成报告
        """
        import json
        from dbrecon.database import DatabaseManager
        from dbrecon.fingerprint import FingerprintEngine
        from dbrecon.scanner import SensitiveDataScanner
        from dbrecon.reporter import ReportGenerator
        from dbrecon.models import DatabaseConnection, TableInfo, ScanResult

        config = DatabaseConnection(**DB_CONFIG)
        manager = DatabaseManager(config)
        assert manager.connect() is True

        tables = manager.get_tables("testdb")
        assert "wp_users" in tables
        assert "wp_woocommerce_orders" in tables

        engine = FingerprintEngine()
        fp_results = engine.analyze(manager, "testdb")
        wp = next((r for r in fp_results if r.application == "WordPress"), None)
        assert wp is not None
        assert wp.version == "5.8.1"
        assert "woocommerce" in wp.installed_plugins

        table_infos = []
        for table_name in tables:
            columns = manager.get_table_structure("testdb", table_name)
            table_infos.append(TableInfo(name=table_name, columns=columns))

        scanner = SensitiveDataScanner()
        sd_results = scanner.scan(manager, "testdb", table_infos)

        data_types = [r.data_type for r in sd_results]
        assert "emails" in data_types

        scan_result = ScanResult(
            scan_info={
                "target": "127.0.0.1:3307",
                "database": "testdb",
                "duration": 30,
            },
            fingerprint_results=fp_results,
            sensitive_data=sd_results,
            urls=[],
            database_structure={},
            recommendations=[
                "Update WordPress to latest version",
                "Review user password strength",
                "Audit WooCommerce security"
            ]
        )

        generator = ReportGenerator()
        json_out = generator.generate(scan_result, "json")
        parsed = json.loads(json_out)

        assert len(parsed["fingerprint_results"]) >= 1
        wp = next(r for r in parsed["fingerprint_results"] if r["application"] == "WordPress")
        assert wp["version"] == "5.8.1"
        assert len(parsed["sensitive_data"]) >= 1
        assert len(parsed["recommendations"]) == 3

        manager.disconnect()
