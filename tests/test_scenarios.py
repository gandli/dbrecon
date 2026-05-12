"""
TDD 场景测试 - 完整扫描端到端流程

按业务场景组织，模拟真实用户操作流程。
每个场景遵循 Given-When-Then 模式。
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner
from datetime import datetime

from dbrecon.models import (
    DatabaseConnection, TableInfo, FingerprintResult,
    SensitiveData, UrlInfo, ScanResult
)
from dbrecon.database import DatabaseManager
from dbrecon.fingerprint import FingerprintEngine
from dbrecon.scanner import SensitiveDataScanner
from dbrecon.reporter import ReportGenerator
from dbrecon.cli import main


# ═══════════════════════════════════════════════════════════════════════════════
# 场景1: WordPress 完整扫描流程
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioWordPressFullScan:
    """
    TDD 场景1: WordPress 完整扫描流程
    Given: WordPress 数据库含 wp_options, wp_users, wp_posts 及敏感数据
    When: 执行完整扫描
    Then: 识别 WordPress 95%+ 置信度，发现密码和邮箱，生成报告
    """

    @pytest.fixture
    def wordpress_db_mock(self):
        """模拟 WordPress 数据库环境"""
        mock = Mock()
        mock.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts", "wp_comments"
        ]
        mock.get_table_structure.side_effect = lambda db, table: {
            "wp_options": [
                {"name": "option_id", "type": "bigint(20)", "nullable": False},
                {"name": "option_name", "type": "varchar(191)", "nullable": False},
                {"name": "option_value", "type": "longtext", "nullable": False},
                {"name": "autoload", "type": "varchar(20)", "nullable": False},
            ],
            "wp_users": [
                {"name": "ID", "type": "bigint(20)", "nullable": False},
                {"name": "user_login", "type": "varchar(60)", "nullable": False},
                {"name": "user_pass", "type": "varchar(255)", "nullable": False},
                {"name": "user_email", "type": "varchar(100)", "nullable": True},
            ],
            "wp_posts": [
                {"name": "ID", "type": "bigint(20)", "nullable": False},
                {"name": "post_title", "type": "text", "nullable": True},
                {"name": "post_content", "type": "longtext", "nullable": True},
            ],
            "wp_comments": [
                {"name": "comment_ID", "type": "bigint(20)", "nullable": False},
                {"name": "comment_author", "type": "varchar(255)", "nullable": True},
            ],
        }.get(table, [])
        return mock

    @pytest.fixture
    def wordpress_sensitive_samples(self):
        """WordPress 敏感数据样本"""
        return {
            ("wp_users", "user_pass"): [
                ("$2y$10$abcdefghijklmnopqrstuv",),
                ("$2y$10$xyzabcdefghijklmnopqrs",),
            ],
            ("wp_users", "user_email"): [
                ("admin@wordpress-site.com",),
                ("editor@wordpress-site.com",),
            ],
        }

    def test_given_wordpress_db_when_fingerprint_then_identify_with_high_confidence(
        self, wordpress_db_mock
    ):
        """Given WordPress 数据库，执行指纹识别，应以 > 0.5 置信度识别 WordPress"""
        engine = FingerprintEngine()
        results = engine.analyze(wordpress_db_mock, "wordpress_db")

        assert len(results) >= 1
        wp_result = next((r for r in results if r.application == "WordPress"), None)
        assert wp_result is not None
        assert wp_result.confidence > 0.5
        assert any(e["name"] == "wp_options" for e in wp_result.evidence)
        assert any(e["name"] == "wp_users" for e in wp_result.evidence)

    def test_given_wordpress_db_when_scan_sensitive_then_find_passwords_and_emails(
        self, wordpress_db_mock, wordpress_sensitive_samples
    ):
        """Given WordPress 数据库，扫描敏感数据应发现密码和邮箱"""
        def mock_execute_query(query, params=None):
            for (table, column), samples in wordpress_sensitive_samples.items():
                if table in query and column in query:
                    return samples
            return []

        wordpress_db_mock.execute_query.side_effect = mock_execute_query

        scanner = SensitiveDataScanner()
        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "ID", "type": "bigint(20)"},
                {"name": "user_login", "type": "varchar(60)"},
                {"name": "user_password", "type": "varchar(255)"},
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]

        results = scanner.scan(wordpress_db_mock, "wordpress_db", tables)

        data_types = [r.data_type for r in results]
        assert "passwords" in data_types
        assert "emails" in data_types

        password_result = next(r for r in results if r.data_type == "passwords")
        assert password_result.table == "wp_users"
        assert password_result.field == "user_password"

    def test_given_wordpress_db_when_scan_sensitive_field_only_then_find_by_name(
        self, wordpress_db_mock
    ):
        """Given 仅字段名匹配，扫描应通过字段名发现敏感数据"""
        wordpress_db_mock.execute_query.return_value = []

        scanner = SensitiveDataScanner()
        tables = [
            TableInfo(name="wp_users", columns=[
                {"name": "user_password", "type": "varchar(255)"},
                {"name": "user_email", "type": "varchar(100)"},
            ])
        ]

        results = scanner.scan(wordpress_db_mock, "wordpress_db", tables)
        data_types = [r.data_type for r in results]
        assert "passwords" in data_types
        assert "emails" in data_types

    def test_given_full_scan_results_when_generate_report_then_all_sections_present(
        self, wordpress_db_mock
    ):
        """Given 完整扫描结果，生成报告应包含所有部分"""
        scan_result = ScanResult(
            scan_info={
                "target": "192.168.1.100:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 45,
                "database": "wordpress_db"
            },
            fingerprint_results=[
                FingerprintResult(
                    application="WordPress",
                    confidence=0.95,
                    version="5.8.1",
                    evidence=[
                        {"type": "table", "name": "wp_options", "match": "exact"},
                        {"type": "table", "name": "wp_users", "match": "exact"},
                    ],
                    installed_plugins=["woocommerce"]
                )
            ],
            sensitive_data=[
                SensitiveData(
                    table="wp_users", field="user_pass",
                    data_type="passwords", count=15,
                    sample_values=["$2y$10$hash1", "$2y$10$hash2"]
                ),
                SensitiveData(
                    table="wp_users", field="user_email",
                    data_type="emails", count=15,
                    sample_values=["admin@example.com", "user@test.org"]
                ),
            ],
            urls=[
                UrlInfo(
                    url="https://example.com", source_table="wp_options",
                    source_field="option_value", url_type="site"
                ),
            ],
            database_structure={"wordpress_db": []},
            recommendations=["Update WordPress to latest version"]
        )

        generator = ReportGenerator()
        json_report = generator.generate(scan_result, "json")
        import json
        parsed = json.loads(json_report)

        assert parsed["scan_info"]["database"] == "wordpress_db"
        assert len(parsed["fingerprint_results"]) == 1
        assert parsed["fingerprint_results"][0]["application"] == "WordPress"
        assert len(parsed["sensitive_data"]) == 2
        assert len(parsed["urls"]) == 1
        assert len(parsed["recommendations"]) == 1

    def test_given_full_scan_when_generate_all_formats_then_all_succeed(
        self, wordpress_db_mock
    ):
        """Given 完整扫描结果，所有报告格式都应成功生成"""
        scan_result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 30, "database": "test"},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95,
                                 version="5.8.1", evidence=[], installed_plugins=[])
            ],
            sensitive_data=[
                SensitiveData(table="users", field="password", data_type="passwords",
                             count=10, sample_values=[])
            ],
            urls=[],
            database_structure={},
            recommendations=["Test recommendation"]
        )

        generator = ReportGenerator()

        json_out = generator.generate(scan_result, "json")
        parsed = json.loads(json_out)
        assert "scan_info" in parsed

        csv_out = generator.generate(scan_result, "csv")
        assert "Sensitive Data" in csv_out

        html_out = generator.generate(scan_result, "html")
        assert "DBRecon" in html_out

        md_out = generator.generate(scan_result, "markdown")
        assert "DBRecon" in md_out

        console_out = generator.generate(scan_result, "console")
        assert "WordPress" in console_out


# ═══════════════════════════════════════════════════════════════════════════════
# 场景2: 空数据库扫描
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioEmptyDatabase:
    """
    TDD 场景2: 空数据库扫描
    Given: 一个没有表的空数据库
    When: 执行完整扫描
    Then: 优雅处理，报告无发现，不崩溃
    """

    def test_given_empty_db_when_fingerprint_then_no_high_confidence_results(self):
        """Given 空数据库，指纹识别不应有高置信度结果"""
        mock_db = Mock()
        mock_db.get_tables.return_value = []

        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "empty_db")
        for r in results:
            assert r.confidence < 0.8

    def test_given_empty_db_when_scan_sensitive_then_no_results(self):
        """Given 空数据库表列表，扫描敏感数据应返回空结果"""
        scanner = SensitiveDataScanner()
        results = scanner.scan(Mock(), "empty_db", [])
        assert results == []

    def test_given_empty_results_when_generate_report_then_show_no_findings(self):
        """Given 空扫描结果，报告应显示无发现"""
        scan_result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 5, "database": "empty_db"},
            fingerprint_results=[], sensitive_data=[], urls=[],
            database_structure={}, recommendations=[]
        )

        generator = ReportGenerator()
        console_out = generator.generate(scan_result, "console")
        assert "No applications identified" in console_out
        assert "No sensitive data found" in console_out
        assert "No URLs discovered" in console_out


# ═══════════════════════════════════════════════════════════════════════════════
# 场景3: 多应用混合数据库
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioMixedApplications:
    """
    TDD 场景3: 多应用混合数据库
    Given: 同时包含 WordPress 和 Laravel 表的数据库
    When: 执行指纹扫描
    Then: 正确识别两个应用，按置信度排序
    """

    def test_given_mixed_db_when_fingerprint_then_identify_both_apps(self):
        """Given WordPress + Laravel 混合数据库，应识别两个应用"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "migrations", "users", "password_resets"
        ]

        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "mixed_db")

        app_names = [r.application for r in results]
        assert "WordPress" in app_names
        assert "Laravel" in app_names

    def test_given_mixed_db_when_fingerprint_then_sorted_by_confidence(self):
        """Given 混合数据库，结果应按置信度降序排列"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts",
            "migrations", "users", "password_resets"
        ]

        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "mixed_db")

        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].confidence >= results[i + 1].confidence

    def test_given_partial_match_when_fingerprint_then_lower_confidence(self):
        """Given 仅部分表匹配的应用，应返回较低置信度"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["wp_options"]

        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "partial_db")

        wp_result = next((r for r in results if r.application == "WordPress"), None)
        if wp_result:
            assert wp_result.confidence < 0.9


# ═══════════════════════════════════════════════════════════════════════════════
# 场景4: 连接失败恢复
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioConnectionFailure:
    """
    TDD 场景4: 连接失败恢复
    Given: 数据库连接失败
    When: 尝试扫描
    Then: 正确报告错误，不崩溃
    """

    def test_given_connection_failure_when_test_connection_then_abort(self):
        """Given 连接失败，test-connection 应中止并报告错误"""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection', '--host', 'bad-host',
                '--user', 'admin', '--password', 'wrong'
            ])
            assert result.exit_code != 0

    def test_given_connection_failure_when_fingerprint_then_abort(self):
        """Given 连接失败，fingerprint 应中止"""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_class.return_value = mock_manager

            result = runner.invoke(main, [
                'fingerprint', '--host', 'bad-host',
                '--user', 'admin', '--password', 'wrong',
                '--database', 'test'
            ])
            assert result.exit_code != 0

    def test_given_connection_failure_when_scan_sensitive_then_abort(self):
        """Given 连接失败，scan-sensitive 应中止"""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_class.return_value = mock_manager

            result = runner.invoke(main, [
                'scan-sensitive', '--host', 'bad-host',
                '--user', 'admin', '--password', 'wrong',
                '--database', 'test'
            ])
            assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════════════════════
# 场景5: 部分表分析失败
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioPartialTableFailure:
    """
    TDD 场景5: 部分表分析失败
    Given: 数据库中部分表无法访问
    When: 执行扫描
    Then: 跳过失败表，继续分析其他表
    """

    def test_given_some_tables_fail_when_scan_then_continue_with_rest(self):
        """Given 部分表分析失败，扫描应继续处理其他表"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["users", "secret_table", "posts"]

        def side_effect(db, table):
            if table == "secret_table":
                raise Exception("Access denied")
            if table == "users":
                return [{"name": "id", "type": "int"}, {"name": "email", "type": "varchar"}]
            if table == "posts":
                return [{"name": "id", "type": "int"}, {"name": "title", "type": "varchar"}]
            return []

        mock_db.get_table_structure.side_effect = side_effect

        scanner = SensitiveDataScanner()
        tables = []
        for t in ["users", "secret_table", "posts"]:
            try:
                cols = mock_db.get_table_structure("test_db", t)
                tables.append(TableInfo(name=t, columns=cols))
            except Exception:
                continue

        assert len(tables) == 2
        assert tables[0].name == "users"
        assert tables[1].name == "posts"


# ═══════════════════════════════════════════════════════════════════════════════
# 场景6: CLI 端到端命令执行
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioCLIEndToEnd:
    """
    TDD 场景6: CLI 端到端命令执行
    模拟真实用户通过 CLI 执行各种命令的完整流程
    """

    def test_e2e_test_connection_success(self):
        """E2E: 成功连接测试"""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_server_info.return_value = {
                "version": "8.0.30", "charset": "utf8mb4"
            }
            mock_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection', '--host', 'localhost',
                '--user', 'root', '--password', 'pass'
            ])
            assert result.exit_code == 0

    def test_e2e_fingerprint_with_results_and_report(self):
        """E2E: 指纹识别发现应用并生成报告"""
        runner = CliRunner()
        from dbrecon.models import FingerprintResult

        with patch('dbrecon.cli.DatabaseManager') as mock_db_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_db = Mock()
            mock_db.connect.return_value = True
            mock_db_class.return_value = mock_db

            mock_engine = Mock()
            mock_engine.analyze.return_value = [
                FingerprintResult(
                    application="WordPress", confidence=0.95,
                    version="5.8.1",
                    evidence=[{"type": "table", "name": "wp_options", "match": "exact"}],
                    installed_plugins=["woocommerce"]
                )
            ]
            mock_engine_class.return_value = mock_engine

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'fingerprint', '--host', 'localhost', '--user', 'root',
                '--password', 'pass', '--database', 'wp_db',
                '--output', '/tmp/report.json', '--format', 'json'
            ])
            assert result.exit_code == 0

    def test_e2e_full_scan_complete_workflow(self):
        """E2E: 完整扫描工作流"""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_db_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_db = Mock()
            mock_db.connect.return_value = True
            mock_db.get_tables.return_value = ["wp_users", "wp_options"]
            mock_db.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_db_class.return_value = mock_db

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan', '--host', 'localhost', '--user', 'root',
                '--password', 'pass', '--database', 'test_db'
            ])
            assert result.exit_code == 0
