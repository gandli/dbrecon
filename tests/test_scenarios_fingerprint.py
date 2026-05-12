"""
TDD 场景测试 - 应用指纹识别与敏感数据发现

按业务场景组织，覆盖各种 CMS/框架的识别和敏感数据类型发现。

场景A: 应用指纹识别
  - WordPress / Drupal / Laravel / Django / Joomla / Magento
  - 版本检测 / 插件检测 / 置信度排序

场景B: 敏感数据发现
  - 密码 / 邮箱 / API密钥 / 手机号 / SSN / 信用卡
  - 字段名匹配 / 数据模式匹配 / 去重合并

场景C: 边界条件
  - 空库 / 单表 / 大量表 / 特殊字符 / Unicode
"""

import pytest
from unittest.mock import Mock, patch
import json

from dbrecon.fingerprint import FingerprintEngine
from dbrecon.scanner import SensitiveDataScanner
from dbrecon.reporter import ReportGenerator
from dbrecon.models import (
    TableInfo, ScanResult, FingerprintResult, SensitiveData,
    UrlInfo
)


# ═══════════════════════════════════════════════════════════════════════════════
# 场景A: 各种应用指纹识别
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioFingerprintWordPress:
    """TDD 场景: WordPress 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_wordpress_full_match(self, engine):
        """WordPress 完整表匹配 → 置信度 > 0.5"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts", "wp_comments", "wp_links"
        ]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert wp.confidence > 0.5

    def test_wordpress_partial_match(self, engine):
        """WordPress 部分表匹配 → 置信度 0.3~0.9"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["wp_options", "wp_users"]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert 0.3 < wp.confidence < 0.95

    def test_wordpress_no_match(self, engine):
        """无 WordPress 表 → 不返回 WordPress 结果"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["random_table"]
        results = engine.analyze(mock_db, "other_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is None

    def test_wordpress_woocommerce_plugin_detected(self, engine):
        """WordPress + WooCommerce 插件表 → 检测到 woocommerce"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts", "wp_woocommerce_orders"
        ]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert "woocommerce" in wp.installed_plugins

    def test_wordpress_yoast_seo_plugin_detected(self, engine):
        """WordPress + Yoast SEO 插件表 → 检测到 yoast-seo"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts", "wp_yoast_indexable"
        ]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert "yoast-seo" in wp.installed_plugins

    def test_wordpress_multiple_plugins(self, engine):
        """WordPress + 多个插件 → 检测到所有插件"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts",
            "wp_woocommerce_orders", "wp_yoast_indexable"
        ]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        assert "woocommerce" in wp.installed_plugins
        assert "yoast-seo" in wp.installed_plugins

    def test_wordpress_evidence_includes_exact_and_optional(self, engine):
        """WordPress 证据应包含 exact 和 optional 匹配"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "wp_options", "wp_users", "wp_posts", "wp_comments"
        ]
        results = engine.analyze(mock_db, "wp_db")
        wp = next((r for r in results if r.application == "WordPress"), None)
        assert wp is not None
        matches = {e["name"]: e["match"] for e in wp.evidence}
        assert matches.get("wp_options") == "exact"
        assert matches.get("wp_comments") == "optional"


class TestScenarioFingerprintDrupal:
    """TDD 场景: Drupal 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_drupal7_match(self, engine):
        """Drupal 7 表匹配 → 识别为 Drupal"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["users", "node", "system", "variable"]
        results = engine.analyze(mock_db, "drupal_db")
        drupal = next((r for r in results if r.application == "Drupal"), None)
        assert drupal is not None
        assert drupal.confidence > 0.5

    def test_drupal8_match(self, engine):
        """Drupal 8 表匹配 → 识别为 Drupal"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "users_field_data", "node_field_data", "config"
        ]
        results = engine.analyze(mock_db, "drupal_db")
        drupal = next((r for r in results if r.application == "Drupal"), None)
        assert drupal is not None
        assert drupal.confidence > 0.5


class TestScenarioFingerprintLaravel:
    """TDD 场景: Laravel 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_laravel_full_match(self, engine):
        """Laravel 完整表匹配 → 高置信度"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "migrations", "users", "password_resets", "jobs", "sessions"
        ]
        results = engine.analyze(mock_db, "laravel_db")
        laravel = next((r for r in results if r.application == "Laravel"), None)
        assert laravel is not None
        assert laravel.confidence > 0.6

    def test_laravel_partial_match(self, engine):
        """Laravel 部分表匹配 → 中等置信度"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["migrations", "users"]
        results = engine.analyze(mock_db, "laravel_db")
        laravel = next((r for r in results if r.application == "Laravel"), None)
        assert laravel is not None
        assert laravel.confidence > 0.3


class TestScenarioFingerprintDjango:
    """TDD 场景: Django 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_django_match(self, engine):
        """Django 表匹配 → 识别为 Django"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "django_migrations", "auth_user", "django_session"
        ]
        results = engine.analyze(mock_db, "django_db")
        django = next((r for r in results if r.application == "Django"), None)
        assert django is not None
        assert django.confidence > 0.5


class TestScenarioFingerprintJoomla:
    """TDD 场景: Joomla 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_joomla_match(self, engine):
        """Joomla 表匹配 → 识别为 Joomla"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["users", "content", "extensions"]
        results = engine.analyze(mock_db, "joomla_db")
        joomla = next((r for r in results if r.application == "Joomla"), None)
        assert joomla is not None
        assert joomla.confidence > 0.5


class TestScenarioFingerprintMagento:
    """TDD 场景: Magento 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_magento_match(self, engine):
        """Magento 表匹配 → 识别为 Magento"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "admin_user", "core_config_data", "catalog_product_entity"
        ]
        results = engine.analyze(mock_db, "magento_db")
        magento = next((r for r in results if r.application == "Magento"), None)
        assert magento is not None
        assert magento.confidence > 0.5


class TestScenarioFingerprintPrestaShop:
    """TDD 场景: PrestaShop 指纹识别"""

    @pytest.fixture
    def engine(self):
        return FingerprintEngine()

    def test_prestashop_match(self, engine):
        """PrestaShop 表匹配 → 识别为 PrestaShop"""
        mock_db = Mock()
        mock_db.get_tables.return_value = [
            "ps_configuration", "ps_customer", "ps_product"
        ]
        results = engine.analyze(mock_db, "prestashop_db")
        ps = next((r for r in results if r.application == "PrestaShop"), None)
        assert ps is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 场景B: 敏感数据发现
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioSensitiveDataPasswords:
    """TDD 场景: 密码字段发现"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_detect_password_by_field_name(self, scanner):
        """字段名包含 password → 识别为密码"""
        table = TableInfo(name="users", columns=[
            {"name": "id", "type": "int"},
            {"name": "user_password", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "passwords" and r.field == "user_password" for r in results)

    def test_detect_password_hash_field(self, scanner):
        """字段名包含 hash → 识别为密码"""
        table = TableInfo(name="accounts", columns=[
            {"name": "password_hash", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "passwords" for r in results)

    def test_detect_passwd_field(self, scanner):
        """字段名包含 passwd → 识别为密码"""
        table = TableInfo(name="auth", columns=[
            {"name": "passwd", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "passwords" for r in results)

    def test_detect_secret_field(self, scanner):
        """字段名包含 secret → 识别为 API 密钥"""
        table = TableInfo(name="config", columns=[
            {"name": "secret_key", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "api_keys" for r in results)


class TestScenarioSensitiveDataEmails:
    """TDD 场景: 邮箱字段发现"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_detect_email_by_field_name(self, scanner):
        """字段名包含 email → 识别为邮箱"""
        table = TableInfo(name="users", columns=[
            {"name": "email_address", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "emails" for r in results)

    def test_detect_mail_field(self, scanner):
        """字段名为 mail → 识别为邮箱"""
        table = TableInfo(name="contacts", columns=[
            {"name": "mail", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "emails" for r in results)


class TestScenarioSensitiveDataApiKeys:
    """TDD 场景: API 密钥字段发现"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_detect_api_key_field(self, scanner):
        """字段名包含 api_key → 识别为 API 密钥"""
        table = TableInfo(name="config", columns=[
            {"name": "api_key", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "api_keys" for r in results)

    def test_detect_token_field(self, scanner):
        """字段名包含 token → 识别为 API 密钥"""
        table = TableInfo(name="users", columns=[
            {"name": "auth_token", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "api_keys" for r in results)


class TestScenarioSensitiveDataPhones:
    """TDD 场景: 手机号字段发现"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_detect_phone_field(self, scanner):
        """字段名包含 phone → 识别为手机号"""
        table = TableInfo(name="contacts", columns=[
            {"name": "phone_number", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "phones" for r in results)

    def test_detect_mobile_field(self, scanner):
        """字段名包含 mobile → 识别为手机号"""
        table = TableInfo(name="users", columns=[
            {"name": "mobile", "type": "varchar"},
        ])
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "phones" for r in results)


class TestScenarioSensitiveDataDataPatterns:
    """TDD 场景: 数据模式匹配发现敏感数据"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_detect_email_by_data_pattern(self, scanner):
        """数据内容匹配邮箱模式 → 识别为邮箱"""
        mock_db = Mock()
        mock_db.execute_query.return_value = [
            ("user@example.com",), ("admin@test.org",)
        ]
        table = TableInfo(name="contacts", columns=[
            {"name": "contact_info", "type": "varchar"}
        ])
        results = scanner._detect_by_data_patterns(
            mock_db, "test_db", table, ["emails"]
        )
        assert any(r.data_type == "emails" for r in results)

    def test_detect_phone_by_data_pattern(self, scanner):
        """数据内容匹配手机号模式 → 识别为手机号"""
        mock_db = Mock()
        mock_db.execute_query.return_value = [
            ("13812345678",), ("13987654321",)
        ]
        table = TableInfo(name="users", columns=[
            {"name": "phone", "type": "varchar"}
        ])
        results = scanner._detect_by_data_patterns(
            mock_db, "test_db", table, ["phones"]
        )
        assert any(r.data_type == "phones" for r in results)

    def test_no_false_positive_on_clean_data(self, scanner):
        """干净数据不应产生误报"""
        mock_db = Mock()
        mock_db.execute_query.return_value = [
            ("hello world",), ("normal text",)
        ]
        table = TableInfo(name="posts", columns=[
            {"name": "content", "type": "text"}
        ])
        results = scanner._detect_by_data_patterns(
            mock_db, "test_db", table, ["emails", "phones", "api_keys"]
        )
        assert results == []


class TestScenarioSensitiveDataDeduplication:
    """TDD 场景: 敏感数据去重合并"""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    def test_dedup_merges_same_field(self, scanner):
        """同一字段多次检测到相同类型 → 合并为一条"""
        results = [
            SensitiveData(table="users", field="email", data_type="emails",
                         count=10, sample_values=["a@b.com"]),
            SensitiveData(table="users", field="email", data_type="emails",
                         count=5, sample_values=["c@d.com"]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 1
        assert deduped[0].count == 15

    def test_dedup_keeps_different_fields(self, scanner):
        """不同字段 → 不去重"""
        results = [
            SensitiveData(table="users", field="email", data_type="emails",
                         count=10, sample_values=[]),
            SensitiveData(table="users", field="phone", data_type="phones",
                         count=5, sample_values=[]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 2

    def test_dedup_keeps_different_data_types(self, scanner):
        """同一字段不同类型 → 不去重"""
        results = [
            SensitiveData(table="users", field="token", data_type="api_keys",
                         count=3, sample_values=[]),
            SensitiveData(table="users", field="token", data_type="passwords",
                         count=3, sample_values=[]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# 场景C: 边界条件
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioBoundaryConditions:
    """TDD 场景: 边界条件测试"""

    def test_single_table_database(self):
        """单表数据库 → 正确处理"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["users"]
        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "single_table_db")
        assert isinstance(results, list)

    def test_many_tables_database(self):
        """大量表数据库 → 正确处理不超时"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["table_{}".format(i) for i in range(500)]
        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "big_db")
        assert isinstance(results, list)

    def test_special_characters_in_table_names(self):
        """特殊字符表名 → 正确处理"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["user-data", "log.entries", "test$table"]
        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "special_db")
        assert isinstance(results, list)

    def test_unicode_table_names(self):
        """Unicode 表名 → 正确处理"""
        mock_db = Mock()
        mock_db.get_tables.return_value = ["用户表", "ログ", "utilisateurs"]
        engine = FingerprintEngine()
        results = engine.analyze(mock_db, "unicode_db")
        assert isinstance(results, list)

    def test_empty_table_no_columns(self):
        """空表（无列）→ 正确处理"""
        scanner = SensitiveDataScanner()
        table = TableInfo(name="empty_table", columns=[])
        results = scanner._detect_by_field_name(table)
        assert results == []

    def test_table_with_many_columns(self):
        """大量列的表 → 正确处理"""
        scanner = SensitiveDataScanner()
        columns = [{"name": "col_{}".format(i), "type": "varchar"} for i in range(200)]
        columns.append({"name": "password", "type": "varchar"})
        table = TableInfo(name="wide_table", columns=columns)
        results = scanner._detect_by_field_name(table)
        assert any(r.data_type == "passwords" for r in results)

    def test_scan_with_empty_data_types_uses_all_patterns(self):
        """空数据类型过滤器 → scan_table 使用所有 patterns"""
        scanner = SensitiveDataScanner()
        mock_db = Mock()
        mock_db.execute_query.return_value = []
        table = TableInfo(name="users", columns=[{"name": "email", "type": "varchar"}])
        results = scanner.scan_table(mock_db, "test_db", table, data_types=[])
        email_result = next((r for r in results if r.field == "email"), None)
        assert email_result is not None
        assert email_result.data_type == "emails"

    def test_report_with_all_empty_sections(self):
        """所有部分为空的报告 → 正确生成"""
        scan_result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 0, "database": "test"},
            fingerprint_results=[], sensitive_data=[], urls=[],
            database_structure={}, recommendations=[]
        )
        generator = ReportGenerator()

        json_out = generator.generate(scan_result, "json")
        parsed = json.loads(json_out)
        assert parsed["fingerprint_results"] == []
        assert parsed["sensitive_data"] == []
        assert parsed["urls"] == []

    def test_report_with_maximum_data(self):
        """最大数据量报告 → 正确生成"""
        scan_result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 3600, "database": "big_db"},
            fingerprint_results=[
                FingerprintResult(
                    application="App{}".format(i), confidence=0.5 + i * 0.01,
                    version="1.0.{}".format(i), evidence=[], installed_plugins=[]
                )
                for i in range(50)
            ],
            sensitive_data=[
                SensitiveData(table="t{}".format(i), field="f{}".format(i),
                             data_type="emails", count=i * 100, sample_values=[])
                for i in range(100)
            ],
            urls=[],
            database_structure={},
            recommendations=["Rec {}".format(i) for i in range(20)]
        )
        generator = ReportGenerator()
        json_out = generator.generate(scan_result, "json")
        parsed = json.loads(json_out)
        assert len(parsed["fingerprint_results"]) == 50
        assert len(parsed["sensitive_data"]) == 100
