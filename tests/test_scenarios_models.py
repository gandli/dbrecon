"""
TDD 场景测试 - 模型验证与报告格式

场景D: Pydantic 模型验证
  - 必填字段 / 默认值 / 类型约束 / 序列化 / 反序列化

场景E: 报告格式全功能验证
  - JSON结构 / CSV列 / HTML标签 / Markdown语法 / 控制台格式
"""

import pytest
import json
import csv
import io
from datetime import datetime
from pydantic import ValidationError

from dbrecon.models import (
    DatabaseConnection, TableInfo, FingerprintResult,
    SensitiveData, UrlInfo, ScanResult, ScanConfig
)
from dbrecon.reporter import ReportGenerator


# ═══════════════════════════════════════════════════════════════════════════════
# 场景D: Pydantic 模型验证
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioModelDatabaseConnection:
    """TDD 场景: DatabaseConnection 模型验证"""

    def test_valid_minimal_config(self):
        """最小有效配置 → 创建成功"""
        config = DatabaseConnection(host="localhost", user="admin", password="pass")
        assert config.host == "localhost"
        assert config.port == 3306
        assert config.ssl_enabled is False
        assert config.timeout == 30
        assert config.database is None

    def test_valid_full_config(self):
        """完整配置 → 所有字段正确"""
        config = DatabaseConnection(
            host="db.example.com", port=3307, user="root",
            password="secret", database="mydb", ssl_enabled=True, timeout=60
        )
        assert config.host == "db.example.com"
        assert config.port == 3307
        assert config.ssl_enabled is True
        assert config.timeout == 60
        assert config.database == "mydb"

    def test_missing_required_host(self):
        """缺少必填 host → ValidationError"""
        with pytest.raises(ValidationError):
            DatabaseConnection(user="admin", password="pass")

    def test_missing_required_user(self):
        """缺少必填 user → ValidationError"""
        with pytest.raises(ValidationError):
            DatabaseConnection(host="localhost", password="pass")

    def test_missing_required_password(self):
        """缺少必填 password → ValidationError"""
        with pytest.raises(ValidationError):
            DatabaseConnection(host="localhost", user="admin")

    def test_default_values(self):
        """默认值 → port=3306, ssl=False, timeout=30"""
        config = DatabaseConnection(host="h", user="u", password="p")
        assert config.port == 3306
        assert config.ssl_enabled is False
        assert config.timeout == 30

    def test_serialization(self):
        """序列化 → dict 包含所有字段"""
        config = DatabaseConnection(host="h", user="u", password="p")
        data = config.model_dump()
        assert data["host"] == "h"
        assert data["port"] == 3306
        assert data["ssl_enabled"] is False

    def test_deserialization(self):
        """反序列化 → 从 dict 创建"""
        data = {"host": "h", "user": "u", "password": "p", "port": 5432}
        config = DatabaseConnection(**data)
        assert config.port == 5432

    def test_json_roundtrip(self):
        """JSON 往返序列化 → 数据一致"""
        config = DatabaseConnection(host="h", user="u", password="p")
        json_str = config.model_dump_json()
        restored = DatabaseConnection.model_validate_json(json_str)
        assert restored.host == config.host
        assert restored.port == config.port


class TestScenarioModelTableInfo:
    """TDD 场景: TableInfo 模型验证"""

    def test_valid_table(self):
        """有效表信息 → 创建成功"""
        table = TableInfo(name="users", columns=[
            {"name": "id", "type": "int", "nullable": False}
        ])
        assert table.name == "users"
        assert len(table.columns) == 1

    def test_table_defaults(self):
        """默认值 → engine=None, row_count=None, columns=[]"""
        table = TableInfo(name="test")
        assert table.engine is None
        assert table.row_count is None
        assert table.columns == []

    def test_missing_name(self):
        """缺少必填 name → ValidationError"""
        with pytest.raises(ValidationError):
            TableInfo(columns=[])


class TestScenarioModelFingerprintResult:
    """TDD 场景: FingerprintResult 模型验证"""

    def test_valid_result(self):
        """有效指纹结果 → 创建成功"""
        result = FingerprintResult(
            application="WordPress", confidence=0.95, version="5.8.1",
            evidence=[{"type": "table", "name": "wp_options", "match": "exact"}],
            installed_plugins=["woocommerce"]
        )
        assert result.application == "WordPress"
        assert result.confidence == 0.95

    def test_defaults(self):
        """默认值 → version=None, evidence=[], plugins=[]"""
        result = FingerprintResult(application="Test", confidence=0.5)
        assert result.version is None
        assert result.evidence == []
        assert result.installed_plugins == []

    def test_confidence_range_zero(self):
        """置信度 0 → 有效"""
        result = FingerprintResult(application="Test", confidence=0.0)
        assert result.confidence == 0.0

    def test_confidence_range_one(self):
        """置信度 1.0 → 有效"""
        result = FingerprintResult(application="Test", confidence=1.0)
        assert result.confidence == 1.0


class TestScenarioModelSensitiveData:
    """TDD 场景: SensitiveData 模型验证"""

    def test_valid_data(self):
        """有效敏感数据 → 创建成功"""
        data = SensitiveData(
            table="users", field="password", data_type="passwords",
            count=10, sample_values=["hash1", "hash2"]
        )
        assert data.table == "users"
        assert data.count == 10

    def test_defaults(self):
        """默认值 → sample_values=[]"""
        data = SensitiveData(table="t", field="f", data_type="passwords", count=0)
        assert data.sample_values == []


class TestScenarioModelScanResult:
    """TDD 场景: ScanResult 模型验证"""

    def test_valid_scan_result(self):
        """有效扫描结果 → 创建成功"""
        result = ScanResult(
            scan_info={"target": "localhost:3306", "database": "test"},
            fingerprint_results=[], sensitive_data=[], urls=[],
            database_structure={}, recommendations=[]
        )
        assert result.scan_info["database"] == "test"

    def test_defaults(self):
        """默认值 → 所有列表为空"""
        result = ScanResult(scan_info={"target": "test"})
        assert result.fingerprint_results == []
        assert result.sensitive_data == []
        assert result.urls == []
        assert result.database_structure == {}
        assert result.recommendations == []

    def test_full_scan_result_serialization(self):
        """完整扫描结果序列化 → JSON 可解析"""
        result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 45, "database": "test"},
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
            recommendations=["Update software"]
        )
        json_str = result.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["fingerprint_results"][0]["application"] == "WordPress"


class TestScenarioModelScanConfig:
    """TDD 场景: ScanConfig 模型验证"""

    def test_defaults(self):
        """默认值 → deep_scan=False, 所有列表为空"""
        config = ScanConfig()
        assert config.deep_scan is False
        assert config.scan_types == []
        assert config.sensitive_data_types == []
        assert config.output_format == "console"
        assert config.output_file is None

    def test_custom_config(self):
        """自定义配置 → 所有字段正确"""
        config = ScanConfig(
            deep_scan=True,
            scan_types=["fingerprint", "sensitive"],
            sensitive_data_types=["passwords", "emails"],
            output_format="html",
            output_file="/tmp/report.html"
        )
        assert config.deep_scan is True
        assert config.scan_types == ["fingerprint", "sensitive"]
        assert config.output_format == "html"


# ═══════════════════════════════════════════════════════════════════════════════
# 场景E: 报告格式全功能验证
# ════════════════════════════════════════════════════════════════════════════════

class TestScenarioReportJSON:
    """TDD 场景: JSON 报告格式验证"""

    @pytest.fixture
    def full_scan_result(self):
        return ScanResult(
            scan_info={
                "target": "192.168.1.100:3306",
                "scan_time": "2024-01-15T10:30:00",
                "duration": 45,
                "database": "wordpress_db"
            },
            fingerprint_results=[
                FingerprintResult(
                    application="WordPress", confidence=0.95, version="5.8.1",
                    evidence=[
                        {"type": "table", "name": "wp_options", "match": "exact"},
                        {"type": "table", "name": "wp_users", "match": "exact"},
                    ],
                    installed_plugins=["woocommerce", "yoast-seo"]
                )
            ],
            sensitive_data=[
                SensitiveData(table="wp_users", field="user_pass",
                             data_type="passwords", count=15,
                             sample_values=["$2y$10$hash1"]),
                SensitiveData(table="wp_users", field="user_email",
                             data_type="emails", count=15,
                             sample_values=["admin@example.com"]),
            ],
            urls=[
                UrlInfo(url="https://example.com", source_table="wp_options",
                       source_field="option_value", url_type="site"),
            ],
            database_structure={"wordpress_db": []},
            recommendations=["Update WordPress", "Enable 2FA"]
        )

    def test_json_structure_complete(self, full_scan_result):
        """JSON 报告应包含所有必需字段"""
        generator = ReportGenerator()
        parsed = json.loads(generator.generate(full_scan_result, "json"))

        assert "scan_info" in parsed
        assert "fingerprint_results" in parsed
        assert "sensitive_data" in parsed
        assert "urls" in parsed
        assert "database_structure" in parsed
        assert "recommendations" in parsed

    def test_json_scan_info_fields(self, full_scan_result):
        """JSON scan_info 应包含 target, scan_time, duration, database"""
        generator = ReportGenerator()
        parsed = json.loads(generator.generate(full_scan_result, "json"))
        info = parsed["scan_info"]

        assert info["target"] == "192.168.1.100:3306"
        assert info["database"] == "wordpress_db"
        assert info["duration"] == 45

    def test_json_fingerprint_fields(self, full_scan_result):
        """JSON fingerprint_results 应包含所有子字段"""
        generator = ReportGenerator()
        parsed = json.loads(generator.generate(full_scan_result, "json"))
        fp = parsed["fingerprint_results"][0]

        assert fp["application"] == "WordPress"
        assert fp["confidence"] == 0.95
        assert fp["version"] == "5.8.1"
        assert len(fp["evidence"]) == 2
        assert "woocommerce" in fp["installed_plugins"]

    def test_json_sensitive_data_fields(self, full_scan_result):
        """JSON sensitive_data 应包含所有子字段"""
        generator = ReportGenerator()
        parsed = json.loads(generator.generate(full_scan_result, "json"))
        sd = parsed["sensitive_data"][0]

        assert sd["table"] == "wp_users"
        assert sd["field"] == "user_pass"
        assert sd["data_type"] == "passwords"
        assert sd["count"] == 15

    def test_json_urls_fields(self, full_scan_result):
        """JSON urls 应包含所有子字段"""
        generator = ReportGenerator()
        parsed = json.loads(generator.generate(full_scan_result, "json"))
        url = parsed["urls"][0]

        assert url["url"] == "https://example.com"
        assert url["source_table"] == "wp_options"
        assert url["url_type"] == "site"

    def test_json_unicode_preserved(self):
        """JSON 报告应保留 Unicode 字符"""
        result = ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 10, "database": "测试库"},
            fingerprint_results=[
                FingerprintResult(application="WordPress日本語", confidence=0.9,
                                 version="5.8", evidence=[], installed_plugins=[])
            ],
            sensitive_data=[], urls=[], database_structure={}, recommendations=[]
        )
        generator = ReportGenerator()
        json_out = generator.generate(result, "json")
        parsed = json.loads(json_out)
        assert parsed["scan_info"]["database"] == "测试库"
        assert parsed["fingerprint_results"][0]["application"] == "WordPress日本語"


class TestScenarioReportCSV:
    """TDD 场景: CSV 报告格式验证"""

    @pytest.fixture
    def full_scan_result(self):
        return ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 30, "database": "test"},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95,
                                 version="5.8.1", evidence=[], installed_plugins=[])
            ],
            sensitive_data=[
                SensitiveData(table="users", field="password", data_type="passwords",
                             count=10, sample_values=[]),
            ],
            urls=[
                UrlInfo(url="https://example.com", source_table="options",
                       source_field="value", url_type="site"),
            ],
            database_structure={},
            recommendations=["Update software"]
        )

    def test_csv_has_header(self, full_scan_result):
        """CSV 应包含表头行"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        lines = csv_out.strip().split("\n")
        assert len(lines) > 0
        assert "Category" in lines[0]

    def test_csv_has_sensitive_data_row(self, full_scan_result):
        """CSV 应包含敏感数据行"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        assert "Sensitive Data" in csv_out

    def test_csv_has_fingerprint_row(self, full_scan_result):
        """CSV 应包含指纹结果行"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        assert "Application Fingerprint" in csv_out

    def test_csv_has_url_row(self, full_scan_result):
        """CSV 应包含 URL 行"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        assert "URL Discovery" in csv_out

    def test_csv_has_recommendation_row(self, full_scan_result):
        """CSV 应包含建议行"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        assert "Recommendation" in csv_out

    def test_csv_parseable(self, full_scan_result):
        """CSV 应可被标准 csv 模块解析"""
        generator = ReportGenerator()
        csv_out = generator.generate(full_scan_result, "csv")
        reader = csv.reader(io.StringIO(csv_out))
        rows = list(reader)
        assert len(rows) > 1


class TestScenarioReportHTML:
    """TDD 场景: HTML 报告格式验证"""

    @pytest.fixture
    def full_scan_result(self):
        return ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 30, "database": "test"},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95,
                                 version="5.8.1", evidence=[], installed_plugins=["woocommerce"])
            ],
            sensitive_data=[
                SensitiveData(table="users", field="password", data_type="passwords",
                             count=10, sample_values=[]),
            ],
            urls=[],
            database_structure={},
            recommendations=["Update"]
        )

    def test_html_contains_doctype(self, full_scan_result):
        """HTML 应包含 DOCTYPE 或 html 标签"""
        generator = ReportGenerator()
        html_out = generator.generate(full_scan_result, "html")
        assert "html" in html_out.lower()

    def test_html_contains_target(self, full_scan_result):
        """HTML 应包含扫描目标"""
        generator = ReportGenerator()
        html_out = generator.generate(full_scan_result, "html")
        assert "localhost:3306" in html_out

    def test_html_contains_fingerprint_table(self, full_scan_result):
        """HTML 应包含指纹结果表格"""
        generator = ReportGenerator()
        html_out = generator.generate(full_scan_result, "html")
        assert "WordPress" in html_out
        assert "5.8.1" in html_out

    def test_html_contains_plugins(self, full_scan_result):
        """HTML 应包含插件信息"""
        generator = ReportGenerator()
        html_out = generator.generate(full_scan_result, "html")
        assert "woocommerce" in html_out

    def test_html_contains_styling(self, full_scan_result):
        """HTML 应包含 CSS 样式"""
        generator = ReportGenerator()
        html_out = generator.generate(full_scan_result, "html")
        assert "<style>" in html_out


class TestScenarioReportMarkdown:
    """TDD 场景: Markdown 报告格式验证"""

    @pytest.fixture
    def full_scan_result(self):
        return ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 30, "database": "test"},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95,
                                 version="5.8.1", evidence=[], installed_plugins=[])
            ],
            sensitive_data=[
                SensitiveData(table="users", field="password", data_type="passwords",
                             count=10, sample_values=[]),
            ],
            urls=[],
            database_structure={},
            recommendations=["Update"]
        )

    def test_md_contains_headers(self, full_scan_result):
        """Markdown 应包含标题"""
        generator = ReportGenerator()
        md_out = generator.generate(full_scan_result, "markdown")
        assert "#" in md_out

    def test_md_contains_target(self, full_scan_result):
        """Markdown 应包含扫描目标"""
        generator = ReportGenerator()
        md_out = generator.generate(full_scan_result, "markdown")
        assert "localhost:3306" in md_out

    def test_md_contains_fingerprint(self, full_scan_result):
        """Markdown 应包含指纹结果"""
        generator = ReportGenerator()
        md_out = generator.generate(full_scan_result, "markdown")
        assert "WordPress" in md_out
        assert "95" in md_out

    def test_md_contains_recommendations(self, full_scan_result):
        """Markdown 应包含建议"""
        generator = ReportGenerator()
        md_out = generator.generate(full_scan_result, "markdown")
        assert "Update" in md_out


class TestScenarioReportConsole:
    """TDD 场景: 控制台报告格式验证"""

    @pytest.fixture
    def full_scan_result(self):
        return ScanResult(
            scan_info={"target": "localhost:3306", "scan_time": "2024-01-01T00:00:00",
                      "duration": 30, "database": "test"},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95,
                                 version="5.8.1", evidence=[], installed_plugins=[])
            ],
            sensitive_data=[
                SensitiveData(table="users", field="password", data_type="passwords",
                             count=15, sample_values=[]),
            ],
            urls=[
                UrlInfo(url="https://example.com", source_table="options",
                       source_field="value", url_type="site"),
            ],
            database_structure={},
            recommendations=["Update software"]
        )

    def test_console_contains_header(self, full_scan_result):
        """控制台报告应包含头部"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "DBRecon" in out

    def test_console_contains_target(self, full_scan_result):
        """控制台报告应包含目标"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "localhost:3306" in out

    def test_console_contains_fingerprint(self, full_scan_result):
        """控制台报告应包含指纹结果"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "WordPress" in out
        assert "95" in out

    def test_console_contains_risk_level(self, full_scan_result):
        """控制台报告应包含风险级别"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "HIGH" in out

    def test_console_contains_urls(self, full_scan_result):
        """控制台报告应包含 URL"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "https://example.com" in out

    def test_console_contains_recommendations(self, full_scan_result):
        """控制台报告应包含建议"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "Update software" in out

    def test_console_contains_footer(self, full_scan_result):
        """控制台报告应包含页脚"""
        generator = ReportGenerator()
        out = generator.generate(full_scan_result, "console")
        assert "DBRecon v0.1.0" in out
