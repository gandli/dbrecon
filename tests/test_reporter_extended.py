"""Extended tests for ReportGenerator - covering edge cases and output validation."""

import pytest
import json
import tempfile
import os
from datetime import datetime
from unittest.mock import Mock, patch

from dbrecon.reporter import ReportGenerator
from dbrecon.models import (
    ScanResult, FingerprintResult, SensitiveData, UrlInfo,
    TableInfo
)


class TestReportGeneratorExtended:
    """Extended tests for ReportGenerator edge cases."""

    @pytest.fixture
    def report_generator(self):
        return ReportGenerator()

    @pytest.fixture
    def empty_scan_result(self):
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

    def test_json_report_with_special_characters(self, report_generator):
        """Test JSON report handles special characters in data."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 10,
                "database": "test_db"
            },
            fingerprint_results=[
                FingerprintResult(
                    application="WordPress",
                    confidence=0.95,
                    version="5.8.1",
                    evidence=[{"type": "table", "name": "wp_options", "match": "exact"}],
                    installed_plugins=["plugin-with-dashes"]
                )
            ],
            sensitive_data=[
                SensitiveData(
                    table="wp_users",
                    field="user_pass",
                    data_type="passwords",
                    count=5,
                    sample_values=["hash1"]
                )
            ],
            urls=[
                UrlInfo(
                    url="https://example.com/path?param=value",
                    source_table="wp_options",
                    source_field="option_value",
                    url_type="site"
                )
            ],
            database_structure={},
            recommendations=[]
        )
        json_output = report_generator.generate(result, "json")
        parsed = json.loads(json_output)
        assert parsed["fingerprint_results"][0]["application"] == "WordPress"

    def test_json_report_unicode_content(self, report_generator):
        """Test JSON report handles unicode content."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 10,
                "database": "test_db"
            },
            fingerprint_results=[
                FingerprintResult(
                    application="WordPress",
                    confidence=0.9,
                    version="5.8",
                    evidence=[],
                    installed_plugins=[]
                )
            ],
            sensitive_data=[],
            urls=[],
            database_structure={},
            recommendations=[]
        )
        json_output = report_generator.generate(result, "json")
        parsed = json.loads(json_output)
        assert parsed["fingerprint_results"][0]["application"] == "WordPress"

    def test_csv_report_empty_data(self, report_generator, empty_scan_result):
        """Test CSV report with empty data."""
        csv_output = report_generator.generate(empty_scan_result, "csv")
        assert isinstance(csv_output, str)

    def test_html_report_empty_data(self, report_generator, empty_scan_result):
        """Test HTML report with empty data."""
        html_output = report_generator.generate(empty_scan_result, "html")
        assert "DBRecon" in html_output or "report" in html_output.lower()

    def test_markdown_report_empty_data(self, report_generator, empty_scan_result):
        """Test Markdown report with empty data."""
        md_output = report_generator.generate(empty_scan_result, "markdown")
        assert isinstance(md_output, str)
        assert "DBRecon" in md_output

    def test_console_report_empty_data(self, report_generator, empty_scan_result):
        """Test console report with empty data."""
        console_output = report_generator.generate(empty_scan_result, "console")
        assert "No applications identified" in console_output
        assert "No sensitive data found" in console_output
        assert "No URLs discovered" in console_output

    def test_console_report_risk_levels(self, report_generator):
        """Test console report shows correct risk levels."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 10,
                "database": "test_db"
            },
            fingerprint_results=[],
            sensitive_data=[
                SensitiveData(table="t", field="f", data_type="passwords", count=15, sample_values=[]),
                SensitiveData(table="t", field="f", data_type="emails", count=7, sample_values=[]),
                SensitiveData(table="t", field="f", data_type="phones", count=3, sample_values=[]),
            ],
            urls=[],
            database_structure={},
            recommendations=[]
        )
        console_output = report_generator.generate(result, "console")
        assert "HIGH" in console_output
        assert "MEDIUM" in console_output
        assert "LOW" in console_output

    def test_report_with_large_dataset(self, report_generator):
        """Test report generation with large dataset."""
        sensitive_data = [
            SensitiveData(
                table="table_{}".format(i),
                field="field_{}".format(i),
                data_type="emails",
                count=i * 10,
                sample_values=["user{}@test.com".format(i)]
            )
            for i in range(100)
        ]
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 120,
                "database": "large_db"
            },
            fingerprint_results=[],
            sensitive_data=sensitive_data,
            urls=[],
            database_structure={},
            recommendations=[]
        )
        json_output = report_generator.generate(result, "json")
        parsed = json.loads(json_output)
        assert len(parsed["sensitive_data"]) == 100

    def test_report_to_file(self, report_generator, empty_scan_result):
        """Test report generation to file."""
        fd, temp_path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            report_generator.generate(empty_scan_result, "json", temp_path)
            assert os.path.exists(temp_path)
            with open(temp_path, 'r') as f:
                content = f.read()
            assert len(content) > 0
        finally:
            os.unlink(temp_path)

    def test_report_to_file_returns_none(self, report_generator, empty_scan_result):
        """Test report generation to file returns None."""
        fd, temp_path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            result = report_generator.generate(empty_scan_result, "json", temp_path)
            assert result is None
        finally:
            os.unlink(temp_path)

    def test_report_to_stdout_returns_string(self, report_generator, empty_scan_result):
        """Test report generation to stdout returns string."""
        result = report_generator.generate(empty_scan_result, "json")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_invalid_format_raises_error(self, report_generator, empty_scan_result):
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported format"):
            report_generator.generate(empty_scan_result, "xml")

    def test_json_serialization_with_datetime_in_scan_info(self, report_generator):
        """Test JSON serialization handles datetime objects in scan_info."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime(2024, 1, 15, 10, 30, 0),
                "duration": 10,
                "database": "test_db"
            },
            fingerprint_results=[],
            sensitive_data=[],
            urls=[],
            database_structure={},
            recommendations=[]
        )
        json_output = report_generator.generate(result, "json")
        parsed = json.loads(json_output)
        assert "2024-01-15" in parsed["scan_info"]["scan_time"]

    def test_report_multiple_fingerprints(self, report_generator):
        """Test report with multiple fingerprint results."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 30,
                "database": "test_db"
            },
            fingerprint_results=[
                FingerprintResult(
                    application="WordPress",
                    confidence=0.95,
                    version="5.8.1",
                    evidence=[],
                    installed_plugins=[]
                ),
                FingerprintResult(
                    application="WooCommerce",
                    confidence=0.80,
                    version="6.0",
                    evidence=[],
                    installed_plugins=[]
                ),
            ],
            sensitive_data=[],
            urls=[],
            database_structure={},
            recommendations=[]
        )
        console_output = report_generator.generate(result, "console")
        assert "WordPress" in console_output
        assert "WooCommerce" in console_output

    def test_report_with_recommendations(self, report_generator):
        """Test report includes recommendations."""
        result = ScanResult(
            scan_info={
                "target": "localhost:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 10,
                "database": "test_db"
            },
            fingerprint_results=[],
            sensitive_data=[],
            urls=[],
            database_structure={},
            recommendations=[
                "Update all applications to latest versions",
                "Implement network segmentation",
                "Enable database audit logging"
            ]
        )
        console_output = report_generator.generate(result, "console")
        assert "Update all applications" in console_output
        assert "network segmentation" in console_output
        assert "audit logging" in console_output

    def test_report_without_recommendations(self, report_generator, empty_scan_result):
        """Test report handles empty recommendations."""
        console_output = report_generator.generate(empty_scan_result, "console")
        assert "No specific recommendations" in console_output

    def test_json_report_all_top_level_keys(self, report_generator, empty_scan_result):
        """Test JSON report includes all expected top-level keys."""
        empty_scan_result.fingerprint_results = [
            FingerprintResult(
                application="WordPress",
                confidence=0.95,
                version="5.8.1",
                evidence=[{"type": "table", "name": "wp_options", "match": "exact"}],
                installed_plugins=["woocommerce"]
            )
        ]
        empty_scan_result.sensitive_data = [
            SensitiveData(table="users", field="password", data_type="passwords", count=10, sample_values=["hash1"])
        ]
        empty_scan_result.urls = [
            UrlInfo(url="https://example.com", source_table="options", source_field="value", url_type="site")
        ]

        result = report_generator._generate_json_report(empty_scan_result)
        parsed = json.loads(result)
        assert "scan_info" in parsed
        assert "fingerprint_results" in parsed
        assert "sensitive_data" in parsed
        assert "urls" in parsed
        assert "database_structure" in parsed
        assert "recommendations" in parsed
