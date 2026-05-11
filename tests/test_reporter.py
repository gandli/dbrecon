import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
from datetime import datetime
from typing import Dict, Any, List

from dbrecon.reporter import ReportGenerator
from dbrecon.models import (
    ScanResult, FingerprintResult, SensitiveData, UrlInfo, 
    TableInfo, ScanConfig
)


class TestReportGenerator:
    """Test cases for ReportGenerator class."""

    @pytest.fixture
    def report_generator(self):
        """Fixture providing a ReportGenerator instance."""
        return ReportGenerator()

    @pytest.fixture
    def sample_scan_result(self):
        """Fixture providing a sample scan result."""
        return ScanResult(
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
                        {"type": "field", "table": "wp_users", "field": "user_pass", "match": "password_hash"}
                    ],
                    installed_plugins=["woocommerce", "yoast-seo"]
                )
            ],
            sensitive_data=[
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
                )
            ],
            urls=[
                UrlInfo(
                    url="https://example.com",
                    source_table="wp_options",
                    source_field="option_value",
                    url_type="site"
                ),
                UrlInfo(
                    url="https://admin.example.com",
                    source_table="wp_options",
                    source_field="option_value",
                    url_type="admin"
                )
            ],
            database_structure={
                "wordpress_db": [
                    TableInfo(
                        name="wp_users",
                        engine="InnoDB",
                        row_count=15,
                        columns=[
                            {"name": "ID", "type": "bigint(20)", "nullable": False},
                            {"name": "user_login", "type": "varchar(60)", "nullable": False},
                            {"name": "user_pass", "type": "varchar(255)", "nullable": False}
                        ]
                    )
                ]
            },
            recommendations=[
                "Change default admin passwords",
                "Update WordPress to latest version",
                "Review installed plugins for security vulnerabilities"
            ]
        )

    @pytest.fixture
    def sample_scan_config(self):
        """Fixture providing a sample scan configuration."""
        return ScanConfig(
            deep_scan=True,
            scan_types=["fingerprint", "sensitive_data", "urls"],
            sensitive_data_types=["passwords", "emails", "api_keys"],
            output_format="json",
            output_file=None
        )

    def test_report_generator_initialization(self, report_generator):
        """Test ReportGenerator initialization."""
        assert report_generator is not None
        assert hasattr(report_generator, 'generate')

    def test_generate_json_report(self, report_generator, sample_scan_result):
        """Test JSON report generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "json", temp_file)
            
            # Verify file was created
            assert os.path.exists(temp_file)
            
            # Verify JSON content
            with open(temp_file, 'r') as f:
                data = json.load(f)
            
            assert data["scan_info"]["target"] == "192.168.1.100:3306"
            assert len(data["fingerprint_results"]) == 1
            assert data["fingerprint_results"][0]["application"] == "WordPress"
            assert len(data["sensitive_data"]) == 2
            assert len(data["urls"]) == 2
            assert len(data["recommendations"]) == 3
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_generate_console_report(self, report_generator, sample_scan_result, capsys):
        """Test console report generation."""
        result = report_generator.generate(sample_scan_result, "console", None)
        assert isinstance(result, str)
        assert "WordPress" in result
        assert "95.0%" in result

    def test_generate_csv_report(self, report_generator, sample_scan_result):
        """Test CSV report generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "csv", temp_file)
            
            # Verify file was created
            assert os.path.exists(temp_file)
            
            # Verify CSV content
            with open(temp_file, 'r') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            header = lines[0]
            assert "Table,Field,Data Type,Count" in header
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_generate_html_report(self, report_generator, sample_scan_result):
        """Test HTML report generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "html", temp_file)
            
            # Verify file was created
            assert os.path.exists(temp_file)
            
            # Verify HTML content
            with open(temp_file, 'r') as f:
                content = f.read()
            
            assert "<!DOCTYPE html>" in content or "<html" in content
            assert "WordPress" in content
            assert "192.168.1.100:3306" in content
            assert "passwords" in content
            assert "emails" in content
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_generate_markdown_report(self, report_generator, sample_scan_result):
        """Test Markdown report generation."""
        result = report_generator.generate(sample_scan_result, "markdown", None)
        assert isinstance(result, str)
        
        assert "# DBRecon Security Assessment Report" in result
        assert "## Application Fingerprint Results" in result
        assert "WordPress" in result
        assert "## Sensitive Data Found" in result
        assert "passwords" in result

    def test_generate_report_no_output_file(self, report_generator, sample_scan_result):
        """Test report generation without output file (should return content)."""
        result = report_generator.generate(sample_scan_result, "json", None)
        
        assert result is not None
        assert isinstance(result, str)
        
        # Parse as JSON to verify structure
        data = json.loads(result)
        assert data["scan_info"]["target"] == "192.168.1.100:3306"

    def test_generate_report_invalid_format(self, report_generator, sample_scan_result):
        """Test report generation with invalid format."""
        with pytest.raises(ValueError, match="Unsupported format"):
            report_generator.generate(sample_scan_result, "invalid_format", None)

    def test_generate_report_empty_results(self, report_generator):
        """Test report generation with empty scan results."""
        empty_result = ScanResult(
            scan_info={
                "target": "192.168.1.100:3306",
                "scan_time": datetime.now().isoformat(),
                "duration": 0,
                "database": "empty_db"
            },
            fingerprint_results=[],
            sensitive_data=[],
            urls=[],
            database_structure={},
            recommendations=[]
        )
        
        result = report_generator.generate(empty_result, "json", None)
        
        data = json.loads(result)
        assert data["scan_info"]["target"] == "192.168.1.100:3306"
        assert len(data["fingerprint_results"]) == 0
        assert len(data["sensitive_data"]) == 0
        assert len(data["urls"]) == 0
        assert len(data["recommendations"]) == 0

    def test_json_serialization_datetime(self, report_generator, sample_scan_result):
        """Test JSON serialization of datetime objects."""
        import datetime as dt
        
        # Ensure scan_info contains datetime
        sample_scan_result.scan_info["scan_time"] = dt.datetime.now()
        
        result = report_generator.generate(sample_scan_result, "json", None)
        
        # Should not raise exception and should be valid JSON
        data = json.loads(result)
        assert "scan_time" in data["scan_info"]

    def test_csv_sensitive_data_formatting(self, report_generator, sample_scan_result):
        """Test CSV formatting of sensitive data."""
        result = report_generator.generate(sample_scan_result, "csv", None)
        assert isinstance(result, str)
        
        lines = result.strip().split('\n')
        header = lines[0]
        assert "Table,Field,Data Type,Count" in header
        
        data_lines = [line for line in lines if "Sensitive Data," in line and "wp_users" in line]
        assert len(data_lines) >= 2

    def test_html_report_styling(self, report_generator, sample_scan_result):
        """Test HTML report contains proper styling."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "html", temp_file)
            
            with open(temp_file, 'r') as f:
                content = f.read()
            
            # Verify CSS styling is included
            assert "<style" in content or "css" in content.lower()
            
            # Verify proper HTML structure
            assert "<head>" in content
            assert "<body>" in content
            assert "<title>" in content
            
            # Verify security-focused styling (e.g., color coding for risks)
            assert "red" in content.lower() or "color" in content.lower()
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_console_report_risk_highlighting(self, report_generator, sample_scan_result, capsys):
        """Test console report highlights security risks."""
        result = report_generator.generate(sample_scan_result, "console", None)
        assert "HIGH" in result or "WARNING" in result
        assert "password" in result.lower()

    def test_markdown_report_structure(self, report_generator, sample_scan_result):
        """Test Markdown report has proper structure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "markdown", temp_file)
            
            with open(temp_file, 'r') as f:
                content = f.read()
            
            # Verify proper Markdown structure
            assert content.startswith("# ")  # Main title
            assert "## " in content  # Section headers
            assert "- " in content or "* " in content  # Lists
            
            # Verify sections exist
            sections = ["Application Fingerprint", "Sensitive Data", "URLs", "Recommendations"]
            for section in sections:
                assert section in content
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_report_file_permissions(self, report_generator, sample_scan_result):
        """Test report file has appropriate permissions."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            report_generator.generate(sample_scan_result, "json", temp_file)
            
            # Verify file exists and is readable
            assert os.path.exists(temp_file)
            assert os.access(temp_file, os.R_OK)
            
            # File should be created with reasonable permissions
            stat = os.stat(temp_file)
            # Should not be executable
            assert not (stat.st_mode & 0o111)
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_large_dataset_report_generation(self, report_generator):
        """Test report generation with large datasets."""
        # Create a scan result with many entries
        large_result = ScanResult(
            scan_info={"target": "192.168.1.100:3306", "scan_time": datetime.now().isoformat()},
            fingerprint_results=[
                FingerprintResult(application="WordPress", confidence=0.95, version="5.8.1")
            ],
            sensitive_data=[
                SensitiveData(
                    table=f"table_{i}",
                    field=f"field_{i}",
                    data_type="emails",
                    count=i * 10,
                    sample_values=[f"user{i}@example.com"]
                ) for i in range(100)  # 100 entries
            ],
            urls=[UrlInfo(url=f"https://site{i}.com", source_table="config", source_field="url", url_type="site") for i in range(50)],
            database_structure={},
            recommendations=["Test recommendation"]
        )
        
        # Should complete without error
        result = report_generator.generate(large_result, "json", None)
        data = json.loads(result)
        
        assert len(data["sensitive_data"]) == 100
        assert len(data["urls"]) == 50

    @pytest.mark.parametrize("format_name", ["json", "csv", "html", "markdown", "console"])
    def test_all_format_support(self, report_generator, sample_scan_result, format_name):
        """Test all supported report formats."""
        if format_name == "console":
            # Console format doesn't create a file
            result = report_generator.generate(sample_scan_result, format_name, None)
            if result:
                assert isinstance(result, str)
        else:
            # Other formats create files
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{format_name}', delete=False) as f:
                temp_file = f.name
            
            try:
                report_generator.generate(sample_scan_result, format_name, temp_file)
                assert os.path.exists(temp_file)
                
                with open(temp_file, 'r') as f:
                    content = f.read()
                
                assert len(content) > 0
                assert "WordPress" in content
                
            finally:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)