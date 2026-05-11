import pytest
from unittest.mock import Mock, patch
from typing import List, Dict, Any

from dbrecon.scanner import SensitiveDataScanner
from dbrecon.models import SensitiveData, TableInfo


class TestSensitiveDataScanner:
    """Test cases for SensitiveDataScanner class."""

    @pytest.fixture
    def scanner(self):
        """Fixture providing a SensitiveDataScanner instance."""
        return SensitiveDataScanner()

    @pytest.fixture
    def mock_db_manager(self):
        """Fixture providing a mock database manager."""
        mock_manager = Mock()
        return mock_manager

    @pytest.fixture
    def sample_user_table(self):
        """Fixture providing sample user table with sensitive data."""
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
    def sample_config_table(self):
        """Fixture providing sample configuration table with secrets."""
        return TableInfo(
            name="config",
            columns=[
                {"name": "id", "type": "int(11)", "nullable": False},
                {"name": "config_key", "type": "varchar(100)", "nullable": False},
                {"name": "config_value", "type": "text", "nullable": True},
                {"name": "description", "type": "text", "nullable": True}
            ]
        )

    def test_scanner_initialization(self, scanner):
        """Test SensitiveDataScanner initialization."""
        assert scanner.patterns is not None
        assert isinstance(scanner.patterns, dict)
        assert "passwords" in scanner.patterns
        assert "api_keys" in scanner.patterns
        assert "emails" in scanner.patterns

    def test_load_patterns(self, scanner):
        """Test loading sensitive data patterns."""
        patterns = scanner.patterns
        
        # Test password patterns
        assert "field_patterns" in patterns["passwords"]
        assert "data_patterns" in patterns["passwords"]
        
        # Test email patterns
        assert "field_patterns" in patterns["emails"]
        assert "data_patterns" in patterns["emails"]
        
        # Verify pattern content
        password_fields = patterns["passwords"]["field_patterns"]
        assert any("*password*" in pattern for pattern in password_fields)

    def test_detect_by_field_name_password(self, scanner, sample_user_table):
        """Test password detection by field name."""
        detected = scanner._detect_by_field_name(sample_user_table)
        
        password_fields = [d for d in detected if d.data_type == "passwords"]
        assert len(password_fields) == 1
        assert password_fields[0].field == "password"
        assert password_fields[0].table == "users"

    def test_detect_by_field_name_email(self, scanner, sample_user_table):
        """Test email detection by field name."""
        detected = scanner._detect_by_field_name(sample_user_table)
        
        email_fields = [d for d in detected if d.data_type == "emails"]
        assert len(email_fields) == 1
        assert email_fields[0].field == "email"
        assert email_fields[0].table == "users"

    def test_detect_by_field_name_api_key(self, scanner, sample_user_table):
        """Test API key detection by field name."""
        detected = scanner._detect_by_field_name(sample_user_table)
        
        api_fields = [d for d in detected if d.data_type == "api_keys"]
        assert len(api_fields) == 1
        assert api_fields[0].field == "api_token"
        assert api_fields[0].table == "users"

    def test_detect_by_field_name_phone(self, scanner, sample_user_table):
        """Test phone number detection by field name."""
        detected = scanner._detect_by_field_name(sample_user_table)
        
        phone_fields = [d for d in detected if d.data_type == "phones"]
        assert len(phone_fields) == 1
        assert phone_fields[0].field == "phone"
        assert phone_fields[0].table == "users"

    def test_detect_by_field_name_no_match(self, scanner):
        """Test field name detection with no matches."""
        table = TableInfo(
            name="products",
            columns=[
                {"name": "id", "type": "int(11)"},
                {"name": "name", "type": "varchar(100)"},
                {"name": "price", "type": "decimal(10,2)"}
            ]
        )
        
        detected = scanner._detect_by_field_name(table)
        assert len(detected) == 0

    def test_detect_by_field_name_case_insensitive(self, scanner):
        """Test case-insensitive field name detection."""
        table = TableInfo(
            name="users",
            columns=[
                {"name": "PASSWORD", "type": "varchar(255)"},
                {"name": "EmailAddress", "type": "varchar(100)"},
                {"name": "API_KEY", "type": "varchar(255)"}
            ]
        )
        
        detected = scanner._detect_by_field_name(table)
        
        data_types = [d.data_type for d in detected]
        assert "passwords" in data_types
        assert "emails" in data_types
        assert "api_keys" in data_types

    @patch('dbrecon.scanner.SensitiveDataScanner._sample_table_data')
    def test_detect_by_data_pattern_emails(self, mock_sample, scanner, sample_user_table):
        """Test email detection by data pattern."""
        mock_sample.return_value = [
            ("user1@example.com",), ("user2@test.org",)
        ]
        
        detected = scanner._detect_by_data_patterns(
            mock_db_manager := Mock(), "test_db", sample_user_table, ["emails"]
        )
        
        email_fields = [d for d in detected if d.data_type == "emails"]
        assert len(email_fields) > 0  # Should detect at least some email fields
        assert any(d.field == "email" for d in email_fields)

    @patch('dbrecon.scanner.SensitiveDataScanner._sample_table_data')
    def test_detect_by_data_pattern_phones(self, mock_sample, scanner, sample_user_table):
        """Test phone number detection by data pattern."""
        mock_sample.return_value = [
            ("+1-555-123-4567",), ("555-987-6543",)
        ]
        
        detected = scanner._detect_by_data_patterns(
            mock_db_manager := Mock(), "test_db", sample_user_table, ["phones"]
        )
        
        phone_fields = [d for d in detected if d.data_type == "phones"]
        assert len(phone_fields) > 0

    @patch('dbrecon.scanner.SensitiveDataScanner._sample_table_data')
    def test_detect_by_data_pattern_urls(self, mock_sample, scanner, sample_config_table):
        """Test URL detection by data pattern."""
        mock_sample.return_value = [
            ("https://example.com",), ("https://api.example.com/v1",)
        ]
        
        detected = scanner._detect_by_data_patterns(
            mock_db_manager := Mock(), "test_db", sample_config_table, ["urls"]
        )
        
        url_fields = [d for d in detected if d.data_type == "urls"]
        assert len(url_fields) > 0

    def test_sample_table_data(self, scanner, mock_db_manager):
        """Test table data sampling."""
        expected_data = [("1", "test@example.com"), ("2", "user@test.org")]
        mock_db_manager.execute_query.return_value = expected_data
        
        result = scanner._sample_table_data(mock_db_manager, "test_db", "users", "email")
        
        assert result == expected_data
        mock_db_manager.execute_query.assert_called_once()
        
        # Verify LIMIT clause is used
        call_args = mock_db_manager.execute_query.call_args[0][0]
        assert "LIMIT" in call_args.upper()

    def test_sample_table_data_error(self, scanner, mock_db_manager):
        """Test table data sampling with database error."""
        mock_db_manager.execute_query.side_effect = Exception("Query failed")
        
        result = scanner._sample_table_data(mock_db_manager, "test_db", "users", "email")
        
        assert result == []

    def test_scan_table_comprehensive(self, scanner, mock_db_manager, sample_user_table):
        """Test comprehensive table scanning."""
        with patch.object(scanner, '_sample_table_data', return_value=[
            ["user1@example.com"], ["user2@test.org"]
        ]):
            results = scanner.scan_table(mock_db_manager, "test_db", sample_user_table)
            email_results = [r for r in results if r.data_type == "emails"]
            assert len(email_results) > 0

    def test_scan_sensitive_data_types_filter(self, scanner, mock_db_manager, sample_user_table):
        """Test scanning with specific data types filter."""
        scanner.scan(mock_db_manager, "test_db", [sample_user_table], data_types=["emails"])
        
        # Should only scan for emails, not other types
        # This would require checking internal method calls or mocking

    def test_scan_empty_table(self, scanner, mock_db_manager):
        """Test scanning empty table."""
        empty_table = TableInfo(name="empty_table", columns=[])
        
        results = scanner.scan_table(mock_db_manager, "test_db", empty_table)
        
        assert len(results) == 0

    def test_scan_table_with_error(self, scanner, mock_db_manager, sample_user_table):
        """Test table scanning with database errors."""
        mock_db_manager.execute_query.side_effect = Exception("Connection lost")
        
        results = scanner.scan_table(mock_db_manager, "test_db", sample_user_table)
        
        # Should handle errors gracefully and return partial results
        # Field name detection should still work
        field_based_results = [r for r in results if r.data_type in ["passwords", "emails", "api_keys"]]
        assert len(field_based_results) > 0

    def test_sample_value_masking(self, scanner):
        """Test sensitive value masking in sample data."""
        # This would test the masking logic for sensitive values
        # Implementation depends on specific masking requirements
        pass

    def test_scan_performance_large_table(self, scanner, mock_db_manager):
        """Test scanning performance with large tables."""
        # Mock a table with many rows
        large_data = [(str(i), f"user{i}@example.com") for i in range(10000)]
        mock_db_manager.execute_query.return_value = large_data[:100]  # Should be limited
        
        table = TableInfo(
            name="large_users",
            columns=[
                {"name": "id", "type": "int(11)"},
                {"name": "email", "type": "varchar(100)"}
            ]
        )
        
        results = scanner.scan_table(mock_db_manager, "test_db", table)
        
        email_results = [r for r in results if r.data_type == "emails"]
        if email_results:
            # Should have reasonable sample size
            assert len(email_results[0].sample_values) <= 5

    @pytest.mark.parametrize("data_type,field_name,expected", [
        ("passwords", "password", True),
        ("passwords", "passwd", True),
        ("passwords", "pwd", True),
        ("passwords", "username", False),
        ("emails", "email", True),
        ("emails", "email_address", True),
        ("emails", "user_email", True),
        ("emails", "name", False),
    ])
    def test_pattern_matching(self, scanner, data_type, field_name, expected):
        """Test pattern matching for different field names."""
        table = TableInfo(
            name="test_table",
            columns=[{"name": field_name, "type": "varchar(255)"}]
        )
        
        detected = scanner._detect_by_field_name(table)
        has_match = any(d.data_type == data_type for d in detected)
        
        assert has_match == expected