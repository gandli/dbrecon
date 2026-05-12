"""
Extended tests for SensitiveDataScanner - covering edge cases and untested paths.
"""

import pytest
from unittest.mock import Mock, patch

from dbrecon.scanner import SensitiveDataScanner
from dbrecon.models import SensitiveData, TableInfo


class TestSensitiveDataScannerExtended:
    """Extended test cases for SensitiveDataScanner edge cases."""

    @pytest.fixture
    def scanner(self):
        return SensitiveDataScanner()

    @pytest.fixture
    def mock_db_manager(self):
        return Mock()

    def test_scanner_with_empty_patterns(self, scanner):
        """Test scanner behavior when patterns dict is empty."""
        scanner.patterns = {}
        result = scanner._detect_by_field_name(
            TableInfo(name="users", columns=[{"name": "password"}])
        )
        assert result == []

    def test_detect_by_field_name_no_match(self, scanner):
        """Test field name detection with no matching patterns."""
        table_info = TableInfo(
            name="products",
            columns=[
                {"name": "product_id", "type": "int"},
                {"name": "product_name", "type": "varchar"},
                {"name": "price", "type": "decimal"}
            ]
        )
        result = scanner._detect_by_field_name(table_info)
        assert result == []

    def test_detect_by_field_name_multiple_data_types(self, scanner):
        """Test field name detection matches multiple data types."""
        table_info = TableInfo(
            name="users",
            columns=[
                {"name": "password_hash", "type": "varchar"},
                {"name": "api_secret_key", "type": "varchar"},
                {"name": "email_address", "type": "varchar"}
            ]
        )
        result = scanner._detect_by_field_name(table_info)
        data_types = [r.data_type for r in result]
        assert "passwords" in data_types
        assert "api_keys" in data_types
        assert "emails" in data_types

    def test_detect_by_field_name_empty_columns(self, scanner):
        """Test field name detection with empty columns."""
        table_info = TableInfo(name="empty_table", columns=[])
        result = scanner._detect_by_field_name(table_info)
        assert result == []

    def test_matches_pattern_wildcard_prefix(self, scanner):
        """Test pattern matching with wildcard prefix."""
        assert scanner._matches_pattern("user_password", "*password") is True
        assert scanner._matches_pattern("admin_password", "*password") is True

    def test_matches_pattern_wildcard_suffix(self, scanner):
        """Test pattern matching with wildcard suffix."""
        assert scanner._matches_pattern("password_hash", "password*") is True
        assert scanner._matches_pattern("password_salt", "password*") is True

    def test_matches_pattern_wildcard_both(self, scanner):
        """Test pattern matching with wildcards on both sides."""
        assert scanner._matches_pattern("user_password_hash", "*password*") is True
        assert scanner._matches_pattern("the_password_field", "*password*") is True

    def test_matches_pattern_case_insensitive(self, scanner):
        """Test pattern matching is case insensitive."""
        assert scanner._matches_pattern("PASSWORD", "password") is True
        assert scanner._matches_pattern("Password", "password") is True

    def test_matches_pattern_no_wildcard(self, scanner):
        """Test pattern matching without wildcards."""
        assert scanner._matches_pattern("user_password", "password") is True
        assert scanner._matches_pattern("password_field", "password") is True

    def test_deduplicate_results_no_duplicates(self, scanner):
        """Test deduplication with no duplicate entries."""
        results = [
            SensitiveData(table="users", field="password", data_type="passwords", count=10),
            SensitiveData(table="users", field="email", data_type="emails", count=5),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 2

    def test_deduplicate_results_with_duplicates(self, scanner):
        """Test deduplication merges duplicate entries."""
        results = [
            SensitiveData(table="users", field="password", data_type="passwords", count=10,
                         sample_values=["hash1"]),
            SensitiveData(table="users", field="password", data_type="passwords", count=5,
                         sample_values=["hash2"]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 1
        assert deduped[0].count == 15

    def test_deduplicate_results_unique_samples(self, scanner):
        """Test deduplication keeps unique samples only."""
        results = [
            SensitiveData(table="users", field="email", data_type="emails", count=5,
                         sample_values=["a@b.com", "c@d.com"]),
            SensitiveData(table="users", field="email", data_type="emails", count=3,
                         sample_values=["a@b.com", "e@f.com"]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped) == 1
        assert len(deduped[0].sample_values) == 3

    def test_deduplicate_results_max_samples(self, scanner):
        """Test deduplication limits to max 5 samples."""
        results = [
            SensitiveData(table="users", field="email", data_type="emails", count=5,
                         sample_values=["a@b.com", "c@d.com", "e@f.com"]),
            SensitiveData(table="users", field="email", data_type="emails", count=3,
                         sample_values=["g@h.com", "i@j.com", "k@l.com"]),
        ]
        deduped = scanner._deduplicate_results(results)
        assert len(deduped[0].sample_values) <= 5

    def test_sample_table_data_success(self, scanner, mock_db_manager):
        """Test sampling table data returns results."""
        mock_db_manager.execute_query.return_value = [
            ("value1",), ("value2",), ("value3",)
        ]
        result = scanner._sample_table_data(mock_db_manager, "test_db", "users", "email")
        assert len(result) == 3

    def test_sample_table_data_error(self, scanner, mock_db_manager):
        """Test sampling table data returns empty on error."""
        mock_db_manager.execute_query.side_effect = Exception("DB error")
        result = scanner._sample_table_data(mock_db_manager, "test_db", "users", "email")
        assert result == []

    def test_sample_table_data_custom_limit(self, scanner, mock_db_manager):
        """Test sampling table data with custom limit."""
        mock_db_manager.execute_query.return_value = []
        scanner._sample_table_data(mock_db_manager, "test_db", "users", "email", limit=50)
        call_args = mock_db_manager.execute_query.call_args[0][0]
        assert "LIMIT 50" in call_args

    def test_detect_by_data_patterns_no_patterns(self, scanner, mock_db_manager):
        """Test data pattern detection when no data_patterns defined."""
        scanner.patterns = {"test_type": {"field_patterns": [], "data_patterns": []}}
        table_info = TableInfo(name="test", columns=[{"name": "data"}])
        mock_db_manager.execute_query.return_value = []
        result = scanner._detect_by_data_patterns(
            mock_db_manager, "test_db", table_info, ["test_type"]
        )
        assert result == []

    def test_detect_by_data_patterns_unknown_data_type(self, scanner, mock_db_manager):
        """Test data pattern detection with unknown data type."""
        table_info = TableInfo(name="test", columns=[{"name": "data"}])
        result = scanner._detect_by_data_patterns(
            mock_db_manager, "test_db", table_info, ["nonexistent_type"]
        )
        assert result == []

    def test_detect_by_data_patterns_no_samples(self, scanner, mock_db_manager):
        """Test data pattern detection when no data samples."""
        scanner.patterns = {
            "emails": {
                "field_patterns": [],
                "data_patterns": [r"[\w.]+@[\w.]+"]
            }
        }
        mock_db_manager.execute_query.return_value = []
        table_info = TableInfo(name="test", columns=[{"name": "email"}])
        result = scanner._detect_by_data_patterns(
            mock_db_manager, "test_db", table_info, ["emails"]
        )
        assert result == []

    def test_scan_with_specific_data_types(self, scanner, mock_db_manager):
        """Test scan with specific data types filter."""
        table_info = TableInfo(
            name="users",
            columns=[
                {"name": "password", "type": "varchar"},
                {"name": "email", "type": "varchar"}
            ]
        )
        result = scanner.scan(mock_db_manager, "test_db", [table_info], data_types=["passwords"])
        for item in result:
            assert item.data_type == "passwords"

    def test_scan_table_error_handling(self, scanner, mock_db_manager):
        """Test scan_table handles errors gracefully."""
        mock_db_manager.execute_query.side_effect = Exception("DB error")
        table_info = TableInfo(name="users", columns=[{"name": "password_hash"}])
        result = scanner.scan_table(mock_db_manager, "test_db", table_info)
        assert isinstance(result, list)

    def test_scan_continues_after_table_error(self, scanner, mock_db_manager):
        """Test scan continues after encountering error in one table."""
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise Exception("DB error")
            return []

        mock_db_manager.execute_query.side_effect = side_effect
        tables = [
            TableInfo(name="table1", columns=[{"name": "data"}]),
            TableInfo(name="table2", columns=[{"name": "password_hash"}]),
        ]
        result = scanner.scan(mock_db_manager, "test_db", tables)
        assert isinstance(result, list)
