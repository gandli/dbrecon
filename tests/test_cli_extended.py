"""
Extended CLI tests - covering edge cases and command execution paths.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock

from dbrecon.cli import main, create_dummy_scan_result, create_complete_scan_result
from dbrecon.models import FingerprintResult, SensitiveData, UrlInfo


class TestCLIExtended:
    """Extended CLI tests for edge cases and error handling."""

    def test_test_connection_with_ssl(self):
        """Test connection command with SSL enabled."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_server_info.return_value = {"version": "8.0.30"}
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection',
                '--host', 'secure-host.example.com',
                '--user', 'admin',
                '--password', 'ssl_pass',
                '--ssl'
            ])

            assert result.exit_code == 0
            mock_manager.connect.assert_called_once()
            mock_manager.disconnect.assert_called_once()

    def test_test_connection_custom_port(self):
        """Test connection command with custom port."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_server_info.return_value = {}
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection',
                '--host', 'db.example.com',
                '--port', '3307',
                '--user', 'admin',
                '--password', 'pass'
            ])

            assert result.exit_code == 0

    def test_test_connection_custom_timeout(self):
        """Test connection command with custom timeout."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_server_info.return_value = {}
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection',
                '--host', 'slow-host.example.com',
                '--user', 'admin',
                '--password', 'pass',
                '--timeout', '120'
            ])

            assert result.exit_code == 0

    def test_test_connection_server_info_error(self):
        """Test connection when server info retrieval fails."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_server_info.side_effect = Exception("Info unavailable")
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass'
            ])

            assert result.exit_code == 0

    def test_fingerprint_command_no_results(self):
        """Test fingerprint command when no applications are found."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            result = runner.invoke(main, [
                'fingerprint',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'empty_db'
            ])

            assert result.exit_code == 0

    def test_fingerprint_command_with_results(self):
        """Test fingerprint command with detected applications."""
        runner = CliRunner()
        from dbrecon.models import FingerprintResult

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = [
                FingerprintResult(
                    application="WordPress",
                    confidence=0.95,
                    version="5.8.1",
                    evidence=[{"type": "table", "name": "wp_options", "match": "exact"}],
                    installed_plugins=["woocommerce"]
                )
            ]
            mock_engine_class.return_value = mock_engine

            result = runner.invoke(main, [
                'fingerprint',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'wp_db'
            ])

            assert result.exit_code == 0

    def test_fingerprint_command_with_output_file(self):
        """Test fingerprint command with output file."""
        runner = CliRunner()
        from dbrecon.models import FingerprintResult

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = [
                FingerprintResult(
                    application="WordPress",
                    confidence=0.95,
                    version="5.8.1",
                    evidence=[],
                    installed_plugins=[]
                )
            ]
            mock_engine_class.return_value = mock_engine

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'fingerprint',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'wp_db',
                '--output', '/tmp/test_report.json',
                '--format', 'json'
            ])

            assert result.exit_code == 0

    def test_full_scan_command_success(self):
        """Test full scan command execution."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users", "posts"]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db'
            ])

            assert result.exit_code == 0

    def test_full_scan_command_deep(self):
        """Test full scan command with deep scan option."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = []
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db',
                '--deep'
            ])

            assert result.exit_code == 0

    def test_scan_sensitive_command_no_tables(self):
        """Test scan-sensitive command when no tables found."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = []
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'empty_db'
            ])

            assert result.exit_code == 0

    def test_scan_sensitive_command_with_data_types(self):
        """Test scan-sensitive with custom data types."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users"]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db',
                '--data-types', 'passwords,emails'
            ])

            assert result.exit_code == 0


class TestCLIHelperFunctions:
    """Test CLI helper functions."""

    def test_create_dummy_scan_result_basic(self):
        """Test creating a basic dummy scan result."""
        result = create_dummy_scan_result([], "test_db")
        assert result.scan_info["database"] == "test_db"
        assert result.fingerprint_results == []
        assert result.sensitive_data == []

    def test_create_dummy_scan_result_with_fingerprints(self):
        """Test creating dummy scan result with fingerprint data."""
        fingerprints = [
            FingerprintResult(
                application="WordPress",
                confidence=0.95,
                version="5.8.1",
                evidence=[],
                installed_plugins=[]
            )
        ]
        result = create_dummy_scan_result(fingerprints, "wp_db")
        assert len(result.fingerprint_results) == 1

    def test_create_dummy_scan_result_with_sensitive_data(self):
        """Test creating dummy scan result with sensitive data."""
        sensitive_data = [
            SensitiveData(
                table="users",
                field="password",
                data_type="passwords",
                count=10,
                sample_values=[]
            )
        ]
        result = create_dummy_scan_result([], "test_db", sensitive_data=sensitive_data)
        assert len(result.sensitive_data) == 1

    def test_create_dummy_scan_result_custom_host_port(self):
        """Test creating dummy scan result with custom host/port."""
        result = create_dummy_scan_result([], "test_db", host="192.168.1.1", port=3307)
        assert result.scan_info["target"] == "192.168.1.1:3307"

    def test_create_complete_scan_result_basic(self):
        """Test creating a complete scan result."""
        result = create_complete_scan_result([], [], [], "test_db", ["users", "posts"])
        assert result.scan_info["database"] == "test_db"
        assert "users" in result.database_structure
        assert "posts" in result.database_structure

    def test_create_complete_scan_result_with_all_data(self):
        """Test creating complete scan result with all data types."""
        fingerprints = [
            FingerprintResult(
                application="WordPress",
                confidence=0.95,
                version="5.8.1",
                evidence=[],
                installed_plugins=[]
            )
        ]
        sensitive_data = [
            SensitiveData(table="users", field="email", data_type="emails", count=5, sample_values=[])
        ]
        urls = [
            UrlInfo(url="https://example.com", source_table="options", source_field="value", url_type="site")
        ]
        result = create_complete_scan_result(
            fingerprints, sensitive_data, urls, "test_db", ["users"]
        )
        assert len(result.fingerprint_results) == 1
        assert len(result.sensitive_data) == 1
        assert len(result.urls) == 1

    def test_create_complete_scan_result_with_db_manager(self):
        """Test creating complete scan result with db_manager for structure."""
        mock_manager = Mock()
        mock_manager.get_table_structure.return_value = [
            {"name": "id", "type": "int", "nullable": False}
        ]
        result = create_complete_scan_result(
            [], [], [], "test_db", ["users"], db_manager=mock_manager
        )
        assert "users" in result.database_structure
        assert len(result.database_structure["users"]) == 1

    def test_create_complete_scan_result_custom_host_port(self):
        """Test creating complete scan result with custom host/port."""
        result = create_complete_scan_result(
            [], [], [], "test_db", [], host="10.0.0.1", port=5432
        )
        assert result.scan_info["target"] == "10.0.0.1:5432"

    def test_create_complete_scan_result_db_manager_exception(self):
        """Test create_complete_scan_result when db_manager.get_table_structure raises."""
        mock_manager = Mock()
        mock_manager.get_table_structure.side_effect = Exception("DB error")
        result = create_complete_scan_result(
            [], [], [], "test_db", ["users"], db_manager=mock_manager
        )
        assert "users" not in result.database_structure

    def test_create_complete_scan_result_no_db_manager(self):
        """Test create_complete_scan_result without db_manager uses empty columns."""
        result = create_complete_scan_result(
            [], [], [], "test_db", ["users", "posts"]
        )
        assert "users" in result.database_structure
        assert result.database_structure["users"][0].columns == []

    def test_cli_main_entry_point(self):
        """Test __main__ entry point is importable."""
        import dbrecon.cli as cli_module
        assert hasattr(cli_module, 'main')


class TestCLIConnectionFailures:
    """Tests for CLI command connection failure paths."""

    def test_test_connection_failure(self):
        """Test connection command when connection fails."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'test-connection',
                '--host', 'bad-host',
                '--user', 'admin',
                '--password', 'wrong'
            ])

            assert result.exit_code != 0

    def test_fingerprint_connection_failure(self):
        """Test fingerprint command when connection fails."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'fingerprint',
                '--host', 'bad-host',
                '--user', 'admin',
                '--password', 'wrong',
                '--database', 'test_db'
            ])

            assert result.exit_code != 0

    def test_scan_sensitive_connection_failure(self):
        """Test scan-sensitive command when connection fails."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'bad-host',
                '--user', 'admin',
                '--password', 'wrong',
                '--database', 'test_db'
            ])

            assert result.exit_code != 0

    def test_full_scan_connection_failure(self):
        """Test full-scan command when connection fails."""
        runner = CliRunner()
        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = False
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'bad-host',
                '--user', 'admin',
                '--password', 'wrong',
                '--database', 'test_db'
            ])

            assert result.exit_code != 0


class TestCLIScanSensitiveDataPaths:
    """Tests for scan-sensitive command data discovery and reporting paths."""

    def test_scan_sensitive_table_analysis_failure(self):
        """Test scan-sensitive when table structure analysis fails."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["table1"]
            mock_manager.get_table_structure.side_effect = Exception("Access denied")
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db'
            ])

            assert result.exit_code == 0

    def test_scan_sensitive_no_tables_analyzed(self):
        """Test scan-sensitive when all table analyses fail."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["t1", "t2"]
            mock_manager.get_table_structure.side_effect = Exception("Error")
            mock_manager_class.return_value = mock_manager

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db'
            ])

            assert result.exit_code == 0

    def test_scan_sensitive_with_findings(self):
        """Test scan-sensitive when sensitive data is found."""
        runner = CliRunner()
        from dbrecon.models import SensitiveData

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users"]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_scanner = Mock()
            mock_scanner.scan.return_value = [
                SensitiveData(
                    table="users",
                    field="password",
                    data_type="passwords",
                    count=15,
                    sample_values=["$2y$10$hash1", "$2y$10$hash2"]
                ),
                SensitiveData(
                    table="users",
                    field="email",
                    data_type="emails",
                    count=8,
                    sample_values=["admin@test.com"]
                ),
            ]
            mock_scanner_class.return_value = mock_scanner

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db'
            ])

            assert result.exit_code == 0

    def test_scan_sensitive_with_output_report(self):
        """Test scan-sensitive with output file and format."""
        runner = CliRunner()
        from dbrecon.models import SensitiveData

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users"]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_scanner = Mock()
            mock_scanner.scan.return_value = [
                SensitiveData(
                    table="users", field="ssn", data_type="ssn",
                    count=5, sample_values=["123-45-6789"]
                )
            ]
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'scan-sensitive',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db',
                '--output', '/tmp/scan_report.json',
                '--format', 'json'
            ])

            assert result.exit_code == 0


class TestCLIFullScanPaths:
    """Tests for full-scan command remaining paths."""

    def test_full_scan_many_tables(self):
        """Test full-scan with more than 10 tables shows ellipsis."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["table_{}".format(i) for i in range(15)]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'big_db'
            ])

            assert result.exit_code == 0

    def test_full_scan_table_structure_failure(self):
        """Test full-scan when table structure analysis fails."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users", "posts"]
            mock_manager.get_table_structure.side_effect = Exception("Error")
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db'
            ])

            assert result.exit_code == 0

    def test_full_scan_with_output(self):
        """Test full-scan with output file saves report."""
        runner = CliRunner()

        with patch('dbrecon.cli.DatabaseManager') as mock_manager_class, \
             patch('dbrecon.cli.FingerprintEngine') as mock_engine_class, \
             patch('dbrecon.cli.SensitiveDataScanner') as mock_scanner_class, \
             patch('dbrecon.cli.ReportGenerator') as mock_reporter_class:
            mock_manager = Mock()
            mock_manager.connect.return_value = True
            mock_manager.get_tables.return_value = ["users"]
            mock_manager.get_table_structure.return_value = [
                {"name": "id", "type": "int", "nullable": False}
            ]
            mock_manager_class.return_value = mock_manager

            mock_engine = Mock()
            mock_engine.analyze.return_value = []
            mock_engine_class.return_value = mock_engine

            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner

            mock_reporter = Mock()
            mock_reporter_class.return_value = mock_reporter

            result = runner.invoke(main, [
                'full-scan',
                '--host', 'localhost',
                '--user', 'admin',
                '--password', 'pass',
                '--database', 'test_db',
                '--output', '/tmp/full_scan_report.html',
                '--format', 'html'
            ])

            assert result.exit_code == 0


class TestCLIMainEntryPoint:
    """Tests for __main__ entry point coverage."""

    def test_main_entry_point_guard(self):
        """Test __name__ == '__main__' guard by running module via runpy."""
        import runpy
        import sys
        import io

        old_argv = sys.argv[:]
        old_stdout = sys.stdout
        try:
            sys.argv = ['dbrecon.cli', '--help']
            sys.stdout = io.StringIO()
            try:
                runpy.run_module('dbrecon.cli', run_name='__main__')
            except SystemExit:
                pass
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout
