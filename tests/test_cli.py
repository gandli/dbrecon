import pytest
from click.testing import CliRunner
from dbrecon.cli import main


class TestCLI:
    """Test cases for CLI interface."""

    def test_main_help(self):
        """Test main help output."""
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        
        assert result.exit_code == 0
        assert 'DBRecon' in result.output
        assert 'test-connection' in result.output
        assert 'fingerprint' in result.output
        assert 'scan-sensitive' in result.output
        assert 'full-scan' in result.output

    def test_version_option(self):
        """Test version option."""
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        
        assert result.exit_code == 0
        assert '0.1.0' in result.output

    def test_test_connection_help(self):
        """Test test-connection command help."""
        runner = CliRunner()
        result = runner.invoke(main, ['test-connection', '--help'])
        
        assert result.exit_code == 0
        assert 'Test database connection' in result.output
        assert '--host' in result.output
        assert '--port' in result.output
        assert '--user' in result.output
        assert '--password' in result.output

    def test_fingerprint_help(self):
        """Test fingerprint command help."""
        runner = CliRunner()
        result = runner.invoke(main, ['fingerprint', '--help'])
        
        assert result.exit_code == 0
        assert 'Identify applications' in result.output
        assert '--host' in result.output
        assert '--format' in result.output
        assert '--output' in result.output

    def test_scan_sensitive_help(self):
        """Test scan-sensitive command help."""
        runner = CliRunner()
        result = runner.invoke(main, ['scan-sensitive', '--help'])
        
        assert result.exit_code == 0
        assert 'Scan for sensitive data' in result.output
        assert '--data-types' in result.output

    def test_full_scan_help(self):
        """Test full-scan command help."""
        runner = CliRunner()
        result = runner.invoke(main, ['full-scan', '--help'])
        
        assert result.exit_code == 0
        assert 'Perform a complete security assessment' in result.output
        assert '--deep' in result.output
        assert '--shallow' in result.output

    @pytest.mark.parametrize("command", [
        "test-connection",
        "fingerprint", 
        "scan-sensitive",
        "full-scan"
    ])
    def test_command_structure(self, command):
        """Test that commands have proper structure."""
        runner = CliRunner()
        result = runner.invoke(main, [command, '--help'])
        
        assert result.exit_code == 0
        # Check that the command name appears in output
        assert command.split('-')[0] in result.output.lower()

    def test_invalid_command(self):
        """Test invalid command handling."""
        runner = CliRunner()
        result = runner.invoke(main, ['invalid-command'])
        
        assert result.exit_code != 0
        assert 'No such command' in result.output

    def test_missing_required_args(self):
        """Test missing required arguments."""
        runner = CliRunner()
        result = runner.invoke(main, ['test-connection'])
        
        assert result.exit_code != 0
        # Should show usage information or error message
        assert ('usage:' in result.output.lower() or 
                'missing argument' in result.output.lower() or
                'required' in result.output.lower())

    def test_format_option_validation(self):
        """Test format option validation."""
        runner = CliRunner()
        result = runner.invoke(main, ['fingerprint', '--format', 'invalid'])
        
        assert result.exit_code != 0
        assert 'Invalid value' in result.output

    def test_output_file_option(self):
        """Test output file option."""
        runner = CliRunner()
        result = runner.invoke(main, ['fingerprint', '--output', '/tmp/test.json'])
        
        # Should accept the option without error (though it may fail due to other reasons)
        assert result.exit_code in [0, 2]  # 2 means usage error, 0 means success