import pytest
from unittest.mock import Mock, patch
from typing import List, Dict, Any

from dbrecon.fingerprint import FingerprintEngine
from dbrecon.models import FingerprintResult, TableInfo


class TestFingerprintEngine:
    """Test cases for FingerprintEngine class."""

    @pytest.fixture
    def fingerprint_engine(self):
        """Fixture providing a FingerprintEngine instance."""
        return FingerprintEngine()

    @pytest.fixture
    def mock_db_manager(self):
        """Fixture providing a mock database manager."""
        mock_manager = Mock()
        return mock_manager

    @pytest.fixture
    def sample_wordpress_tables(self):
        """Fixture providing sample WordPress table structure."""
        return [
            TableInfo(
                name="wp_options",
                columns=[
                    {"name": "option_id", "type": "bigint(20)", "nullable": False},
                    {"name": "option_name", "type": "varchar(191)", "nullable": False},
                    {"name": "option_value", "type": "longtext", "nullable": False},
                    {"name": "autoload", "type": "varchar(20)", "nullable": False}
                ]
            ),
            TableInfo(
                name="wp_users",
                columns=[
                    {"name": "ID", "type": "bigint(20)", "nullable": False},
                    {"name": "user_login", "type": "varchar(60)", "nullable": False},
                    {"name": "user_pass", "type": "varchar(255)", "nullable": False},
                    {"name": "user_email", "type": "varchar(100)", "nullable": True}
                ]
            ),
            TableInfo(
                name="wp_posts",
                columns=[
                    {"name": "ID", "type": "bigint(20)", "nullable": False},
                    {"name": "post_title", "type": "text", "nullable": True},
                    {"name": "post_content", "type": "longtext", "nullable": True}
                ]
            )
        ]

    @pytest.fixture
    def sample_laravel_tables(self):
        """Fixture providing sample Laravel table structure."""
        return [
            TableInfo(
                name="migrations",
                columns=[
                    {"name": "id", "type": "int(10)", "nullable": False},
                    {"name": "migration", "type": "varchar(255)", "nullable": False},
                    {"name": "batch", "type": "int(11)", "nullable": False}
                ]
            ),
            TableInfo(
                name="users",
                columns=[
                    {"name": "id", "type": "int(10)", "nullable": False},
                    {"name": "name", "type": "varchar(255)", "nullable": False},
                    {"name": "email", "type": "varchar(255)", "nullable": False},
                    {"name": "password", "type": "varchar(255)", "nullable": False}
                ]
            )
        ]

    def test_fingerprint_engine_initialization(self, fingerprint_engine):
        """Test FingerprintEngine initialization."""
        assert fingerprint_engine.signatures is not None
        assert isinstance(fingerprint_engine.signatures, dict)
        assert "wordpress" in fingerprint_engine.signatures
        assert "laravel" in fingerprint_engine.signatures

    def test_load_signatures(self, fingerprint_engine):
        """Test loading fingerprint signatures from config."""
        signatures = fingerprint_engine.signatures
        
        # Test WordPress signature structure
        wp_sig = signatures.get("wordpress")
        assert wp_sig is not None
        assert "name" in wp_sig
        assert "priority" in wp_sig
        assert "tables" in wp_sig
        assert "required" in wp_sig["tables"]
        
        # Test Laravel signature structure
        laravel_sig = signatures.get("laravel")
        assert laravel_sig is not None
        assert "name" in laravel_sig
        assert "priority" in laravel_sig

    def test_calculate_table_score_exact_match(self, fingerprint_engine):
        """Test table scoring with exact matches."""
        tables = ["wp_options", "wp_users", "wp_posts"]
        
        score = fingerprint_engine._calculate_table_score(tables, "wordpress")
        
        assert score >= 0.8  # High score for exact matches
        assert score <= 1.0

    def test_calculate_table_score_partial_match(self, fingerprint_engine):
        """Test table scoring with partial matches."""
        tables = ["wp_options", "wp_users", "custom_table", "another_table"]
        
        score = fingerprint_engine._calculate_table_score(tables, "wordpress")
        
        assert 0 < score < 0.8  # Lower score for partial matches

    def test_calculate_table_score_no_match(self, fingerprint_engine):
        """Test table scoring with no matches."""
        tables = ["custom_table1", "custom_table2", "custom_table3"]
        
        score = fingerprint_engine._calculate_table_score(tables, "wordpress")
        
        assert score == 0.0  # No score for no matches

    def test_calculate_field_score_exact_match(self, fingerprint_engine, sample_wordpress_tables):
        """Test field scoring with exact matches."""
        score = fingerprint_engine._calculate_field_score(sample_wordpress_tables, fingerprint_engine.signatures["wordpress"])
        
        assert score > 0.7  # High score for matching field structure

    def test_calculate_field_score_no_match(self, fingerprint_engine):
        """Test field scoring with no matching fields."""
        tables = [
            TableInfo(
                name="custom_table",
                columns=[
                    {"name": "id", "type": "int"},
                    {"name": "data", "type": "text"}
                ]
            )
        ]
        
        score = fingerprint_engine._calculate_field_score(tables, fingerprint_engine.signatures["wordpress"])
        
        assert score < 0.3  # Low score for no matching fields

    @patch.object(FingerprintEngine, '_detect_version')
    def test_detect_wordpress(self, mock_detect_version, fingerprint_engine, mock_db_manager, sample_wordpress_tables):
        """Test WordPress detection."""
        mock_detect_version.return_value = "5.8.1"
        mock_db_manager.get_tables.return_value = [table.name for table in sample_wordpress_tables]
        mock_db_manager.get_table_structure.side_effect = lambda db, table: next(
            (t.columns for t in sample_wordpress_tables if t.name == table), []
        )

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        wp_results = [r for r in results if r.application == "WordPress"]
        assert len(wp_results) == 1
        assert wp_results[0].confidence > 0.8
        assert wp_results[0].version == "5.8.1"
        assert len(wp_results[0].evidence) > 0

    @patch.object(FingerprintEngine, '_detect_version')
    def test_detect_laravel(self, mock_detect_version, fingerprint_engine, mock_db_manager, sample_laravel_tables):
        """Test Laravel detection."""
        mock_detect_version.return_value = "8.0.0"
        mock_db_manager.get_tables.return_value = [table.name for table in sample_laravel_tables]
        mock_db_manager.get_table_structure.side_effect = lambda db, table: next(
            (t.columns for t in sample_laravel_tables if t.name == table), []
        )

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        laravel_results = [r for r in results if r.application == "Laravel"]
        assert len(laravel_results) == 1
        assert laravel_results[0].confidence > 0.6
        assert laravel_results[0].version == "8.0.0"

    def test_detect_no_match(self, fingerprint_engine, mock_db_manager):
        """Test detection with no matching applications."""
        mock_db_manager.get_tables.return_value = ["random_table1", "random_table2"]
        mock_db_manager.get_table_structure.return_value = []

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        assert len(results) > 0  # Should detect some applications
        assert all(0 < r.confidence < 1.0 for r in results)

    @patch.object(FingerprintEngine, '_detect_version')
    def test_confidence_ranking(self, mock_detect_version, fingerprint_engine, mock_db_manager):
        """Test that results are ranked by confidence score."""
        mock_detect_version.return_value = None
        
        # Mock tables that partially match multiple applications
        mock_db_manager.get_tables.return_value = ["users", "posts", "options"]
        mock_db_manager.get_table_structure.return_value = [
            {"name": "id", "type": "int"},
            {"name": "name", "type": "varchar(255)"}
        ]

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        # Results should be sorted by confidence (descending)
        confidences = [r.confidence for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_version_detection_wordpress(self, fingerprint_engine, mock_db_manager):
        """Test WordPress version detection."""
        mock_db_manager.execute_query.return_value = [["51788"]]
        
        version = fingerprint_engine._detect_version(mock_db_manager, "test_db", "wordpress")
        
        assert version == "5.8.1"
        mock_db_manager.execute_query.assert_called_once()

    def test_version_detection_no_version(self, fingerprint_engine, mock_db_manager):
        """Test version detection when no version info is found."""
        mock_db_manager.execute_query.return_value = []
        
        version = fingerprint_engine._detect_version(mock_db_manager, "test_db", "wordpress")
        
        assert version is None

    def test_plugin_detection(self, fingerprint_engine, mock_db_manager):
        """Test plugin/module detection for detected applications."""
        # Mock WordPress tables with plugins
        tables = ["wp_options", "wp_users", "wp_posts", "wp_woocommerce_coupons", "wp_yoast_seo_links"]
        mock_db_manager.get_tables.return_value = tables
        
        # Mock table structures
        def mock_structure(db, table):
            if "wp_options" in table:
                return [{"name": "option_name", "type": "varchar(191)"}]
            return []
        
        mock_db_manager.get_table_structure.side_effect = mock_structure

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        wp_results = [r for r in results if r.application == "WordPress"]
        if wp_results:
            # Check if plugins are detected
            plugins = wp_results[0].installed_plugins
            assert "woocommerce" in plugins or "yoast-seo" in plugins

    @pytest.mark.parametrize("app_name,expected_priority", [
        ("wordpress", 100),
        ("laravel", 95),
        ("drupal", 90),
        ("unknown", 0)
    ])
    def test_application_priority(self, fingerprint_engine, app_name, expected_priority):
        """Test application priority values."""
        if app_name == "unknown":
            assert app_name not in fingerprint_engine.signatures
        else:
            assert fingerprint_engine.signatures[app_name]["priority"] == expected_priority

    def test_evidence_collection(self, fingerprint_engine, mock_db_manager, sample_wordpress_tables):
        """Test evidence collection for fingerprinting results."""
        mock_db_manager.get_tables.return_value = [table.name for table in sample_wordpress_tables]
        mock_db_manager.get_table_structure.side_effect = lambda db, table: next(
            (t.columns for t in sample_wordpress_tables if t.name == table), []
        )

        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        
        wp_results = [r for r in results if r.application == "WordPress"]
        if wp_results:
            evidence = wp_results[0].evidence
            assert len(evidence) > 0
            
            # Check for table evidence (at least 3 core tables should match)
            table_evidence = [e for e in evidence if e["type"] == "table"]
            assert len(table_evidence) >= 3  # wp_options, wp_users, wp_posts
            
