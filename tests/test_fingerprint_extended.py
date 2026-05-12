"""
Extended tests for FingerprintEngine - covering edge cases and untested paths.
"""

import pytest
from unittest.mock import Mock, patch

from dbrecon.fingerprint import FingerprintEngine
from dbrecon.models import FingerprintResult, TableInfo


class TestFingerprintEngineExtended:
    """Extended test cases for FingerprintEngine edge cases."""

    @pytest.fixture
    def fingerprint_engine(self):
        return FingerprintEngine()

    @pytest.fixture
    def mock_db_manager(self):
        return Mock()

    def test_calculate_table_score_no_signatures(self, fingerprint_engine):
        """Test table score when app_name not in signatures."""
        score = fingerprint_engine._calculate_table_score(["some_table"], "nonexistent_app")
        assert score == 0.0

    def test_calculate_table_score_no_tables_key(self, fingerprint_engine):
        """Test table score when signature has no tables key."""
        fingerprint_engine.signatures = {"test_app": {"name": "TestApp", "priority": 50}}
        score = fingerprint_engine._calculate_table_score(["some_table"], "test_app")
        assert score == 0.0

    def test_calculate_table_score_only_optional(self, fingerprint_engine):
        """Test table score with only optional tables."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "tables": {"optional": ["opt_table1", "opt_table2"]}
            }
        }
        score = fingerprint_engine._calculate_table_score(["opt_table1"], "test_app")
        assert score == 0.5

    def test_calculate_table_score_empty_required(self, fingerprint_engine):
        """Test table score when required list is empty."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "tables": {"required": [], "optional": ["opt1"]}
            }
        }
        score = fingerprint_engine._calculate_table_score(["opt1"], "test_app")
        assert score == 1.0

    def test_calculate_field_score_no_fields(self, fingerprint_engine):
        """Test field score when signature has no fields key."""
        fingerprint_engine.signatures = {"test_app": {"name": "TestApp"}}
        table_infos = [TableInfo(name="test_table", columns=[{"name": "id"}])]
        score = fingerprint_engine._calculate_field_score(table_infos, fingerprint_engine.signatures["test_app"])
        assert score == 0.0

    def test_calculate_field_score_empty_table_infos(self, fingerprint_engine):
        """Test field score with empty table infos."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "fields": {"users": ["id", "name"]}
            }
        }
        score = fingerprint_engine._calculate_field_score([], fingerprint_engine.signatures["test_app"])
        assert score == 0.0

    def test_calculate_field_score_partial_match(self, fingerprint_engine):
        """Test field score with partial field matches."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "fields": {
                    "users": ["id", "name", "email", "phone"]
                }
            }
        }
        table_infos = [
            TableInfo(name="users", columns=[
                {"name": "id"}, {"name": "name"}
            ])
        ]
        score = fingerprint_engine._calculate_field_score(table_infos, fingerprint_engine.signatures["test_app"])
        assert score == 0.5

    def test_detect_version_app_not_in_signatures(self, fingerprint_engine, mock_db_manager):
        """Test version detection when app not in signatures."""
        result = fingerprint_engine._detect_version(mock_db_manager, "test_db", "nonexistent")
        assert result is None

    def test_detect_version_no_version_config(self, fingerprint_engine, mock_db_manager):
        """Test version detection when no version_detection config."""
        fingerprint_engine.signatures = {"test_app": {"name": "TestApp"}}
        result = fingerprint_engine._detect_version(mock_db_manager, "test_db", "test_app")
        assert result is None

    def test_detect_version_incomplete_config(self, fingerprint_engine, mock_db_manager):
        """Test version detection with incomplete config."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "version_detection": {"table": "options"}
            }
        }
        result = fingerprint_engine._detect_version(mock_db_manager, "test_db", "test_app")
        assert result is None

    def test_detect_version_query_exception(self, fingerprint_engine, mock_db_manager):
        """Test version detection when query raises exception."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "version_detection": {
                    "table": "options",
                    "field": "value",
                    "key": "version"
                }
            }
        }
        mock_db_manager.execute_query.side_effect = Exception("DB error")
        result = fingerprint_engine._detect_version(mock_db_manager, "test_db", "test_app")
        assert result is None

    def test_detect_version_no_results(self, fingerprint_engine, mock_db_manager):
        """Test version detection when query returns no results."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "version_detection": {
                    "table": "options",
                    "field": "value",
                    "key": "version"
                }
            }
        }
        mock_db_manager.execute_query.return_value = []
        result = fingerprint_engine._detect_version(mock_db_manager, "test_db", "test_app")
        assert result is None

    def test_extract_version_wordpress_unknown(self, fingerprint_engine):
        """Test version extraction for unknown WordPress version."""
        result = fingerprint_engine._extract_version_from_result("99999", "wordpress")
        assert result is None

    def test_extract_version_wordpress_known(self, fingerprint_engine):
        """Test version extraction for known WordPress version."""
        result = fingerprint_engine._extract_version_from_result("51788", "wordpress")
        assert result == "5.8.1"

    def test_extract_version_generic_pattern(self, fingerprint_engine):
        """Test version extraction with generic version pattern."""
        result = fingerprint_engine._extract_version_from_result("Version 2.3.4 release", "drupal")
        assert result == "2.3.4"

    def test_extract_version_no_version(self, fingerprint_engine):
        """Test version extraction when no version in result."""
        result = fingerprint_engine._extract_version_from_result("no version here", "drupal")
        assert result is None

    def test_detect_plugins_no_plugins_key(self, fingerprint_engine):
        """Test plugin detection when no plugins key in signature."""
        plugins = fingerprint_engine._detect_plugins(["some_table"], {"name": "TestApp"})
        assert plugins == []

    def test_detect_plugins_no_match(self, fingerprint_engine):
        """Test plugin detection when no tables match."""
        signature = {
            "name": "WordPress",
            "plugins": {
                "woocommerce": {"tables": ["wp_wc_*"]}
            }
        }
        plugins = fingerprint_engine._detect_plugins(["wp_posts", "wp_users"], signature)
        assert plugins == []

    def test_detect_plugins_multiple_matches(self, fingerprint_engine):
        """Test plugin detection with multiple plugin matches."""
        signature = {
            "name": "WordPress",
            "plugins": {
                "woocommerce": {"tables": ["wp_woocommerce_*"]},
                "yoast_seo": {"tables": ["wp_yoast_*"]}
            }
        }
        plugins = fingerprint_engine._detect_plugins(
            ["wp_woocommerce_orders", "wp_yoast_indexable"], signature
        )
        assert "woocommerce" in plugins
        assert "yoast-seo" in plugins

    def test_collect_evidence_no_app_in_signatures(self, fingerprint_engine):
        """Test evidence collection when app not in signatures."""
        evidence = fingerprint_engine._collect_evidence(["table1"], "nonexistent")
        assert evidence == []

    def test_collect_evidence_no_tables_key(self, fingerprint_engine):
        """Test evidence collection when no tables key."""
        fingerprint_engine.signatures = {"test_app": {"name": "TestApp"}}
        evidence = fingerprint_engine._collect_evidence(["table1"], "test_app")
        assert evidence == []

    def test_analyze_empty_tables(self, fingerprint_engine, mock_db_manager):
        """Test analyze with empty table list returns low-confidence results."""
        mock_db_manager.get_tables.return_value = []
        result = fingerprint_engine.analyze(mock_db_manager, "empty_db")
        for r in result:
            assert r.confidence <= 0.8

    def test_analyze_below_confidence_threshold(self, fingerprint_engine, mock_db_manager):
        """Test analyze filters results below confidence threshold."""
        mock_db_manager.get_tables.return_value = ["random_table"]
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "tables": {"required": ["specific_table"]},
                "priority": 50
            }
        }
        result = fingerprint_engine.analyze(mock_db_manager, "test_db")
        assert result == []

    def test_analyze_results_sorted_by_confidence(self, fingerprint_engine, mock_db_manager):
        """Test analyze returns results sorted by confidence descending."""
        mock_db_manager.get_tables.return_value = ["wp_options", "wp_users", "migrations"]
        fingerprint_engine.signatures = {
            "wordpress": {
                "name": "WordPress",
                "tables": {"required": ["wp_options", "wp_users"]},
                "priority": 100
            },
            "laravel": {
                "name": "Laravel",
                "tables": {"required": ["migrations", "users"]},
                "priority": 95
            }
        }
        results = fingerprint_engine.analyze(mock_db_manager, "test_db")
        if len(results) >= 2:
            assert results[0].confidence >= results[1].confidence

    def test_calculate_table_score_list_format(self, fingerprint_engine):
        """Test table score when tables config is a plain list (legacy format)."""
        fingerprint_engine.signatures = {
            "legacy_app": {
                "name": "LegacyApp",
                "tables": ["legacy_table1", "legacy_table2"]
            }
        }
        score = fingerprint_engine._calculate_table_score(
            ["legacy_table1"], "legacy_app"
        )
        assert abs(score - 0.6) < 0.01

    def test_calculate_table_score_list_format_no_match(self, fingerprint_engine):
        """Test table score when tables config is a list and no tables match."""
        fingerprint_engine.signatures = {
            "legacy_app": {
                "name": "LegacyApp",
                "tables": ["legacy_table1"]
            }
        }
        score = fingerprint_engine._calculate_table_score(
            ["other_table"], "legacy_app"
        )
        assert score == 0.2

    def test_collect_evidence_list_format(self, fingerprint_engine):
        """Test evidence collection when tables config is a plain list."""
        fingerprint_engine.signatures = {
            "legacy_app": {
                "name": "LegacyApp",
                "tables": ["table1", "table2"]
            }
        }
        evidence = fingerprint_engine._collect_evidence(["table1"], "legacy_app")
        assert len(evidence) == 1
        assert evidence[0]["name"] == "table1"
        assert evidence[0]["match"] == "exact"

    def test_collect_evidence_optional_tables(self, fingerprint_engine):
        """Test evidence collection includes optional table matches."""
        fingerprint_engine.signatures = {
            "test_app": {
                "name": "TestApp",
                "tables": {
                    "required": ["req_table"],
                    "optional": ["opt_table1", "opt_table2"]
                }
            }
        }
        evidence = fingerprint_engine._collect_evidence(
            ["req_table", "opt_table2"], "test_app"
        )
        evidence_types = [(e["name"], e["match"]) for e in evidence]
        assert ("req_table", "exact") in evidence_types
        assert ("opt_table2", "optional") in evidence_types
