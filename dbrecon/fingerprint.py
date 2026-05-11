import yaml
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from dbrecon.models import FingerprintResult, TableInfo
from dbrecon.database import DatabaseManager


class FingerprintEngine:
    """Application fingerprinting engine for identifying CMS and frameworks."""
    
    def __init__(self, signatures_path: Optional[str] = None):
        """Initialize fingerprint engine with signatures."""
        if signatures_path is None:
            signatures_path = Path(__file__).parent.parent / "configs" / "signatures.yaml"
        
        self.signatures = self._load_signatures(signatures_path)
    
    def _load_signatures(self, path: str) -> Dict[str, Any]:
        """Load fingerprint signatures from YAML file."""
        with open(path, 'r') as f:
            return yaml.safe_load(f)["applications"]
    
    def analyze(self, db_manager: DatabaseManager, database: str) -> List[FingerprintResult]:
        """Analyze database to identify applications."""
        tables = db_manager.get_tables(database)
        
        results = []
        for app_name, signature in self.signatures.items():
            confidence = self._calculate_confidence(tables, signature, db_manager, database, app_name)
            
            if confidence > 0.3:  # Minimum confidence threshold
                result = FingerprintResult(
                    application=signature["name"],
                    confidence=confidence,
                    version=self._detect_version(db_manager, database, app_name),
                    evidence=self._collect_evidence(tables, app_name),
                    installed_plugins=self._detect_plugins(tables, signature)
                )
                results.append(result)
        
        # Sort by confidence (descending)
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
    
    def _calculate_confidence(self, tables: List[str], signature: Dict[str, Any], 
                            db_manager: DatabaseManager, database: str, app_name: str) -> float:
        """Calculate confidence score for application match."""
        table_score = self._calculate_table_score(tables, app_name)
        field_score = self._calculate_field_score(
            self._get_table_info(tables, db_manager, database), signature
        )
        
        # Weight table matches more heavily than field matches
        confidence = (table_score * 0.7) + (field_score * 0.3)
        return min(confidence, 1.0)
    
    def _calculate_table_score(self, tables: List[str], app_name: str) -> float:
        """Calculate score based on table name matches."""
        if app_name not in self.signatures or "tables" not in self.signatures[app_name]:
            return 0.0
        
        signature = self.signatures[app_name]
        table_config = signature["tables"]
        
        # Handle different table configurations
        if isinstance(table_config, dict):
            required_tables = table_config.get("required", [])
            optional_tables = table_config.get("optional", [])
        else:
            # Handle legacy format or simple list
            required_tables = table_config if isinstance(table_config, list) else []
            optional_tables = []
        
        # Check required tables
        required_matches = sum(1 for table in required_tables if table in tables)
        required_score = required_matches / len(required_tables) if required_tables else 1.0
        
        # Check optional tables
        optional_matches = sum(1 for table in optional_tables if table in tables)
        optional_score = optional_matches / len(optional_tables) if optional_tables else 1.0
        
        # Weight required tables more heavily
        if required_tables:
            return (required_score * 0.8) + (optional_score * 0.2)
        else:
            return optional_score
    
    def _calculate_field_score(self, table_infos: List[TableInfo], signature: Dict[str, Any]) -> float:
        """Calculate score based on field structure matches."""
        if "fields" not in signature:
            return 0.0
        
        field_config = signature["fields"]
        total_score = 0.0
        matched_tables = 0
        
        for table_name, expected_fields in field_config.items():
            table_info = next((t for t in table_infos if t.name == table_name), None)
            if table_info:
                field_matches = sum(1 for field in expected_fields 
                                  if any(col["name"] == field for col in table_info.columns))
                table_score = field_matches / len(expected_fields)
                total_score += table_score
                matched_tables += 1
        
        return total_score / len(field_config) if field_config else 0.0
    
    def _get_table_info(self, tables: List[str], db_manager: DatabaseManager, 
                       database: str) -> List[TableInfo]:
        """Get detailed information for tables."""
        table_infos = []
        for table in tables:
            try:
                columns = db_manager.get_table_structure(database, table)
                table_info = TableInfo(name=table, columns=columns)
                table_infos.append(table_info)
            except Exception:
                # Skip tables that can't be analyzed
                continue
        
        return table_infos
    
    def _detect_version(self, db_manager: DatabaseManager, database: str, 
                       app_name: str) -> Optional[str]:
        """Detect application version."""
        if app_name not in self.signatures:
            return None
        
        signature = self.signatures[app_name]
        if "version_detection" not in signature:
            return None
        
        version_config = signature["version_detection"]
        table = version_config.get("table")
        field = version_config.get("field")
        key = version_config.get("key")
        
        if not all([table, field, key]):
            return None
        
        try:
            query = f"SELECT {field} FROM {database}.{table} WHERE {field} LIKE %s LIMIT 1"
            results = db_manager.execute_query(query, (f"%{key}%",))
            
            if results and len(results) > 0 and len(results[0]) > 0:
                # Extract version from result (implementation depends on specific app)
                return self._extract_version_from_result(results[0][0], app_name)
        except Exception:
            pass
        
        return None
    
    def _extract_version_from_result(self, result: str, app_name: str) -> Optional[str]:
        """Extract version number from query result."""
        if app_name == "wordpress":
            # WordPress stores version as numeric value, need mapping
            version_map = {
                "51788": "5.8.1",
                "51787": "5.8",
                "50928": "5.7.2",
                # Add more mappings as needed
            }
            return version_map.get(str(result))
        
        # For other applications, implement specific extraction logic
        version_pattern = r'(\d+\.\d+(?:\.\d+)*)'
        match = re.search(version_pattern, str(result))
        return match.group(1) if match else None
    
    def _collect_evidence(self, tables: List[str], app_name: str) -> List[Dict[str, str]]:
        """Collect evidence supporting the fingerprint."""
        evidence = []
        
        if app_name in self.signatures and "tables" in self.signatures[app_name]:
            signature = self.signatures[app_name]
            table_config = signature["tables"]
            
            # Handle different table configuration formats
            if isinstance(table_config, dict):
                required_tables = table_config.get("required", [])
                optional_tables = table_config.get("optional", [])
            else:
                required_tables = table_config if isinstance(table_config, list) else []
                optional_tables = []
            
            # Add table evidence
            for table in required_tables:
                if table in tables:
                    evidence.append({
                        "type": "table",
                        "name": table,
                        "match": "exact"
                    })
            
            for table in optional_tables:
                if table in tables:
                    evidence.append({
                        "type": "table", 
                        "name": table,
                        "match": "optional"
                    })
        
        return evidence
    
    def _detect_plugins(self, tables: List[str], signature: Dict[str, Any]) -> List[str]:
        """Detect installed plugins or modules."""
        plugins = []
        
        if "plugins" in signature:
            plugin_config = signature["plugins"]
            
            for plugin_name, plugin_info in plugin_config.items():
                plugin_tables = plugin_info.get("tables", [])
                
                for pattern in plugin_tables:
                    # Convert wildcard pattern to regex
                    regex_pattern = pattern.replace("*", ".*")
                    if any(re.match(regex_pattern, table) for table in tables):
                        plugins.append(plugin_name.replace("_", "-"))
                        break
        
        return plugins