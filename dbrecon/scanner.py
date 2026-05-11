import re
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path

from dbrecon.models import SensitiveData, TableInfo
from dbrecon.database import DatabaseManager


class SensitiveDataScanner:
    """Scans databases for sensitive information."""
    
    def __init__(self, patterns_path: Optional[str] = None):
        """Initialize scanner with sensitive data patterns."""
        if patterns_path is None:
            patterns_path = Path(__file__).parent.parent / "configs" / "signatures.yaml"
        
        self.patterns = self._load_patterns(patterns_path)
    
    def _load_patterns(self, path: str) -> Dict[str, Any]:
        """Load sensitive data patterns from YAML file."""
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get("sensitive_patterns", {})
    
    def scan(self, db_manager: DatabaseManager, database: str, 
             tables: List[TableInfo], data_types: Optional[List[str]] = None) -> List[SensitiveData]:
        """Scan database tables for sensitive data."""
        if data_types is None:
            data_types = list(self.patterns.keys())
        
        all_sensitive_data = []
        
        for table_info in tables:
            try:
                sensitive_data = self.scan_table(db_manager, database, table_info, data_types)
                all_sensitive_data.extend(sensitive_data)
            except Exception as e:
                # Log error and continue with other tables
                continue
        
        return all_sensitive_data
    
    def scan_table(self, db_manager: DatabaseManager, database: str, 
                   table_info: TableInfo, data_types: Optional[List[str]] = None) -> List[SensitiveData]:
        """Scan a specific table for sensitive data."""
        if data_types is None:
            data_types = list(self.patterns.keys())
        
        all_detected = []
        
        # First pass: detect by field names
        field_based = self._detect_by_field_name(table_info)
        all_detected.extend(field_based)
        
        # Second pass: detect by data patterns (sample data)
        pattern_based = self._detect_by_data_patterns(
            db_manager, database, table_info, data_types
        )
        all_detected.extend(pattern_based)
        
        return self._deduplicate_results(all_detected)
    
    def _detect_by_field_name(self, table_info: TableInfo) -> List[SensitiveData]:
        """Detect sensitive fields by their names."""
        detected = []
        
        for data_type, patterns in self.patterns.items():
            field_patterns = patterns.get("field_patterns", [])
            
            for column in table_info.columns:
                column_name = column["name"].lower()
                
                # Check if any pattern matches the field name
                for pattern in field_patterns:
                    if self._matches_pattern(column_name, pattern):
                        detected.append(SensitiveData(
                            table=table_info.name,
                            field=column["name"],
                            data_type=data_type,
                            count=0,  # Will be updated when sampling data
                            sample_values=[]
                        ))
                        break  # Found a match, no need to check other patterns
        
        return detected
    
    def _detect_by_data_patterns(self, db_manager: DatabaseManager, database: str,
                                table_info: TableInfo, data_types: List[str]) -> List[SensitiveData]:
        """Detect sensitive data by analyzing actual data content."""
        detected = []
        
        for data_type in data_types:
            if data_type not in self.patterns:
                continue
            
            patterns = self.patterns[data_type].get("data_patterns", [])
            
            for column in table_info.columns:
                column_name = column["name"]
                
                # Sample data from this column
                samples = self._sample_table_data(
                    db_manager, database, table_info.name, column_name
                )
                
                if not samples:
                    continue
                
                # Count matches for each pattern
                total_matches = 0
                sample_matches = []
                
                for row in samples:
                    if len(row) > 0:
                        value = str(row[0])
                        
                        for pattern in patterns:
                            if re.search(pattern, value, re.IGNORECASE):
                                total_matches += 1
                                if len(sample_matches) < 5:  # Limit samples
                                    sample_matches.append(value)
                                break  # Count each value only once per column
                
                # If we found matches, add to results
                if total_matches > 0:
                    detected.append(SensitiveData(
                        table=table_info.name,
                        field=column_name,
                        data_type=data_type,
                        count=total_matches,
                        sample_values=sample_matches[:5]  # Limit sample size
                    ))
        
        return detected
    
    def _sample_table_data(self, db_manager: DatabaseManager, database: str, 
                          table_name: str, column_name: str, limit: int = 100) -> List[tuple]:
        """Sample data from a specific table column."""
        try:
            query = f"SELECT {column_name} FROM {database}.{table_name} LIMIT {limit}"
            return db_manager.execute_query(query)
        except Exception:
            return []
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Check if text matches the given pattern (supports wildcards)."""
        if "*" in pattern:
            # Convert wildcard pattern to regex
            regex_pattern = pattern.replace("*", ".*")
            return bool(re.match(regex_pattern, text, re.IGNORECASE))
        else:
            return pattern.lower() in text.lower()
    
    def _deduplicate_results(self, results: List[SensitiveData]) -> List[SensitiveData]:
        """Remove duplicate detections and merge similar ones."""
        # Group by table, field, and data type
        grouped = {}
        
        for result in results:
            key = (result.table, result.field, result.data_type)
            if key not in grouped:
                grouped[key] = result
            else:
                # Merge counts and combine samples
                existing = grouped[key]
                existing.count += result.count
                existing.sample_values.extend(result.sample_values)
                # Keep only unique samples
                existing.sample_values = list(set(existing.sample_values))[:5]
        
        return list(grouped.values())