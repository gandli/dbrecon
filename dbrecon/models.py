from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class DatabaseConnection(BaseModel):
    """Database connection configuration."""
    host: str = Field(..., description="Database host address")
    port: int = Field(3306, description="Database port")
    user: str = Field(..., description="Database username")
    password: str = Field(..., description="Database password")
    database: Optional[str] = Field(None, description="Target database name")
    ssl_enabled: bool = Field(False, description="Enable SSL connection")
    timeout: int = Field(30, description="Connection timeout in seconds")


class TableInfo(BaseModel):
    """Database table information."""
    name: str = Field(..., description="Table name")
    engine: Optional[str] = Field(None, description="Storage engine")
    row_count: Optional[int] = Field(None, description="Approximate row count")
    columns: List[Dict[str, Any]] = Field(default_factory=list, description="Column information")


class FingerprintResult(BaseModel):
    """Application fingerprinting result."""
    application: str = Field(..., description="Detected application name")
    confidence: float = Field(..., description="Confidence score (0.0-1.0)")
    version: Optional[str] = Field(None, description="Detected version")
    evidence: List[Dict[str, str]] = Field(default_factory=list, description="Supporting evidence")
    installed_plugins: List[str] = Field(default_factory=list, description="Detected plugins/modules")


class SensitiveData(BaseModel):
    """Sensitive data discovery result."""
    table: str = Field(..., description="Table name")
    field: str = Field(..., description="Field name")
    data_type: str = Field(..., description="Type of sensitive data")
    count: int = Field(..., description="Number of records found")
    sample_values: List[str] = Field(default_factory=list, description="Sample values (masked)")


class UrlInfo(BaseModel):
    """URL and host information."""
    url: str = Field(..., description="Discovered URL")
    source_table: str = Field(..., description="Source table")
    source_field: str = Field(..., description="Source field")
    url_type: str = Field(..., description="URL type (site, admin, api, etc.)")


class ScanResult(BaseModel):
    """Complete scan result."""
    scan_info: Dict[str, Any] = Field(..., description="Scan metadata")
    fingerprint_results: List[FingerprintResult] = Field(default_factory=list)
    sensitive_data: List[SensitiveData] = Field(default_factory=list)
    urls: List[UrlInfo] = Field(default_factory=list)
    database_structure: Dict[str, List[TableInfo]] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Scan configuration options."""
    deep_scan: bool = Field(False, description="Perform deep scan")
    scan_types: List[str] = Field(default_factory=list, description="Types of scans to perform")
    sensitive_data_types: List[str] = Field(default_factory=list, description="Types of sensitive data to scan for")
    output_format: str = Field("console", description="Output format (console, json, html)")
    output_file: Optional[str] = Field(None, description="Output file path")