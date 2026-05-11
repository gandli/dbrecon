import json
import csv
from typing import Optional, Dict, Any
from datetime import datetime

from dbrecon.models import ScanResult


class ReportGenerator:
    """Generates security assessment reports in various formats."""
    
    def generate(self, scan_result: ScanResult, output_format: str = "json", 
                output_file: Optional[str] = None) -> Optional[str]:
        """Generate report in specified format.
        
        Args:
            scan_result: Complete scan results to report on
            output_format: Format of the report (json, csv, html, markdown, console)
            output_file: Path to save report file (None for string return)
            
        Returns:
            Formatted report string if output_file is None, otherwise None
        """
        if output_format == "json":
            content = self._generate_json_report(scan_result)
        elif output_format == "csv":
            content = self._generate_csv_report(scan_result)
        elif output_format == "html":
            content = self._generate_html_report(scan_result)
        elif output_format == "markdown":
            content = self._generate_markdown_report(scan_result)
        elif output_format == "console":
            content = self._generate_console_report(scan_result)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            return None
        else:
            return content
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON formatted report."""
        # Convert datetime objects to strings for JSON serialization
        # Convert scan_info to JSON serializable format
        scan_info = scan_result.scan_info.copy()
        if isinstance(scan_info.get("scan_time"), datetime):
            scan_info["scan_time"] = scan_info["scan_time"].isoformat()
        
        report_data = {"scan_info": scan_info,
            "fingerprint_results": [
                {
                    "application": r.application,
                    "confidence": r.confidence,
                    "version": r.version,
                    "evidence": r.evidence,
                    "installed_plugins": r.installed_plugins
                }
                for r in scan_result.fingerprint_results
            ],
            "sensitive_data": [
                {
                    "table": r.table,
                    "field": r.field,
                    "data_type": r.data_type,
                    "count": r.count,
                    "sample_values": r.sample_values
                }
                for r in scan_result.sensitive_data
            ],
            "urls": [
                {
                    "url": u.url,
                    "source_table": u.source_table,
                    "source_field": u.source_field,
                    "url_type": u.url_type
                }
                for u in scan_result.urls
            ],
            "database_structure": {
                db: [
                    {
                        "name": t.name,
                        "engine": t.engine,
                        "row_count": t.row_count,
                        "columns": t.columns
                    }
                    for t in tables
                ]
                for db, tables in scan_result.database_structure.items()
            },
            "recommendations": scan_result.recommendations
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_csv_report(self, scan_result: ScanResult) -> str:
        """Generate CSV formatted report."""
        output_lines = []
        
        # Header
        output_lines.append("Category,Table,Field,Data Type,Count,Version,URL,Recommendation")
        
        # Sensitive data rows
        for sensitive_data in scan_result.sensitive_data:
            row = (
                "Sensitive Data",
                sensitive_data.table,
                sensitive_data.field,
                sensitive_data.data_type,
                str(sensitive_data.count),
                "",
                "",
                ""
            )
            output_lines.append(",".join(row))
        
        # URL rows
        for url_info in scan_result.urls:
            row = (
                "URL Discovery",
                url_info.source_table,
                url_info.source_field,
                "",
                "",
                "",
                url_info.url,
                ""
            )
            output_lines.append(",".join(row))
        
        # Application fingerprint rows
        for fingerprint in scan_result.fingerprint_results:
            row = (
                "Application Fingerprint",
                "",
                "",
                "",
                "",
                fingerprint.version or "",
                "",
                f"{fingerprint.application} ({fingerprint.confidence:.1%})"
            )
            output_lines.append(",".join(row))
        
        # Recommendations
        for recommendation in scan_result.recommendations:
            row = (
                "Recommendation",
                "",
                "",
                "",
                "",
                "",
                "",
                recommendation
            )
            output_lines.append(",".join(row))
        
        return "\n".join(output_lines)
    
    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate HTML formatted report."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DBRecon Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 30px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .high-risk {{ color: #d32f2f; font-weight: bold; }}
        .medium-risk {{ color: #ff9800; }}
        .low-risk {{ color: #388e3c; }}
        .plugin {{ background-color: #e3f2fd; padding: 5px; border-radius: 3px; display: inline-block; margin: 2px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 DBRecon Security Assessment Report</h1>
        <p><strong>Target:</strong> {scan_result.scan_info.get('target', 'Unknown')}</p>
        <p><strong>Scan Time:</strong> {scan_result.scan_info.get('scan_time', 'Unknown')}</p>
        <p><strong>Duration:</strong> {scan_result.scan_info.get('duration', 0)} seconds</p>
    </div>

    <div class="section">
        <h2>📊 Application Fingerprint Results</h2>
        <table>
            <tr>
                <th>Application</th>
                <th>Confidence</th>
                <th>Version</th>
                <th>Installed Plugins</th>
            </tr>
"""
        
        for result in scan_result.fingerprint_results:
            plugins_html = " ".join([f'<span class="plugin">{plugin}</span>' 
                                   for plugin in result.installed_plugins])
            
            html_content += f"""
            <tr>
                <td>{result.application}</td>
                <td>{result.confidence:.1%}</td>
                <td>{result.version or 'Unknown'}</td>
                <td>{plugins_html}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>

    <div class="section">
        <h2>⚠️ Sensitive Data Found</h2>
        <table>
            <tr>
                <th>Table</th>
                <th>Field</th>
                <th>Type</th>
                <th>Count</th>
                <th>Sample Values</th>
            </tr>
"""
        
        for data in scan_result.sensitive_data:
            sample_values = ", ".join(data.sample_values[:3]) + ("..." if len(data.sample_values) > 3 else "")
            
            html_content += f"""
            <tr class="high-risk">
                <td>{data.table}</td>
                <td>{data.field}</td>
                <td>{data.data_type}</td>
                <td>{data.count}</td>
                <td><code>{sample_values}</code></td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>

    <div class="section">
        <h2>🌐 URLs and Hosts Discovered</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Source Table</th>
                <th>Source Field</th>
                <th>Type</th>
            </tr>
"""
        
        for url in scan_result.urls:
            html_content += f"""
            <tr>
                <td><a href="{url.url}" target="_blank">{url.url}</a></td>
                <td>{url.source_table}</td>
                <td>{url.source_field}</td>
                <td>{url.url_type}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>

    <div class="section">
        <h2>🛠️ Recommendations</h2>
        <ul>
"""
        
        for recommendation in scan_result.recommendations:
            html_content += f"<li>{recommendation}</li>\n"
        
        html_content += """
        </ul>
    </div>

    <div class="footer" style="margin-top: 50px; text-align: center; color: #666;">
        <p>Generated by DBRecon v0.1.0 - Database Reconnaissance Tool</p>
        <p>This report was generated for authorized security assessment purposes only.</p>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def _generate_markdown_report(self, scan_result: ScanResult) -> str:
        """Generate Markdown formatted report."""
        md_content = f"""# DBRecon Security Assessment Report

## Scan Information
- **Target:** {scan_result.scan_info.get('target', 'Unknown')}
- **Scan Time:** {scan_result.scan_info.get('scan_time', 'Unknown')}
- **Duration:** {scan_result.scan_info.get('duration', 0)} seconds

## Application Fingerprint Results

"""
        
        for result in scan_result.fingerprint_results:
            plugins_text = ", ".join(result.installed_plugins) if result.installed_plugins else "None"
            md_content += f"""### {result.application}
- **Confidence:** {result.confidence:.1%}
- **Version:** {result.version or 'Unknown'}
- **Plugins:** {plugins_text}

"""
        
        md_content += """## Sensitive Data Found

| Table | Field | Type | Count | Sample Values |
|-------|-------|------|-------|---------------|
"""
        
        for data in scan_result.sensitive_data:
            sample_values = ", ".join(data.sample_values[:3]) + ("..." if len(data.sample_values) > 3 else "")
            md_content += f"| {data.table} | {data.field} | {data.data_type} | {data.count} | `{sample_values}` |\n"
        
        md_content += """
## URLs and Hosts Discovered

| URL | Source Table | Source Field | Type |
|-----|--------------|--------------|------|
"""
        
        for url in scan_result.urls:
            md_content += f"| {url.url} | {url.source_table} | {url.source_field} | {url.url_type} |\n"
        
        md_content += """
## Recommendations

"""
        
        for i, recommendation in enumerate(scan_result.recommendations, 1):
            md_content += f"{i}. {recommendation}\n"
        
        md_content += f"""
---
*Report generated by DBRecon v0.1.0*
"""
        
        return md_content
    
    def _generate_console_report(self, scan_result: ScanResult) -> str:
        """Generate console-friendly formatted report."""
        output = []
        
        # Header
        output.append("=" * 70)
        output.append("DBRecon Security Assessment Report")
        output.append("=" * 70)
        output.append(f"Target: {scan_result.scan_info.get('target', 'Unknown')}")
        output.append(f"Scan Time: {scan_result.scan_info.get('scan_time', 'Unknown')}")
        output.append(f"Duration: {scan_result.scan_info.get('duration', 0)} seconds")
        output.append("-" * 70)
        
        # Application fingerprints
        output.append("\n🔍 APPLICATION FINGERPRINT RESULTS")
        output.append("-" * 40)
        
        if scan_result.fingerprint_results:
            for result in scan_result.fingerprint_results:
                confidence_pct = f"{result.confidence:.1%}"
                output.append(f"✓ {result.application} (Confidence: {confidence_pct})")
                if result.version:
                    output.append(f"   Version: {result.version}")
                if result.installed_plugins:
                    output.append(f"   Plugins: {', '.join(result.installed_plugins)}")
        else:
            output.append("No applications identified.")
        
        # Sensitive data
        output.append("\n⚠️  SENSITIVE DATA FOUND")
        output.append("-" * 40)
        
        if scan_result.sensitive_data:
            for data in scan_result.sensitive_data:
                risk_level = "HIGH" if data.count > 10 else "MEDIUM" if data.count > 5 else "LOW"
                output.append(f"• {data.table}.{data.field} ({data.data_type}) - {risk_level} risk")
                output.append(f"  Count: {data.count}")
                if data.sample_values:
                    samples = ", ".join(data.sample_values[:3])
                    output.append(f"  Samples: {samples}")
        else:
            output.append("No sensitive data found.")
        
        # URLs
        output.append("\n🌐 DISCOVERED URLs")
        output.append("-" * 40)
        
        if scan_result.urls:
            for url in scan_result.urls:
                output.append(f"• {url.url} (from {url.source_table}.{url.source_field})")
        else:
            output.append("No URLs discovered.")
        
        # Recommendations
        output.append("\n🛠️  RECOMMENDATIONS")
        output.append("-" * 40)
        
        if scan_result.recommendations:
            for i, rec in enumerate(scan_result.recommendations, 1):
                output.append(f"{i}. {rec}")
        else:
            output.append("No specific recommendations at this time.")
        
        # Footer
        output.append("\n" + "=" * 70)
        output.append("Report generated by DBRecon v0.1.0")
        output.append("For authorized security assessment use only")
        output.append("=" * 70)
        
        return "\n".join(output)