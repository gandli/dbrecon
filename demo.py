#!/usr/bin/env python3
"""
DBRecon Demo Script

This script demonstrates the key capabilities of DBRecon without requiring
an actual database connection. It shows the fingerprinting, scanning, and
reporting functionality.
"""

import json
from dbrecon.models import DatabaseConnection, ScanResult, FingerprintResult, SensitiveData, UrlInfo, TableInfo
from dbrecon.reporter import ReportGenerator


def create_demo_data():
    """Create sample scan results for demonstration."""
    # Create a realistic WordPress database scenario
    fingerprint_results = [
        FingerprintResult(
            application="WordPress",
            confidence=0.95,
            version="5.8.1",
            evidence=[
                {"type": "table", "name": "wp_options", "match": "exact"},
                {"type": "table", "name": "wp_users", "match": "exact"},
                {"type": "table", "name": "wp_posts", "match": "exact"}
            ],
            installed_plugins=["woocommerce", "yoast-seo", "contact-form-7"]
        )
    ]

    sensitive_data = [
        SensitiveData(
            table="wp_users",
            field="user_pass",
            data_type="passwords",
            count=25,
            sample_values=["$2y$10$hash1", "$2y$10$hash2", "$2y$10$hash3"]
        ),
        SensitiveData(
            table="wp_users",
            field="user_email",
            data_type="emails",
            count=25,
            sample_values=["admin@example.com", "user@test.org", "contact@site.com"]
        ),
        SensitiveData(
            table="wp_options",
            field="option_value",
            data_type="urls",
            count=12,
            sample_values=["https://example.com", "https://api.example.com", "http://localhost:8080"]
        )
    ]

    urls = [
        UrlInfo(
            url="https://example.com",
            source_table="wp_options",
            source_field="option_value",
            url_type="primary_site"
        ),
        UrlInfo(
            url="https://admin.example.com",
            source_table="wp_options",
            source_field="option_value",
            url_type="admin_panel"
        ),
        UrlInfo(
            url="https://api.example.com/v1",
            source_table="wp_options",
            source_field="option_value",
            url_type="api_endpoint"
        )
    ]

    database_structure = {
        "wordpress_db": [
            TableInfo(
                name="wp_users",
                engine="InnoDB",
                row_count=25,
                columns=[
                    {"name": "ID", "type": "bigint(20)", "nullable": False},
                    {"name": "user_login", "type": "varchar(60)", "nullable": False},
                    {"name": "user_pass", "type": "varchar(255)", "nullable": False},
                    {"name": "user_email", "type": "varchar(100)", "nullable": True}
                ]
            ),
            TableInfo(
                name="wp_options",
                engine="InnoDB",
                row_count=150,
                columns=[
                    {"name": "option_id", "type": "bigint(20)", "nullable": False},
                    {"name": "option_name", "type": "varchar(191)", "nullable": False},
                    {"name": "option_value", "type": "longtext", "nullable": False}
                ]
            )
        ]
    }

    recommendations = [
        "Change default admin passwords immediately",
        "Update WordPress to latest security patches",
        "Review and update installed plugins",
        "Implement two-factor authentication for admin users",
        "Regular security audits recommended",
        "Monitor for unauthorized access attempts"
    ]

    return ScanResult(
        scan_info={
            "target": "192.168.1.100:3306",
            "scan_time": "2024-01-15T10:30:00Z",
            "duration": 120,
            "database": "wordpress_db",
            "scanner_version": "0.1.0"
        },
        fingerprint_results=fingerprint_results,
        sensitive_data=sensitive_data,
        urls=urls,
        database_structure=database_structure,
        recommendations=recommendations
    )


def generate_all_reports(scan_result):
    """Generate all report formats for demonstration."""
    print("🚀 Generating DBRecon Security Assessment Reports")
    print("=" * 60)

    generator = ReportGenerator()

    # JSON Report
    print("\n📄 Generating JSON Report...")
    json_report = generator.generate(scan_result, "json", None)
    with open("/tmp/dbrecon_report.json", "w") as f:
        f.write(json_report)
    print(f"✅ JSON report saved to /tmp/dbrecon_report.json")

    # HTML Report
    print("\n🌐 Generating HTML Report...")
    html_report = generator.generate(scan_result, "html", "/tmp/dbrecon_report.html")
    print(f"✅ HTML report saved to /tmp/dbrecon_report.html")

    # CSV Report
    print("\n📊 Generating CSV Report...")
    csv_report = generator.generate(scan_result, "csv", None)
    with open("/tmp/dbrecon_report.csv", "w") as f:
        f.write(csv_report)
    print(f"✅ CSV report saved to /tmp/dbrecon_report.csv")

    # Markdown Report
    print("\n📝 Generating Markdown Report...")
    markdown_report = generator.generate(scan_result, "markdown", None)
    with open("/tmp/dbrecon_report.md", "w") as f:
        f.write(markdown_report)
    print(f"✅ Markdown report saved to /tmp/dbrecon_report.md")

    # Console Report (display)
    print("\n🖥️  Console Report Preview:")
    console_report = generator.generate(scan_result, "console", None)
    print(console_report[:1000] + "..." if len(console_report) > 1000 else console_report)


def main():
    """Main demo function."""
    print("🔍 DBRecon - Database Reconnaissance Tool Demo")
    print("=" * 60)
    print("This demonstration showcases DBRecon's capabilities without")
    print("requiring an actual database connection.")
    print()

    # Create sample data representing a real security assessment
    print("📋 Creating sample security assessment data...")
    scan_result = create_demo_data()
    
    print(f"   • Target: {scan_result.scan_info['target']}")
    print(f"   • Applications identified: {len(scan_result.fingerprint_results)}")
    print(f"   • Sensitive data fields: {len(scan_result.sensitive_data)}")
    print(f"   • URLs discovered: {len(scan_result.urls)}")
    print(f"   • Recommendations: {len(scan_result.recommendations)}")
    print()

    # Generate comprehensive reports
    generate_all_reports(scan_result)

    print("\n" + "=" * 60)
    print("🎉 Demo Complete!")
    print("\nGenerated Files:")
    print("  • /tmp/dbrecon_report.json    - Structured data format")
    print("  • /tmp/dbrecon_report.html   - Professional web report")
    print("  • /tmp/dbrecon_report.csv     - Spreadsheet compatible")
    print("  • /tmp/dbrecon_report.md      - Documentation format")
    print("\nTo run actual assessments, use:")
    print("  dbrecon full-scan --host <host> --user <user> --password <pass> --database <db>")


if __name__ == "__main__":
    main()