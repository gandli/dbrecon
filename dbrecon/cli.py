import click
from typing import List, Optional

from dbrecon.models import DatabaseConnection, ScanConfig
from dbrecon.database import DatabaseManager
from dbrecon.fingerprint import FingerprintEngine
from dbrecon.scanner import SensitiveDataScanner
from dbrecon.reporter import ReportGenerator


@click.group()
@click.version_option(version="0.1.0")
def main():
    """DBRecon - Database Reconnaissance Tool for Penetration Testing"""
    pass


@main.command()
@click.option("--host", required=True, help="Database host address")
@click.option("--port", default=3306, type=int, help="Database port (default: 3306)")
@click.option("--user", required=True, help="Database username")
@click.option("--password", required=True, help="Database password")
@click.option("--database", help="Target database name")
@click.option("--ssl/--no-ssl", default=False, help="Enable SSL connection")
@click.option("--timeout", default=30, type=int, help="Connection timeout in seconds")
def test_connection(host, port, user, password, database, ssl, timeout):
    """Test database connection."""
    config = DatabaseConnection(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        ssl_enabled=ssl,
        timeout=timeout
    )
    
    db_manager = DatabaseManager(config)
    success = db_manager.connect()
    
    if success:
        click.echo("✅ Connection successful!")
        
        # Get server info if connected
        try:
            server_info = db_manager.get_server_info()
            if server_info:
                click.echo(f"📊 Server Version: {server_info.get('version', 'Unknown')}")
                click.echo(f"🌍 Character Set: {server_info.get('charset', 'Unknown')}")
        except Exception as e:
            click.echo(f"⚠️  Could not retrieve server info: {e}")
        
        db_manager.disconnect()
    else:
        click.echo("❌ Connection failed!")
        raise click.Abort()


@main.command()
@click.option("--host", required=True, help="Database host address")
@click.option("--port", default=3306, type=int, help="Database port (default: 3306)")
@click.option("--user", required=True, help="Database username")
@click.option("--password", required=True, help="Database password")
@click.option("--database", required=True, help="Target database name")
@click.option("--deep/--shallow", default=False, help="Perform deep scan")
@click.option("--format", "output_format", 
              type=click.Choice(["json", "csv", "html", "markdown", "console"]),
              default="console", help="Output format")
@click.option("--output", "-o", help="Output file path")
def fingerprint(host, port, user, password, database, deep, output_format, output):
    """Identify applications running on the database."""
    config = DatabaseConnection(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        ssl_enabled=False,  # Simplified for fingerprinting
        timeout=30
    )
    
    db_manager = DatabaseManager(config)
    
    if not db_manager.connect():
        click.echo("❌ Failed to connect to database!")
        raise click.Abort()
    
    try:
        click.echo(f"🔍 Analyzing database '{database}' for application fingerprints...")
        
        # Perform fingerprinting
        engine = FingerprintEngine()
        results = engine.analyze(db_manager, database)
        
        if not results:
            click.echo("❓ No recognizable applications found.")
            return
        
        # Display results
        for result in results:
            confidence_pct = f"{result.confidence:.1%}"
            click.echo(f"\n📋 {result.application} (Confidence: {confidence_pct})")
            
            if result.version:
                click.echo(f"   🏷️  Version: {result.version}")
            
            if result.installed_plugins:
                plugins_text = ", ".join(result.installed_plugins)
                click.echo(f"   🔌 Plugins: {plugins_text}")
            
            if result.evidence:
                click.echo("   📝 Evidence:")
                for evidence in result.evidence[:5]:  # Limit to first 5
                    if evidence["type"] == "table":
                        click.echo(f"      • Table: {evidence['name']} ({evidence['match']})")
        
        # Generate report if requested
        if output or output_format != "console":
            scan_result = create_dummy_scan_result(results, database)
            generator = ReportGenerator()
            generator.generate(scan_result, output_format, output)
            
            if output:
                click.echo(f"\n💾 Report saved to: {output}")
        
    finally:
        db_manager.disconnect()


@main.command()
@click.option("--host", required=True, help="Database host address")
@click.option("--port", default=3306, type=int, help="Database port (default: 3306)")
@click.option("--user", required=True, help="Database username")
@click.option("--password", required=True, help="Database password")
@click.option("--database", required=True, help="Target database name")
@click.option("--data-types", default="passwords,emails,api_keys,phones",
              help="Comma-separated list of data types to scan")
@click.option("--format", "output_format", 
              type=click.Choice(["json", "csv", "html", "markdown", "console"]),
              default="console", help="Output format")
@click.option("--output", "-o", help="Output file path")
def scan_sensitive(host, port, user, password, database, data_types, output_format, output):
    """Scan for sensitive data in the database."""
    config = DatabaseConnection(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        ssl_enabled=False,
        timeout=30
    )
    
    db_manager = DatabaseManager(config)
    
    if not db_manager.connect():
        click.echo("❌ Failed to connect to database!")
        raise click.Abort()
    
    try:
        click.echo(f"🔍 Scanning database '{database}' for sensitive data...")
        
        # Parse data types
        data_type_list = [dt.strip() for dt in data_types.split(",")]
        
        # Get all tables
        tables = db_manager.get_tables(database)
        if not tables:
            click.echo("❌ No tables found in the specified database.")
            return
        
        click.echo(f"📊 Found {len(tables)} tables. Starting scan...")
        
        # Perform scanning
        scanner = SensitiveDataScanner()
        
        # Convert string table names to TableInfo objects
        from dbrecon.models import TableInfo
        table_infos = []
        for table_name in tables:
            try:
                columns = db_manager.get_table_structure(database, table_name)
                table_info = TableInfo(name=table_name, columns=columns)
                table_infos.append(table_info)
            except Exception:
                continue  # Skip tables that can't be analyzed
        
        if not table_infos:
            click.echo("❌ Could not analyze any tables.")
            return
        
        sensitive_data = scanner.scan(db_manager, database, table_infos, data_type_list)
        
        # Display results
        if sensitive_data:
            click.echo(f"\n⚠️  Found {len(sensitive_data)} sensitive data fields:")
            click.echo("-" * 50)
            
            for data in sensitive_data:
                risk_level = "HIGH" if data.count > 10 else "MEDIUM" if data.count > 5 else "LOW"
                click.echo(f"🔴 {data.table}.{data.field} ({risk_level} risk)")
                click.echo(f"   Type: {data.data_type}")
                click.echo(f"   Count: {data.count}")
                
                if data.sample_values:
                    samples = ", ".join(data.sample_values[:3])
                    click.echo(f"   Samples: {samples}")
                
                click.echo()
        else:
            click.echo("✅ No sensitive data found.")
        
        # Generate report if requested
        if output or output_format != "console":
            scan_result = create_dummy_scan_result([], database, sensitive_data)
            generator = ReportGenerator()
            generator.generate(scan_result, output_format, output)
            
            if output:
                click.echo(f"💾 Report saved to: {output}")
        
    finally:
        db_manager.disconnect()


@main.command()
@click.option("--host", required=True, help="Database host address")
@click.option("--port", default=3306, type=int, help="Database port (default: 3306)")
@click.option("--user", required=True, help="Database username")
@click.option("--password", required=True, help="Database password")
@click.option("--database", required=True, help="Target database name")
@click.option("--deep/--shallow", default=False, help="Perform deep scan")
@click.option("--format", "output_format", 
              type=click.Choice(["json", "csv", "html", "markdown", "console"]),
              default="console", help="Output format")
@click.option("--output", "-o", help="Output file path")
def full_scan(host, port, user, password, database, deep, output_format, output):
    """Perform a complete security assessment."""
    config = DatabaseConnection(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        ssl_enabled=False,
        timeout=30
    )
    
    db_manager = DatabaseManager(config)
    
    if not db_manager.connect():
        click.echo("❌ Failed to connect to database!")
        raise click.Abort()
    
    try:
        click.echo("🚀 Starting comprehensive security assessment...")
        click.echo("=" * 60)
        
        # Phase 1: Application Fingerprinting
        click.echo("\n🔍 Phase 1: Application Fingerprinting")
        click.echo("-" * 40)
        
        engine = FingerprintEngine()
        fingerprint_results = engine.analyze(db_manager, database)
        
        # Phase 2: Database Structure Analysis
        click.echo(f"\n🗂️  Phase 2: Database Structure Analysis")
        click.echo("-" * 40)
        
        tables = db_manager.get_tables(database)
        click.echo(f"Found {len(tables)} tables:")
        for table in tables[:10]:  # Show first 10
            click.echo(f"  • {table}")
        if len(tables) > 10:
            click.echo(f"  ... and {len(tables) - 10} more")
        
        # Phase 3: Sensitive Data Discovery
        click.echo(f"\n🔎 Phase 3: Sensitive Data Discovery")
        click.echo("-" * 40)
        
        from dbrecon.models import TableInfo
        table_infos = []
        for table_name in tables:
            try:
                columns = db_manager.get_table_structure(database, table_name)
                table_info = TableInfo(name=table_name, columns=columns)
                table_infos.append(table_info)
            except Exception:
                continue
        
        scanner = SensitiveDataScanner()
        sensitive_data = scanner.scan(db_manager, database, table_infos)
        
        # Phase 4: URL Discovery (simplified)
        click.echo(f"\n🌐 Phase 4: URL Discovery")
        click.echo("-" * 40)
        
        urls = []  # Placeholder for URL discovery
        
        # Generate final report
        scan_result = create_complete_scan_result(
            fingerprint_results, sensitive_data, urls, database, tables,
            db_manager=db_manager
        )
        
        generator = ReportGenerator()
        generator.generate(scan_result, output_format, output)
        
        # Summary
        click.echo(f"\n📊 Assessment Summary:")
        click.echo("-" * 40)
        click.echo(f"Applications identified: {len(fingerprint_results)}")
        click.echo(f"Sensitive data fields: {len(sensitive_data)}")
        click.echo(f"URLs discovered: {len(urls)}")
        
        if output:
            click.echo(f"Full report saved to: {output}")
        
    finally:
        db_manager.disconnect()


def create_dummy_scan_result(fingerprint_results, database, sensitive_data=None, host="localhost", port=3306):
    """Create a minimal scan result for reporting."""
    from dbrecon.models import ScanResult
    
    if sensitive_data is None:
        sensitive_data = []
    
    return ScanResult(
        scan_info={
            "target": f"{host}:{port}",
            "scan_time": __import__('datetime').datetime.now().isoformat(),
            "duration": 10,
            "database": database
        },
        fingerprint_results=fingerprint_results,
        sensitive_data=sensitive_data,
        urls=[],
        database_structure={},
        recommendations=["Review findings and implement security measures"]
    )


def create_complete_scan_result(fingerprint_results, sensitive_data, urls, 
                              database, tables, db_manager=None, host="localhost", port=3306):
    """Create a complete scan result with all data."""
    from dbrecon.models import ScanResult, TableInfo
    
    # Create database structure info
    db_structure = {}
    for table_name in tables:
        if db_manager is not None:
            try:
                columns = db_manager.get_table_structure(database, table_name)
                db_structure[table_name] = [TableInfo(name=table_name, columns=columns)]
            except Exception:
                continue
        else:
            db_structure[table_name] = [TableInfo(name=table_name, columns=[])]
    
    return ScanResult(
        scan_info={
            "target": f"{host}:{port}",
            "scan_time": __import__('datetime').datetime.now().isoformat(),
            "duration": 60,
            "database": database
        },
        fingerprint_results=fingerprint_results,
        sensitive_data=sensitive_data,
        urls=urls,
        database_structure=db_structure,
        recommendations=[
            "Implement proper access controls",
            "Regular security audits recommended",
            "Update applications to latest versions"
        ]
    )


if __name__ == "__main__":
    main()