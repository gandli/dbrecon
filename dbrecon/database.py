import mysql.connector
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

from dbrecon.models import DatabaseConnection, TableInfo


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, config: DatabaseConnection):
        """Initialize database manager with connection configuration."""
        self.config = config
        self.connection = None
    
    def connect(self) -> bool:
        """Establish database connection."""
        if self.connection and self.connection.is_connected():
            return True
        
        try:
            self.connection = mysql.connector.connect(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                password=self.config.password,
                database=self.config.database,
                ssl_disabled=not self.config.ssl_enabled,
                connection_timeout=self.config.timeout
            )
            return True
        except mysql.connector.Error:
            return False
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def execute_query(self, query: str, params: Optional[tuple] = None) -> List[tuple]:
        """Execute a SQL query and return results."""
        if not self.connection or not self.connection.is_connected():
            raise RuntimeError("No active database connection")
        
        cursor = self.connection.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        finally:
            cursor.close()
    
    def get_databases(self) -> List[str]:
        """Get list of all databases."""
        results = self.execute_query("SHOW DATABASES")
        return [row[0] for row in results]
    
    def get_tables(self, database: str) -> List[str]:
        """Get list of tables in specified database."""
        results = self.execute_query(f"SHOW TABLES FROM {database}")
        return [row[0] for row in results]
    
    def get_table_structure(self, database: str, table: str) -> List[Dict[str, Any]]:
        """Get structure information for a specific table."""
        results = self.execute_query(f"DESCRIBE {database}.{table}")
        
        columns = []
        for row in results:
            columns.append({
                "name": row[0],
                "type": row[1],
                "nullable": row[2] == "YES",
                "key": row[3],
                "default": row[4],
                "extra": row[5]
            })
        
        return columns
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get database server information."""
        if not self.connection:
            return {}
        
        return {
            "version": self.connection.get_server_info(),
            "charset": getattr(self.connection, 'charset', None),
            "time_zone": getattr(self.connection, 'time_zone', None)
        }
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor."""
        if not self.connection or not self.connection.is_connected():
            raise RuntimeError("No active database connection")
        
        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()