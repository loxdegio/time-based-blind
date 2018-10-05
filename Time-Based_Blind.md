## Time-Based Blind SQLi Challenge (Challenge 1)

La challenge prevedeva di sfruttare la vulnerabilità di SQLi sulla pagina http://[[CyberGym host]]/sqli/time_based_blind.php
della CyberGym.

La pagina si presenta come un form di recupero password con un solo campo per l'immissione della email personale.

Analizzandone il comportamento si scopre che la pagina lancia una richiesta con metodo GET a se stessa per effettuare l'azione.

L'unico parametro passato è un campo chiamato email.

Testando questo campo con un payload come "lorenzo@degioanni.it" la risposta è immediata, mentre con uno come "' OR 1 = 1 AND SLEEP(5) -- -"
la risposta arriva in ritardo di almeno 5 secondi come previsto.

Dopo aver verificato che la pagina è vulnerabile all'attacco richiesto ho cominciato ad elaborare l'attacco generando uno script python che 
deve essere eseguito in più passaggi:

Visto che, il campo era una stringa ho pensato di "wrappare" le query di payload, elencate nel [README.md](README.md) 
generale, con "' AND (" + query + ") AND 1=1 -- -", mentre, nel caso il campo fosse numerico, ho previsto un "incapsulamento" del tipo
"1+IF((" + query + ") IS NULL, 0, 1)"

Prima di tutto mi serviva conoscere il nome del database sul quale sono storati i dati, ma per riuscirci mi è sembrato necessario estrarre la
lista degli schema e, per evitare overhead, ho predisposto, per ogni tipo di estrazione, un conteggio degli elementi effettivamente presenti.

(vedere query (1.) count ed extraction per recupero database nel [README.md](README.md) generale)

Da questa analisi scopro che oltre gli schema classici di gestione di MySQL c'è un database chiamato 'scotchbox' che deduco essere il nostro 
obiettivo.
Avendo necessità di poter bypassare anche l'escaping della funzione mysql_real_escape_string() della seconda challenge, decido di non passare 
il nome del database come text plain, ma di usare l'accortezza di passare alla funzione MySQL CONCAT() la lista dei codici UTF8 in notazione
esadecimale dei singoli caratteri del nome del database target.

(vedere query (2.)  count ed extraction per recupero tabelle nel [README.md](README.md) generale)

Il database contiene 3 tabelle:
- accounts
- datacapture
- messages

La consegna richiede il recupero dei dati dalla tabella accounts e ho pensato di concatenare con un ':' tutte le colonne per fare 
un'estrazione unica dei dati necessari.
Ho pensato quindi che mi servisse conoscere prima l'anatomia della tabella target estraendo nomi e tipo delle colonne componenti.
Per usare come parametro di ricerca il nome della tabella ho usato la stessa tecnica utilizzata per il passaggio del nome del database.

(vedere query (3.) count ed extraction per recupero nomi colonne nel [README.md](README.md) generale)

In questo modo ottengo la lista dei nomi delle colonne e dei loro relativi tipi di dato:
- id:int
- first_name:varchar
- last_name:varchar
- email:varchar
- password:varchar

A questo punto posso passare la lista delle colonne allo script per estrarre i valori richiesti dalla consegna riportata nel [README.md](README.md) generale.

(vedere query (4.) count ed extraction per recupero dati della tabella nel [README.md](README.md) generale)

Ho incluso nel repository il file [time-based_blind.sh](time-based_blind.sh) che ripercorre tutti i passaggi effettuati per l'estrazione dei dati anche dalla pagina 
http://[[CyberGym host]]/sqli/time_based_blind.php che riepiloga tutti i passaggi necessari per l'estrazione.
