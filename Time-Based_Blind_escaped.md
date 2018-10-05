## Time-Based Blind SQLi Escaped Challenge (Challenge 2)

La challenge prevedeva di sfruttare la vulnerabilità di SQLi sulla pagina http://[[CyberGym host]]/sqli/time_based_blind_escaped.php
della CyberGym.

La pagina si presenta come un form di contatto con una "tendina" per la selezione del destinatario collegata al parametro numerico "to"
della richiesta post e un campo di testo Message collegato con il parametro "msg" della richiesta. 

Come differenza dallo script per la prima challenge ho dovuto prevedere la possibilità di effettuare richieste con il metodo POST
(il parametro --data) e ho sfruttato il tipo numerico del parametro "to" per aggirare il mysql_real_escape_string() con il wrapping dedicato
"1+IF((" + query + ") IS NULL, 0, 1)" come già anticipato nella prima challenge, ma i passi seguiti sono i medesimi in quanto ho riutilizzato 
lo stesso script python.

Ho incluso nel repository il file [time-based_blind_escaped.sh](time-based_blind_escaped.sh) che ripercorre tutti i passaggi effettuati per l'estrazione dei dati anche dalla pagina 
http://[[CyberGym host]]/sqli/time_based_blind_escaped.php che riepiloga tutti i passaggi necessari per l'estrazione.
