## Time-Based Blind SQLi Challenge (Challenge 1)

The challenge was to exploit the SQLi vulnerability on page http://[[CyberGym host]]/sqli/time_based_blind.php
of CyberGym.

The page is presented as a password recovery form with only one field for entering the personal email.

Analyzing the behavior it turns out that the page launches a request with GET method to itself to carry out the action.

The only parameter passed is a field called email.

Testing this field with a payload like "lorenzo@degioanni.it" the answer is immediate, while with one like "'OR 1 = 1 AND SLEEP (5) -- -" the answer is delayed by at least 5 seconds as expected.

After verifying that the page is vulnerable to the requested attack I began to process the attack by generating a python script that it must be performed in several steps:

Since the field was a string I thought to "wrap" the payload queries, listed in [README.md] (README.md)
general, with "'AND (" + query + ") AND 1 = 1 - -", while, if the field is numeric, I have foreseen an "encapsulation" of the type "1 + IF ((" + query + ") IS NULL, 0, 1)"

First of all I needed to know the name of the database on which the data are stored, but to do so, it seemed necessary to extract the list of the schema and, to avoid overhead, I prepared, for each type of extraction, a count of the elements actually present.

From this analysis I discover that in addition to the classic MySQL management scheme there is a database called 'scotchbox' which I deduce is our
target.
Needing to be able to bypass the escaping of the mysql_real_escape_string () function of the second challenge, I decide not to pass
the name of the database as text plain, but to use the caution to switch to the MySQL CONCAT function () the list of UTF8 codes in notation
hexadecimal of the individual characters of the target database name.

(see query (2.) count and extraction for table recovery in the general [README.md](README.md))

The database contains 3 tables:
- accounts
- datacapture
- messages

The delivery requires the recovery of data from the accounts table and I thought to concatenate with a ':' all the columns to do
a unique extraction of the necessary data.
So I thought I needed to know the anatomy of the target table first by extracting the names and types of the component columns.
To use the table name as a search parameter, I used the same technique used to pass the database name.

(see query (3.) count and extraction for retrieving column names in the general [README.md](README.md))

In this way I get the list of the names of the columns and their relative data types:
- id:int
- first_name:varchar
- last_name:varchar
- email:varchar
- password:varchar

At this point I can pass the list of columns to the script to extract the values ​​required by the delivery reported in the general [README.md] (README.md).

(see query (4.) count and extraction for retrieving columns data in the general [README.md](README.md))

I have included in the repository the file [time-based_blind.sh] (time-based_blind.sh) which traces all the steps taken for data extraction also from the page
http://[[CyberGym host]]/sqli/time_based_blind.php which summarizes all the steps necessary for the extraction.
The login data retrieved from the accounts table are as follows:

email            | password(sha1)                           | password in chiaro
-----------------|------------------------------------------|-------------------
arthur@guide.com | d00ee262cdcbe7543210bb85f6f1cac257b4e994 | Bathrobe
ford@guide.com   | 30f5cc99c17426a0d28acf8905c6d776039ad022 | Betelgeuse
tricia@guide.com | bcb3358e273b5772ee0ae1799b612e13cc726b04 | Trillian
zaphod@guide.com | 0c38530eaca4dbc0f49c459c0c52b362f14215c3 | Pan-GalacticGargleBlaster

The plaintext passwords were obtained through the [https://github.com/s0md3v/Hash-Buster] (Hash Buster v3.0) tool

Finally, from the analysis of the jitter of the responses I noticed that (in my local environment, virtualized) this was very oscillating, but anyway
it always stood below 0.1 seconds, leading me to suppose this value as sufficient for a correct extraction of the searched results for both challenges
