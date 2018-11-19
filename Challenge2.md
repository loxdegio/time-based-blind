## Time-Based Blind SQLi Escaped Challenge (Challenge 2)

The challenge was to exploit the SQLi vulnerability on page http://[[CyberGym host]]/sqli/time_based_blind_escaped.php
of CyberGym.

The page is presented as a contact form with a "drop-down" for the selection of the recipient connected to the numerical parameter "to"
of the post request and a Message text field connected with the "msg" parameter of the request.

As a difference from the script for the first challenge I had to provide the possibility to make requests with the POST method
(the --data parameter) and I used the numeric type of the "to" parameter to bypass the mysql_real_escape_string () with the dedicated wrapping
"1 + IF ((" + query + ") IS NULL, 0, 1)" as already mentioned in the first challenge, but the steps followed are the same since I reused the same python script.

I have included in the repository the file [time-based_blind_escaped.sh] (time-based_blind_escaped.sh) that traces all the steps taken for data extraction also from the page
http://[[CyberGym host]]/sqli/time_based_blind_escaped.php which summarizes all the steps necessary for the extraction.

The login data retrieved from the accounts table are as follows:

email            | password(sha1)                           | password in chiaro
-----------------|------------------------------------------|-------------------
arthur@guide.com | d00ee262cdcbe7543210bb85f6f1cac257b4e994 | Bathrobe
ford@guide.com   | 30f5cc99c17426a0d28acf8905c6d776039ad022 | Betelgeuse
tricia@guide.com | bcb3358e273b5772ee0ae1799b612e13cc726b04 | Trillian
zaphod@guide.com | 0c38530eaca4dbc0f49c459c0c52b362f14215c3 | Pan-GalacticGargleBlaster

Finally, from the analysis of the jitter of the responses I noticed that (in my local environment, virtualized) this was very oscillating, but anyway it always stood below 0.1 seconds, leading me to suppose this value as sufficient for a correct extraction of the searched results for both challenges
