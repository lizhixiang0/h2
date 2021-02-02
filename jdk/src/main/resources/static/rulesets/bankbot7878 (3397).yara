/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: BankBot7878
    Rule id: 3397
    Created at: 2017-08-17 10:16:48
    Updated at: 2017-08-17 10:17:05
    
    Rating: #0
    Total detections: 4
*/

import "androguard"

rule Trojan_BankBot_7878 {
		
	strings:
		$a0 = "twitter.com"
		$a1 = ":7878"

		$b0 = "Security protection"
		$b1 = "admin"
		$b2 = "WebServiceRobot"

		$c0 = "b3betb4"
		$c1 = "drenpngepgod235v"
		$c2 = "fkmlcbvio4eboi45"
		$c3 = "odsvr4i35b3"
		$c4 = "ooifjceiu523v"
		$c5 = "powv34b439"
		$c10 = "botId"
		$c11 = "bot_id"
    
	    $d0 = "url_db5o45"
	    $d1 = "url_dbnu56un4"
	    $d2 = "url_debrm454"
	    $d3 = "url_dnednr8643fg"
	    $d4 = "url_dnjs456y3"
	
	condition:
		all of ($a*) 
		and 2 of ($b*) 
		and 2 of ($c*) 
		and 1 of ($d*) 
	
}
