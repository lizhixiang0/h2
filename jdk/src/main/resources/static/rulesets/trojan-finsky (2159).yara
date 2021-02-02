/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan FinSky
    Rule id: 2159
    Created at: 2017-01-19 11:55:49
    Updated at: 2017-01-19 12:01:37
    
    Rating: #2
    Total detections: 9
*/

rule Finsky {
	meta:
	sample = "f10ff63c0a8b7a102d6ff8b4e4638edb8512f772,a5b9ca61c2c5a3b283ad56c61497df155d47f276"
	description = "http://vms.drweb.ru/virus/?_is=1&i=14891022"
		
	strings:
		$hooker1 = "hooker.dex"
		$hooker2 = "hooker.so"
		
		$wzh = "wzhtest1987"
		
		$finsky = "finsky"
		
		$cc = "api.sgccrsapi.com"
		
	condition:
		1 of ($hooker*) and ($cc or $wzh) and $finsky
		
}
