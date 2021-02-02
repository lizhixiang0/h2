/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: PUPs
    Rule id: 1656
    Created at: 2016-07-21 08:43:11
    Updated at: 2016-07-21 09:02:08
    
    Rating: #0
    Total detections: 20997
*/

rule clicksummer
{
	meta:
		description = "test clicksummer"

	strings:
		$a = "statsevent.clickmsummer.com:80/log"
		$b = "54.149.205.221:8080/MobiLog/log"

	condition:
 		1 of them
		
}


rule SMS1
{
	meta:
		description = "test com.pigeon.pimento.pimple"

	strings:
		$a = "SHA1-Digest: Itv2yusaL6KWWE/TLZFej7FVCO0="

	condition:
 		1 of them
		
}
