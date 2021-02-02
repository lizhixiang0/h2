/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: No Name
    Rule id: 2226
    Created at: 2017-02-08 10:20:23
    Updated at: 2017-02-08 14:24:05
    
    Rating: #0
    Total detections: 8817
*/

rule non_named
{
	meta:
	description = "This rule detects something"

	strings:
		$a = "SHA1-Digest: D1KOexBGmlpJS53iK7KjJcyzt7o="

	condition:
		all of them
		
}
