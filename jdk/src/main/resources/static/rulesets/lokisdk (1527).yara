/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: loki.sdk
    Rule id: 1527
    Created at: 2016-06-23 09:58:21
    Updated at: 2016-06-23 10:08:02
    
    Rating: #1
    Total detections: 111
*/

rule loki_skd
{
	meta:
	description = "This rule detects com.loki.sdk"

	strings:
		$a = "com/loki/sdk/"
		$b = "com.loki.sdk.ClientService"

	condition:
		$a or $b
		
}
