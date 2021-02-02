/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSSender
    Rule id: 1263
    Created at: 2016-03-10 12:14:24
    Updated at: 2016-03-16 08:02:01
    
    Rating: #0
    Total detections: 110265
*/

rule SMSSender
{
	meta:
		description = "This rule detects a type of SMSSender"
		sample = "96d449f5073bd7aaf50e06a6ed1eb2ed0afaca3ed60581c5c838aa7119fb0e97"
		search = "package_name:com.nys.mm"

	strings:
		$url1 = "http://117.79.227.178:9991"
		$url2 = "http://172.17.236.157:8082/app/mobile/json"
		$json = "\"tn\":\"%s\",\"user\":\"%s\",\"locale\":\"%s\",\"terminal_version\":\"%s\""
		$fail_message = "Fail to construct message"

	condition:
		all of them
		
}

rule SMSSender2
{
	meta:
		description = "This rule detects another type of SMSSender"
		sample = "a653bd23569aadf02a2202c9a75e83af1263297fbac8cdd14ef4c83426bdc145"

	strings:
		$string_1 = "470,471,472,473,474,475,476,477,478,479,482,483"
		$string_2 = "890,898,899"
		$string_3 = "029,910,911,912,913,914,915,916,917,919"
		$characteristic = "notniva=0220C"
		$icon_name = "mili_smspay_close.png"

	condition:
		all of them
		
}
