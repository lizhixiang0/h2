/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: x4x1m
    Rule name: Dropper
    Rule id: 2005
    Created at: 2016-12-02 20:02:21
    Updated at: 2016-12-02 20:07:59
    
    Rating: #0
    Total detections: 23
*/

rule dropper
{
	meta:
		description = "Detects a dropper"
		samples = "4144f5cf8d8b3e228ad428a6e3bf6547132171609893df46f342d6716854f329, e1afcf6670d000f86b9aea4abcec7f38b7e6294b4d683c04f0b4f7083b6b311e"

	strings:
		$a = "splitPayLoadFromDex"
		$b = "readDexFileFromApk"
		$c = "payload_odex"
		$d = "payload_libs"
		$e = "/payload.apk"
		$f = "makeApplication"

	condition:
		all of them
		
}
