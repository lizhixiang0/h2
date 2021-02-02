/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Unknown trojan agent
    Rule id: 869
    Created at: 2015-09-28 12:04:40
    Updated at: 2015-09-28 12:14:40
    
    Rating: #0
    Total detections: 217739
*/

rule unknown:agent
{
	meta:
		description = "This rule detects a new malware family that is under study"
		sample = "405314192f39a587a1f87b1599fcd12cf1387d65b96ce3a857baaf7863420ef7"
		sample2 = "4913737c1bfa69a01e8b03dd31b90735657cd331a415f507b0e87dd4f1715cb2"
		sample3 = "52de577ce4ce1b078cb4963a73aa88a07e99b4c3e8e33474c59ed6e77741eef2"

	strings:
		$a = "ShellReceiver.onReceive()"
		$b = "Lcom/sns/e/bi;"
		$c = "W5M0MpCehiHzreSzNTczkc9d"

	condition:
		all of them
		
}
