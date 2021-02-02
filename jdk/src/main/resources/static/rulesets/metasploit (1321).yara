/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Metasploit
    Rule id: 1321
    Created at: 2016-03-29 10:35:38
    Updated at: 2016-03-31 09:14:32
    
    Rating: #2
    Total detections: 11280
*/

rule metasploit 
{
	meta:
		description = "This rule detects apps made with metasploit framework"
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

	strings:
		$a = "*Lcom/metasploit/stage/PayloadTrustManager;"
		$b = "(com.metasploit.stage.PayloadTrustManager"
		$c = "Lcom/metasploit/stage/Payload$1;"
		$d = "Lcom/metasploit/stage/Payload;"

	condition:
		all of them
		
}

rule metasploit_obsfuscated
{
	meta:
		description = "This rule tries to detect apps made with metasploit framework but with the paths changed"

	strings:
		$a = "currentDir"
		$b = "path"
		$c = "timeouts"
		$d = "sessionExpiry"
		$e = "commTimeout"
		$f = "retryTotal"
		$g = "retryWait"
		$h = "payloadStart"
		$i = "readAndRunStage"
		$j = "runStageFromHTTP"
		$k = "useFor"
		

	condition:
		all of them
		
}
