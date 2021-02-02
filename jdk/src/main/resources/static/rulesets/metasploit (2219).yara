/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rocky
    Rule name: metaSploit
    Rule id: 2219
    Created at: 2017-02-06 13:20:57
    Updated at: 2017-02-07 08:05:34
    
    Rating: #0
    Total detections: 6333
*/

rule android_metasploit : android
{
	meta:
	  author = "https://twitter.com/plutec_net"
	  description = "This rule detects apps made with metasploit framework"

	strings:
	  $a = "*Lcom/metasploit/stage/PayloadTrustManager;"
	  $b = "(com.metasploit.stage.PayloadTrustManager"
	  $c = "Lcom/metasploit/stage/Payload$1;"
	  $d = "Lcom/metasploit/stage/Payload;"
	  
	condition:
	  $a or $b or $c or $d
}
