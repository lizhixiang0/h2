/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: SpyNote
    Rule id: 2500
    Created at: 2017-04-20 08:22:06
    Updated at: 2017-04-20 17:22:11
    
    Rating: #0
    Total detections: 1516
*/

rule Trojan_Spynote
{
    meta:
		author = "https://twitter.com/SadFud75"
        description = "Yara rule for detection of SpyNote"

    strings:
        $cond_1 = "SERVER_IP" nocase
        $cond_2 = "SERVER_NAME" nocase
        $cond_3 = "content://sms/inbox"
        $cond_4 = "screamHacker" 
    condition:
        all of ($cond_*)
}
