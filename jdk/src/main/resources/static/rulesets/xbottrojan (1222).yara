/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: Xbot.Trojan
    Rule id: 1222
    Created at: 2016-02-19 18:13:42
    Updated at: 2016-02-19 19:31:20
    
    Rating: #2
    Total detections: 99
*/

import "androguard"
import "file"
import "cuckoo"

rule Xbot_certs
{
	meta:
		description = "http://researchcenter.paloaltonetworks.com/2016/02/new-android-trojan-xbot-phishes-credit-cards-and-bank-accounts-encrypts-devices-for-ransom/"
		sample = "595fa0c6b7aa64c455682e2f19d174fe4e72899650e63ab75f63d04d1c538c00"
		
	condition:
		androguard.certificate.sha1("CC9966F3860984948D55176357F853D5DBB5C15F") or
		androguard.certificate.sha1("25D6A5507F3262ADF65639C0BA7B0997AE35C36D") or
		androguard.certificate.sha1("27F8BD306E03B3BAAB8A57A7EC6F1CAE71B321EE")
}

rule Xbot_domains
{
	meta:
        description = "Xbot domains/IPs"
		
	strings:
		$1 = "melon25.ru" wide ascii
		$2 = "market155.ru" wide ascii
		$3 = "illuminatework.ru" wide ascii
		$4 = "yetiathome15.ru" wide ascii
		$5 = "leeroywork3.co" wide ascii
		$6 = "morning3.ru" wide ascii	
		$7 = "52.24.219.3/action.php" wide ascii			
		$8 = "192.227.137.154/request.php" wide ascii
		$9 = "23.227.163.110/locker.php" wide ascii
		$10 = "81.94.205.226:8021" wide ascii
		$11 = "104.219.250.16:8022" wide ascii			
		
   	condition:
		1 of them or
		cuckoo.network.dns_lookup(/melon25.ru/) or
		cuckoo.network.dns_lookup(/market155.ru/) or
		cuckoo.network.dns_lookup(/illuminatework.ru/) or
		cuckoo.network.dns_lookup(/yetiathome15.ru/) or
		cuckoo.network.dns_lookup(/leeroywork3.co/) or
		cuckoo.network.dns_lookup(/morning3.ru/)
}

rule Xbot_pass
{
	meta:
        description = "Xbot password"
		
	strings:
		$1 = "resetPassword" wide ascii
		$2 = "1811blabla" wide ascii
		
   	condition:
		all of them
}

rule Xbot_evidences
{
	meta:
        description = "Xbot evidences"
		
	strings:
		$1 = "Lcom/xbot/core/activities/BrowserActivity" wide ascii
		$2 = "/xBot.log.txt" wide ascii
		$3 = "com.xbot.core" wide ascii		
		
   	condition:
		1 of them
}
