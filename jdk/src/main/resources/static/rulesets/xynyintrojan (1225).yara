/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: Xynyin.Trojan
    Rule id: 1225
    Created at: 2016-02-21 20:15:38
    Updated at: 2016-03-02 05:47:04
    
    Rating: #1
    Total detections: 377
*/

import "androguard"
import "file"
import "cuckoo"

/**/

private rule Xynyin_certs
{
	meta:
		description = "Fake developers certs and email: smo_XXXX_t@gmail.com"

	condition:
		androguard.certificate.issuer(/smo_[0-9]{3,4}_t\@gmail\.com/) or	
		androguard.certificate.sha1("A1B5344F6E8EB1305EE7B742CDDBEFAF2041CB89") or
		androguard.certificate.sha1("CB48901569936E9322103EA806F386ED2401583F") or
		androguard.certificate.sha1("171F1EFF24F580EE28AF7C30C1190AB717A96DCE") or
		androguard.certificate.sha1("DCD5BA60AC48996A11D126354978E9A909D90229")		

}

private rule Xynyin_cyphered
{
	meta:
		description = "Cyphered files by Xynyin"

	strings:	
		$1 = "assets/version.txt" wide ascii
		$2 = "assets/ecode"	 wide ascii
		$3 = "assets/ecode_64" wide ascii	
		
	condition:
		all of them
}

rule Xynyin_strings
{
	meta:
		description = "Xynyin particular strings"

	strings:	
		$2 = "zzzsurpriseprjsnotificationcontent" wide ascii
		$3 = "zzzltid" wide ascii		
		
	condition:
		1 of them and Xynyin_cyphered and Xynyin_certs
}

rule shuabang_evidences
{
	meta:
		description = "Xynyin/shuabang based"
		
	strings:			
		$1 = "ShuaBangBase"
		$2 = "ShuaPublicConfig"
		$3 = "Start BindLMT!"

	condition:
		all of them and Xynyin_certs
}
