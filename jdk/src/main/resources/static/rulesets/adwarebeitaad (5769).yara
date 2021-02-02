/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Adware.BeiTaAd
    Rule id: 5769
    Created at: 2019-07-18 16:24:10
    Updated at: 2019-07-19 04:16:51
    
    Rating: #1
    Total detections: 13
*/

//https://blog.lookout.com/beitaplugin-adware



import "androguard"


rule BeiTaPlugin
{

	strings:
		$a1 = "assets/beita.renc"
		$a2 = "assets/icon-icomoon-gemini.renc"
		$a3 = "assets/icon-icomoon-robin.renc"
		
		$b = "Yaxiang Robin High"   // Decryption key

	condition:
		any of them// and
		//androguard.certificate.sha1("21AB588FC1114119FAE40BE76FD9F18B63A1CA48")
		
}
