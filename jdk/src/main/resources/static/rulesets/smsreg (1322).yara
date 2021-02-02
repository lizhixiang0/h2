/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReg
    Rule id: 1322
    Created at: 2016-03-29 12:32:26
    Updated at: 2016-03-29 13:26:06
    
    Rating: #0
    Total detections: 593
*/

import "androguard"

rule smsreg
{
	meta:
		sample = "1c2e1083f9c73a222af21351b243d5072fcc3360a5be6fa4d874e4a94249a68d"
		search = "package_name:com.dnstore.vn"

	strings:
		//$url1 = "http://bitly.com/360Riverads"
		//$url2 = "http://bitly.com/UCriverads"
		$a = "var msg2_4 = \"DSD zombie\";"
		//$url3 = "http://bitly.com/apuslaunchereway"
		$b = "Ldnteam/gamevui2014/net/ScriptInterface$Downloader3"

	condition:
		($a and $b) or androguard.package_name("com.dnstore.vn")
		
}
