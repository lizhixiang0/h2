/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Vidroid
    Rule id: 2180
    Created at: 2017-01-25 10:40:49
    Updated at: 2017-01-25 10:43:49
    
    Rating: #0
    Total detections: 1292
*/

import "androguard"

rule vidroid
{
	meta:
		description = "This rule detects vidroid malware"
		sample = "855c40a5bc565fc16a6293757f822fbe1abc82708974046e940fd71230b1df32"

	strings:
		$a = "Mozilla/5.0 (Linux; U; {app_id}; {android_version}; de-ch; Vid4Droid) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
		$b = "Lcom/vid4droid/PleechActivity$MyChromeWebViewClient;"
	condition:
		androguard.package_name("com.vid4droid") or 
		($a and $b) 
}
