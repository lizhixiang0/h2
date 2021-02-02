/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud
    Rule id: 1324
    Created at: 2016-03-30 08:01:44
    Updated at: 2016-08-26 11:48:24
    
    Rating: #0
    Total detections: 251
*/

import "androguard"

rule smsfraud
{
	meta:
		//description = "This rule detects the koodous application, used to show all Yara rules potential"
		
		sample = "7ea9a489080fa667b90fb454b86589ac8b018c310699169b615aabd5a0f066a8"
		search = "cert:14872DA007AA49E5A17BE6827FD1EB5AC6B52795"


	condition:
		androguard.certificate.sha1("14872DA007AA49E5A17BE6827FD1EB5AC6B52795")
		
}

rule smsfraud2 {
	strings:
		$a = "isUserAMonkey" 
		$b = "android.permission.CHANGE_CONFIGURATION" wide ascii
		$c = "%android.permission.MODIFY_PHONE_STATE" wide ascii
		$d = "+android.permission.SEND_SMS_NO_CONFIRMATION" wide ascii
		$e = "&android.permission.PACKAGE_USAGE_STATS" wide ascii
		$f = "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"
		$g = "res/layout/authenticator.xml" wide ascii
		$h = "eQdPXV^QZ"
		$i = "my_transparent"
		$j = "android.intent.action.DATE_CHANGED" wide ascii
		$k = "Gxq3/70q/>7q;>*/:+<<1<p>6>"
		$l = "__modsi3"
		$m = "MService.java"
	condition:
		all of them
}
