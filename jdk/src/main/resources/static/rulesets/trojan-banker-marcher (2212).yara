/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan Banker Marcher
    Rule id: 2212
    Created at: 2017-02-02 09:23:21
    Updated at: 2017-02-15 10:02:08
    
    Rating: #0
    Total detections: 411
*/

rule Trojan_Banker:Marcher {

	strings:
		$ = "Landroid/telephony/SmsManager"
		$ = "szClassname"
		$ = "szICCONSEND"
		$ = "szModuleSmsStatus"
		$ = "szModuleSmsStatusId"
		$ = "szName"
		$ = "szNomer"
		$ = "szNum"
		$ = "szOk"
		$ = "szTel"
		$ = "szText"
		$ = "szpkgname"

	condition:
		all of them
}
