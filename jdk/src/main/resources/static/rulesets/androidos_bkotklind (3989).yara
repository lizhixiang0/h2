/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: ANDROIDOS_BKOTKLIND
    Rule id: 3989
    Created at: 2018-01-11 10:16:18
    Updated at: 2018-01-11 10:19:27
    
    Rating: #0
    Total detections: 1
*/

rule PornSlocker
{
	meta:
		
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/first-kotlin-developed-malicious-app-signs-users-premium-sms-services/"

	strings:
	
		$ = "52.76.80.41"
		$ = "adx.gmpmobi.com"
     
	
	condition:
		
		all of them
	

}
