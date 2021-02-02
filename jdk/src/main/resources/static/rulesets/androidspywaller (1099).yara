/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Android.Spywaller
    Rule id: 1099
    Created at: 2016-01-05 17:22:24
    Updated at: 2016-05-24 09:05:00
    
    Rating: #0
    Total detections: 30056
*/

import "androguard"
import "file"
import "cuckoo"

rule Spywaller
{
	meta:
		description = "Android.Spywaller"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		credits = "http://www.symantec.com/connect/blogs/spyware-androidspywaller-uses-legitimate-firewall-thwart-security-software"
		credits_2 = "http://www.symantec.com/security_response/writeup.jsp?docid=2015-121807-0203-99&tabid=2"
	
	strings:
		$a = "com.qihoo360.mobilesafe" //Malware looks for this app to remove it from device
		$b = "com.lbe.security"
		$c = "cn.opda.a.phonoalbumshou"
		$d = "safety_app"
		
	condition:
		all of them
		and androguard.permission(/android.permission.RESTART_PACKAGES/)
}
