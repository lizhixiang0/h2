/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan_Dropper
    Rule id: 2942
    Created at: 2017-06-07 14:22:00
    Updated at: 2017-06-08 11:44:25
    
    Rating: #0
    Total detections: 11
*/

import "androguard"

rule commasterclean
{
	
		//sample = "8c4741662f179e3b7a0ec8a504135f5b12379f3c6743bd4d7c32e7659bbdb747"
		//blogpost = "https://www.zscaler.com/blogs/research/malicious-android-ads-leading-drive-downloads"
		
	
	strings:

		$d1 = "kstest.8rln3ufc.pw"
		$d2 = "newappsdk.fbvxi8mz.pw"
		$d3 = "newstr.pkw9tq2v.pw"
		$d4 = "sscapi.goytd2by.pw"
		$d5 = "ks.urva3ucp.pw"
		$d6 = "app.urva3ucp.pw"
		$d7 = "newstrapi.pkw9tq2v.pw"
		$d8 = "newapi.fbvxi8mz.pw"

		$ip = "52.199.190.161"
		
		$c = "eu/chainfire/libsuperuser/HideOverlaysReceiver"
		
		$s0 = "com.master.clean.relate.CrkService"
		$s1 = "com.master.clean.relate.FcService"
		$s2 = "com.master.clean.relate.PoniService"
		$s3 = "com.master.clean.relate.ScreenServer"
		$s4 = "com.master.clean.relate.SjkJobService"
		

	condition:
		(1 of ($d*) or $ip ) or
		($c and 3 of ($s*))
}

rule CleanupRadar
{
	condition:
	androguard.package_name("com.Airie.CleanupRadar")

}
