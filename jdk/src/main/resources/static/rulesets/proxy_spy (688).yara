/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: proxy_spy
    Rule id: 688
    Created at: 2015-07-14 06:59:09
    Updated at: 2015-08-06 15:20:53
    
    Rating: #0
    Total detections: 5
*/

import "androguard"

rule proxy_spy : trojan
{
	meta:
		description = "This rule detects http://b0n1.blogspot.com.es/2015/04/android-trojan-spy-goes-2-years.html"
		sample = "00341bf1c048956223db2bc080bcf0e9fdf2b764780f85bca77d852010d0ec04"

	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.activity(/\.*proxy\.MainActivity/i) and
		androguard.url(/proxylog\.dyndns\.org/)	
}
