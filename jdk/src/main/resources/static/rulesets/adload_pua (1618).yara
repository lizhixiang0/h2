/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xoreax
    Rule name: Adload_PUA
    Rule id: 1618
    Created at: 2016-07-13 12:51:09
    Updated at: 2016-07-13 12:53:26
    
    Rating: #0
    Total detections: 8551
*/

import "androguard"
import "file"
import "cuckoo"


rule Adload_PUA
{
	meta:
		description = "This rule detects the Adload potential Unwanted"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "aquery/temp"
		$b = "Ljava/security/Permission;"
		$c = "getActiveNetworkInfo"
		$d = "com.appquanta.wk.MainService.DOWNLOAD_PROGRESS"
		$e = "modifyThread"
		$f = "init_url"

	condition:
		all of them		
}
