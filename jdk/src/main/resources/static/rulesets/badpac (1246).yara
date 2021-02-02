/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Gaurav
    Rule name: Badpac
    Rule id: 1246
    Created at: 2016-03-03 05:13:33
    Updated at: 2016-03-03 07:06:25
    
    Rating: #1
    Total detections: 21
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Badpac adware"
		sample = "41911f5e76b7c367d8d4ee33fe17e12a6fe90633300d30a990278fc74b0c9535"

	strings:
	
	$sig1 = {2F 41 70 70 41 63 74 69 76 69 74 79 3B 00} // /AppActivity;
	$sig2 = {2F 4C 6F 63 6B 54 61 73 6B 3B 00} // /LockTask;
	$sig3 = {0A 72 65 63 65 6E 74 61 70 70 73 00} // recentapps
	$sig4 = {0B 68 6F 6D 65 63 6F 6E 74 72 6F 6C 00} // homecontrol
	$sig5 = {0E 63 68 65 63 6B 54 69 6D 65 42 79 44 61 79 00} // checkTimeByDay
	$sig6 = {16 6C 69 76 65 50 6C 61 74 66 6F 72 6D 41 64 43 61 74 65 67 6F 72 79 00} // livePlatformAdCategory

	condition:
		androguard.permission(/GET_TASKS/) and
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		((all of them) or
		(2 of them and androguard.certificate.sha1("C0ACB33AF5EC1F66835566F9273165CCF8F8FBA4"))
		)	
		
}
