/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: DroidPlugin_strict
    Rule id: 2184
    Created at: 2017-01-26 16:09:33
    Updated at: 2017-01-26 16:11:10
    
    Rating: #0
    Total detections: 9545
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Strings from droidplugin code"
		sample_based_on = "49ff608d2bdcbc8127302256dc7b92b12ea9449eb96255f9ab4d1da1a0405a1b"

	strings:
		$dbhook = "SQLiteDatabaseHook"
		$message_str = "preMakeApplication FAIL"

	condition:
		all of them

		
}
