/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xoreax
    Rule name: Android/Iop
    Rule id: 1570
    Created at: 2016-07-05 09:18:20
    Updated at: 2016-07-05 10:48:13
    
    Rating: #0
    Total detections: 688
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the Android/Iop Malware"
		sample = "04addfd91ce7c31ce7e328dc310bafe0d7cf5ffc633fe1c5f2bc8a63a5812b07"

	strings:
		$a = "android.intent.action.USER_PRESENT"
		$b = "aHR0cHM6Ly93d3cuYmFpZHUuY29tLw=="
		$c = "IHN0YXJ0IC0tdXNlciAwIA=="
		$d = "/httpTrack"
		$e = "http://noicon.117q.com"
		$f = "android.intent.action.TIME_TICK"

	condition:
		all of them
}
