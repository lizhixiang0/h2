/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Dendroid
    Rule id: 1409
    Created at: 2016-05-19 14:06:05
    Updated at: 2016-07-27 02:42:21
    
    Rating: #1
    Total detections: 1186
*/

import "androguard"

rule Android_Dendroid
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"

	condition:
		(androguard.service(/com.connect.RecordService/i) or
		androguard.activity(/com.connect.Dendroid/i)) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}
