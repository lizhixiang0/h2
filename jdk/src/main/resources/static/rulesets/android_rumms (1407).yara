/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Android_RuMMS
    Rule id: 1407
    Created at: 2016-05-19 13:13:57
    Updated at: 2016-07-02 04:12:25
    
    Rating: #0
    Total detections: 2119
*/

import "androguard"

rule Android_RuMMS
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detects Android.Banking.RuMMS"
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		(androguard.service(/\.Tb/) and 
		 androguard.service(/\.Ad/) and 
		 androguard.receiver(/\.Ac/) and 
		 androguard.receiver(/\.Ma/)) or
        (androguard.url(/http\:\/\/37\.1\.207/) and 
		 androguard.url(/\/api\/\?id\=7/))
		
}
