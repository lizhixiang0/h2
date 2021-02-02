/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: AndroRat
    Rule id: 1576
    Created at: 2016-07-06 08:59:54
    Updated at: 2016-07-06 09:02:15
    
    Rating: #0
    Total detections: 4527
*/

import "androguard"

rule Android_AndroRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-July-2016"
		description = "This rule will be able to tag all the AndroRat samples."
		source = "http://www.symantec.com/connect/nl/blogs/remote-access-tool-takes-aim-android-apk-binder"

	condition:
		androguard.service(/my.app.client/i) and
        androguard.receiver(/BootReceiver/i) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/i)
}
