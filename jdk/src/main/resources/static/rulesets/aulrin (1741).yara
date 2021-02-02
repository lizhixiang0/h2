/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Aulrin
    Rule id: 1741
    Created at: 2016-08-14 15:37:33
    Updated at: 2018-07-25 10:09:44
    
    Rating: #0
    Total detections: 21
*/

import "androguard"

rule Android_Aulrin
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect Aulrin. This"
	condition:
		androguard.receiver(/z.core.OnBootHandler/i) and
		androguard.receiver(/z.core.SMSReciever/i) and
		androguard.service(/z.core.RunService/i) and
		androguard.activity(/xamarin.media.MediaPickerActivity/i) and 
        androguard.permission(/android.permission.CHANGE_COMPONENT_ENABLED_STATE/i)
}
