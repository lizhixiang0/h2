/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RootSniff
    Rule name: Locker_K
    Rule id: 1581
    Created at: 2016-07-06 14:04:42
    Updated at: 2016-07-08 07:43:45
    
    Rating: #0
    Total detections: 3793
*/

import "androguard"

rule Locker_K
{
	meta:
		description = "This rulset detects the Android Screen Locker"
		date = "06-July-2016"
		sample = "e8c9bc0f37395572a6ad43a4f1e11f8eeb86b6f471f443714f6fb1bcb465e685"

	strings:
		$a = "<br>Do not turn off or reboot your phone during update"

	condition:
		androguard.filter(/DEVICE_ADMIN_ENABLED/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
		
}
