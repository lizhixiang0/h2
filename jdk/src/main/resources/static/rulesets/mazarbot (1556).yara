/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: MazarBot
    Rule id: 1556
    Created at: 2016-07-02 04:11:18
    Updated at: 2016-07-05 05:53:31
    
    Rating: #0
    Total detections: 473
*/

import "androguard"

rule Android_MazarBot
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects MazarBot"
		source = "https://heimdalsecurity.com/blog/security-alert-new-android-malware-post-denmark/"

	condition:
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/reportsent/i)) or
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/com\.whats\.process/i))
}
