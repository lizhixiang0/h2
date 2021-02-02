/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: baal
    Rule name: CyberPolice ransomware
    Rule id: 1440
    Created at: 2016-05-26 17:28:10
    Updated at: 2016-05-26 18:54:29
    
    Rating: #0
    Total detections: 16
*/

import "androguard"



rule CyberPolice_ransomware
{
	meta:
		description = "CyberPolice Ransomware"
		sample = "0d369ed70cfe7fc809b7e963df22703d078bd881cd75404da8bf610423e9b12a"

	strings:
		$a = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACABAMAAAAxEHz4AAAAGFBMVEVMaXGUwUWTwEaT"
		$b = "assets/anthology.apk"
		$c = "assets/assets/responded.bmp"

	condition:
		androguard.permission(/android.permission.ACCESS_COARSE_UPDATES/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.RESTART_PACKAGES/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WRITE_SETTINGS/) and	
		androguard.permission(/android.permission.WRITE_CONTACTS/) and

		$a and ($b or $c)
		
}
