/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: Slempo targeting installed Apps
    Rule id: 2407
    Created at: 2017-04-04 08:12:12
    Updated at: 2017-04-26 13:40:25
    
    Rating: #1
    Total detections: 68
*/

import "androguard"


rule Slempo : targeting installed Apps
{
	meta:
		description = "Banker 'Slempo' targeting installed Apps with Overlay"

	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		
		$installedAppsMethod = "getInstalledAppsList"
		
	condition:
		3 of ($command_*)
		and $installedAppsMethod
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule Slempo_2 : targeting MastercardData
{

	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		
		$overlay = "mastercard_securecode_logo"
		
	condition:
		3 of ($command_*)
		and $overlay
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}
