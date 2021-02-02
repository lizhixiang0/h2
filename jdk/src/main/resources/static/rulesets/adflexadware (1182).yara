/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: AdFlex.Adware
    Rule id: 1182
    Created at: 2016-02-08 10:37:42
    Updated at: 2016-02-13 12:59:28
    
    Rating: #0
    Total detections: 14905
*/

rule Adflex
{
	meta:
		description = "AdFlex SDK evidences"
		sample = "cae88232c0f929bb67919b98da52ce4ada831adb761438732f45b88ddab26adf"

	strings:
		$1 = "AdFlexSDKService" wide ascii
		$2 = "AdFlexBootUpReceiver" wide ascii
		$3 = "adflex_tracker_source" wide ascii
		$4 = "vn/adflex/sdk/AdFlexSDK" wide ascii

	condition:
		all of them
		
}
