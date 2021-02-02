/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: SLocker.Ransomware
    Rule id: 619
    Created at: 2015-06-22 10:57:10
    Updated at: 2016-07-24 00:33:51
    
    Rating: #0
    Total detections: 249
*/

import "cuckoo"

rule SLocker
{
	meta:
        description = "SLocker variant ransomware gates/IP evidences"
		
	strings:
		$1 = "adobe/videoprayer/Sms"

   	condition:
		$1 or
    	cuckoo.network.http_get(/pha\?android_version/) or
		cuckoo.network.dns_lookup(/148.251.154.104/)
}

rule SLocker_notifications
{
	meta:
        description = "SLocker ransomware notifications"
		
	strings:
		$1 = { D094D0BED181D182D183D0BF20D0BA20D0B2D0B0D188D0B5D0BCD18320D183D181D182D180D0BED0B9D181D182D0B2D18320D0B2D180D0B5D0BCD0B5D0BDD0BDD0BE20D097D090D091D09BD09ED09AD098D0A0D09ED092D090D09D2C20D0B020D0B2D181D0B520D092D0B0D188D0B820D09BD098D0A7D09DD0ABD09520D094D090D09DD09DD0ABD0952028D0B2D0BAD0BBD18ED187D0B0D18F20D0B4D0B0D0BDD0BDD18BD0B520D0A1D09ED0A6D098D090D09BD0ACD09DD0ABD0A520D181D0B5D182D0B5D0B92C20D0B1D0B0D0BDD0BAD0BED0B2D181D0BAD0B8D18520D0BAD0B0D180D1822920D097D090D0A8D098D0A4D0A0D09ED092D090D09DD09DD0AB20D0B820D09FD095D0A0D095D09DD095D0A1D095D09DD0AB20D0BDD0B020D09DD090D0A820D181D0B5D180D0B2D0B5D180 } //Your phone is locked , and all your personal data
		$2 = { D092D0B2D0B5D0B4D0B8D182D0B520D0BDD0BED0BCD0B5D18020D182D0B5D0BBD0B5D184D0BED0BDD0B0202B33383039373231313436363220D0B820D0BDD0B0D0B6D0BCD0B8D182D0B520D0B4D0B0D0BBD0B5D0B5 } //Enter the phone number 380 972 114 662 and press next
   	
	condition:
		1 of them
}

rule SLocker_cyphers
{
	meta:
        description = "SLocker ransomware cyphers"
		
	strings:
		$A0 = "javax/crypto/Cipher"
		$A1 = "9UDrh3PmFT7utYzJ"
		$A2 = "tb24bOHQ7LIPGip6"
   	condition:
		all of ($A*)
}

rule ZerUnOkLoK_detect
{
	meta:
		description = "ZerUnOkLoK, related to SLocker/Ramsomware"
		sample = "7470b65a8c0008c456a235095ea7b1b932b38fe68b3059f48a4b979185030680 from https://koodous.com/apks/4762cf911137d59f615c608e7f344d38b305d9f6843ad540fc376e4ef80af92a"

	strings:
		$a = "ZerUnOkLoK"

	condition:
		$a
		
}

rule Slocker_components
{
	meta:
		sample = "cbf11c080a27986f7583e7838a580bd0f59d5a32ed00717c6d4a6eff58322822"

	strings:
		$1 = "com/android/commonwallsense/LockActivity"

	condition:
		1 of them
		
}
