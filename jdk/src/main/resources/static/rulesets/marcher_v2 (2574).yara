/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: Marcher_v2
    Rule id: 2574
    Created at: 2017-04-27 09:43:18
    Updated at: 2017-06-08 12:05:27
    
    Rating: #1
    Total detections: 730
*/

import "androguard"
import "file"
import "cuckoo"


rule Marcher : more obfuscated versions
{
	meta:
		description = "This rule detects more obfuscated versions of marcher - 2017-04-27"
		sample = "e5ee5285b004faf53fca9b7c5e2c74316275413ef92f3bcd3a457c9b81a1c13e"

	strings:
		$string_1 = "gp_dialog_password" nocase
		$string_2 = "Visa password" nocase
		$string_3 = "Amex SafeKey password" nocase
		$string_4 = "Secure Code Password" nocase

	condition:
		2 of ($string_*)
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.GET_TASKS/)
		and androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}

rule Marcher2 : more obfuscated versions
{
	meta:
		description = "This rule detects more obfuscated versions of marcher - 2017-06-08"
		sample = "a61e97e4b1fa49560dd6d08e2a135b0bf6c27550953671d56ca37b95f017b19d"

	strings:
		$string_gp = "gp_dialog_password" nocase
		$string_cc_1 = "amex_verified" nocase
		$string_cc_2 = "mastercard_verified" nocase
		$string_cc_3 = "visa_verified" nocase

	condition:
		$string_gp
		and 1 of ($string_cc_*)
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		and androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}
