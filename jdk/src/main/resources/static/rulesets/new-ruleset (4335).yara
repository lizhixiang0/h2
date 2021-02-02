/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 4335
    Created at: 2018-04-13 09:04:35
    Updated at: 2018-04-13 09:05:33
    
    Rating: #0
    Total detections: 302
*/

import "androguard"
import "file"
import "cuckoo"


rule BankBot : banker
{
	meta:
		description = "bankbot samples"

	strings:

		$strings_a = "de.dkb.portalapp"
		$strings_b = "de.adesso.mobile.android.gadfints"
		$strings_c = "de.commerzbanking.mobil"
		$strings_d = "de.ing_diba.kontostand"
		$strings_e = "de.postbank.finanzassistent"
		$strings_f = "com.isis_papyrus.raiffeisen_pay_eyewdg"

	

	condition:
		2 of ($strings_*)
}
