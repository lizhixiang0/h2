/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: Cheshmak Network
    Rule id: 4582
    Created at: 2018-06-25 08:26:46
    Updated at: 2018-09-26 23:13:31
    
    Rating: #0
    Total detections: 165
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Cheshmak Network"

	condition:
		androguard.package_name("me.cheshmak.android.sdk.core") or
		androguard.url(/sdk\.cheshmak\.me/) or
		androguard.url(/cheshmak\.me/) or
		androguard.url(/123\.cheshmak\.me/)
}
