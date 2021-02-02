/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xo
    Rule name: AgentGenDetect
    Rule id: 1924
    Created at: 2016-10-20 06:43:42
    Updated at: 2016-10-20 06:46:05
    
    Rating: #0
    Total detections: 38
*/

import "androguard"

rule AgentGen : test
{
        meta:
                description = "Artemis Detecti ANDROID/Hiddad.P.Gen "
                sample = "7cf36007b51a319b3d1de2041a57c48a957965c9fe87194a5a7ab3303b50ea74"
        strings:

                $string_1 = "mmAUtjAeH"

        condition:
                $string_1 and
                androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") or
                androguard.url("http://apk-market.net/l2/aacc2ffc4d3e18ef12f908921ad235be")
}
