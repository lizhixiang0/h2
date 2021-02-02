/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: anubisNew_July2019
    Rule id: 5724
    Created at: 2019-07-10 23:30:19
    Updated at: 2019-07-10 23:31:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule anubisNew_July2019 {

        meta:
                md5="3157e807e597bcd89f9af94e512583f6"
				blog="https://blog.trendmicro.com/trendlabs-security-intelligence/anubis-android-malware-returns-with-over-17000-samples/"

        strings:
                $a1 = "android.permission.WRITE_EXTERNAL_STORAGE"
                $a2 = "android.permission.READ_EXTERNAL_STORAGE"

                $b1 = "level_name"
                $b2 = "password"
                $b3 = "username"
                $b4 = "salary"
                $b5 = "name"
                $b6 = "id"
                $b7 = "employee"

                $c1 = "aHR0cDovL21hcmt1ZXpkbmJycy5vbmxpbmUvZGVuZW1lL2FwaTIucGhw"
                $c2 = "kdv.xml"
                $c3 = "aHR0cDovL3N1Y2Nlc3Npb25kYXIueHl6L2NvbnRpbnVpbmcvcmVzaWduZWQucGhw"
                $c4 = "config.xml"

        condition:
                all of ($a*) and
                all of ($b*) and
                2 of ($c*)
}
