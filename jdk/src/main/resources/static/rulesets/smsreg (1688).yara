/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReg
    Rule id: 1688
    Created at: 2016-07-28 10:25:00
    Updated at: 2016-07-28 12:09:13
    
    Rating: #0
    Total detections: 2660
*/

rule SMSReg
{
        meta:
                description = "This rule detects SMSReg apps"
                sample = "ed3c5d4a471ee4bf751af4b846645efdeafcdd5f85c1f3bdc58b84119b7d60e8"
				packagename = "com.sm.a36video1"

        strings:
                $a = "kFZFZUIF"
                $b = "btn_title_shop"
                $c = "more_about_version" wide
                $d = "$on}$fxfThjfnyj$hdembl;"
                $e = "ad_video_vip" wide

        condition:
                all of them

}
