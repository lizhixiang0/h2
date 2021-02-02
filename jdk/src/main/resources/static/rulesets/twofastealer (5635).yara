/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: TwoFaStealer
    Rule id: 5635
    Created at: 2019-06-21 00:08:31
    Updated at: 2019-07-02 17:33:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule TwoFaStealer
{
	meta:
		sample = "126547985987c3ecb1321a3a565d8565b64d437fd28418a6ba4bbc3220f684d2"
		description = "This rule detects samples that steal 2fa from the notifications"
		blog = "https://www.welivesecurity.com/2019/06/17/malware-google-permissions-2fa-bypass/"
	strings:
		$a1 = "code_servise"
        $a2 = "code_maiin"
        $a3 = "coin"
        $a4 = "ACTION_NOTIFICATION_LISTENER_SETTINGS"
  

	condition:
		all of ($a*)

}
