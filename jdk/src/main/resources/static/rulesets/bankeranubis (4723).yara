/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker.Anubis
    Rule id: 4723
    Created at: 2018-08-02 07:00:38
    Updated at: 2018-10-30 13:47:46
    
    Rating: #0
    Total detections: 194
*/

import "androguard"
import "cuckoo"
import "droidbox"


rule anubis
{
	meta:
		description = "Trojan-Banker.AndroidOS.Anubis"
		
	condition:
		droidbox.written.data(/spamSMS/i) and
		droidbox.written.data(/indexSMSSPAM/i) and
		droidbox.written.data(/RequestINJ/i) and
		droidbox.written.data(/VNC_Start_NEW/i) and
		droidbox.written.data(/keylogger/i) 
		
}
