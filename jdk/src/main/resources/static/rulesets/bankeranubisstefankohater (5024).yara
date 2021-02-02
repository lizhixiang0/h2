/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker.Anubis.StefankoHater
    Rule id: 5024
    Created at: 2018-10-30 13:48:03
    Updated at: 2018-10-30 13:52:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"
import "droidbox"


rule anubis_stefanko_hater
{
	meta:
		description = "Trojan-Banker.AndroidOS.Anubis"
		
	condition:
		( droidbox.written.data(/stefan/i) or droidbox.written.data(/lukas/i) ) and 
		droidbox.written.data(/spamSMS/i) and
		droidbox.written.data(/indexSMSSPAM/i) and
		droidbox.written.data(/RequestINJ/i) and
		droidbox.written.data(/VNC_Start_NEW/i) and
		droidbox.written.data(/keylogger/i) 
		
}
