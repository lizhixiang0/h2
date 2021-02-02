/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSSend
    Rule id: 1554
    Created at: 2016-06-30 10:51:40
    Updated at: 2016-07-02 09:59:24
    
    Rating: #1
    Total detections: 323782
*/

rule SMSSend
{
	meta:
		description = "This rule detects applications that send SMSs"
		sample = "ee95d232e73ba60cbe31dbae820c13789b5583b1b972df01db24d2d2159446d7"

	strings:
		$a = "\" cmcc = \"21\" cuc = \"50\" cnc = \"\">20</province>" wide ascii
		$b = "\" cmcc = \"10\" cuc = \"36\" cnc = \"\">19</province>" wide ascii
		$key_file = "assets/keycode.txtbinlangPK"

	condition:
		any of them
		
}
