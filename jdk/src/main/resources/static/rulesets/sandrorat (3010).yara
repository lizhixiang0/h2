/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roskyfrosky
    Rule name: SandroRAT
    Rule id: 3010
    Created at: 2017-06-20 14:47:59
    Updated at: 2017-06-20 18:45:12
    
    Rating: #0
    Total detections: 1361
*/

import "androguard"
import "file"
import "cuckoo"


rule SandroRAT{

	meta :
		description = "rule for detected SandroRAT Samples"

	strings:
		$a = "SandroRat_Configuration_Database"
		$b = "SandroRat_BrowserHistory_Database"
		$c = "SandroRat_Configuration_Database"
		$d = "SandroRat_CallRecords_Database"
		$e = "SandroRat_RecordedSMS_Database"
		$f = "SandroRat_CurrentSMS_Database"
		$g = "SandroRat_Contacts_Database"

	condition:
		any of them or 
		androguard.receiver(/net.droidjack.server/i) or
		androguard.package_name("net.droidjack.server")
		


}
