/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SandroRat
    Rule id: 1142
    Created at: 2016-01-21 10:36:53
    Updated at: 2016-01-21 10:42:28
    
    Rating: #1
    Total detections: 11801
*/

rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"

	strings:
		$a = "SandroRat_Configuration_Database"
		$b = "SandroRat_BrowserHistory_Database"
		$c = "SandroRat_Configuration_Database"
		$d = "SandroRat_CallRecords_Database"
		$e = "SandroRat_RecordedSMS_Database"
		$f = "SandroRat_CurrentSMS_Database"
		$g = "SandroRat_Contacts_Database"

	condition:
		any of them
		
}
