/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SmsSend
    Rule id: 2029
    Created at: 2016-12-13 10:24:20
    Updated at: 2017-01-25 08:47:20
    
    Rating: #0
    Total detections: 960
*/

rule smssend
{
	meta:
		description = "This rule detects smssend trojan"
		sample = "fcfe5c16b96345c0437418565dbf9c09e9e97c266c48a3b04c8b947a80a6e6c3"

	strings:
		$a = "generatesecond"
		$b = "res/layout/notification_download_finished.xml"
		$c = "m_daemonservice"
		$d = "((C)NokiaE5-00/SymbianOS/9.1 Series60/3.0"
		$e = "respack.tar"

	condition:
		all of them
		
		
}
