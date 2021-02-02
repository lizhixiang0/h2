/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Ransom-FBI
    Rule id: 1863
    Created at: 2016-09-30 11:44:16
    Updated at: 2016-09-30 11:45:25
    
    Rating: #1
    Total detections: 6137
*/

rule FBI: ransomware
{
	meta:
		sample = "d7c5cb817adfa86dbc9d9c0d401cabe98a3afe85dad02dee30b40095739c540d"

	strings:
		$a = "close associates will be informed by the authorized FBI agents" wide ascii
		$b = "ed on the FBI Cyber Crime Department's Datacenter" wide ascii
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar" wide ascii

	condition:
		all of them
}
