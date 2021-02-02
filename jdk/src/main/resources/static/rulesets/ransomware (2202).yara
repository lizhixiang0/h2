/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roskyfrosky
    Rule name: Ransomware
    Rule id: 2202
    Created at: 2017-02-01 07:00:37
    Updated at: 2017-05-12 07:58:47
    
    Rating: #0
    Total detections: 244
*/

import "androguard"
import "file"
import "cuckoo"


rule ransomware
{
	meta:
		description = "This rule detects ransomware android app"
		sample = "b3a9f2023e205fc8e9ff07a7e1ca746b89a7db94a0782ffd18db4f50558a0dd8"

	strings:
		$a = "You are accused of commiting the crime envisaged"
	condition:
		androguard.package_name("com.android.locker") or
		androguard.package_name("com.example.testlock") or
		androguard.url(/api33\/api\.php/) or 
		$a
		
}
