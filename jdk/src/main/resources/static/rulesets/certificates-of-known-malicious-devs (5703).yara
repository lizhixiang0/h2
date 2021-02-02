/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Certificates of known malicious devs
    Rule id: 5703
    Created at: 2019-07-09 21:33:16
    Updated at: 2019-07-20 12:40:17
    
    Rating: #0
    Total detections: 25
*/

import "androguard"


rule certificates
{
	meta:
		description = "Identifies apps signed with certificates that are known to be from developers who make malicious apps"
			
	condition:
		androguard.certificate.sha1("2FC3665C8DAAE9A61CB7FA26FB3FEDE604DA4896") or
		androguard.certificate.sha1("3645AF60F8302526D376405C596596158379C7C2")

}
