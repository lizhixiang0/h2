/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mi3security
    Rule name: Risky Android Certificates
    Rule id: 2195
    Created at: 2017-01-28 19:57:28
    Updated at: 2017-02-06 00:36:56
    
    Rating: #0
    Total detections: 54839
*/

import "androguard"


rule risky_android_certificates {

	meta:
		description="An ongoing list of certificates that are used to create adware/malware"
		
	condition:							androguard.certificate.sha1("81:3A:3A:D3:7D:87:AA:36:12:0D:FE:C6:41:46:C3:11:DB:5F:4C:A9") or
		androguard.certificate.issuer(/BestToolbars/) or

		androguard.certificate.sha1("8C:BD:58:1C:77:76:7B:CA:B8:0C:D4:BE:DE:DD:5F:A2:A2:28:69:E8") or 
		androguard.certificate.issuer(/android-debug/) or

		androguard.certificate.sha1("62:71:54:7B:66:8C:E8:81:20:82:49:F8:59:5F:53:15:E3:90:EB:2E") or 
		androguard.certificate.issuer(/Chineseall/) or

		androguard.certificate.sha1("94:3B:C6:E0:82:7F:09:B0:50:B0:28:30:68:5A:76:73:4E:56:61:68") or 

		androguard.certificate.sha1("AC:9B:0D:8F:AE:26:2C:90:3A:E3:37:49:C0:C1:4B:D0:9F:64:B8:22") or 
		androguard.certificate.issuer(/Internet Widgits/) or

		androguard.certificate.sha1("BF:C7:3C:8C:C6:F0:DF:CC:90:EF:8B:E4:9B:2E:17:CB:B7:85:6F:EE") or 
		androguard.certificate.issuer(/Gall me/) or

		androguard.certificate.sha1("C6:7F:8F:C6:3E:25:C1:F2:D3:D3:62:32:10:D1:26:BC:96:AF:EE:69") or 
		androguard.certificate.issuer(/Alex Popov/) or

		androguard.certificate.sha1("E0:30:A3:1B:E3:12:FF:93:8A:AF:3F:31:49:34:B1:E9:2A:F2:5D:60") or 
		androguard.certificate.issuer(/hjgjhg/) or

androguard.certificate.sha1("DB:87:39:0F:55:B3:FE:B6:D7:A0:5C:64:6B:F0:97:91:67:13:73:CC") or
androguard.certificate.sha1("06:14:68:81:20:29:0A:8F:6F:88:8A:A6:EC:24:72:AF:A6:3E:8B:66")
}
