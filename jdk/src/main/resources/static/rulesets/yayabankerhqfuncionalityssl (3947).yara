/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaBankerHQFuncionalitySSL
    Rule id: 3947
    Created at: 2018-01-03 14:19:59
    Updated at: 2018-01-10 14:25:33
    
    Rating: #0
    Total detections: 14
*/

import "androguard"
import "cuckoo"


rule YaYaBankerHQFuncionalitySSL: rule0 {
	meta:
		author = "YaYaGen --/ Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=204f2e5e18691156036cbcfc69fa759272a2180fba77a74415ccb2c7469a670b%20OR%2086aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"

	condition:
		
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\?\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\?\:\\\\b\|\$\|\^\)\(\?\:\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \'https\:\/\/\'/)
}
