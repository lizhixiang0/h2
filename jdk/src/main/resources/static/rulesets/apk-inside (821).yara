/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: APK inside
    Rule id: 821
    Created at: 2015-09-11 08:58:12
    Updated at: 2015-11-20 06:14:09
    
    Rating: #0
    Total detections: 265
*/

rule apk_inside
{
	meta:
		description = "This rule detects an APK file inside META-INF folder, which is not checked by Android system during installation"
		inspiration = "http://blog.trustlook.com/2015/09/09/android-signature-verification-vulnerability-and-exploitation/"

	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
		
}
