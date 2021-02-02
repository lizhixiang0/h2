/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Ransomware.RU
    Rule id: 2396
    Created at: 2017-03-31 08:55:07
    Updated at: 2017-04-03 13:00:46
    
    Rating: #0
    Total detections: 5
*/

rule Ransomware
{
	meta:
		description = "https://www.zscaler.de/blogs/research/new-android-ransomware-bypasses-all-antivirus-programs"


	strings:
		$a = "SHA1-Digest: xIzMBOypVosF45yRiV/9XQtugE0=" nocase


	condition:
		1 of them
		
}

rule Locker
{
	strings:
		$a = "SHA1-Digest: CbQPkm4OYwAEh3NogHhWeN7dA/o=" nocase
		
	condition:
		1 of them

}
