/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: iBanking
    Rule id: 458
    Created at: 2015-05-01 19:21:08
    Updated at: 2015-08-06 15:20:01
    
    Rating: #0
    Total detections: 152
*/

rule Android_Malware : iBanking
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}
