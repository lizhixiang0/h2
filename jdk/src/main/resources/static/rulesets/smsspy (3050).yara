/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSSpy
    Rule id: 3050
    Created at: 2017-06-27 10:05:38
    Updated at: 2017-06-27 10:09:08
    
    Rating: #0
    Total detections: 1010
*/

rule smsspy
{
	meta:
		description = "This rule detects SMSSpy from Korea"
		sample = "ed1541efb7052dfe76e5e17338d68b291d68e9115e33e28b326dc4b63c7bfded"

	strings:
		$a = "getBodyParts"
		$b = "audioMode"
		$c = "InsertContacts"
		$d = "where cnt_phone="
		$e = "CallStateReceiver.java"
		$f = "CallBlock"
		$g = "set cnt_block="
		$h = "cnt_mail text"
		$i = "bSMSBlockState"
		$j = "cnt_phone text"
		$k = "getsmsblockstate.php?telnum="
		
	condition:
		all of them
		
}
