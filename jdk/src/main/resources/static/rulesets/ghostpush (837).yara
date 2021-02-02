/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: GhostPush
    Rule id: 837
    Created at: 2015-09-21 08:57:53
    Updated at: 2015-09-21 08:58:51
    
    Rating: #1
    Total detections: 1410
*/

rule ghostpush
{
	meta:
		sample = "bf770e42b04ab02edbb57653e4e0c21b2c983593073ad717b82cfbdc0c7d535b"

	strings:
		$a = "assets/import.apkPK"
		$b = "assets/protect.apkPK"

	condition:
		all of them
		
}
