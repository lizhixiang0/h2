/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Ijiami Packer
    Rule id: 1596
    Created at: 2016-07-08 19:05:20
    Updated at: 2016-07-08 19:11:53
    
    Rating: #0
    Total detections: 19908
*/

rule packers : Ijiami
{
	meta:
		description = "This rule detects packers based on files used by them"

	strings:
		$Ijiami_1 = "libexecmain.so"
		$Ijiami_2 = "libexec.so"
		$Ijiami_3 = "ijiami.ajm"
	condition:
		all of them
		
}
