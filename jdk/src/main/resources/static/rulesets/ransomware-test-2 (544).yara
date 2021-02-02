/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Ransomware Test 2
    Rule id: 544
    Created at: 2015-06-02 15:25:35
    Updated at: 2015-08-06 15:20:12
    
    Rating: #1
    Total detections: 40741
*/

//c1e886861285757750107327840b79048eeb81d30a44326b485c1b291dbc5ab4
//abff543c25194d64e509a6cb64d31233529516a3c4a32252e63b6c518f641f36
//567afc8029ba5bb52bb46a9d76eff8ee9ec0ebbe748f255b13989353b3a5262f
//cd83e81a6925822b4af84aa2c67c06a15740e9219bc5f21e3d67d6f47764674d

rule Ransomware : banker
{
	meta:
		description = "Ransomware Test 2"
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "!2,.B99^GGD&R-"
		$strings_b = "22922222222222222222Q^SAAWA"
		$strings_c = "t2222222222229222Q^SAAWA"

	

	condition:
		any of ($strings_*)
}
