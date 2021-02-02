/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan Switcher
    Rule id: 2100
    Created at: 2017-01-05 09:34:42
    Updated at: 2017-01-05 09:34:58
    
    Rating: #0
    Total detections: 70
*/

rule Trojan_Switcher {
	meta:
	sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
	description = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
		
	strings:
		$dns1 = "101.200.147.153"
		$dns2 = "112.33.13.11"
		$dns3 = "120.76.249.59"
		
		$account1 = "admin:00000000@"
		$account2 = "admin:000000@"
		$account3 = "admin:0123456789@"
		$account4 = "admin:110110@"
		$account5 = "admin:110120@"
		$account6 = "admin:1111111@"
		$account7 = "admin:111111@"
		$account8 = "admin:11223344@"
		$account9 = "admin:112233@"
		$account10= " admin:123123123@"
		$account11= " admin:123123@"
		$account12= " admin:1234567890@"
		$account13= " admin:123456789@"
		$account14= " admin:123456789a@"
		$account15= " admin:12345678@"
		$account16= " admin:123456@"
		$account17= " admin:147258369@"
		$account18= " admin:5201314@"
		$account19= " admin:520520@" 
		$account20= " admin:66666666@"
		$account21= " admin:666666@"
		$account22= " admin:66668888@"
		$account23= " admin:789456123@"
		$account24= " admin:87654321@"
		$account25= " admin:88888888@"
		$account26= " admin:888888@"
		$account27= " admin:987654321@"
		$account28= " admin:admin@" 
		
	condition:
		1 of ($dns*) and 2 of ($account*)
		
}
