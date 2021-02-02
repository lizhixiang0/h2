/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Gunpoder
    Rule id: 873
    Created at: 2015-09-29 05:26:50
    Updated at: 2015-09-29 06:02:53
    
    Rating: #0
    Total detections: 558
*/

rule gunpoderType1
{
	meta:
		sample = "4a0da8da1116fbc6d85057110d1d8580dcc5f2746e492415f0f6c19965e71c9c"
		sample2 = "68d3548306c9667b4d1a6e483cbf2d2f7566213a639316512d4958ff0b2e8f94"
		sample3 = "77ee18a207bb79c86fa5976b9f5a4fe36f4ecd429dc9846fa71c6585b6df85b5"
		sample4 = "844ba4b96b7f1df89a3e31544cf22bac9acf1ab97a4d9972daf8aa3fbb149c37"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"

	strings:
		$a = "stopWaitSMS"
		$b = "saldo de PayPal o su tarjeta de"
		$c = "name=\"cc_card_expires\">Expires MM"
		$d = "CardIOActivity"

	condition:
		all of them
		
}

rule gunpoderType2
{
	meta:
		sample = "2788c90a320f3cd8fac34a223b868c830ce2b3702b648bcecc21b3d39d3618f3"
		sample2 = "99ad2bb26936a7178bc876f1cdc969c8b0697f4f63f3bdd29b0fff794af4b43c"
		sample3 = "2c5251ce74342d0329dd8acc5a38c2a96a1d6ee617857aca8d11e2e818e192ce"
		sample4 = "bac759e73bf3b00a25ff9d170465219cb9fb8193adf5bbc0e07c425cc02a811d"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"

	strings:
		$a = "\"Return of the Invaders\""
		$b = "cmd_proxy_destroy"
		$c = "mhtu119.bin"
		$d = "robocopu  \"Robocop (US revision 1)\""

	condition:
		all of them
		
}

rule gunpoderType3
{
	meta:
		sample = "00872f2b17f2c130c13ac3f71abb97a9f7d38406b3f5ed1b0fc18f21eaa81b50"
		sample2 = "28b3bd3b9eb52257c0d7709c1ca455617d8e51f707721b834efe1ad461c083f0"
		sample3 = "df411483f2b57b42fd85d4225c6029000e96b3d203608a1b090c0d544b4de5b0"
		sample4 = "72c5fd8b77e6e02396ff91887ba4e622ab8ee4ea54786f68b93a10fcfa32f926"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"

	strings:
		$a = "email_md5"
		$b = "10.0.0.172"
		$c = "66The lastest version has been downloaded, install now ?"
		$d = "0aHR0cHM6Ly9hcGkuYWlycHVzaC5jb20vdjIvYXBpLnBocA=="

	condition:
		all of them
		
}
