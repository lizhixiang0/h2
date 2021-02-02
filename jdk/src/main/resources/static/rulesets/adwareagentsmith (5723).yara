/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Adware.AgentSmith
    Rule id: 5723
    Created at: 2019-07-10 22:20:55
    Updated at: 2019-07-18 16:08:55
    
    Rating: #2
    Total detections: 3
*/

//https://research.checkpoint.com/agent-smith-a-new-species-of-mobile-malware/


import "androguard"



rule main
{

	meta:
		description = "Identify Agent Smith core app"
		sample_analysis = "https://www.hybrid-analysis.com/sample/a3e95b5774c3f4d0f742fbc61ec0b3536deba4388840a398a8ec9c3eb351a177"
	
	
	strings:
		$a1 = "adsdk.zip"
		$a2 = "boot.zip"
		$a3 = "patch.zip"
				
		$b1 = "com.infectionAds.AdsManagement"
		$b2 = "com.infectionAds.AdmobPulic"
		$b3 = "com.infectionapk.patchMain"
		
		$c1 = /assets\/fonts\/DIsplay[0-9]*\.jpg/  //Encrypted malware


	condition:
		2 of ($a*) and (any of ($b*) or any of ($c*))

		
}



rule dropper
{

	meta:
		description = "Identifies a few known dropper apps"
		sample_analysis = "https://www.hybrid-analysis.com/sample/850253669b80ea2bf3ab02b3035ee330a8b718d7690f3fc0bf5d11b29e71b6ca/5d262933038838e412e9d9d1"
	
	
	//strings:
		//$b1 = "androVM.vbox_dpi"
		//$b2 = "qemu.sf.fake_camera"
	
	
	condition:
		androguard.certificate.sha1("895d1abd26aaf7da4e52d37fa37d4e4a08bd5ca2") and
		(androguard.package_name("com.cool.temple007") or
		androguard.package_name("com.cool.rabbit.temple"))
				
}



rule JaguarKillSwitch : dropper_variant
{

	meta:
		description = "Identify (currently) dormant variants of Agent Smith droppers containing the 'Jaguar Kill Switch'"
	
	
	strings:
		$a1 = /com[\.\/]jaguar/
		$a2 = "hippo-sdk"
				
		$b1 = /tt.androidcloud.net/
		$b2 = /sdk.ihippogame.com/
		$b3 = /sdk.soonistudio.com/
		

	condition:
		all of ($a*) and any of ($b*)

}
