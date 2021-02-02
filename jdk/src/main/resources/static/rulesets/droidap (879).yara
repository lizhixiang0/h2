/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: DroidAp
    Rule id: 879
    Created at: 2015-10-02 11:32:33
    Updated at: 2015-10-02 17:48:40
    
    Rating: #0
    Total detections: 594
*/

rule droidap
{
	meta:
		description = "This rule detects DroidAp trojans"
		sample = "4da3d9ed1a02833496324263709bebe783723e1c14755c080449a28f6aa111dc"
		sample2 = "c4c9b79d288b0a38812b81e62d41a49e3b79fb8b04c58376c26c920547e23ac3"
		sample3 = "51f93aa72ca0364860e6bffccc1bef5171692275650d9e1988d37ce748ea0558"
		reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Andr~DroidAp-A/detailed-analysis.aspx"

	strings:
		$a = "_DroidPhoneStateListener.java"
		$b = "nameOfElement1"
		$c = "3 fjPjJj"

	condition:
		all of them
		
}

rule droidap2
{
	meta:
		description = "This rule detects DroidAp trojans"
		sample = "ad3cd118854e939ab6a9bb6e98b63740e353ab96116f980de0d76fa698e0577a"
		sample2 = "b9a9b500068fd8afaf341fd6290834c3437f62e04701922336644a26bfc7a6d8"
		sample3 = "f31116a7f8639d91288baa868222984e90556b2832a444f2ef3beccd8c6def3e"
		reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Andr~DroidAp-A/detailed-analysis.aspx"

	strings:
		$a = "KWM4oC=0_"
		$b = "Name: classes.dey"
		$c = "com.hbw.droidapp.FromAlarm"

	condition:
		all of them
		
}
