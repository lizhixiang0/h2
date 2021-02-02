/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Generic.Agent
    Rule id: 1316
    Created at: 2016-03-28 14:31:06
    Updated at: 2016-12-02 10:27:39
    
    Rating: #0
    Total detections: 7425
*/

rule unknown
{
	meta:
		//description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "ee05cbd6f7862f247253aa1efdf8de27c32f7a9fc2624c8e82cbfd2aab0e9438"
		search = "package_name:com.anrd.bo"

	strings:
		$a = "543b9536fd98c507670030b9" wide
		$b = "Name: assets/su"

	condition:
		all of them
}
