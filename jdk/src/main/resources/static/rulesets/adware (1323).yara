/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Adware
    Rule id: 1323
    Created at: 2016-03-29 15:36:26
    Updated at: 2016-03-29 15:39:41
    
    Rating: #0
    Total detections: 384
*/

rule adware
{
	meta:
		//description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "28e2d0f5e6dca1b108bbdc82d8f80cfbf9acd1df2e89f7688a98806dc01a89ba"
		search = "package_name:com.blackbean.cnmeach"

	strings:
		$a = "CREATE TABLE IF NOT EXISTS loovee_molove_my_date_history"
		$b = "loovee_molove_my_dating_task_delete_bak"

	condition:
		all of them
		
}
