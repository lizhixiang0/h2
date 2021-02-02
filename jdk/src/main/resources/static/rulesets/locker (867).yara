/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Locker
    Rule id: 867
    Created at: 2015-09-27 17:15:33
    Updated at: 2015-09-27 17:19:01
    
    Rating: #0
    Total detections: 0
*/

rule locker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "45b74b69378429e7670e50e3e4d502baf701cf33fbbf341125b998dc8c316369"
		sample2 = "76187efe8a59128b5becb4f13812b846edda58e270579b6938269ce24d2b2e9b"
		sample3 = "50f39306f85f4f26c272c46068bdc995fec3433d7671fdb68506e5777c983043"
		sample4 = "f467d7e0c0fc8b5a02859ab40545205baf92919fa391a24fc38b4ccb54d919ed"

	strings:
		$a = "4Landroid/hardware/camera2/CameraCharacteristics$Key;"
		$b = "yYE-[xX>i"
		$c = "/You device will be unprotectable. Are you sure?"
		$d = "8android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED"

	condition:
		all of them
		
}
