/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Ransomware_cromosome
    Rule id: 1583
    Created at: 2016-07-06 16:43:07
    Updated at: 2016-07-06 16:53:24
    
    Rating: #0
    Total detections: 8573
*/

rule ransomware : from_cromosome
{
	meta:
		description = "This rule detects ransomware"
		sample = "created with the help of cromosome.py and a ransomware dataset with the families fakedefender, kiler, pletor, ransombo, scarepackage, slocker and svpeng "

	strings:

	$cromo_0 ="android.app.device_admin"
	$cromo_1 ="AndroidManifest.xmlPK"
	$cromo_2 ="$Landroid/telephony/TelephonyManager;"
	$cromo_3 ="$android.permission.BIND_DEVICE_ADMIN"
	$cromo_4 ="*Landroid/content/SharedPreferences$Editor;"
	$cromo_5 ="getSharedPreferences"
	$cromo_6 ="'android.app.action.DEVICE_ADMIN_ENABLED"
	$cromo_7 ="&android.permission.SYSTEM_ALERT_WINDOW"
	$cromo_8 =")android.permission.RECEIVE_BOOT_COMPLETED"
	$cromo_9 =")android.permission.WRITE_EXTERNAL_STORAGE"
	$cromo_10 ="$android.intent.action.BOOT_COMPLETED"
	$cromo_11 ="android.intent.category.HOME"
	$cromo_12 ="android.permission.GET_TASKS"
	$cromo_13 ="#Landroid/content/SharedPreferences;"
	$cromo_14 ="android.permission.READ_CONTACTS"
	$cromo_15 ="Landroid/os/Build;"
	$cromo_16 ="#android.permission.READ_PHONE_STATE"
	$cromo_17 ="'Landroid/app/admin/DevicePolicyManager;"
	$cromo_18 ="'Landroid/app/admin/DeviceAdminReceiver;"


	

	condition:
		16 of them
	
		
}
