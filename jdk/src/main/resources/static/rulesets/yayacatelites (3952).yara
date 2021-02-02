/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaCatelites
    Rule id: 3952
    Created at: 2018-01-04 15:37:10
    Updated at: 2018-01-04 15:38:24
    
    Rating: #0
    Total detections: 34
*/

import "androguard"
import "cuckoo"


rule YaYaCatelites: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "04 Jan 2018"
		url = "https://koodous.com/apks?search=0e741a21228f4f7ffdbb891524f3a246b60bee287965a74fe15009127f6de280%20OR%20%2014c7e547cb8dc8f5d629725fdbdd2e8c33693dd407b2f36cd03c613e59af2cc7%20OR%20%20efe6d86d7482fbcb5b1e7e12e22c2b086e4ec988939ebdffc9d363413e5a3326%20OR%20%20bf6a4b8c24cd4cf233137dcee735bc33849d34e659ec2fa5e0fa9b425fee9b4e%20OR%20%20e174dd174c5e21daa86064562aaf274d3f6fe84f4a3970beed48c02c3b605d58%20OR%20%20b81e0b6fe123b8d4cf7d99c20de1c694360d146bf80d9490b1b0325a00bf7f5a%20OR%20%200c50311ee3e30fe5be1b863db1b60b32bc9afa8d4264b852a836220751c7e3b2%20OR%20%20d8452b39b1962239e9dbe12e8a9d8d0ee098b9c8de8a8d55b5a95b67b552102f%20OR%20%2053dc796e2e77689b115701a92ad2bdaeb0c7a4e87bc9e9a0bbeda057b77e22ee"

	condition:
		androguard.app_name("System Application") and 

		androguard.filter("android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON")
}
