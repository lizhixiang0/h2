/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: OmniRat
    Rule id: 1779
    Created at: 2016-08-30 12:35:18
    Updated at: 2016-09-16 14:25:23
    
    Rating: #0
    Total detections: 39
*/

import "androguard"

rule koodous : official
{
	meta:
		description = "This rule detects omnirat trojan"
		sample = "43e9ffbb92929e3abd652fdd03091cc4f63b33976c7ddbba482d20468fee737a"

	strings:
		$a = "com.android.engine"
		$b = "divideMessage"

	condition:
		$a and $b and 
		androguard.permission(/com\.android\.launcher\.permission\.UNINSTALL_SHORTCUT/) and
		androguard.permission(/com\.android\.browser\.permission\.READ_HISTORY_BOOKMARKS/) and
		androguard.permission(/com\.android\.browser\.permission\.WRITE_HISTORY_BOOKMARKS/) and
		androguard.permission(/com\.android\.launcher\.permission\.INSTALL_SHORTCUT/) and
		androguard.permission(/android\.permission\.TRANSMIT_IR/) and
		androguard.permission(/android\.permission\.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android\.permission\.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android\.permission\.BLUETOOTH/) and
		androguard.permission(/android\.permission\.CAMERA/) and
		androguard.permission(/android\.permission\.INTERNET/) and
		androguard.permission(/android\.permission\.BLUETOOTH_ADMIN/) and
		androguard.permission(/android\.permission\.MANAGE_ACCOUNTS/) and
		androguard.permission(/android\.permission\.SEND_SMS/) and
		androguard.permission(/android\.permission\.WRITE_SMS/) and
		androguard.permission(/android\.permission\.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android\.permission\.SET_WALLPAPER/) and
		androguard.permission(/android\.permission\.READ_CALL_LOG/) and
		androguard.permission(/android\.permission\.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android\.permission\.RECORD_AUDIO/) and
		androguard.permission(/android\.permission\.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android\.permission\.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android\.permission\.AUTHENTICATE_ACCOUNTS/) and
		androguard.permission(/android\.permission\.CALL_PHONE/) and
		androguard.permission(/android\.permission\.READ_PHONE_STATE/) and
		androguard.permission(/android\.permission\.READ_SMS/) and
		androguard.permission(/android\.permission\.VIBRATE/) and
		androguard.permission(/android\.permission\.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android\.permission\.ACCESS_WIFI_STATE/) and
		androguard.permission(/android\.permission\.WAKE_LOCK/) and
		androguard.permission(/android\.permission\.CHANGE_WIFI_STATE/) and
		androguard.permission(/android\.permission\.RECEIVE_SMS/) and
		androguard.permission(/android\.permission\.READ_CONTACTS/) and
		androguard.permission(/android\.permission\.DOWNLOAD_WITHOUT_NOTIFICATION/) and
		androguard.permission(/android\.permission\.GET_ACCOUNTS/)
		
}
