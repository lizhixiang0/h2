/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: FalseGuide
    Rule id: 2567
    Created at: 2017-04-26 11:17:43
    Updated at: 2017-04-27 08:30:24
    
    Rating: #0
    Total detections: 29
*/

import "androguard"


rule FalseGuide
{
	meta:
		description = "http://blog.checkpoint.com/2017/04/24/falaseguide-misleads-users-googleplay/"
		sample = "9d8888f3e8a3ce16108827333af3447c"

	condition:
	  (androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")and
	  androguard.filter("android.intent.action.BOOT_COMPLETED")and
	  androguard.filter("android.intent.action.MAIN")and
	  androguard.filter("android.intent.action.QUICKBOOT_POWERON")and
	  androguard.filter("com.android.vending.INSTALL_REFERRER")and
	  androguard.filter("com.google.android.c2dm.intent.RECEIVE")and
	  androguard.filter("com.google.android.c2dm.intent.REGISTRATION")and
	  androguard.receiver("com.google.android.gms.measurement.AppMeasurementInstallReferrerReceiver")and
	  androguard.receiver("com.google.android.gms.measurement.AppMeasurementReceiver")and
	  androguard.receiver("com.google.firebase.iid.FirebaseInstanceIdInternalReceiver")and
	  androguard.receiver("com.google.firebase.iid.FirebaseInstanceIdReceiver")and
	  androguard.receiver("com.yandex.metrica.MetricaEventHandler")and
	  androguard.receiver(/AdminReceiver/)and
	  androguard.receiver(/BootReceiver/)and
	  androguard.service("com.flymob.sdk.common.server.FlyMobService")and
	  androguard.service("com.google.android.gms.measurement.AppMeasurementService")and
	  androguard.service("com.google.firebase.iid.FirebaseInstanceIdService")and
	  androguard.service("com.google.firebase.messaging.FirebaseMessagingService")and
	  androguard.service("com.yandex.metrica.MetricaService") and
	  androguard.service(/MessagingService/) and
	  androguard.service(/MyService/)) or
	  
	  androguard.certificate.sha1("FBE76CAE248E420E0D02F3E7362F8C3C1CEC75C4") or
	  androguard.certificate.sha1("630CC5A2192230B02BE7ED89164514D1E971E4BA") or
	  androguard.certificate.sha1("D0A83D20D80C29F35A84FBDE45F61E2B867C199B")
	  		
}
