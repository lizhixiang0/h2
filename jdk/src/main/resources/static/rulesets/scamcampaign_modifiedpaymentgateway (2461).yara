/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: silverfoxy
    Rule name: ScamCampaign_ModifiedPaymentGateway
    Rule id: 2461
    Created at: 2017-04-14 09:57:17
    Updated at: 2017-04-14 16:34:42
    
    Rating: #0
    Total detections: 39
*/

import "androguard"


rule ScamCampaign_ModifiedPaymentGateway
{
	meta:
		description = "This campaign spreads fake applications like undresser camera, modifies the payment gateway using javascript in webview to change the payment amount"
		sample = "190c8484286857f68adf6db31b7927548bef613a65376d86894f503f1d104066"

	strings:
		$SuperCamera_1 = "SuperCamera.Cameraaa, SuperCamera"
		$SuperCamera_2 = "SuperCamera.About, SuperCamera"
		
		$PocketTV_1 = "CustomRowView.listchanels, CustomRowView"
		$PocketTV_2 = "CustomRowView.pay, CustomRowView"

	condition:
		($SuperCamera_1 and $SuperCamera_2) or
		($PocketTV_1 and $PocketTV_2) or
		androguard.activity("md552a6ea15d8d57b628a7925702f10e901.Cameraaa") or
		androguard.activity("md5d8359e76a35968359354b626b6df299b.listchanels")		
}
