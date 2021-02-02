/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReciever:banker
    Rule id: 671
    Created at: 2015-07-08 06:06:35
    Updated at: 2015-08-06 15:20:52
    
    Rating: #0
    Total detections: 186
*/

rule SMSReviever : banker
{
	meta:
		description = "To found apps with a typo error, is classified too as ibanking"
		sample = "6903ce617a12e2a74a3572891e1df11e5d831632fae075fa20c96210d9dcd507"

	strings:
	$a = {53 6D 73 52 65 63 69 65 76 65 72 75 70 64 61 74 65} //SmsRevieverupdate

	condition:
		$a
		
}
