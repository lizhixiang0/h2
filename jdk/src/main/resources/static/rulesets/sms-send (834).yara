/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Sms send
    Rule id: 834
    Created at: 2015-09-18 08:10:07
    Updated at: 2015-09-18 11:10:03
    
    Rating: #0
    Total detections: 1086236
*/

rule SMSsend
{
	meta:
		sample = "cbadcd7d1b99f330665b3fc68d1bdafb5d0a38f36c76505b48b283a2c1bbb48a"
		sample2 = "e3cd70b5ec2fa33d151043d4214ea3ab9623874a45ae04cc0816ebf787c045ff"
		sample3 = "cc21dc0d3b09a47f008cd68a3c7086f0112c93a027b18ed4283541182d0dfc13"
		
	strings:
		$a = "SHA1-Digest: ZEVCPDHNa58Z+ad4DBPhHzHs2Q0="
		$b = "5148cfbb-cd66-447b-a3dc-f0b4e416d152"
		$c = "merchantOrderTime"
		$d = "dialog_content_l"

	condition:
		all of them
		
}

rule SMSSend2
{
	meta:
		sample = "5e5645bfc4fa8d539ef9ef79066dab1d98fdeab81ac26774e65b1c92f437b5b7"
		sample2 = "bf1529540c3882c2dfa442e9b158e5cc00e52b5cf5baa4c20c4bdce0f1bb0a6f"
		sample3 = "0deb55c719b4104ba1715da20efbc30e8f82cbff7da4d4c00837428e6dc11a24"
		
	strings:
		$a = "unicom_closepress"
		$b = "UpDownArrow=02195"
		$c = "SHA1-Digest: yMpAl55vjxeiLiY1ZwkqDUztpfg="
		$d = "&&res/drawable-xhdpi/hfb_btn_normal2.png"

	condition:
		all of them
}
