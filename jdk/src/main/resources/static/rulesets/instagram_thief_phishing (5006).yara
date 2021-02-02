/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Esmaeil
    Rule name: instagram_thief_phishing
    Rule id: 5006
    Created at: 2018-10-20 08:17:09
    Updated at: 2018-10-20 08:18:25
    
    Rating: #0
    Total detections: 1
*/

import "androguard"


rule instagram_thief_phishing
{
	meta:
		description = "This rule detects the instagram password stealing in apks"

	strings:
		$string_a_1 = "tapinsta.ir/LoginPagei.html" nocase
		$string_a_2 = "mmbers.ir/FollowerGramNew/Instagram-Login" nocase
		$string_a_3 = "instagramapi.sinapps.ir" nocase
		$string_a_4 = "userplusapp.ir/instaup/LoginPage.html" nocase
		$string_a_5 = "instaplus.ir/instagram/login/index.php" nocase
		$string_a_6 = "hicell-developer.ir/OneFollow/Instagram-Login" nocase
		$string_a_7 = "x2net.ir/followerLike/login/instagram.html" nocase
		$string_a_8 = "cloobinsta.space/ClopInsta/Instagram-Login" nocase
		$string_a_9 = "login.instagramiha.org" nocase
		$string_a_10 = "elyasm.ir/cafeinstaz/LoginPage.html" nocase
		$string_a_11 = "takfollow.ir/instagram/login/index.php" nocase
		$string_a_12 = "instaclubbizans.com/InstaClub/Instagram-Login" nocase
		$string_a_13 = "login.instaregion.ir" nocase
		$string_a_14 = "hasan.followerapp.net/Instagram-Login" nocase

	condition:
		any of ($string_a_*)
}
