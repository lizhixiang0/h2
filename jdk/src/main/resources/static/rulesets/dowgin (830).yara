/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Dowgin
    Rule id: 830
    Created at: 2015-09-17 08:19:07
    Updated at: 2015-09-17 08:22:01
    
    Rating: #0
    Total detections: 76402
*/

rule dowgin:adware
{
	meta:
		sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
		sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
		sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
		sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"

	strings:
		$a = "http://112.74.111.42:8000"
		$b = "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
		$c = "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
		$d = "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"

	condition:
		all of them
		
}
