/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: GenericSMS
    Rule id: 831
    Created at: 2015-09-17 08:35:13
    Updated at: 2015-09-20 12:36:42
    
    Rating: #0
    Total detections: 39526
*/

rule genericSMS : smsFraud
{
	meta:
		sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
		sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"

	strings:
		$a = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
		$b = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
		$c = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
		$d = "pitchfork=022D4"

	condition:
		all of them
		
}

rule genericSMS2 : smsFraud
{
	meta:
		sample = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
		sample2 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
		sample3 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

	strings:
		$a = "NotLeftTriangleEqual=022EC"
		$b = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
		$c = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
		$d = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"

	condition:
		all of them
		
}

rule genericSMS3 : smsFraud
{
	meta:
		sample = "100de47048f17b7ea672573809e6cd517649b0f04a296c359e85f2493cdea366"
		sample2 = "0c5392b7ec1c7a1b5ec061f180b5db4d59b476f7f6aaa1d034b7c94df96d4a36"
		sample3 = "1002ab2d97ee45565cdec4b165d6b4dcd448189201adad94ea8152d8a9cadac3"

	strings:
		$a = "res/drawable-xxhdpi/abc_textfield_search_selected_holo_dark.9.pngPK"
		$b = "SHA1-Digest: Jxn4OLlRA7rJLn731JTR4YDWdiY="
		$c = "\\-'[%]W["
		$d = "_ZN6N0Seed10seedStatusE"

	condition:
		all of them
		
}
