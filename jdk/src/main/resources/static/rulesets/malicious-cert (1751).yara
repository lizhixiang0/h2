/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Malicious cert
    Rule id: 1751
    Created at: 2016-08-19 12:39:31
    Updated at: 2016-08-20 10:43:04
    
    Rating: #0
    Total detections: 1113
*/

import "androguard"

rule malicious_certs
{
	condition:
		androguard.certificate.sha1("437423567AA682723D3ADD8BAD316BD578F2EB85") or
		androguard.certificate.sha1("9BB11D691804256616B232C1D803ADC3CDFF4B6D") or
		androguard.certificate.sha1("D5274E3BF8B2F0B6E3D69ECF064D38CD74B3E64B") or
		androguard.certificate.sha1("0ECA59048B29A69FC7F9655C0534EB97BFF15893") or
		androguard.certificate.sha1("8B373E842398325296B6FDC302296AD1F6CFCEDA")
		or androguard.certificate.sha1("1B1DE0EF592C729D2BC578A259F6D740FE3E1C4E")
		or androguard.certificate.sha1("1D4A315F36C933028F1938979354D68F69217993")
		or androguard.certificate.sha1("046BF157D644F2DE7BF0BCEC8C5D4E240C9F1901")
		or androguard.certificate.sha1("9465535F221311ECDE7CB0886930E639AA4A47C2")
		or androguard.certificate.sha1("F55C09CF87F998364C5B679E8219475FDB708F56")
		or androguard.certificate.sha1("19E98203E736DE818F79A8BC9541D8BF6A0EC7DE")
		or androguard.certificate.sha1("34E39C32B5561EC307FB133ABA3C637A99D62E3A")
		or androguard.certificate.sha1("A66802E44869280D14FECE10661370D6AA13F79E")
		or androguard.certificate.sha1("69DA14E583BF3127015ADD077B997DB1474A5312")
		or androguard.certificate.sha1("97C962C8AC89663B9041CC0E08057200A65560F2")
		or androguard.certificate.sha1("A1480C8895A8B10A34C714867FFFD3CF98A5C8B5")
		or androguard.certificate.sha1("34E39C32B5561EC307FB133ABA3C637A99D62E3A")
		or androguard.certificate.sha1("3B2097D66D27A248B8F45332A52F7B83DC98F2D3")
		or androguard.certificate.sha1("623CFF4004DB8D106FB47EDD20A53138892CD7DD")
		or androguard.certificate.sha1("EED7DF45045A39EC7D11991CE983DFC50D91ACF7")
		or androguard.certificate.sha1("6668C30E3C4DB3FD68C1EC79DA3468457B2B3028")
}
