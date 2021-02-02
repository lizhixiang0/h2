/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: PornDroid
    Rule id: 1625
    Created at: 2016-07-14 09:08:53
    Updated at: 2016-10-03 07:44:20
    
    Rating: #0
    Total detections: 1966
*/

rule PornDroid
{
	meta:
		description = "This rule detects PornDroid by Childporn Picture"
		sample = "9A51993C3AE511FCE77CF2373DA4056512FC36ED05E5374DCA57256BEDC17609"

	strings:
		$a = "SHA1-Digest: vvk8TC2RhKdWraPlu6Egxbqc4hI=" nocase
		$b = "SHA1-Digest: kEhfn3oMaOvZTWYpjZmf1aOjhkQ=" nocase
		$c = "SHA1-Digest: bCjLPQvLogt1yegnGOe70nFwVz0=" nocase
		$d = "SHA1-Digest: /llINcHHI5e4YRLrLjH+xSllEtg=" nocase

	condition:
		1 of them
		
}
