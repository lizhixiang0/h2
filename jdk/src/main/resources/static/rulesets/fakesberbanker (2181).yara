/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: FakeSberBanker
    Rule id: 2181
    Created at: 2017-01-25 12:03:50
    Updated at: 2017-01-25 12:04:13
    
    Rating: #0
    Total detections: 38
*/

rule Trojan_SberBank:Generic {

	strings:
		$ = "SHA1-Digest: 0RYXrwza/VlrQipZh52pDBGYSv4=" // res/layout/html_win.xml
		$ = "SHA1-Digest: 2MulKCZR+tONx7LwGwYj0iu6p1k=" // res/layout/chat_sent.xml
		$ = "SHA1-Digest: 4igVIY5xayNxe5Sde9RKcRtwCZM=" // res/layout-v17/chat_interface.xml
		$ = "SHA1-Digest: 9XFO5nLfmU2zFKMEg5WZpgf+QDs=" // res/menu-v11/sba.xml
		$ = "SHA1-Digest: EpKx2fb1krx+1ur7MvFMXS/kMxA=" // res/drawable/border_white.xml
		$ = "SHA1-Digest: IJrFgK4WHwDca+LzUXjqZp2pay0=" // res/xml/shhtdi.xml
		$ = "SHA1-Digest: Krc08hysIogRi8pojcDE29oQCnI=" // res/layout/chat_receive.xml
		$ = "SHA1-Digest: MPo0HYhkXD7dsSBWAf8Rszo0bdI=" // res/layout-v17/chat_row.xml
		$ = "SHA1-Digest: P/3/FuaWSmTJzhEqPKhcSn4X00Y=" // res/xml/rotatter.xml
		$ = "SHA1-Digest: R1Vm5lb43YlHLnwI1pO68trQnxw=" // res/layout/adm_win.xml
		$ = "SHA1-Digest: j8bj2Jwy/rSyyR3pMorEje8InWI=" // res/xml/ashp.xml
		$ = "SHA1-Digest: oC1yBCAMYEJUij+pELT2JTSNizg=" // res/xml/da.xml
		$ = "SHA1-Digest: rUYGYMmoO8HjIdBex+fX/xLL0t0=" // res/layout/chat_interface.xml
		$ = "SHA1-Digest: yJi5Vu0G3AqXbLAdSlIgvxYQaw8=" // res/anim/dialog_close.xml
		$ = "SHA1-Digest: zY4Ma7dxptRI8YdoKrdIegQ4a9o=" // res/anim/dialog_open.xml
		$a = "Sberbank" nocase
	
	condition:
		all of ($) and $a


}
