rule FacebookVideoScam_pdf
{
meta:
author = "NioGuard Security Lab"
info = "Detecting the Facebook video scam"
hash = "e6fbf5739992311fd56cfae08a3f380e33b99d52"
reference = "https://nioguard.com/"

strings:
$a1 = ".jof.date/"
$a2 = "%PDF"
$a3 = "JG JPEG"
 
condition:
$a1 and ($a2 at 0) and $a3
}