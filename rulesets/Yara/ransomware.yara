rule ShadeCryptolocker_nomoreransom
{
    meta: 
        author = "NioGuard Security Lab"
        info = "Detecting the Shade (Troldesh) cryptolocker process"
        reference = "http://nioguard.com/"

    strings:
        $a1 = "Client Server Runtime Subsystem"
        $a2 = "a4ad4ip2xzclh6fd.onion"
        $a3 = "reg.php"
        $a4 = "prog.php"
        $a5 = "err.php"
        $a6 = "cmd.php"
        $a7 = "sys.php"
        $a8 = "shd.php"
        $a9 = ".no_more_ransom"
        
    condition:
      all of ($a*)
}

rule WannaCry20_peexe
{
meta:
author = "NioGuard Security Lab"
info = "Detecting the WannaCry dropper"
hash = "db349b97c37d22f5ea1d1841e3c89eb4"
reference = "http://nioguard.com/"

strings:
$a1 = "tasksche.exe"
$a2 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"

condition:
all of them
}