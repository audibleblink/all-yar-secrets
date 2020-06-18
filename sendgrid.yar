include "includes/global.yar"

rule Sendgrid : sendgrid
{

        meta:
                description = "Finds Sendgrid API tokens"

        strings:
                $s1 = /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/ nocase wide ascii fullword
                $s2 = "SG." base64 base64wide

        condition:
                any of ($s*)
}
