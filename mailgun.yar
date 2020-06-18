include "includes/global.yar"

rule MailGun : mailgun
{

        meta:
                description = "Finds MailGun API tokens"

        strings:
                $s1 = /key-[0-9a-zA-Z]{32}/ nocase wide ascii fullword
                $s2 = "key-" base64 base64wide

        condition:
                any of ($s*)
}
