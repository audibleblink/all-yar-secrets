// include "../includes/global.yar"

rule MailChimp : mailchimp
{

        meta:
                description = "Finds MailChimp API tokens"

        strings:
                $s1 = /[0-9a-f]{32}-us[0-9]{12}/ nocase wide ascii fullword

        condition:
                any of ($s*)
}
