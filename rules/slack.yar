include "../includes/global.yar"

rule SlackToken : slack
{

        meta:
                description = "Finds Slack API tokens"

        strings:
                $s1 = /xox[pboa]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[0-9a-z]{32}/ nocase wide ascii fullword

                $s2 = "xoxp-" base64 base64wide
                $s3 = "xoxb-" base64 base64wide
                $s4 = "xoxo-" base64 base64wide
                $s5 = "xoxa-" base64 base64wide

        condition:
                any of ($s*)
}
