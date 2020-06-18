include "includes/global.yar"

rule SlackWebhooks : slack
{

        meta:
                description = "Finds Slack Webhooks"

        strings:
                $s1 = /https:\/\/hooks.slack.com\/services\/T[a-z0-9_]{8}\/B[a-z0-9_]{8}\/[a-z0-9_]{24}/ nocase wide ascii fullword
                $s2 = "https://hooks.slack.com/services/" base64 base64wide

        condition:
                any of ($s*)
}
