include "includes/global.yar"

rule GitHubToken : github
{

        meta:
                description = "Finds GitHub API tokens"

        strings:
                $s1 = "github_api"      nocase wide ascii private
                $s2 = "github_access"   nocase wide ascii private
                $s3 = "github_token"    nocase wide ascii private
                $s4 = "personal_access" nocase wide ascii private
                $s5 = "homebrew_github" nocase wide ascii private

                $token = /[0-9a-f]{40}/ nocase wide ascii fullword

        condition:
                $token and any of ($s*)
}
