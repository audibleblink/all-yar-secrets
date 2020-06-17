
private rule SHA1 
{
        meta:
                description = "Finds SHA1 hashes"

        strings:
                $s = /[0-9a-f]{40}/ nocase wide ascii fullword

        condition:
                $s
}
