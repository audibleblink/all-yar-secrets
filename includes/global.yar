global private rule Needles 
{

        meta:
                description = "Global ruleset evaluated before includer's rules"

        strings:
                $ = "\n"

        condition:
                any of them
}
