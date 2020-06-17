global private rule Needles 
{

        meta:
                description = "Global ruleset evaluated before includer's rules"

        strings:
                $ = /./

        condition:
                any of them
}
