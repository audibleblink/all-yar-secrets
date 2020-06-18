global private rule Needles 
{

        meta:
                description = "Global ruleset evaluated before includer's rules"

        // will be evaulated first, by any includers, and bail if not found
        // useful for scoping to a specific company
        strings:
                $ = "contoso"
                $ = "microsoft"

        condition:
                any of them
}
