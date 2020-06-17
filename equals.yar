rule Equals
{

        meta:
                description = "Utility rule to check equality. Ex: filename checks"
                usage = "yara -d want=config.yml -d got=$file equals.yar $file"

        condition:
                got == want
}
