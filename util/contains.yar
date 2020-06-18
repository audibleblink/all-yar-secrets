rule Contains
{

        meta:
                description = "Utility rule to check substrings. Ex: filename extensions"
                usage = "yara -d want=.yml -d got=$file contains.yar $file"

        condition:
                got contains want
}
