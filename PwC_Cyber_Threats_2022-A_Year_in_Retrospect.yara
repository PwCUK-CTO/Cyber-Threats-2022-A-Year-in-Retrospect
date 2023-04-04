rule Brute_Ratel_PE_Badger_API_Loading_Routine : Heuristic_and_General
{
    meta:
        description = "Detects Brute Ratel Badger payloads (PE and DLL) based on a unique routine used to dynamically load APIs"
        TLP = "AMBER"
        author = "PwC Threat Intelligence"
        copyright = "Copyright PwCIL 2022 (C)"
        created_date = "2022-09-29"
        modified_date = "2022-09-29"
        revision = "0"
        hash = "4de333f164d70b59849c3aa12a9c95cdcbecae3023386ee08c15b38874260941"
        hash = "dc71c5721fa6b3148a3a0564931dc063d03694ca57aa61e8c2532b5a565b2548"
        hash = "ef803ea871c974623ceb678548c938826b683c857adc85a6bf8af34c8b61fc52"

    strings:
        // 8B5324 MOV EDX,DWORD PTR [RBX+24]
        // 4D01DB ADD R11,R11
        // 8B431C MOV EAX,DWORD PTR [RBX+1C]
        // 4D01D3 ADD R11,R10
        // 410FB71413 MOVZX EDX,WORD PTR [R11+RDX]
        // 498D1492 LEA RDX,[R10+RDX*4]
        // 8B0402 MOV EAX,DWORD PTR [RDX+RAX]
        // 4C01D0 ADD RAX,R10
        $ = {8B53244D01DB8B431C4D01D3410FB71413498D14928B04024C01D0}

    condition:
        all of them
}

rule Sliver_Protobuf_Symbol : Heuristic_and_General
{
    meta:
        description = "Detects symbol in Sliver implants (PE, ELF, Mach-O and shellcode) referencing a custom protobuf module"
        TLP = "AMBER"
        author = "PwC Threat Intelligence"
        copyright = "Copyright PwCIL 2022 (C)"
        created_date = "2022-10-18"
        modified_date = "2022-10-18"
        revision = "0"
        hash = "41cf473fe535b932c68e9f295680fe228cde0094a8bac70ccb68c21aaff22188"
        hash = "c12c33111b41bf2be458004d532f1255fd734057d2c7bf59e0877e31dbedfd4e"
        hash = "3b4c57e04422825609bc70dfa5bf741cded6961df87369b530c45720eee828fd"
        hash = "4c668595d6767e9cdb68f875aab9d4d39ae0ff94d94e76dc301eb336f1d74096"
        reference = "https://github.com/BishopFox/sliver"

    strings:
        $ = ".sliverpb."

    condition:
        // Note, you can remove these file signature checks to wider the rule further
        (
            // PE
            uint16(0) == 0x5A4D or
            // Shellcode
            uint32be(0) == 0x4883e4f0 or
            // Mach-O
            uint32be(0) == 0xcffaedfe or
            // ELF
            uint32be(0) == 0x7f454c46
        ) and
        any of them
}