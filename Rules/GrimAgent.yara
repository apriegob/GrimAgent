rule GrimAgent_strings {
    meta:
        author = "Albert Priego"
        company = "Group-IB"
        family = "GrimAgent"
        sample = "63BD614434A70599FBAADD0EF749A9BB68F712ACA0F92C4B8E30A3C4B4DB5CAF"
        severity = 5
 
    strings:
        $sentinel1 = "@@@@@@" ascii wide
        $sentinel2 = "@@@@@d" ascii wide
        $str1 = "Agent" fullword ascii wide
        $str2 = "RL HIGHEST" fullword ascii wide
        $str3 = "-----BEGIN PUBLIC KEY-----" fullword ascii wide
        $str4 = "-----END PUBLIC KEY-----" fullword ascii wide
        $ref1 = "google.com" fullword ascii wide
        $ref2 = "microsoft.com" fullword ascii wide
        $ref3 = "ebay.com" fullword ascii wide
        $ref4 = "youtube.com" fullword ascii wide
        $ref5 = "amazon.com" fullword ascii wide
 
    condition:
        filesize < 1MB and uint16(0) == 0x5a4d and all of ($sentinel*) and all of ($str*) and 2 of ($ref*)
}
 
rule GrimAgent_string_decryption
{
    meta:
        author = "Albert Priego"
        company = "Group-IB"
        family = "GrimAgent"
        sample = "d6ee553f52f20127301f737237b174ef6241ec9049ab22155dce73144ef2354d"
        severity = 5
 
    strings:
    /*
    0x13310bd 60 pushal
    0x13310be 33DB xor ebx, ebx
    0x13310c0 8B5D08 mov ebx, dword ptr [ebp + 8]
    0x13310c3 035DFC add ebx, dword ptr [ebp - 4]
    0x13310c6 8A03 mov al, byte ptr [ebx]
    0x13310c8 33C9 xor ecx, ecx
    0x13310ca 8B4DF8 mov ecx, dword ptr [ebp - 8]
    0x13310cd D2C8 ror al, cl
    0x13310cf 8803 mov byte ptr [ebx], al
    0x13310d1 61 popal
    0x13310d2 EB15 jmp 0x13310e9
    */
    $decrypt_strings1 = {60 33 DB 8B 5D ?? 03 5D ?? 8A 03 33 C9 8B 4D ?? D2 C8 88 03 61 EB ??}
 
    /*
    0x1331036 60 pushal
    0x1331037 33C0 xor eax, eax
    0x1331039 668B45FC mov ax, word ptr [ebp - 4]
    0x133103d 33C9 xor ecx, ecx
    0x133103f 8B4DF8 mov ecx, dword ptr [ebp - 8]
    0x1331042 66D3C8 ror ax, cl
    0x1331045 668945FC mov word ptr [ebp - 4], ax
    0x1331049 61 popal
    0x133104a EB14 jmp 0x1331060
    0x133104c 60 pushal
    0x133104d 33C0 xor eax, eax
    0x133104f 668B45FC mov ax, word ptr [ebp - 4]
    0x1331053 33C9 xor ecx, ecx
    0x1331055 8B4DF8 mov ecx, dword ptr [ebp - 8]
    0x1331058 66D3C0 rol ax, cl
    0x133105b 668945FC mov word ptr [ebp - 4], ax
    0x133105f 61 popal
    */
    $decrypt_strings2 = {60 33 C0 66 8B 45 ?? 33 C9 8B 4D ?? 66 D3 C8 66 89 45 ?? 61 EB ?? 60 33 C0 66 8B 45 ?? 33 C9 8B 4D ?? 66 D3 C0 66 89 45 ?? 61}
 
 
    condition:
        filesize < 1MB and uint16(0) == 0x5a4d and all of them
}


rule GrimAgent_32b_Launcher
{
    meta:
        author = "Albert Priego"
        company = "Group-IB"
        family = "GrimAgent.32bLauncher"
        sample = "63BD614434A70599FBAADD0EF749A9BB68F712ACA0F92C4B8E30A3C4B4DB5CAF"
        severity = 5
	
    strings:
        $snippet = {
            C6 45 ?? 40 8B 55 ?? 89 55 ?? EB ??	8B 45 ?? 83 E8 01 89 45 ?? 83 7D ?? 07 0F
            8E ?? ?? ?? ?? 8B 4D ?? 03 4D ?? 0F BE 11 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03
            4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0	75 ?? 8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE
            45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D
            ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F BE 51 ??
            0F BE 45 ?? 3B D0 75 ??	8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0	75 ??
            8B 4D ?? 89 4D ?? E9 ?? ?? ?? ?? 8B 55 ?? 03 55 ?? 0F BE 02 83 F8 64 75 ?? 8B
            4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F BE 51
            ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0 75
            ?? 8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F
            BE 51 ?? 0F BE 45 ?? 3B D0 75 ?? 8B 4D ?? 03 4D ?? 0F BE 51 ?? 0F BE 45 ?? 3B
            D0 75 ?? 8B 4D ?? 89 4D ??
        }
	
    condition:
        filesize < 1MB and uint16(0) == 0x5a4d and any of them
	
}


rule GrimAgent_64b_Launcher
{
    meta:
        author = "Albert Priego"
        company = "Group-IB"
        family = "GrimAgent.64bLauncher"
        sample = "63BD614434A70599FBAADD0EF749A9BB68F712ACA0F92C4B8E30A3C4B4DB5CAF"
        severity = 5
	
    strings:
        $snippet = {
            C6 44 24 ?? 40 8B 44 24 ?? 89 44 24 ?? EB ?? 8B 44 24 ?? FF C8 89 44 24 ?? 83 7C
            24 ?? 07 0F 8E ?? ?? ?? ?? 48 63 44 24 ?? 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24
            ?? 3B C1 0F 85 ?? ?? ?? ?? 8B 44 24 ?? FF C8 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F
            BE 4C 24 ?? 3B C1 0F 85 ?? ?? ?? ?? 8B 44 24 ?? 83 E8 02 48 98 48 8B 4C 24 ?? 0F
            BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24 ?? 83 E8 03 48 98 48 8B 4C 24 ?? 0F
		    BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24 ?? 83 E8 04 48 98 48 8B 4C 24 ?? 0F
            BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24 ?? 83 E8 05 48 98 48 8B 4C 24 ?? 0F
            BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24 ?? 83 E8 06 48 98 48 8B 4C 24 ?? 0F
            BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24 ?? 89 44 24 ?? E9 ?? ?? ?? ?? 48 63
            44 24 ?? 48 8B 4C 24 ?? 0F BE 04 01 83 F8 64 0F 85 ?? ?? ?? ?? 8B 44 24 ?? FF C8
            48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 0F 85 ?? ?? ?? ?? 8B 44 24
            ?? 83 E8 02 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24
            ?? 83 E8 03 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24
            ?? 83 E8 04 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24
            ?? 83 E8 05 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24
            ?? 83 E8 06 48 98 48 8B 4C 24 ?? 0F BE 04 01 0F BE 4C 24 ?? 3B C1 75 ?? 8B 44 24
            ?? 89 44 24 ??
        }

    condition:
         filesize < 1MB and uint16(0) == 0x5a4d and any of them
}

