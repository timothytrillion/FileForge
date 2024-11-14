FileForge is designed to inflate executable files by appending data until a specified target size is reached. It can pad files using several methods, including dictionary-based padding, random data, repetitive patterns, character sequences, compression-like patterns, dynamic sentences, MAC address formats, and UUIDs. This flexibility helps FileForge reduce entropy and evade certain AV and EDR detections, like those from CrowdStrike Falcon, which analyze entropy to assess executable trustworthiness. Additionally, FileForge includes an AES encryption option to further obfuscate the padded data, enhancing its ability to bypass security scans that look for indicators such as null-byte padding.

Inspired by much smarter people/projects:
https://github.com/njcve/inflate.py
https://github.com/optiv/Mangle
https://github.com/RedSiege/DigDug
