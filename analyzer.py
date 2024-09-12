import pefile
import collections
import math
import lief

from dotenv import load_dotenv
from signify.authenticode import SignedPEFile


def get_iat_eat(file_path):
    pe = pefile.PE(file_path)
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe.parse_data_directories(directories=d)
    import_info = []
    export_info = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for file in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info = {
                'DLL': file.dll.decode(),
                'Functions': [
                    function.name.decode() if function.name else f"ordinal {function.ordinal}"
                    for function in file.imports
                    # {"Function": function.name.decode() if function.name else f"ordinal {function.ordinal}"}
                    # for function in file.imports
                ]
            }
            import_info.append(dll_info)

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        for export in sorted(exports):
            export_info.append(export)

    ans = {
        'IAT':import_info,
        'EAT':export_info
    }
    return ans


file_path = "./xfoil.exe"
iat_eat = get_iat_eat(file_path)
print(iat_eat)