# 탐지 기능 수행
# 호출 방식: 파일경로로 호출
import pefile
import collections
import math
import lief

from dotenv import load_dotenv
from signify.authenticode import SignedPEFile


load_dotenv()


def check_entropy(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    byte_cnt = collections.Counter(data)
    file_length = len(data)

    entropy = 0

    for cnt in byte_cnt.values():
        p = cnt / file_length

        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def get_rich_header(file_path):
    try:
        pe = pefile.PE(file_path)
        rich_header = pe.parse_rich_header()

        if rich_header != None:
            print(f"Key: {rich_header.keys}")
            if 'records' in rich_header:
                records = rich_header['records']

                return "Rich header and Key Found"
            else:
                return "No Rich header"
        else:
            return "No key found"

    except Exception as e:
        return None


def get_iat_eat(file_path):
    pe = pefile.PE(file_path)
    import_info = []
    export_info = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for file in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info = {
                'DLL': file.dll.decode(),
                'Functions': [
                    {"Function": function.name.decode() if function.name else f"ordinal {function.ordinal}"}
                    for function in file.imports
                ]
            }
            import_info.append(dll_info)

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        # 추후 추가 예정
        print("export")


# 출처: https://github.com/ralphje/signify/blob/master/examples/authenticode_info.py
def get_certification_info_R1(file_path):

    with open(file_path, "rb") as file_obj:
        try:
                pe = SignedPEFile(file_obj)
                for signed_data in pe.signed_datas:
                    print("    Included certificates:")
                    for cert in signed_data.certificates:  # 포함된 인증서 목록, 사용여부 무관
                        print("      - Subject: {}".format(cert.subject.dn))
                        print("        Issuer: {}".format(cert.issuer.dn))
                        print("        Serial: {}".format(cert.serial_number))
                        print("        Valid from: {}".format(cert.valid_from))
                        print("        Valid to: {}".format(cert.valid_to))

                    print()
                    print("    Signer:")
                    print("        Issuer: {}".format(signed_data.signer_info.issuer.dn))
                    print("        Serial: {}".format(signed_data.signer_info.serial_number))
                    print("        Program name: {}".format(signed_data.signer_info.program_name))
                    print("        More info: {}".format(signed_data.signer_info.more_info))

                    if signed_data.signer_info.countersigner:
                        print()
                        if hasattr(signed_data.signer_info.countersigner, 'issuer'):
                            print("    Countersigner:")
                            print("        Issuer: {}".format(signed_data.signer_info.countersigner.issuer.dn))
                            print("        Serial: {}".format(signed_data.signer_info.countersigner.serial_number))
                        if hasattr(signed_data.signer_info.countersigner, 'signer_info'):
                            print("    Countersigner (nested RFC3161):")
                            print("        Issuer: {}".format(
                                signed_data.signer_info.countersigner.signer_info.issuer.dn
                            ))
                            print("        Serial: {}".format(
                                signed_data.signer_info.countersigner.signer_info.serial_number
                            ))
                        print("        Signing time: {}".format(signed_data.signer_info.countersigner.signing_time))

                        if hasattr(signed_data.signer_info.countersigner, 'certificates'):
                            print("        Included certificates:")
                            for cert in signed_data.signer_info.countersigner.certificates:
                                print("          - Subject: {}".format(cert.subject.dn))
                                print("            Issuer: {}".format(cert.issuer.dn))
                                print("            Serial: {}".format(cert.serial_number))
                                print("            Valid from: {}".format(cert.valid_from))
                                print("            Valid to: {}".format(cert.valid_to))

                    print()
                    print("    Digest algorithm: {}".format(signed_data.digest_algorithm.__name__))
                    print("    Digest: {}".format(signed_data.spc_info.digest.hex()))

                    print()

                    result, e = signed_data.explain_verify()
                    print("    {}".format(result))
                    if e:
                        print("    {}".format(e))
                    print("--------")

                result, e = pe.explain_verify()
                print(result)
                if e:
                    print(e)

        except Exception as e:
            print("    Error while parsing: " + str(e))


# https://lief.re/doc/latest/tutorials/13_pe_authenticode.html
def get_certification_info_R3(file_path):
    ans = {
        'number of certificates': 0,
        'serial numbers': [],
    }
    try:
            pe = lief.parse(file_path)
            signature = pe.signatures[0]
            ans["number of certificates"] = len(list(signature.certificates))

            for crt in signature.certificates:
                ans["serial numbers"].append(int.from_bytes(crt.serial_number, 'big'))

    except Exception as e:
        print("    Error while parsing: " + str(e))

    return ans

path = "uploads/pplot.exe"
print(get_certification_info_R1(path))

