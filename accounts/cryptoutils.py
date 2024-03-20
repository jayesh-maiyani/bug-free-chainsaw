import base64
import binascii
import os
import tempfile

import rsa
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from .exceptions import BadRequest

# from cryptography.hazmat.primitives.asymmetric import rsa



def decode_base64_decode(data):
    if isinstance(data, str):
        data = str.encode(data)
        return base64.b64decode(data)



def decrypt_decode(s, private_key):
    try:
        tf = tempfile.NamedTemporaryFile(delete=False)
        decoded_string = base64.b64decode(s)

        file_out = open(tf.name, "wb")
        file_out.write(decoded_string)
        file_out.close()

        file_in = open(tf.name, 'rb')
        private_key = RSA.import_key(private_key)

        enc_session_key, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), -1)]

    # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        data = unpad(cipher_aes.decrypt(ciphertext))
    
        file_in.close()
        tf.close()
        os.unlink(tf.name)
        return data.decode('utf-8')
    except ValueError:
        raise BadRequest()





def generate_key():
    return binascii.hexlify(os.urandom(30)).decode()


def encode_base64(data):
    if isinstance(data, str):
        data = str.encode(data)
    return base64.b64encode(data)


def decode_base64(data):
    # if isinstance(data, str):
    #     data = str.encode(data)
    return base64.b64decode(data)


def gen_keys():
    public_key, private_key = rsa.newkeys(2048)
    public_pem = public_key.save_pkcs1('PEM')
    private_pem = private_key.save_pkcs1('PEM')
    return encode_base64(public_pem), encode_base64(private_pem)


pad = lambda s: s + ((32 - len(s) % 32) * chr(32 - len(s) % 32)).encode('utf-8')
unpad = lambda s: s[0:-ord(s[-1:])]

def encrypt(s, public_key):
    public_key = RSA.import_key(public_key)
    session_key = get_random_bytes(32)
    tf = tempfile.NamedTemporaryFile(delete=False)
    file_out = open(tf.name, 'wb')
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext = cipher_aes.encrypt(pad(s))

    [file_out.write(x) for x in (enc_session_key, ciphertext)]
    file_out.close()
    file_in = open(tf.name, "rb")

    encoded_string = base64.b64encode(file_in.read())
    file_in.close()
    tf.close()
    os.unlink(tf.name)

    return encoded_string


def decrypt(s, private_key):
    try:
        tf = tempfile.NamedTemporaryFile(delete=False)
        decoded_string = base64.b64decode(s)

        file_out = open(tf.name, "wb")
        file_out.write(decoded_string)
        file_out.close()

        file_in = open(tf.name, 'rb')
        private_key = RSA.import_key(private_key)

        enc_session_key, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        data = unpad(cipher_aes.decrypt(ciphertext))
        file_in.close()
        tf.close()
        os.unlink(tf.name)
        data=base64.b64decode(data)
        return data.decode('utf-8')
    except ValueError:
        raise BadRequest()



if __name__ == '__main__':
    pass
    # key = """LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwdStiRDFCc3VvdUxSMVBLbVFiMgovTUFPY0Z4VmpwZkU5NDlhREUrMDhqWG5HWVNzVzFvamxjcmcvb3BjVUU3TktBZzNnUUdHaWRHM0puWHF3NFRQClZHczVnU0cvRmpFdUtnYlNEVkZuS1J3VkFGR2JONStIbXdtWFpWRzNhRHBQTGdibllzTzcvU3A0UllRTkdYamEKbVhXanhPWFo2a1FpalVXQ3pUVzBPdnU3Qm91SzZjVHQ4ZDkvbjA5aUhjSFphaXRJTGMva2Y5THZnSWNuR1VUVwpqblRvRVhvMjN3aWtaZU9HM1RmMER5SStYRWNTdjN4SEpualpKUnVRRUMzNW9UbUVlUkhnZ0c2czZlaUl0Z1k2Cm9SUGtQQXU5Q1dHSHpQUTZrQm02YUVwcFZmYUc1QlB1azhOd0phb1NjRkFLbnFLK0JrSk10OEVzQytMdE5NQ0MKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="""
    # pk = """LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFM3NXNQVUd5Nmk0dEgKVThxWkJ2Yjh3QTV3WEZXT2w4VDNqMW9NVDdUeU5lY1poS3hiV2lPVnl1RCtpbHhRVHMwb0NEZUJBWWFKMGJjbQpkZXJEaE05VWF6bUJJYjhXTVM0cUJ0SU5VV2NwSEJVQVVaczNuNGViQ1pkbFViZG9Pazh1QnVkaXc3djlLbmhGCmhBMFplTnFaZGFQRTVkbnFSQ0tOUllMTk5iUTYrN3NHaTRycHhPM3gzMytmVDJJZHdkbHFLMGd0eitSLzB1K0EKaHljWlJOYU9kT2dSZWpiZkNLUmw0NGJkTi9RUElqNWNSeEsvZkVjbWVOa2xHNUFRTGZtaE9ZUjVFZUNBYnF6cAo2SWkyQmpxaEUrUThDNzBKWVlmTTlEcVFHYnBvU21sVjlvYmtFKzZUdzNBbHFoSndVQXFlb3I0R1FreTN3U3dMCjR1MDB3SUpOQWdNQkFBRUNnZ0VBZTVQS21TYzUrL1FpN2UvR0l1NzBwbER5Wkp1RHVGMXNGTWtVTFdCSkZ4bkQKUWF6N3VTMU82Y1FKR3JiK3JFSHVhWVNlMStLSDZwaEZuNisza1VKdW9QdU1uZjJpVUtNUmM2ZTVTZm9sNE96RgoxUUQ2V1pVSndpZlZYWk9KU3ZQV1RaWFgyNEhtMGNRZTRFTWoxWWQ3TWlxOGZtOVd3cXVXUG9PNXhQV3dtRml2CjVpYVMvMkRtbU8zNm0xd0N3ZzJzWHJKZXR1K09VQWtqOUt0OTVQYU9Wb2ZDVVdYbWp3blp1ZDIxMytDb2o5Rk8KcitDMHZFQjFDeG9tTUtBam5xYzBLSTArdVpiUU00OS9GUGxOTnpVMk9IN0tJVUxrT0lrYXBtRjZ2RGQ2QkR4Kwo5VUJ0QmRWSkIvNlhqbmMwdzkrRWpLUUh5TEJmQVd6bHJpNDhQNW44WVFLQmdRRHY5d3ZIVXJLSStuSGdzTFRHCldTdy9pL0VwaFByNG9TQmFBWmtNb00vSCs5eVpxWkNKOURBWXpmdmxtOHRMNUpZaFl5THAramJMQ0sxMTBGTU4KY2l1cVBMY0t6VXJodzZ6YlRZL0VDdjFQMlRvVjNza25hNi91RWxHa0FpMmlJckR4R2o5bWxuZ1pxbGlUL0lZRgpSckJTNFhsb0NiN3EwR1FsaGNabkRXcWFwUUtCZ1FEaEIvbVY1NHkzbDN3MlpXd0ZpTnFOeW10bGtzZkhLdmllCnErN1crTmdrSW9iQWJTYnF4QTBxd3oycHI2S2UrYVJPYVdnVmdpUXkwcmQ5ZWVFVUZZOGhOVTY0VTdJUzRLRmwKbnNWcnpuVGphSWdheVlpM2pyeCtlQXVxN1B5T0xyYU5XZDBGeXBPR1hCVGZMa05ZNTc4c0hxTVA3clhia3dVTAo4YTNvSWxqQWlRS0JnUURjdWpiSWF1WTBuNEkrZHV4aUFzWnowWXJNY1RqVm1JaUVvakdnN3c4UldqZ3AxRkpTCnd4MjJ3MHB3Z3VUMmMxWXhjZG84dE43UDFiU1F5VWFMK0xmM2lJK3FUUG9UUHdWeVdCN2s2bUxsbnVBU0cvS1YKNHpWWjNObmg3ZXNCMTcxQW1hODE4elNZRHh3WlM5QVBiRjFtYjJaWWI1YUFzWjFjOG5kMGRWL1l6UUtCZ0RQawppK2pHdWN1SWttdFUzaUUwbXZuQnFSeUdTYTJqT2l3VkNBSG81cWNHa3o2Q3JVdk1KQ0V0WHVYbmk3L1BYOVY1Ck56aG1oNFIwMVQySlFwOUlEWGFoL1dKQ1lyazV0ZDVpUzdKOXJMVFlZVEtVTVFQclZZcHdrbmc3S0U1OWRUbUoKZEkrbVZIalNlVG15U0hPVEZhSE4rdHBzdU9GR3VRNDFFRjZNdFJ6SkFvR0JBTlNPWnkxeEZNYi9ZT0pIZXJIUwpOVWxmSHRLcW5HUmJlb09GcHp1K2duK1ByMTQ3L1JaY0NQTFlmZUYxR1Y2dGxZS0tQSEdCWVNMSzBxaWVIdEttCncrc1htVmNkSVg1ZDg2NGd5bkM3MURxUkxZc1plaE5FZFk3NTN1dXo0alhTVXE1a09XNGVudUx3UHZpVTA4SWoKOXl1TVlhTnNxSW4wUGljVGZjMkpXZWEvCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"""
    # pub = decode_base64(key)
    # puk = decode_base64(pk)
    # data = str.encode("""{"serial_no":"ABC577910077207","mac_address":"2C-8F-08-3D-DE-FE","authorization_token":"1328c341-fa53-4be1-8b4b-be94e862773b","public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFvbjkwZUZTRm5qZFBtYjlUYStHMQovUlhYbHgxT2wvdW0xVTRXNFBXTDhjekJoZkJ1MlNRY0JOSk9lb1ZwdXg0a3dOSlZiMnNZMzdDbVNONUZGMWRkCitCek5MY0xiTUpKNTcwb0N3QWtiNVBvUkpTZlE1cWtVUFJleEVqUVgvUDhXckZ1c0VtbzJSaTE5SmVyVUdQVGcKL2tESllMeVVYWTdXdDdIUWlrOGhlbGJpVXFzR2dDMm5nV1k2N2xwbjE1RmR6Q3R1eHliVWlxVWZGVlRGdGN2NgoyK2g5Yjd6TDJmY2FRZTlJM3I5d1NIbXB4eFNwUkZnbFRmeXMxOXBzVTU3QWlEbWFIZVB5MWtNRkNFeEhWcGt5CkJOYjVFcmRZSzUyazEvU0NPVG4zV2dvZ21ERHl0MFI4N3FBVDB2QVNNbC9tRWR5cHBGK3h5dzlDeXNSWnl5RnUKb3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"}
    # """)
    # ed = encrypt(data, pub)
    # print(ed)
    # dc = decrypt(ed, puk)
    # print(dc)
    # data = b"{'hello':1}"
    # e = encrypt(data, decode_base64(key))
    # print(e)
    # d = decrypt(e, decode_base64(pk))
    # print(d)
