#!/usr/bin/env python
import requests

import tldextract

import random
import binascii
import logging

logging.basicConfig(level=logging.ERROR)

import time
import hashlib
import sys
from datetime import datetime

# from ocsp_crl_parser import *
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

sys.path.insert(0, "/home/tjchung/v2/local/lib/python2.7/site-packages")

import pyasn1
from pyasn1_modules import rfc2560
from pyasn1_modules import rfc2459
from pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.codec.native.encoder import encode as native_encoder
from pyasn1.type import univ

import base64
import json
import pprint
import os
from collections import deque

pp = pprint.PrettyPrinter()
sha1oid = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))


def makeOcspRequest(issuerCert, userSerialNumber=None, userCert=None, add_nonce=False):
    issuerTbsCertificate = issuerCert.getComponentByName('tbsCertificate')
    if (userCert is None):
        issuerSubject = issuerTbsCertificate.getComponentByName('subject')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    else:
        # c = pem.readPemFromString( userCert )
        # userCert, _ = decoder.decode( c, asn1Spec=rfc2459.Certificate())
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        issuerSubject = userTbsCertificate.getComponentByName('issuer')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName(
        'subjectPublicKey')

    issuerKeyHash = hashlib.sha1(issuerSubjectPublicKey.asOctets()).digest()

    if (userSerialNumber is None):
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')
        userSerialNumber = userTbsCertificate.getComponentByName('serialNumber')

    request = rfc2560.Request()
    reqCert = request.setComponentByName('reqCert').getComponentByName('reqCert')

    hashAlgorithm = reqCert.setComponentByName('hashAlgorithm').getComponentByName('hashAlgorithm')
    hashAlgorithm.setComponentByName('algorithm', sha1oid)

    reqCert.setComponentByName('issuerNameHash', issuerHash)
    reqCert.setComponentByName('issuerKeyHash', issuerKeyHash)
    reqCert.setComponentByName('serialNumber', userSerialNumber)

    ocspRequest = rfc2560.OCSPRequest()

    tbsRequest = ocspRequest.setComponentByName('tbsRequest').getComponentByName('tbsRequest')
    tbsRequest.setComponentByName('version', 'v1')

    if (add_nonce):
        requestExtensions = tbsRequest.setComponentByName('requestExtensions').getComponentByName('requestExtensions')

        extension = rfc2459.Extension()
        extension.setComponentByName('extnID', rfc2560.id_pkix_ocsp_nonce)
        extension.setComponentByName('critical', 0)

        length = len("0410EAE354B142FE6DE525BE7708307F80C2")
        nonce = (str(random.randint(0, 123489598219)) + str(time.time()).replace(".", "")[:19])
        nonce = nonce.ljust(length, '0')
        # nonce = "0410EAE354B142FE6DE525BE7708307F80C2"

        # print (nonce)
        ## ASN1: Tag (04: Integer) - Length (10:16 bytes) - Value  Encoding
        ## See: http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art062
        ## current version of pyasn1_modules do not support nonce

        extension.setComponentByName('extnValue', binascii.unhexlify(nonce))

        requestExtensions.setComponentByPosition(0, extension)

    requestList = tbsRequest.setComponentByName('requestList').getComponentByName('requestList')
    requestList.setComponentByPosition(0, request)

    return ocspRequest


if __name__ == '__main__':

    # ocsps.ssl.com
    issuer_cert = open("ocsps.ssl.com/issuer_cert.pem")
    client_cert_pem = open('ocsps.ssl.com/client_cert.pem')
    ocspURL = "http://ocsps.ssl.com"

    # Wisekey
    # issuer_cert = open("ocsp.wisekey.com/issuer_cert.pem")
    # client_cert_pem = open('ocsp.wisekey.com/client_cert.pem')
    # ocspURL = "http://ocsp.wisekey.com"

    # Akamai
    # issuer_cert = open("dvcasha2.ocsp-certum.com/issuer_cert.pem")
    # client_cert_pem = open('dvcasha2.ocsp-certum.com/client_cert.pem')
    # ocspURL = "http://dvcasha2.ocsp-certum.com"

    # Cloudflare
    # issuer_cert = open("GEANT.ocsp.sectigo.com/issuer_cert.pem")
    # client_cert_pem = open('GEANT.ocsp.sectigo.com/client_cert.pem')
    # ocspURL = "http://GEANT.ocsp.sectigo.com"
    # ocspURL = "http://104.18.14.101" ## geant.ocsp.sectigo.com

    # Cloudflare
    # issuer_cert = open("globalsign/issuer_cert.pem")
    # client_cert_pem = open('globalsign/client_cert.pem')
    # ocspURL = "http://ocsp.globalsign.com/ca/gsatlasr3alphasslca2023q1"

    headers = {'Connection': 'Keep-Alive', \
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', \
               'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0", \
               'Content-Type': 'application/ocsp-request', \
               'Host': "%s" % (".".join(tldextract.extract(ocspURL)))
               }

    c = pem.readPemFromFile(issuer_cert)
    issuerCert, _ = decoder.decode(c, asn1Spec=rfc2459.Certificate())

    c = pem.readPemFromFile(client_cert_pem)
    userCert, _ = decoder.decode(c, asn1Spec=rfc2459.Certificate())

    ## Dummy Request
    session = requests.session()
    ## TCP Algorithm
    for i in range(0, 10):
        userSerialNumber = random.randint(0, 1231231231231)
        ocspReq = makeOcspRequest(issuerCert, userSerialNumber=userSerialNumber, userCert=userCert, add_nonce=False)
        resp = session.post(ocspURL, data=encoder.encode(ocspReq), headers=headers)
        resp.content

    for i in range(0, 50):
        userSerialNumber = None
        # userSerialNumber = random.randint(0,1231231231231)
        ocspReq = makeOcspRequest(issuerCert, userSerialNumber=userSerialNumber, userCert=userCert, add_nonce=False)

        start_time = time.time()
        with session.post(ocspURL, data=encoder.encode(ocspReq), headers=headers) as resp:
            r = resp.content
            end_time = time.time()

            result = {"serial": "hoho",
                      "response": dict({"response_body": str(base64.b64encode(r))}),
                      "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}

            print(json.dumps(result))
            print("%.3f " % (end_time - start_time))
"""
async def parse(der):
    asn1_obj, extra_info = der_decoder(der, asn1Spec=rfc2560.OCSPResponse())
    basic_der = native_encoder(asn1_obj['responseBytes']['response'])
    res, extra_info = der_decoder(basic_der, asn1Spec=rfc2560.BasicOCSPResponse())
    print (res)

"""
