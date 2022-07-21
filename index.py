# -*- coding:utf-8 -*-
import hashlib, hmac, json, os, sys, time
from datetime import datetime
import requests

def reset_ip (ip_addr):

    # 密钥参数，云API密匙查询: https://console.cloud.tencent.com/cam/capi
    secret_id = "AK"
    secret_key = "SK"

    service = "dnspod"
    host = "dnspod.tencentcloudapi.com"
    endpoint = "https://" + host
    action = "ModifyRecord"
    version = "2021-03-23"
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
    # 实际调用需要更新参数，这里仅作为演示签名验证通过的例子
    params = {
        "Domain": "domainname",
        "SubDomain": "subdomianname",
        "RecordType": "A",
        "RecordLine": "默认",
        "Value": ip_addr,
        "RecordId": RecordId
    }

    # ************* 步骤 1：拼接规范请求串 *************
    http_request_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json; charset=utf-8"
    payload = json.dumps(params)
    canonical_headers = "content-type:%s\nhost:%s\n" % (ct, host)
    signed_headers = "content-type;host"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (http_request_method + "\n" +
                        canonical_uri + "\n" +
                        canonical_querystring + "\n" +
                        canonical_headers + "\n" +
                        signed_headers + "\n" +
                        hashed_request_payload)

    # ************* 步骤 2：拼接待签名字符串 *************
    credential_scope = date + "/" + service + "/" + "tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = (algorithm + "\n" +
                    str(timestamp) + "\n" +
                    credential_scope + "\n" +
                    hashed_canonical_request)


    # ************* 步骤 3：计算签名 *************
    # 计算签名摘要函数
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    secret_date = sign(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # ************* 步骤 4：拼接 Authorization *************
    authorization = (algorithm + " " +
                    "Credential=" + secret_id + "/" + credential_scope + ", " +
                    "SignedHeaders=" + signed_headers + ", " +
                    "Signature=" + signature)

    x = requests.post(endpoint, data=payload, headers={\
        'Authorization': authorization, \
        'Content-Type':'application/json; charset=utf-8', \
        'Host':host, \
        'X-TC-Action':action, \
        'X-TC-Timestamp':str(timestamp), \
        'X-TC-Version':version\
        })

    return x.text   

def handler (event, context):

    client_ip_address = event['headers']['x-forwarded-for'].split(',')[0]
    
    ret = reset_ip(client_ip_address)
    # json.dumps(event)

    return {
        "statusCode": 200,
        "isBase64Encoded": False,
        "body": ret,
        "headers": {
            "Content-Type": "application/json"
        }

    }