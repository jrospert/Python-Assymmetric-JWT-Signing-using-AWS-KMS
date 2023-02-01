import base64
import json
import jwt
import boto3

def _jwt_kms_assemtric_encryption(jwt_head, jwt_payload, aws_key_arn):
  
    # Dict containing "header" and "payload" - the first 2 of 3 parts of the JWT
    # "header": takes the raw json, jwt_head, dumps into string, encodes it into UTF-8, 
    #     decodes it back to its original contents in string form, strips any "=" chars,
    #     and then base64encodes it all
    # "payload": Does same operations as header
    # json.dumps(): converts json to string
    # encode(): encodes a json to UTF-8 format. E.g. (jwt_head).encode() = b'{"alg":"ES256"}
    # decode(): decodes string into original contents. E.g. (jwt_head).encode().decode() = {"alg":"ES256"}
    token_components = {
        "header": base64.urlsafe_b64encode(json.dumps(jwt_head).encode()).decode().rstrip("="),
        "payload": base64.urlsafe_b64encode(json.dumps(jwt_payload).encode()).decode().rstrip("="),
    }
    message = f'{token_components.get("header")}.{token_components.get("payload")}'

    # Boto3 is the  Python SDK for AWS to interact with the AWS API
    # Client class is boto3 client to represent AWS KMS
    kms_client = boto3.client('kms')
    
    # Client.sign() expects 'KeyId'='string', Message=b'bytes', MessageType='RAW'|'DIGEST',
    #     SigningAlgorithm='RSASSA_PSS_SHA_256'|'ECDSA_SHA_256' and more.
    # NOTE: Case matters
    # Documentation here: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.sign
    response = kms_client.sign(
        KeyId = aws_key_arn,
        Message = message.encode(),
        MessageType = "RAW",
        SigningAlgorithm="ECDSA_SHA_256"
    )

    # Client response returns is in binary
    # Encode the binary to Base64URL encoding
    token_components["signature"] = base64.urlsafe_b64encode(response["Signature"]).decode()

    # Return the JWT
    return f'{token_components.get("header")}.{token_components.get("payload")}.{token_components["signature"]}'

if __name__ == "__main__":
    aws_kms_key_arn = "KMS KEY ARN address"
    public_key_file_path = "Local location of public key"
    
    # Create the JWT Header
    header = {
        "alg": "ES256",
        "typ": "JWT"
    }

    # Create the JWT Payload
    payload = {
        "user_id": "Joel"
    }

    # Sign the JWT with the private key
    jwt_encoded = _jwt_kms_assemtric_encryption(header, payload, aws_kms_key_arn)
    
    # Open the public key for JWT verification
    key = ""
    with open(public_key_file_path, "r") as f:
       key = f.read()

    # Verify the JWT signature
    decoded_data = jwt.decode(jwt_encoded, key, algorithms=["ES256"])
    print(decoded_data) 