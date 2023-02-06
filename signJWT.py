import base64
import json
import boto3
from botocore.exceptions import ClientError

# Encode the header and payload
# return the string
# return type: string, format: xxxxx.yyyyy
def _create_jwt_header_payload(f_header, f_payload):

    # Dict containing "header" and "payload" - the first 2 of 3 parts of the JWT
    token_components = {
        "header": base64.urlsafe_b64encode(json.dumps(f_header).encode()).decode().rstrip("="),
        "payload": base64.urlsafe_b64encode(json.dumps(f_payload).encode()).decode().rstrip("="),
    }
    message = f'{token_components.get("header")}.{token_components.get("payload")}'
    return message

# Sign the the header and payload
# return the encoded digital signature
# return type: string
def _jwt_kms_asymmetric_sign(f_header_payload, aws_key_arn):      

    kms_client = boto3.client('kms')  
    try: 
        sign = kms_client.sign(
            KeyId = aws_key_arn,
            Message = f_header_payload.encode(),
            SigningAlgorithm="ECDSA_SHA_256"
        )
    except ClientError:
        print("Could not create the digital signature")

    else:
        digital_signature = base64.urlsafe_b64encode(sign["Signature"]).decode()
        return digital_signature

# Verify the JWT signature
# return if the signature is verified
# return type: boolean
def _jwt_kms_asymmetric_verify(message, signature, aws_key_arn):
    message_encoded = bytes(message, 'utf-8')    
    jwt_signature = bytes(base64.urlsafe_b64decode(signature))   
    kms_client = boto3.client('kms')
    isVerified = kms_client.verify(
        KeyId = aws_key_arn,
        Message = message_encoded,
        Signature = jwt_signature,
        SigningAlgorithm="ECDSA_SHA_256"
    )
   
    return(isVerified["SignatureValid"])

if __name__ == "__main__":
    aws_kms_key_arn = "arn:aws:kms:us-east-1:394485393101:key/caf01cef-0498-4b85-9268-fbb6f978d097"
    
    # Create the JWT Header
    header = {
        "alg": "ES256",
        "typ": "JWT"
    }

    # Create the JWT Payload
    payload = {
        "user_id": "Bob"
    }

    # Create the message (header + payload) to be signed
    jwt_header_payload = _create_jwt_header_payload(header, payload)

    # Sign the JWT with the private key
    jwt_signature = _jwt_kms_asymmetric_sign(jwt_header_payload, aws_kms_key_arn)    
  
    # Fully signed JWT
    jwt_full = (jwt_header_payload + "." + jwt_signature).rstrip("=")
    print("The signed JWT is: " + jwt_full)
    
    # Verify the JWT
    isVerified = _jwt_kms_asymmetric_verify(jwt_header_payload, jwt_signature, aws_kms_key_arn)
    print("Is the signature valid? " + str(isVerified))