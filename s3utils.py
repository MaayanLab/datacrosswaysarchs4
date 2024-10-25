import boto3
import json
import app

def delete_file(file_uuid, file_name):
    print(file_uuid)
    print(file_name)
    s3_client = get_aws_client(app.conf["aws"])
    s3_client.delete_objects(
        Bucket=app.conf["aws"]["bucket"],
        Delete={
            'Objects': [
                {
                    'Key': file_uuid+"/"+file_name
                }
            ],
            'Quiet': True
        }
    )

def get_aws_client(cred):
    s3_client = boto3.client(
        's3',
        region_name=cred["region"],
        aws_access_key_id=cred["aws_id"],
        aws_secret_access_key=cred["aws_key"],
    )
    return s3_client

def sign_get_file(file_name, cred):
    
    s3_client = get_aws_client(cred)

    url = s3_client.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': cred["bucket"],
            'Key': file_name,
        },
        ExpiresIn=60*60
    )
    return url

def sign_upload_file(file_name, cred):

    s3_client = get_aws_client(cred)

    response = s3_client.generate_presigned_post(cred["bucket"],
        file_name,
        Fields=None,
        Conditions=None,
        ExpiresIn=600)

    return response

def start_multipart(filename, cred):
    s3_client = get_aws_client(cred)
    return s3_client.create_multipart_upload(Bucket=cred["bucket"], Key=filename)['UploadId']

def sign_multipart(filename, upload_id, part_number, cred):
    s3_client = get_aws_client(cred)
    signed_url = s3_client.generate_presigned_url(
        ClientMethod='upload_part',
        Params={'Bucket': cred['bucket'], 
        'Key': filename, 
        'UploadId': upload_id, 
        'PartNumber': part_number})
    return signed_url

def complete_multipart(filename, upload_id, parts, cred):
    s3_client = get_aws_client(cred)
    res = s3_client.complete_multipart_upload(
        Bucket=cred["bucket"],
        Key=filename,
        MultipartUpload={'Parts': parts},
        UploadId=upload_id)

def get_file_size(filename):
    s3_client = get_aws_client(app.conf["aws"])
    response = s3_client.head_object(Bucket='mssm-test', Key='kWbmk5955QM7/kallisto')
    return response['ContentLength']

def get_file_checksum(filename):
    s3_client = get_aws_client(app.conf["aws"])
    response = s3_client.head_object(Bucket=app.conf["aws"]["bucket"], Key=filename)
    return response['Metadata'].get("checksum")
