import boto3
import requests
import json
import os

def read_config():
    f = open('secrets/config.json')
    return json.load(f)

config = read_config()

s3_client = boto3.client(
    's3',
    region_name='us-east-1',
    aws_access_key_id=config["aws"].get("aws_id", None),
    aws_secret_access_key=config["aws"].get("aws_key", None),
    use_ssl=True,
)

bucket_name = config["aws"]["bucket_name"]
filename = "multipart/test.fastq"
file = "test/test.fastq"
file_size = os.path.getsize(file)
print(file_size)

max_size = 5 * 1024 * 1024 #you can define your own size

res = s3_client.create_multipart_upload(Bucket=bucket_name, Key=filename)
upload_id = res['UploadId']

# please note this is for only 1 part of the file, you have to do it for all parts and store all the etag, partnumber in a list 

parts=[]

def read_in_chunks(file_object, chunk_size=1024*1024):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

part_no = 1
f = open(file, 'rb')
for file_chunk in read_in_chunks(f, max_size):
    signed_url = s3_client.generate_presigned_url(ClientMethod='upload_part',Params={'Bucket': bucket_name, 'Key': filename, 'UploadId': upload_id, 'PartNumber': part_no})
    res = requests.put(signed_url, data=file_chunk)
    print(res.request.headers)
    print(res.request.body[0:20])
    etag = res.headers['ETag']
    parts.append({'ETag': etag, 'PartNumber': part_no})
    part_no = part_no+1

f.close()

#After completing for all parts, you will use complete_multipart_upload api which requires that parts list 
res = s3_client.complete_multipart_upload(
        Bucket=bucket_name,
        Key=filename,
        MultipartUpload={'Parts': parts},
        UploadId=upload_id)

# s3_client
# abort_multipart_upload
# s3_client.list_multipart_uploads(Bucket=bucket_name)