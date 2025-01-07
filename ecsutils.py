import boto3
import json
import app

def get_pipeline_status(cred):
    ecs_client = boto3.client(
        'ecs',
        region_name=cred["region"],
        aws_access_key_id=cred["aws_id"],
        aws_secret_access_key=cred["aws_key"],
    )
    cluster_name = cred["cluster"]
    # List all container instance ARNs in the cluster
    container_instance_arns = ecs_client.list_container_instances(
        cluster=cluster_name
    )['containerInstanceArns']
    
    if not container_instance_arns:
        return 0
    
    # Describe the container instances to get their details
    container_instances = ecs_client.describe_container_instances(
        cluster=cluster_name,
        containerInstances=container_instance_arns
    )['containerInstances']
    
    # Calculate total CPU
    total_cpu_count = sum(instance['registeredResources'][0]['integerValue']
                          for instance in container_instances
                          if instance['registeredResources'][0]['name'] == 'CPU')
    
    return total_cpu_count