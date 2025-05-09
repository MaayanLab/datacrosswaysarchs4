import boto3
import json
import app
from botocore.exceptions import ClientError
from datetime import datetime

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

def scale_pipeline(cred, desired_capacity=0):
        client = boto3.client(
            'autoscaling',
            region_name=cred["autoscaling_region"],
            aws_access_key_id=cred["aws_id"],
            aws_secret_access_key=cred["aws_key"],
        )

        try:
            # Update the desired capacity of the Auto Scaling Group
            response = client.set_desired_capacity(
                AutoScalingGroupName=cred["autoscaling_name"],
                DesiredCapacity=desired_capacity,
                HonorCooldown=True  # Optional: set to False if you want to ignore cooldown periods
            )
            
            print(f"Successfully scaled {cred['autoscaling_name']} to {desired_capacity} instances.")
            print(response)  # You can log the response for more details

        except Exception as e:
            print(f"Error scaling Auto Scaling Group: {e}")

def discover_samples(cred):
    """
    Deploy an ECS task definition in a specified cluster.

    :param cluster_name: The name of the ECS cluster.
    :return: Response from the run_task API call.
    """
    # Create an ECS client
    ecs_client = boto3.client('ecs',
                    region_name="us-east-1",
                    aws_access_key_id=cred["aws_id"],
                    aws_secret_access_key=cred["aws_key"],
                )

    # Run the task
    response = ecs_client.run_task(
        cluster=cred["packaging_cluster"],
        taskDefinition=cred["sample_discovery_task"],
        count=1,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ['subnet-cfe33fe2', 'subnet-4f801743', 'subnet-b01ddc8c', 'subnet-97f47bde', 'subnet-bd741fd8', 'subnet-594b9b02'],
                'assignPublicIp': 'ENABLED',
                'securityGroups': ['sg-6f7f9312'],
            }
        }
    )
    
    return response

def package_samples(cred):
    """
    Deploy an ECS task definition in a specified cluster.

    :param cluster_name: The name of the ECS cluster.
    :return: Response from the run_task API call.
    """
    # Create an ECS client
    ecs_client = boto3.client('ecs',
                    region_name="us-east-1",
                    aws_access_key_id=cred["aws_id"],
                    aws_secret_access_key=cred["aws_key"],
                )

    # Run the tasks
    responses = []
    for task in cred["packaging_tasks"]:
        response = ecs_client.run_task(
            cluster=cred["packaging_cluster"],
            taskDefinition=task,
            count=1,
            launchType='FARGATE',
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': ['subnet-cfe33fe2', 'subnet-4f801743', 'subnet-b01ddc8c', 'subnet-97f47bde', 'subnet-bd741fd8', 'subnet-594b9b02'],
                    'assignPublicIp': 'ENABLED',
                    'securityGroups': ['sg-6f7f9312'],
                }
            }
        )
        responses.append(response)
    
    return responses


def get_task_status(cred, task_definition_arn):
    """
    Get the status of a task for a given task definition ARN.
    Returns a status object with task_arn, status (running/offline), created_at, and optional error.
    """
    try:
        ecs_client = boto3.client('ecs',
                    region_name="us-east-1",
                    aws_access_key_id=cred["aws_ecs"]["aws_id"],
                    aws_secret_access_key=cred["aws_ecs"]["aws_key"],
                )
        
        # List tasks associated with the task definition in the cluster
        response = ecs_client.list_tasks(
            cluster=cred["aws_ecs"]["packaging_cluster"],
            family=task_definition_arn.split('/')[-1].split(':')[0]  # Extract family name
        )
        
        task_arns = response.get('taskArns', [])
        if not task_arns:
            return {
                'task_arn': task_definition_arn,
                'status': 'offline',
                'created_at': 'N/A'
            }

        # Describe tasks to get their status
        tasks_response = ecs_client.describe_tasks(
            cluster=cred["aws_ecs"]["packaging_cluster"],
            tasks=task_arns
        )
        
        # If multiple tasks, select the most recent based on created_at
        most_recent_task = None
        latest_time = None
        for task in tasks_response.get('tasks', []):
            created_at = task.get('createdAt')
            if created_at and (latest_time is None or created_at > latest_time):
                most_recent_task = task
                latest_time = created_at
        
        if most_recent_task:
            task_arn = most_recent_task['taskArn']
            ecs_status = most_recent_task['lastStatus']
            status = 'running' if ecs_status in ['RUNNING', 'PENDING', 'STARTING'] else 'offline'
            created_at = str(most_recent_task.get('createdAt', 'N/A'))
            return {
                'task_arn': task_arn,
                'status': status,
                'created_at': created_at
            }
        
        return {
            'task_arn': task_definition_arn,
            'status': 'offline',
            'created_at': 'N/A'
        }

    except ClientError as e:
        return {
            'task_arn': task_definition_arn,
            'status': 'offline',
            'created_at': 'N/A',
            'error': f"Error querying tasks: {str(e)}"
        }

def get_task_pipeline_status(cred):
    # Organized dictionary for tasks
    organized_tasks = {
        'sample_discovery': cred['aws_ecs']['sample_discovery_task'],
        'human': {
            'gene': next(t for t in cred['aws_ecs']['packaging_tasks'] if 'human_gene' in t),
            'transcript': next(t for t in cred['aws_ecs']['packaging_tasks'] if 'human_transcript' in t),
            'tpm': next(t for t in cred['aws_ecs']['packaging_tpm_tasks'] if 'human_tpm' in t)
        },
        'mouse': {
            'gene': next(t for t in cred['aws_ecs']['packaging_tasks'] if 'mouse_gene' in t),
            'transcript': next(t for t in cred['aws_ecs']['packaging_tasks'] if 'mouse_transcript' in t),
            'tpm': next(t for t in cred['aws_ecs']['packaging_tpm_tasks'] if 'mouse_tpm' in t)
        }
    }

    # Get status for each task
    status_report = {
        'sample_discovery': get_task_status(cred, organized_tasks['sample_discovery']),
        'human': {
            'gene': get_task_status(cred, organized_tasks['human']['gene']),
            'transcript': get_task_status(cred, organized_tasks['human']['transcript']),
            'tpm': get_task_status(cred, organized_tasks['human']['tpm'])
        },
        'mouse': {
            'gene': get_task_status(cred, organized_tasks['mouse']['gene']),
            'transcript': get_task_status(cred, organized_tasks['mouse']['transcript']),
            'tpm': get_task_status(cred, organized_tasks['mouse']['tpm'])
        }
    }

    return status_report

def launch_task(cred, task_arn):
    """
    Deploy an ECS task definition in a specified cluster.

    :param cluster_name: The name of the ECS cluster.
    :return: Response from the run_task API call.
    """
    # Create an ECS client
    ecs_client = boto3.client('ecs',
                    region_name="us-east-1",
                    aws_access_key_id=cred["aws_ecs"]["aws_id"],
                    aws_secret_access_key=cred["aws_ecs"]["aws_key"],
                )

    response = ecs_client.run_task(
        cluster=cred["packaging_cluster"],
        taskDefinition=task_arn,
        count=1,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ['subnet-cfe33fe2', 'subnet-4f801743', 'subnet-b01ddc8c', 'subnet-97f47bde', 'subnet-bd741fd8', 'subnet-594b9b02'],
                'assignPublicIp': 'ENABLED',
                'securityGroups': ['sg-6f7f9312'],
            }
        }
    )
    
    return response