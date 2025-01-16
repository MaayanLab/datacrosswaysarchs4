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
