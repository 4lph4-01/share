import boto3

# Description: Enumerates AWS resources

# Initialize a session using Amazon EC2
session = boto3.Session(profile_name='default')
ec2 = session.resource('ec2')

# List all instances
instances = ec2.instances.all()
for instance in instances:
    print(instance.id, instance.instance_type)

