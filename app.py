import json
import boto3

ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')

def get_instances(filters=[]):
    response = ec2.describe_instances(
        Filters=filters,
        MaxResults=1000
    )

    if len(response) > 0:
        return response['Reservations'][0]['Instances']
    return []

def get_list_command_invocations(command_id, filters=[]):
    response = ssm.list_command_invocations(
        CommandId=command_id,
        Details=False,
        MaxResults=1000,
        Filters=filters
    )

    return response['CommandInvocations']

def event_handler(event, context):
    if 'patch_group_id' not in event:
        raise Exception("Missing patch group id")
    
    sns = boto3.client('sns')
    region = context.invoked_function_arn.split(':')[3]
    ec2_filters = [
        {
            "Name": "tag:PatchGroup",
            "Values": event.get('patch_group_id').split(',')
        }
    ]

    if 'patch_event_type' in event and event['patch_event_type'] == 'scan':
        try:
            response = get_instances(ec2_filters)
            instances = [instance['InstanceId'] for instance in response]

            if len(instances) > 0:
                print(f"Scan {event['patch_group_id']} Patch Group instances for patch compliance")

                response = ssm.send_command(
                    Comment='Scan for patch compliance',
                    DocumentName='AWS-RunPatchBaseline',
                    Targets=ec2_filters,
                    Parameters={
                        'Operation': ['Scan'],
                        'RebootOption': ['NoReboot'],
                        'ApprovalRules': [
                            {
                                'PatchFilters': [
                                    {
                                        'Key': 'SEVERITY',
                                        'Values': ['Critical', 'Important', 'Medium', 'Low']
                                    }
                                ]
                            }
                        ]
                    },
                    OutputS3Region=region,
                    OutputS3BucketName=event['output_s3_bucket_name'],
                    CloudWatchOutputConfig={
                        'CloudWatchLogGroupName': event['cloudwatch_log_group_name'],
                        'CloudWatchOutputEnabled': True if 'cloudwatch_log_group_name' in event else False
                    },
                    TimeoutSeconds=600
                )

                return {
                    "statusCode": 200,
                    "body": {
                        "message": "Instances are being scanned for compliance",
                        "command_id": response['Command']['CommandId'],
                        "instance_count": len(instances),
                        "max_check_scan_attempts": int(event['max_check_scan_attempts']),
                        "max_check_apply_attempts": int(event['max_check_apply_attempts']),
                    },
                }
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "There are no instances that need to be scanned for patching",
                    "command_id": response['Command']['CommandId']
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'check_scan':
        try:
            scan_operation_command_id = event['command_id']

            command_runs = get_list_command_invocations(scan_operation_command_id, [
                {
                    'key': 'Status',
                    'value': 'Pending'
                },
                {
                    'key': 'Status',
                    'value': 'InProgress'
                }
            ])

            if len(command_runs) > 0:
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "message": "Scan operation is still running",
                        "status": False
                    }),
                }
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Scan operation is complete",
                    "status": True
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'apply':
        try:
            print(f"Apply patch to all instance(s) in Patch Group ${event['patch_group_id']}")

            response = ssm.send_command(
                Comment='Apply patch',
                DocumentName='AWS-RunPatchBaseline',
                Targets=ec2_filters,
                Parameters={
                    'Operation': ['Install'],
                    'RebootOption': ['NoReboot'],
                    'PatchGroups': [event['patch_group_id']],
                    'ApprovalRules': [
                        {
                            'PatchFilters': [
                                {
                                    'Key': 'SEVERITY',
                                    'Values': ['Critical', 'Important', 'Medium', 'Low']
                                }
                            ]
                        }
                    ]
                },
                MaxConcurrency='100%',
                MaxErrors='0%',
                ServiceRoleArn=event['sns_topic_role_arn'],
                NotificationConfig={
                    'NotificationArn': event['sns_notification_arn'],
                    'NotificationEvents': event['sns_notification_events'].split(',') if 'sns_notification_events' in event else ['All'],
                    'NotificationType': event['sns_notification_type'] if 'sns_notification_type' in event else 'Command'
                },
                OutputS3Region=region,
                OutputS3BucketName=event['output_s3_bucket_name'],
                CloudWatchOutputConfig={
                    'CloudWatchLogGroupName': event['cloudwatch_log_group_name'],
                    'CloudWatchOutputEnabled': True if 'cloudwatch_log_group_name' in event else False
                },
                TimeoutSeconds=600,
            )

            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Patching instances",
                    "command_id": response['Command']['CommandId'],
                    "max_check_scan_attempts": event['max_check_scan_attempts'],
                    "max_check_apply_attempts": event['max_check_apply_attempts'],
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'check_apply':
        try:
            response = get_instances(ec2_filters)

            patch_operation_command_id = event['command_id']
            instance_count = len(response)

            command_runs = get_list_command_invocations(patch_operation_command_id, [
                {
                    'key': 'Status',
                    'value': 'Success'
                }
            ])

            if len(command_runs['CommandInvocations']) == instance_count:
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "message": "Patch operation is complete",
                        "status": True
                    }),
                }
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Patch operation is still running",
                    "status": False
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'verify_patch':
        try:
            patch_groups = event['patch_group_name'].split(',')
            command_id = event['command_id']

            failed_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'Failed'
                },
                {
                    'key': 'Status',
                    'value': 'TimedOut'
                },
                {
                    'key': 'Status',
                    'value': 'Undeliverable'
                },
                {
                    'key': 'Status',
                    'value': 'Cancelled'
                },
                {
                    'key': 'Status',
                    'value': 'Terminated'
                }
            ])

            failed = []

            # Checks that the command ran on the instance unsuccessfully in general for any instance
            if len(failed_command_runs['CommandInvocations']) > 0:
                print(f"Failed command runs: {command_id} has failed to run on one or more instances")

                for instance in failed_command_runs['CommandInvocations']:
                    failed.append({
                        'instance_id': instance['InstanceId'],
                        'status': instance['Status'],
                        'status_details': instance['StatusDetails'],
                        'trace_output': instance['TraceOutput']
                    })

                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "message": "Failed patching operations",
                        "failed_command_runs": failed
                    }),
                }

            # Check patch error counts for any instance within a patch group
            for element in patch_groups:
                failed_instances = ssm.describe_instance_patch_states_for_patch_group(
                    PatchGroup=element,
                    Filters=[
                        {
                            'Key': 'FailedCount',
                            'Value': '1',
                            'Type': 'GreaterThan'
                        },
                        {
                            'Key': 'MissingCount',
                            'Value': '1',
                            'Type': 'GreaterThan'
                        }
                    ],
                    MaxResults=1000,
                )

                if len(failed_instances['InstancePatchStates'] > 0):
                    for instance in failed_instances['InstancePatchStates']:
                        failed.append({
                            'instance_id': instance['InstanceId'],
                            'baseline_id': instance['BaselineId'],
                            'missing_count': instance['MissingCount'],
                            'failed_count': instance['FailedCount'],
                            'installed_rejected_count': instance['InstalledRejectedCount'],
                            'operation': instance['Operation'], 
                            'last_no_reboot_install_operation_time': instance['LastNoRebootInstallOperationTime'],
                            'other_non_compliant_count': instance['OtherNonCompliantCount']
                        })

                    return {
                        "statusCode": 200,
                        "body": json.dumps({
                            "message": "Failed instance patching",
                            "failed_instance_patches": failed
                        }),
                    }
                
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "All instances patched successfully",
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'reboot':
        try:
            rebooted_instances = get_instances(ec2_filters)
            instance_ids = [instance['InstanceId'] for instance in rebooted_instances]

            response = ec2.reboot_instances(
                InstanceIds=instance_ids
            )

            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Failed instance patching",
                    "patch_group_id": event['patch_group_id'],
                }),
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'send_manual_approval':
        try:
            sns.publish(
                TopicArn=event['sns_topic_arn'],
                Message=f"Manual approval required for rebooting {event['patch_group_id']} instances",
                Subject='Rebooting Manual Approval'
            )
        except Exception as e:
            print(e)
            raise e
    else:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "Invalid patch event type"
            }),
        }