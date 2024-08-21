import boto3
import urllib.parse

class InvalidPatchEventTypeException(Exception): pass
class MissingPatchGroupException(Exception): pass
class InstancesNotAvailableException(Exception): pass
class ScanAttemptsExceededException(Exception): pass
class ApplyAttemptsExceededException(Exception): pass
class InstancePatchingFailureException(Exception): pass
class InstancesNotFullyPatchedFailureException(Exception): pass

ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')

def get_instances(filters=[]) -> list:
    response = ec2.describe_instances(
        Filters=filters,
        MaxResults=50
    )

    if 'Reservations' in response and len(response['Reservations']) > 0:
        return response['Reservations']
    return []

def get_list_command_invocations(command_id: str, filters=[]) -> list:
    response = ssm.list_command_invocations(
        CommandId=command_id,
        Details=False,
        MaxResults=50,
        Filters=filters
    )

    if 'CommandInvocations' in response and len(response['CommandInvocations']) > 0:
        return response['CommandInvocations']
    return []

def event_handler(event, context):
    if 'patch_group_id' not in event:
        raise MissingPatchGroupException("Missing patch group id")
    
    sns = boto3.client('sns')
    region = context.invoked_function_arn.split(':')[3]
    ec2_filters = [
        {
            "Name": "tag:PatchGroup",
            "Values": event.get('patch_group_id').split(',')
        }
    ]
    command_targets = [
        {
            'Key': "tag:PatchGroup",
            'Values': event.get('patch_group_id').split(',')
        }
    ]

    if 'patch_event_type' in event and event['patch_event_type'] == 'scan':
        try:
            response = get_instances(ec2_filters)
            instances = []

            for reservation in response:
                for instance in reservation['Instances']:
                    instances.append(instance['InstanceId'])

            if len(instances) > 0:
                print(f"Scan {event['patch_group_id']} Patch Group instances for patch compliance")

                response = ssm.send_command(
                    Comment=f"Scan for patch compliance for {event['patch_group_id']} patch group",
                    DocumentName='AWS-RunPatchBaseline',
                    Targets=command_targets,
                    Parameters={
                        'Operation': ['Scan'],
                        'RebootOption': ['NoReboot']
                    },
                    # ServiceRoleArn=event['sns_topic_role_arn'],
                    # NotificationConfig={
                    #     'NotificationArn': event['sns_notification_arn'],
                    #     'NotificationEvents': event['sns_notification_events'].split(',') if 'sns_notification_events' in event else ['All'],
                    #     'NotificationType': event['sns_notification_type'] if 'sns_notification_type' in event else 'Command'
                    # },
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
                    "body": {
                        "message": "Instances are being scanned for compliance",
                        "command_id": response['Command']['CommandId'],
                        "instance_count": len(instances),
                        "check_scan_wait_period": event['check_scan_wait_period']
                    },
                }
            return {
                "statusCode": 200,
                "body": {
                    "message": "There are no instances that need to be scanned for patching"
                },
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'check_scan':
        try:
            scan_count = 1 if 'scan_attempts' not in event else int(event['scan_attempts'])

            if scan_count == event['max_check_scan_attempts']:
                raise ScanAttemptsExceededException("Maximum scan attempts exceeded")

            scan_operation_command_id = event['Input']['body']['command_id']

            command_runs_pending = get_list_command_invocations(scan_operation_command_id, [
                {
                    'key': 'Status',
                    'value': 'Pending'
                }
            ])

            command_runs_inprogress = get_list_command_invocations(scan_operation_command_id, [
                {
                    'key': 'Status',
                    'value': 'InProgress'
                }
            ])

            if len(command_runs_pending) > 0 or len(command_runs_inprogress) > 0:
                scan_count += 1

                return {
                    "statusCode": 200,
                    "body": {
                        "message": "Scan operation is still running",
                        "command_id": scan_operation_command_id,
                        "status": False,
                        "scan_attempts": scan_count,
                        "check_scan_wait_period": event['check_scan_wait_period']
                    },
                }
            return {
                "statusCode": 200,
                "body": {
                    "message": "Scan operation is complete",
                    "status": True,
                    "scan_attempts": scan_count
                },
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'apply':
        try:
            print(f"Apply patch to all instance(s) in Patch Group {event['patch_group_id']}")

            response = ssm.send_command(
                Comment=f"Apply patches to {event['patch_group_id']} patch group",
                DocumentName='AWS-RunPatchBaseline',
                Targets=command_targets,
                Parameters={
                    'Operation': ['Install'],
                    'RebootOption': ['NoReboot']
                },
                MaxConcurrency='100%',
                MaxErrors='0%',
                # ServiceRoleArn=event['sns_topic_role_arn'],
                # NotificationConfig={
                #     'NotificationArn': event['sns_notification_arn'],
                #     'NotificationEvents': event['sns_notification_events'].split(',') if 'sns_notification_events' in event else ['All'],
                #     'NotificationType': event['sns_notification_type'] if 'sns_notification_type' in event else 'Command'
                # },
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
                "body": {
                    "message": "Patching instances",
                    "command_id": response['Command']['CommandId'],
                    "check_apply_wait_period": event['check_apply_wait_period']
                },
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'check_apply':
        try:
            apply_count = 1 if 'apply_attempts' not in event else int(event['apply_attempts'])

            if apply_count == event['max_check_apply_attempts']:
                raise ApplyAttemptsExceededException("Maximum apply attempts exceeded")
            
            response = get_instances(ec2_filters)

            patch_operation_command_id = event['Input']['body']['command_id']
            instance_count = len(response)

            command_runs = get_list_command_invocations(patch_operation_command_id, [
                {
                    'key': 'Status',
                    'value': 'Success'
                }
            ])

            print(len(command_runs))
            print(instance_count)

            if len(command_runs) != instance_count:
                apply_count += 1

                return {
                    "statusCode": 200,
                    "body": {
                        "message": "Patch operation is still running",
                        "status": False,
                        "apply_attempts": apply_count,
                        "command_id": patch_operation_command_id,
                        "check_apply_wait_period": event['check_apply_wait_period']
                    },
                }
            return {
                "statusCode": 200,
                "body": {
                    "message": "Patch operation is complete",
                    "status": True,
                    "apply_attempts": apply_count,
                    "command_id": patch_operation_command_id
                },
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'verify_patch':
        try:
            patch_groups = event['patch_group_id'].split(',')
            command_id = event['Input']['body']['command_id']

            failed_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'Failed'
                }
            ])

            timedout_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'TimedOut'
                }
            ])

            undeliverable_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'Undeliverable'
                }
            ])

            cancelled_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'Cancelled'
                }
            ])

            terminated_command_runs = get_list_command_invocations(command_id, [
                {
                    'key': 'Status',
                    'value': 'Terminated'
                }
            ])

            failed = []

            # Checks that the command ran on the instance unsuccessfully in general for any instance
            if len(failed_command_runs) > 0 or len(timedout_command_runs) > 0 or len(undeliverable_command_runs) > 0 or len(cancelled_command_runs) > 0 or len(terminated_command_runs) > 0:
                print(f"Failed command runs: {command_id} has failed to run on one or more instances")

                for instance in failed_command_runs:
                    failed.append({
                        'instance_id': instance['InstanceId'],
                        'status': instance['Status'],
                        'status_details': instance['StatusDetails'],
                        'trace_output': instance['TraceOutput']
                    })

                print("Failed patching operations:", failed)

                raise InstancePatchingFailureException("Failed patching operations on instances")

            # Check patch error counts for any instance within a patch group
            for element in patch_groups:
                failed_instances = ssm.describe_instance_patch_states_for_patch_group(
                    PatchGroup=element,
                    Filters=[
                        {
                            'Key': 'FailedCount',
                            'Values': ['1'],
                            'Type': 'GreaterThan'
                        },
                        {
                            'Key': 'MissingCount',
                            'Values': ['1'],
                            'Type': 'GreaterThan'
                        }
                    ],
                    MaxResults=50,
                )

                if len(failed_instances['InstancePatchStates']) > 0:
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

                    print(failed)

                    raise InstancesNotFullyPatchedFailureException("All necessary patches were not applied to instances")
                
            return {
                "statusCode": 200,
                "body": {
                    "message": "All instances patched successfully",
                },
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'send_manual_approval':
        try:
            token = urllib.parse.quote(event['ExecutionContext']['Task']['Token'])

            message = f"""
            Manual approval required for rebooting {event['patch_group_id']} patch group instances.\n\n
            Please, approve the rebooting of the instances.\n\n
            {event['api_gateway_endpoint']}/approve?task_token={token}\n\n
            Or reject the rebooting of the instances.\n\n
            {event['api_gateway_endpoint']}/reject?task_token={token}
            """
            
            response = sns.publish(
                TopicArn=event['sns_notification_arn'],
                Message=message,
                Subject=f"{event['patch_group_id']} Patch Group Rebooting Manual Approval"
            )

            return {
                "statusCode": 200,
                "body": {
                    "message": "Manual approval sent",
                    "sns_response": response['MessageId']
                }
            }
        except Exception as e:
            print(e)
            raise e
    elif 'patch_event_type' in event and event['patch_event_type'] == 'reboot':
        try:
            response = get_instances(ec2_filters)
            rebooted_instance_ids = []

            for reservation in response:
                for instance in reservation['Instances']:
                    rebooted_instance_ids.append(instance['InstanceId'])

            response = ec2.reboot_instances(
                InstanceIds=rebooted_instance_ids
            )

            return {
                "statusCode": 200,
                "body": {
                    "message": f"Rebooting instances for {event['patch_group_id']} patch group",
                    "patch_group_id": event['patch_group_id'],
                },
            }
        except Exception as e:
            print(e)
            raise e
    else:
        raise InvalidPatchEventTypeException("Invalid patch event type submitted!")