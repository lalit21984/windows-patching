import boto3

class TaskTokenNotFoundException(Exception): pass

def event_handler(event, context):
    try:
        if 'task_token' not in event['queryStringParameters']:
            raise TaskTokenNotFoundException('Task token is required')
        
        sfn = boto3.client('stepfunctions')
        task_token = event['queryStringParameters']['task_token']

        if 'path' in event and event.get('path')[1:] == 'approve':
            sfn.send_task_success(
                taskToken=task_token,
                output='{"message": "Manual approval accepted"}'
            )
        else:
            sfn.send_task_failure(
                taskToken=task_token,
                error='ManualApprovalRejected',
                cause='User declined to approve rebooting instances'
            )
    except Exception as e:
        print(e)
        raise e