# (c) 2019 Amazon Web Services, Inc. or its affiliates.  All Rights
# Reserved. This AWS Content is provided subject to the terms of the
# AWS Customer Agreement available at http://aws.amazon.com/agreement
# or other written agreement between Customer and Amazon Web Services,
# Inc.


"""index module

This module demonstrates an example API returning an example JSON
response.
"""


import json
import logging


# Logger setup.  For more information on the 'logging' module, please
# refer to the relevant Python documentation page:
# https://docs.python.org/2/library/logging.html
logger = logging.getLogger()

# Using logging.INFO as the default level.  If you wish to do some
# troubleshooting on this example script, you can also consider using
# (or switching) the logging level to logging.DEBUG
logger.setLevel(logging.INFO)
# logger.setLevel(logging.DEBUG)

# Using sys.stderr for logging in this example
logging_streamhandler = logging.StreamHandler(stream=None)
logging_streamhandler.setFormatter(logging.Formatter(
    fmt='%(asctime)s %(levelname)-8s %(message)s'))
logger.addHandler(logging_streamhandler)

# Get logger for botocore and setting logging level
# (commenting out the two lines below: not used here)
# botocore_logger = logging.getLogger('botocore')
# botocore_logger.setLevel(logging.CRITICAL)


def lambda_handler(event, context):
    """This is the main function.  This example function returns a
    dictionary with statusCode, body and headers defined as a
    response.

    Keyword arguments:
    event LambdaEvent -- the Lambda Event received from Invoke API
    context LambdaContext -- the Lambda Context runtime methods and attributes
    """
    logging.info('Returning API response.')
    return {
        'statusCode': 200,
        'body': json.dumps(
            {
                'message': 'example_message',
            }
        ),
        'headers': {
            'Content-Type': 'application/json'
        }
    }
