
import gzip
import json
import logging
import os
from base64 import b64decode
from datetime import datetime
from datetime import timezone
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

NOTIBOY_ENDPOINT = os.environ['notiboy_endpoint']
SLACK_CHANNEL = os.environ['slack_channel']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    raw_data = str(event['awslogs']['data'])
    logger.debug('event_data => {}'.format(raw_data))

    decompressed = gzip.decompress(b64decode(raw_data)).decode('utf-8')
    event_data = json.loads(decompressed)
    logger.info('Event => {}'.format(json.dumps(event_data, indent=4)))

    log_event = event_data['logEvents'][0]
    payload = {
        'channel': SLACK_CHANNEL,
        'message': make_slack_message(log_event['message'],
                                      event_data['logStream'],
                                      log_event['timestamp']//1000)
    }
    req = Request(NOTIBOY_ENDPOINT, data=json.dumps(payload).encode('utf-8'),
                  headers={'Content-Type': 'application/json'})
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", payload['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def make_slack_message(log_message, log_stream, timestamp):
    logger.info('Log stream => {}'.format(log_stream))
    logger.info('Log message => {}'.format(log_message))

    escaped_message = log_message.replace('&', '&amp;')\
        .replace('<', '&lt;').replace('>', '&gt;')
    utc_time = datetime.utcfromtimestamp(timestamp).replace(tzinfo=timezone.utc)
    logger.info('Log time => {}'.format(utc_time))
    formatted_time = '<!date^{}^Reported {{date_num}} {{time_secs}}|Reported {}>'\
        .format(timestamp, utc_time.strftime('%Y-%m-%d %I:%M:%S %p'))
    return '{}\nLog stream: {}\nLogs: {}'\
        .format(formatted_time, log_stream, escaped_message)
