#!/usr/bin/python3

from format_json_logs import CustomJsonFormatter
import boto3
from botocore.exceptions import ClientError
import time
import re
import sys
import logging
import os
from datetime import datetime
import requests
import json

# what to get from environment variables
debug = os.environ.get('DEBUG', None)
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY', None)


# db configs
aws_access_key_id = '[your key here]'
region_name = 'us-east-1'
# hosted zone idea for the CNAME reference
hosted_zone_id = '[your id here]'
# identifier of the target to be cloned
identifier = 'production'
# where to CNAME the clone to
cname_name = 'staging-db.yourdomain.com'
# clone instance type
instance_type = 'db.m4.large'

if debug:
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logHandler = logging.StreamHandler()
    formatter = CustomJsonFormatter('(timestamp) (level) (name) (message)')
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)
else:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logHandler = logging.StreamHandler()
    formatter = CustomJsonFormatter('(timestamp) (level) (name) (message)')
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

if not aws_access_key_id:
    logging.error(
        "ERROR: no environment variable 'AWS_ACCESS_KEY_ID' defined!")
    sys.exit(1)

if not aws_secret_access_key:
    logging.error(
        "ERROR: no environment variable 'AWS_SECRET_ACCESS_KEY' defined!")
    sys.exit(1)


def report_error(message):
    logging.error(message)
    sys.exit(1)

def latest_snapshot_by_identifier(db_identifier):
    rds_client = boto3.client('rds', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, region_name=region_name)
    snapshot_list = []
    try:
        snapshots = rds_client.describe_db_snapshots()
        for i in snapshots['DBSnapshots']:
            if i['DBInstanceIdentifier'] == db_identifier:
                pattern = re.compile(r'rds:' + db_identifier +
                            r'\-\d{4}\-\d{2}\-\d{2}\-\d{2}\-\d{2}')
                result = re.match(
                    pattern, i['DBSnapshotIdentifier'])
                if result:
                    snapshot_list.append(i['DBSnapshotIdentifier'])
        return sorted(snapshot_list)[-1:][0]
    except ClientError as e:
        report_error(e)

def list_restored_dbs(db_identifier):
    try:
        rds_client = boto3.client('rds', aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key, region_name=region_name)
        dbs = []
        instances = rds_client.describe_db_instances()
        for db in instances['DBInstances']:
            logging.debug("**** checking %s" % db['DBInstanceIdentifier'])
            pattern = re.compile(db_identifier +
                                r'\-\d{4}\-\d{2}\-\d{2}\-\d{2}\-\d{2}\-restored')
            result = re.match(
                pattern, db['DBInstanceIdentifier'])
            if result:
                dbs.append(db['DBInstanceIdentifier'])
        logging.debug("**** Previous db versions:")
        logging.debug(dbs)
        return dbs
    except ClientError as e:
        report_error(e)

def describe_instance(db_identifier):
    try:
        rds_client = boto3.client('rds', aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key, region_name=region_name)
        response = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_identifier)
        return response['DBInstances'][0]
    except ClientError as e:
        report_error(e)


def delete_db(instance_list):
    if instance_list:
        try:
            rds_client = boto3.client('rds', aws_access_key_id=aws_access_key_id,
                                      aws_secret_access_key=aws_secret_access_key, region_name=region_name)
            for instance in instance_list:
                logging.info("Deleting: %s" % (instance))
                response = rds_client.delete_db_instance(
                    DBInstanceIdentifier=instance,
                    SkipFinalSnapshot=True,
                    DeleteAutomatedBackups=True
                )
                return response
        except ClientError as e:
            report_error(e)
    else:
        logging.info(
            "No previous instances to remove. Skipping deletion phase")

def create_instance_from_snapshot(params):
    rds_client = boto3.client('rds', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, region_name=region_name)
    # set some defaults
    if 'MultiAZ' not in params.keys():
        params['MultiAZ'] = False
    if 'Iops' not in params.keys():
        params['Iops'] = 0
    if 'PubliclyAccessible' not in params.keys():
        params['PubliclyAccessible'] = False
    if 'AutoMinorVersionUpgrade' not in params.keys():
        params['AutoMinorVersionUpgrade'] = False
    if 'DeletionProtection' not in params.keys():
        params['DeletionProtection'] = False
    try:
        response = rds_client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=params['DBInstanceIdentifier'],
            DBSnapshotIdentifier=params['DBSnapshotIdentifier'],
            DBInstanceClass=params['DBInstanceClass'],
            AvailabilityZone=params['AvailabilityZone'],
            DBSubnetGroupName=params['DBSubnetGroupName'],
            MultiAZ=params['MultiAZ'],
            Iops=params['Iops'],
            PubliclyAccessible=params['PubliclyAccessible'],
            AutoMinorVersionUpgrade=params['AutoMinorVersionUpgrade'],
            OptionGroupName=params['OptionGroupName'],
            Tags=[
                {
                    'Key': 'rds_restored',
                    'Value': params['DBSnapshotIdentifier']
                },
            ],
            StorageType=params['StorageType'],
            VpcSecurityGroupIds=params['VpcSecurityGroupIds'],
            UseDefaultProcessorFeatures=True,
            DBParameterGroupName=params['DBParameterGroupName'],
            DeletionProtection=params['DeletionProtection']
        )
        return response
    except ClientError as e:
        report_error(e)

def db_upsert_cname(target, cname):
    '''Create a cname record in route53.'''
    try:
        client = boto3.client('route53', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, region_name=region_name)
        logging.info("Creating CNAME for %s, pointing to %s" % (cname, target))
        response = client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Comment': 'add %s -> %s' % (cname, target),
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': cname,
                            'Type': 'CNAME',
                                    'TTL': 300,
                            'ResourceRecords': [{'Value': target}]
                        }
                    }]
            })
        return response
    except ClientError as e:
        report_error(e)

def wait_for_available(instance):
    inst = describe_instance(instance)
    if inst['DBInstanceStatus'] != 'available':
        logging.debug('Waiting for %s to become available; current status: %s' % (
            instance, inst['DBInstanceStatus']))
        time.sleep(30)
        wait_for_available(instance)
    return inst

def clone_staging():
    snapshot = latest_snapshot_by_identifier(identifier)
    if not snapshot:
        message = "unable to find a valid snapshot for instance % s" % (identifier)
        report_error(message)
    else:
        previous_instances = list_restored_dbs(identifier)
        target_instance = "%s-restored" % (snapshot.split(':')[1])
        if target_instance in previous_instances:
            message = "%s already exists! Doing nothing!" % target_instance
            (target_instance)
            logging.warning(message)
        else:
            instance_info = describe_instance(identifier)
            logging.debug("####### instance_info:")
            logging.debug(instance_info)
            params = {}
            params['DBInstanceIdentifier'] = target_instance
            params['DBSnapshotIdentifier'] = snapshot
            params['DBInstanceClass'] = instance_type
            params['AvailabilityZone'] = instance_info['AvailabilityZone']
            params['DBSubnetGroupName'] = instance_info['DBSubnetGroup']['DBSubnetGroupName']
            params['OptionGroupName'] = instance_info['OptionGroupMemberships'][0]['OptionGroupName']
            params['StorageType'] = instance_info['StorageType']
            security_groups = []
            for group in instance_info['VpcSecurityGroups']:
                security_groups.append(group['VpcSecurityGroupId'])
            params['VpcSecurityGroupIds'] = security_groups
            params['DBParameterGroupName'] = instance_info['DBParameterGroups'][0]['DBParameterGroupName']
            logging.debug("####### params:")
            logging.debug(params)
            logging.debug("####### Found snapshot: %s for identifier %s" %
                (snapshot, identifier))
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.restore_db_instance_from_db_snapshot
            logging.info("####### Creating %s based on snapshot %s" %
                (target_instance, params['DBSnapshotIdentifier']))
            create_result = create_instance_from_snapshot(params)
            logging.debug(create_result)
            # wait for instance to be ready
            wait_for_available(target_instance)
            new_instance_info = describe_instance(target_instance)
            logging.debug(new_instance_info)
            cname_target = new_instance_info['Endpoint']['Address']
            logging.debug("cname_target: %s" % (cname_target))
            # update CNAME
            upsert_result = db_upsert_cname(cname_target, cname_name)
            logging.debug(upsert_result)
            # remove old instances
            delete_response = delete_db(previous_instances)
            logging.debug(delete_response)
            message = "Restore of %s to %s complete." % (
                params['DBSnapshotIdentifier'], cname_name)
            logging.info(message)


if __name__ == '__main__':
    clone_staging()
