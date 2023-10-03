
import typing
from tqdm import tqdm
import concurrent.futures
import jwt  # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests  # requests version 2.18.4 as of the time of authoring.
import json
from datetime import datetime, timedelta
import logging
import argparse
from pathlib import Path
import time
import platform
import os
import binascii
import sys
from urllib import parse
# import config
import configparser
from pathlib import Path
if os.name == 'nt':
    os.environ['ANSI_COLORS_DISABLED'] = "1"
import pprint
import pymongo
import bson


class LancelotException(Exception):
    pass


# APP_ID = config.APP_ID
# APP_SECRET = config.APP_SECRET
# TENANT_ID = config.TENANT_ID
# URI = config.APIENDPOINT
# ACCESS_KEY=config.ACCESS_KEY
# SECRET_ACCESS_KEY=config.SECRET_ACCESS_KEY
# BUCKET=config.BUCKET

LOGGER = logging.getLogger("lancelot")
LOGGER.setLevel(logging.INFO)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

LOGGER.setLevel(logging.INFO)


class Lancelot(object):
    def __init__(self,
                 tenant_uri: str = None,
                 tenant_id: str = None,
                 app_id: str = None,
                 app_secret: str = None,
                 s3_key: str = None,
                 s3_secret: str = None,
                 s3_bucket: str = None,
                 datadir: str = None,
                 mongodburi: str = None,
                 profile: str = 'lancelot',
                 debug: bool = False,
                 ssl_verify: bool = True):
        if debug:
            LOGGER.setLevel(logging.DEBUG)

        if datadir is not None:
            self.datadir = datadir
        else:
            self.datadir = os.path.join(Path.home(), ".lancelot")
            if not os.path.exists(self.datadir):
                os.makedirs(self.datadir)
        self.ssl_verify=ssl_verify
        self.profile = profile
        self.mongodburi = mongodburi
        self.tenant_uri = tenant_uri
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.app_secret = app_secret
        self.s3_key = s3_key
        self.s3_secret = s3_secret
        self.s3_bucket = s3_bucket
        self.token = None
        self.timeout = None
        self.cfg_path = os.path.join(self.datadir, "config.ini")
        options = ["tenant_uri",
                   "tenant_id",
                   "app_id",
                   "app_secret",
                   "s3_key",
                   "s3_secret",
                   "s3_bucket"]

        if os.path.exists(self.cfg_path):
            config = configparser.ConfigParser()
            config.read(self.cfg_path)
            try:
                for k in options:
                    if getattr(self, k, None) is None:
                        v = config.get(self.profile, k)
                        # print(k,v)
                        if v is not None:
                            setattr(self, k, v)
            except configparser.NoSectionError:
                pass
        for k in options:
            if getattr(self, k, None) is None:
                raise LancelotException(
                    f"Missing value {k} - not in config or parameter")

        self.s3_destination = f"https://{self.s3_key}:{parse.quote(self.s3_secret)}@{self.s3_bucket}.s3.amazonaws.com/"
        # print(os.getcwd())

    def _getJWTToken(self):
        # 30 minutes from now
        timeout = 1800
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        self.timeout = timeout_datetime
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int(
            (timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())
        # tid_val = "" # The tenant's unique identifier.
        # app_id = "" # The application's unique identifier.
        # app_secret = "" # The application's secret to sign the auth token with.
        AUTH_URL = "{}/auth/v2/token".format(self.tenant_uri)
        claims = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": self.app_id,
            "tid": self.tenant_id,
            "jti": jti_val
            # The following is optional and is being noted here as an example on how one can restrict
            # the list of scopes being requested
            # "scp": "policy:create, policy:list, policy:read, policy:update"
        }
        # from IPython import embed
        # embed()
        encoded = jwt.encode(claims, self.app_secret,
                             algorithm='HS256')#.decode('utf8')
        LOGGER.debug("auth_token:" + encoded)
        payload = {"auth_token": encoded}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        resp = requests.post(AUTH_URL, headers=headers,
                             data=json.dumps(payload),verify=self.ssl_verify)
        LOGGER.debug("http_status_code: " + str(resp.status_code))
        j = resp.json()
        LOGGER.debug("access_token:" + j['access_token'])
        return j['access_token']

    def _issueReqest(self, method, *args, **kwargs):
        m = getattr(requests, method)
        url = args[0]
        LOGGER.debug(f"{method} {url}")
        kwargs['allow_redirects'] = False
        kwargs['verify']=self.ssl_verify
        response = m(*args, **kwargs)
        if response.status_code not in (200, 202):
            e = LancelotException("Error while performing request {}".format(
                "{} {}" .format(response.request.method, response.request.url)))
            e.response = response
            # from requests_toolbelt.utils import dump
            # dump.dump_all(response.request)
            LOGGER.error("Response STATUS CODE: {}".format(response.status_code))
            LOGGER.error(f"Request URL: {method} {response.request.url}")
            LOGGER.error(f"Request headers: {response.request.headers}")
            LOGGER.error(f"Request body: {response.request.body.decode('utf8')}")
            LOGGER.error(f"Resposne headers: {response.headers}")
            LOGGER.error(f"Response content: {response.content}")
            raise e
        return response

    def _callCylanceAPI(self, 
        endpoint: str, 
        params: dict = None, 
        payload: dict = None, 
        all_pages: bool = True, 
        page_size: int = 200,
        method: str = None) -> dict:

        if self.token is None:
            self.token = self._getJWTToken()

        if params is None:
            params = {}

        headers = {"Accept": "Application/json",
                   "Content-Type": "application/json",
                   "Authorization": "Bearer {}".format(self.token)}

        ret = None

        url = "{}{}".format(self.tenant_uri, endpoint)

        if payload:  # post case
            LOGGER.debug(f"Method: {method}")
            if method:
                httpMethod=method
            else:
                httpMethod="post"
            response = self._issueReqest(httpMethod,
                                         url,
                                         headers=headers,
                                         json=payload,
                                         params=params)
            # print(response.headers)
            # print(payload)
            # print(response.request.url)
            # print(response.request.headers)
            # print("BODY: " + response.request.body.decode("utf8"))
            # print(response.content)
            # LOGGER.debug(f"DDDDDD Resposne to {url} code: {response.status_code}")
            try:
                if len(response.content)>0:
                    j=response.json()
                    return j
                else:
                    return None
            except json.decoder.JSONDecodeError as e:
                LOGGER.error(f"Unable to decode JSON: {e}")
                LOGGER.debug(response.content)

        else:  # get case
            params['page'] = 1
            params['page_size'] = page_size
            while True:
                response = self._issueReqest(
                    "get",
                    url,
                    headers=headers,
                    params=params

                )
                j = response.json()
                ret = j['page_items']
                total_pages = j['total_pages']
                LOGGER.debug("There are {} pages in total, page size is {}".format(
                    total_pages, page_size))
                if total_pages > 1 and all_pages == False:
                    LOGGER.warn(
                        "There are {} pages to retrieve but I will not be retrieving".format(total_pages))
                elif total_pages > 1:
                    for i in range(2, response.json()['total_pages']+1):
                        LOGGER.debug("Retrieving page {}".format(i))
                        params['page'] = i
                        response = self._issueReqest(
                            "get",
                            url,
                            headers=headers,
                            params=params
                        )
                        ret.extend(response.json()['page_items'])
                    LOGGER.debug("Fetched {} pages".format(i))
                    break
                else:
                    break

        return ret

    def _getPackages(self) -> list:
        endpoint = "/packages/v2"
        return self._callCylanceAPI(endpoint)

    def getPackages(self, verbose: bool = False):
        packages = self._getPackages()
        if verbose:
            pprint.pprint(packages)
        else:
            for p in packages:
                print(f"{p['packageDescriptor']['name']}")

    def _getDeviceCachePath(self):
        return os.path.join(self.datadir, f"{self.profile}_devices.json")

    def getDevices(self, ignore_cache: bool = False):
        devpath = self._getDeviceCachePath()
        if ignore_cache == False:  # try cache first
            if os.path.exists(devpath):
                last_mod = datetime.fromtimestamp(os.path.getmtime(devpath))
                if datetime.now()-last_mod > timedelta(days=1):
                    LOGGER.warning(
                        f"Your device cache is older than one day (last refreshed {last_mod.isoformat()}")
                    # return
                try:
                    devices = json.load(open(devpath))
                    LOGGER.debug(
                        "Loaded {} devices from cache".format(len(devices)))
                    return devices
                except Exception as e:
                    LOGGER.error(
                        "Unable to read the devices cache from {}: {}".format(devpath, e))
        # Device cache either didn't work or wasn't available
        endpoint = "/devices/v2"
        devices = self._callCylanceAPI(endpoint, page_size=1000)
        self._saveDevices(devices)
        return devices

    def _saveDevices(self, devices):
        devpath = self._getDeviceCachePath()
        LOGGER.debug("Saving to {}".format(devpath))
        json.dump(devices, open(devpath, "w"),indent=4)

    def _getZoneCachePath(self):
        devpath = os.path.join(self.datadir, f"{self.profile}_zones.json")
        return devpath

    def getZones(self, ignore_cache: bool = False):
        devpath = self._getZoneCachePath()
        if ignore_cache == False:  # try cache first
            if os.path.exists(devpath):
                try:
                    devices = json.load(open(devpath))
                    LOGGER.debug(
                        "Loaded {} zones from cache".format(len(devices)))
                    return devices
                except Exception as e:
                    LOGGER.error(
                        "Unable to read the zones cache from {}: {}".format(devpath, e))
        # Device cache either didn't work or wasn't available
        endpoint = "/zones/v2"
        devices = self._callCylanceAPI(endpoint, page_size=200)
        LOGGER.debug("Saving to {}".format(devpath))
        json.dump(devices, open(devpath, "w"))
        return devices

    def _findPackagesByName(self, names):
        if type(names) == str:
            names = [names]
        packages = self._getPackages()
        return [p['packageId'] for p in packages if p['packageDescriptor']['name'] in names]

    def _findZoneIdsByName(self, names, opticsFormat=False):
        if type(names) == str:
            names = [names]
        zones = self.getZones()
        z = [p['id'] for p in zones if p['name'] in names]
        if opticsFormat:
            z = [x.upper().replace("-", "") for x in z]
        return z

    def writeConfig(self):
        config = configparser.ConfigParser()
        try:
            config.read(self.cfg_path)
        except Exception:
            pass
        config.add_section(self.profile)
        config.set(self.profile, 'APP_ID', self.app_id)
        config.set(self.profile, 'APP_SECRET', self.app_secret)
        config.set(self.profile, 'TENANT_ID', self.tenant_id)
        config.set(self.profile, 'TENANT_URI', self.tenant_uri)
        config.set(self.profile, 'S3_KEY', self.s3_key)
        config.set(self.profile, 'S3_SECRET', self.s3_secret)
        config.set(self.profile, 'S3_BUCKET', self.s3_bucket)
        with open(self.cfg_path, "w") as f:
            config.write(f)
        LOGGER.info(f"Wrote config to {self.datadir}")

    def deployPackage(self,
                      directory: str,
                      package: str,
                      *args,
                      name: str = None,
                      devices: list = None,
                      deviceids: list = None,
                      zones: list = None,
                      keepResultsLocally: bool = False,
                      encode: bool = False
                      ):
        if directory is None:
            raise LancelotException(
                "Cannot deploy in root directory, please add folder path")
        if devices is None and zones is None and deviceids is None:
            raise LancelotException(
                "Either devices,deviceids or zones have to be provided")
        if len([x for x in [devices, zones, deviceids] if x is not None]) > 1:
            raise LancelotException(
                "Provide only one of devices, deviceids or zones")

        destination = parse.urljoin(self.s3_destination, directory)
        LOGGER.info(f"Results will be in {destination}")

        cy_args = []
        for a in args:
            k, v = a.split("=", 1)
            cy_args.append(f"-{k}")
            if encode:
                cy_args.append(binascii.b2a_base64(
                    v.encode("utf8")).decode("utf8").strip())
            else:
                cy_args.append(v)
        # packages=self.getPack
        # destination_url=parse.urlparse(destination)
        if name is None:
            name = f"lancelot-{platform.node()}"
        schema = {
            'execution': {
                'name': name,
                'target': {
                    'devices': [],
                    'zones': []
                },
                'destination': destination,
                # 'packageExecutions': [],
                'packageExecutions': [
                    # {
                    #     "arguments": [],

                    #     "package":"129469df-9bb6-4908-b0c0-1518655a0a17"#https://content-apse2.cylance.com/B60A68E0421645FFB93E9B75A8484568"
                    # }
                ],
                'keepResultsLocally': keepResultsLocally

            }
        }

        cy_packages = self._findPackagesByName(package)
        if len(cy_packages) == 0:
            LOGGER.error(
                "No package by name {} were found, aborting".format(package))
            return None

        schema['execution']['packageExecutions'].append({
            "arguments": cy_args,
            "package": cy_packages[0]
        })
        if deviceids:
            if type(deviceids) == str:
                deviceids = [deviceids]
            deviceids = [x.upper().replace("-", "") for x in deviceids]
            schema['execution']['target']['devices'] = deviceids
        elif devices:
            deviceIds = self._findDeviceIDsByName(devices, opticsFormat=True)
            if len(deviceIds) == 0:
                LOGGER.error("No device IDs found")
                return
            schema['execution']['target']['devices'] = deviceIds
        elif zones:
            zoneIds = self._findZoneIdsByName(zones, opticsFormat=True)
            if len(zoneIds) == 0:
                LOGGER.error("No zoneIds found")
                return
            schema['execution']['target']['zones'] = zoneIds
        endpoint = "/packages/v2/executions"
        LOGGER.info(f"Deploying package {package} with arguments {cy_args}")
        # return
        return self._callCylanceAPI(endpoint, payload=schema)

    def deployPackages(self,
                       directory: str,
                       packages: list,
                       name: str = None,
                       devices: list = None,
                       zones: list = None,
                       keepResultsLocally: bool = False):
        if directory is None:
            raise LancelotException(
                "Cannot deploy in root directory, please add folder path")
        if devices is None and zones is None:
            raise LancelotException(
                "Either devices or zones have to be provided")
        if devices and zones:
            raise LancelotException(
                "Either devices or zones have to be provided BUT NOT BOTH")

        destination = parse.urljoin(self.s3_destination, directory)
        LOGGER.info(f"Results will be in {destination}")

        # packages=self.getPack
        # destination_url=parse.urlparse(destination)
        if name is None:
            name = f"lancelot-{platform.node()}"
        schema = {
            'execution': {
                'name': name,
                'target': {
                    'devices': [],
                    'zones': []
                },
                'destination': destination,
                # 'packageExecutions': [],
                'packageExecutions': [
                    # {
                    #     "arguments": [],

                    #     "package":"129469df-9bb6-4908-b0c0-1518655a0a17"#https://content-apse2.cylance.com/B60A68E0421645FFB93E9B75A8484568"
                    # }
                ],
                'keepResultsLocally': keepResultsLocally

            }
        }

        package = self._findPackagesByName(packages)
        if len(package) == 0:
            LOGGER.error(
                "No packages by name {} were found, aborting".format(packages))
            return None

        for p in package:
            schema['execution']['packageExecutions'].append({
                "arguments": [],
                "package": p
            })
        if devices:
            deviceIds = self._findDeviceIDsByName(devices, opticsFormat=True)
            if len(deviceIds) == 0:
                LOGGER.error("No device IDs found")
                return
            schema['execution']['target']['devices'] = deviceIds
        if zones:
            zoneIds = self._findZoneIdsByName(zones, opticsFormat=True)
            if len(zoneIds) == 0:
                LOGGER.error("No zoneIds found")
                return
            schema['execution']['target']['zones'] = zoneIds
        endpoint = "/packages/v2/executions"
        return self._callCylanceAPI(endpoint, payload=schema)

    def _findDeviceIDsByName(self, devices, opticsFormat=False):

        if type(devices) == str:
            devices = [devices]
        LOGGER.debug("Got devices: {}".format(devices))
        accum = []
        allDevices = self.getDevices()
        for entry in allDevices:
            # LOGGER.debug(entry['name'])
            if entry['name'] in devices:
                deviceId = entry['id']
                if opticsFormat:
                    deviceId = deviceId.upper().replace("-", "")
                accum.append(deviceId)
        return accum

    def scheduledDeploy(self,
                        packages: list,
                        directory: str = None,
                        targets: str = None,
                        delay: float = 0):
        if targets is None:
            raise LancelotException("No targets file found")
        elif not os.path.exists(targets):
            raise LancelotException(f"File {targets} not found")
        hosts = open(targets, "r").readlines()
        hosts = list(map(str.strip, hosts))
        current_package = 1
        total = len(hosts)
        if delay == 0:
            LOGGER.info(f"Mass deployment command issued (no-delay)..")
            return self.deployPackage(f"bulk_delployment-x{total}", packages, directory, hosts)
        for host in hosts:
            LOGGER.info(
                f"Deploying packages:{packages}  for host:{host} [{current_package}/{total}]")
            if self.token is not None:
                LOGGER.debug("Token is not none - packageDeploy")
                if not ((self.timeout - datetime.utcnow()).total_seconds() - 60 > 0):
                    LOGGER.debug(
                        f"Timeout - current time less than 60 seconds : {(self.timeout - datetime.utcnow()).total_seconds()}")
                    self.token = None
                else:
                    LOGGER.debug(
                        f"Timeout - current time more than 60 seconds : {(self.timeout - datetime.utcnow()).total_seconds()}")
            if type(packages) == list:
                self.deployPackage(host+"-".join(packages),
                                   packages, directory, host)
            else:
                self.deployPackage(host+"-"+packages,
                                   packages, directory, host)
            time.sleep(delay)
            current_package = current_package + 1
            LOGGER.debug(f"Sleeping for {delay} seconds")

    def getDeviceZone(self, name, ignore_cache: bool = False):
        devices = self.getDevices(ignore_cache=ignore_cache)
        for d in devices:
            if d['name'] == name:
                # print(d)
                if ignore_cache or 'zone' not in d:
                    zone = self._getDeviceZone(d['id'])
                    d['zone'] = zone
                else:
                    zone = d['zone']
        self._saveDevices(devices)
        return zone

    def updateDeviceZones(self, workers=None):
        devices = self.getDevices()
        ids = {d['id']: None for d in devices}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_url = {
                executor.submit(self._getDeviceZone, devid): devid for devid in ids.keys()
            }
            for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(ids.keys())):
                devid = future_to_url[future]
                try:
                    zone = future.result()
                    LOGGER.debug(f"Device's {devid} zones are: {zone}")
                except Exception as exc:
                    LOGGER.error(f"Unable to get device {devid} zone : {exc}")
                else:
                    ids[devid] = zone
        # print(ids)
        for d in devices:
            if d['id'] in ids:                
                d['zone'] = ids[d['id']]
        self._saveDevices(devices)

    def _getDeviceZone(self, deviceid):
        endpoint = f"/zones/v2/{deviceid}/zones"
        LOGGER.debug(f"Retrieving device {deviceid} zone memberships")
        deviceZones = self._callCylanceAPI(endpoint)
        return deviceZones

    def _getDevicesFromZone(self, zone):
        devices = self.getDevices()
        zone_devices = []
        for d in devices:
            if 'zone' in d:
                for z in d['zone']:
                    if z['name'] == zone:
                        zone_devices.append((d['name'], d['id']))
            else:
                LOGGER.warning(
                    f"No zone information for {d['name']}, update device zones!")
        return zone_devices
    
    def _getDeviceById(self,devid):
        for d in self.getDevices():
            if devid==d['id']:
                return d
        else:
            raise LancelotException(f"Device with {devid} not found")

    def _updateDevice(self,deviceid,
                name:str=None,
                policy_id:str=None,
                add_zone_ids:typing.List[str]=None,
                remove_zone_ids:typing.List[str]=None,
                ):
        endpoint = f"/devices/v2/{deviceid}"

        d=self._getDeviceById(deviceid)
        data={
            'policy_id':d['policy']['id'],
            'name':d['name'],
            'add_zone_ids':[],
            'remove_zone_ids':[]
        }
        
        if name is not None:
            data['name']=name
        
        if policy_id is not None:
            data['policy_id']=policy_id
        
        if add_zone_ids is not None:
            data['add_zone_ids']=add_zone_ids

        if remove_zone_ids is not None:
            data['remove_zone_ids']=remove_zone_ids

        LOGGER.debug(f"Updating device {deviceid} details with: {data}")
        return self._callCylanceAPI(endpoint,payload=data,method="put")

    def _getZoneByName(self,zoneName):
        zones=self.getZones()        
        for z in zones:
            if zoneName==z['name']:
                return z
        else:
            raise LancelotException(f"Zone with name {zoneName} not found")


    def addDevicesToZone(self,
                zoneName:str,
                devices=None,
                deviceFile=None,
                workers=None
                ):

        # make a list of devices
        if not devices and not deviceFile:
            raise LancelotException("Please provide either devices or device file")
        
        if type(devices)==str:
            devlist=[devices]
        else:
            devlist=devices
        
        
        if deviceFile:
            with open(deviceFile,"r") as f:
                if devlist is None:
                    devlist=[]
                devlist.extend([x.strip() for x in f.readlines() if x])
        
        #remove dupes
        devlist=set(devlist)
        
        # Get zone ID
        zoneId=self._getZoneByName(zoneName)['id']

        devmap={}
        allDevices=self.getDevices()
        for devName in devlist:
            for d in allDevices:
                if devName == d['name']:
                    devmap[d['id']]=d
                    continue
            else:
                LOGGER.warning(f"Device {devName} not found")
        # devmap = {d['id']: d for d in self.getDevices() if d['name'] in devlist}
        LOGGER.debug(f"Adding {len(devmap)} devices to {zoneName}({zoneId})")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_url = {
                executor.submit(self._updateDevice, devid,add_zone_ids=[zoneId]): devid for devid in devmap.keys()
                #executor.submit(self._updateDevice, devid,add_zone_ids=[zoneName]): devid for devid in devmap.keys()
            }
            for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(devmap)):
                devid = future_to_url[future]
                try:
                    _ = future.result()
                    LOGGER.debug(f"Added device's {devmap[devid]}({devid}) to zones {zoneName}")
                except Exception as exc:
                    LOGGER.error(f"Unable to add device {devmap[devid]}({devid}) to zone {zoneName} : {exc}")        
                    import traceback
                    print(traceback.format_exc())

    def createJob(self,
                  jobName: str,
                  package: str,
                  *arguments,
                  zone: str = None,
                #   expiry: datetime = None,
                  devices: typing.List[str] = None,
                  keepResultsLocally: bool = False,
                  encode: bool = False,
                  directory: str = None
                  ):
        jobid = bson.objectid.ObjectId()
        client = pymongo.MongoClient(self.mongodburi)
        if zone and devices:
            raise LancelotException(
                "Specify either zone or devices, but not both!")

        all_devices = self.getDevices()

        if devices:
            deviceids = [d['id'] for d in all_devices if d['id'] in devices]
        else:  # zone
            deviceids = [x[1] for x in self._getDevicesFromZone(zone)]
            # print(deviceids)
            # return
        device_records = [d for d in all_devices if d['id'] in deviceids]
        LOGGER.info(f"Selected {len(device_records)} devices for deployment")
        # return

        db = client.lancelot
        coll_jobs = db.jobs
        
        # Set to expire 24h from now
        expiry = datetime.now()+timedelta(days=1)
        
        
        if not directory:
            directory = f"/lancelot/jobs/{jobid}"

        job = {
            '_id': jobid,
            'name': jobName,
            'package': package,
            'arguments': arguments,
            'expiry': expiry,
            'devices': devices
        }
        job = coll_jobs.insert_one(job)
        LOGGER.info(
            f"Created a new job {jobName} with expiry {expiry.isoformat()} for {len(device_records)} devices to run package {package} (f{job.inserted_id}")

        coll_dev_exec = db.device_exec

        # bucket devices by name, otherwise cylance will overwrite device output 
        # with same name...
        dev_bucket=bucket(device_records,lambda x: x['name'])
        LOGGER.info(f"Bucketed into {len(dev_bucket)} buckets")
        for i,b in enumerate(dev_bucket):
            bucket_directory=f"{directory}/{i}"
            bucket_deviceids=[x['id'] for x in b]
            LOGGER.info(f"Deploying bucket {i} with {len(b)} devices")
            execution = self.deployPackage(bucket_directory,
                                        package,
                                        *arguments,
                                        encode=encode,
                                        name=f"{jobName}-{jobid}-{i}",
                                        keepResultsLocally=keepResultsLocally,
                                        deviceids=bucket_deviceids
                                        )

      
        
            creation_time=datetime.strptime(execution['createdAt'],"%Y-%m-%dT%H:%M:%S.%fZ")
            executions = [
                {
                    'deviceid':d['id'],
                    'directory': bucket_directory,
                    'executionId':execution['id'],
                    'createdAt':creation_time,
                    'status':None,
                    'job':jobid} 
                for d in b
            ]
            coll_dev_exec.insert_many(executions)
    # def getJobStatus(self,jobName=None,jobId=None):
    #     from zipfile import ZipFile
    #     from smart_open import open as sopen
    #     session = boto3.Session(
    #     aws_access_key_id="AKIAXJFYST6QKBDRB3HK",
    #     aws_secret_access_key="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",
    # )
    #     url = 's3://projectj/lancelot/jobs/5f3803361c55b94a3a9e938d/2/Pos1_271D3E1F6E3F4ABA80D82B89EF46D69F.zip'
    #     with sopen(url,"rb",transport_params=dict(session=session)) as f:
    #         with ZipFile(f,"r") as z:        
    #             with z.open('1/ExecutionMetadata') as emd:
    #                 j=json.load(emd)
    #                 print(j['ExecutionRequest']['ExecutionId'])
    
def bucket(data,f) -> list:
    buckets=[]
    # i=0
    for d in data:
        
        if len(buckets)==0: # very first iteration
            buckets.append([d])
            continue
        x=f(d)
        for b in buckets:
            # check if there isn't an element with same name in current bucket
            ids=[f(y) for y in b]
            if x not in ids: 
                b.append(d)
                break
        else:
            buckets.append([d])
    return buckets    


def main():
    import fire
    fire.Fire(Lancelot)


if __name__ == '__main__':
    main()
