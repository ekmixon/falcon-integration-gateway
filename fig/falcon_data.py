from .falcon import Event


class TranslatorError(Exception):
    pass


class EventDataError(TranslatorError):
    pass


class FalconAPIDataError(TranslatorError):
    pass


class FalconCache():
    def __init__(self, falcon_api):
        self.falcon_api = falcon_api
        self._host_detail = {}
        self._mdm_id = {}

    def device_details(self, sensor_id):
        if not sensor_id:
            return EventDataError("Cannot process event. SensorId field is missing: ")

        if sensor_id not in self._host_detail:
            resources = self.falcon_api.device_details(sensor_id)
            if len(resources) > 1:
                raise FalconAPIDataError(
                    'Cannot process event for device: {}, multiple devices exists'.format(sensor_id))
            if len(resources) == 0:
                raise FalconAPIDataError('Cannot process event for device {}, device not known'.format(sensor_id))
            detail = self.falcon_api.device_details(sensor_id)[0]

            if not detail.get('service_provider'):
                # No need to cache device detail if we know that it is not relevant to the clouds.
                # Let's just cache the information about the device existence and irrelevance.
                detail = {}

            self._host_detail[sensor_id] = detail

        return self._host_detail[sensor_id]

    def mdm_identifier(self, sensor_id):
        if not sensor_id:
            return EventDataError("Cannot process event. SensorId field is missing: ")

        if sensor_id not in self._mdm_id or self._mdm_id[sensor_id] == None:
            session = self.falcon_api.init_rtr_session(sensor_id)
            command = self.falcon_api.execute_rtr_command(session[0]['session_id'], 'reg query', 'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" DeviceClientId')
            response = self.falcon_api.check_rtr_command_status(command[0]['cloud_request_id'], 0)[0]

            while not response['complete']:
                response = self.falcon_api.check_rtr_command_status(command[0]['cloud_request_id'], 0)[0]
            if (response['stderr']):
                self._mdm_id[sensor_id] = None
            else:
                self._mdm_id[sensor_id] = response['stdout'].split(' = ')[1].split('\n')[0]

        return self._mdm_id[sensor_id]


class FalconEvent():
    def __init__(self, original_event: Event, cache: FalconCache):
        self.original_event = original_event
        self.cache = cache

    @property
    def device_details(self):
        return self.cache.device_details(self.original_event.sensor_id)

    @property
    def mdm_identifier(self):
        return self.cache.mdm_identifier(self.original_event.sensor_id)

    @property
    def cloud_provider(self):
        return self.device_details.get('service_provider', None)

    @property
    def cloud_provider_account_id(self):
        return self.device_details.get('service_provider_account_id')

    @property
    def instance_id(self):
        return self.device_details['instance_id']

    @property
    def falcon_link(self):
        return self.original_event['event']['FalconHostLink']

    @property
    def event_id(self):
        return self.original_event['event']['DetectId']

    @property
    def time(self):
        return self.original_event.creation_time

    @property
    def severity(self):
        return self.original_event['event']['SeverityName']

    @property
    def detect_description(self):
        return self.original_event['event']['DetectDescription']

    @property
    def detect_name(self):
        return self.original_event['event']['DetectName']
