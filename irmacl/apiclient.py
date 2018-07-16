# Copyright (c) 2013-2018 Quarkslab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import requests
import json
from marshmallow import fields, Schema
import time
try:
    # Python 2 import
    from urllib import quote, urlencode
except ImportError:
    # Python 3 import
    from urllib.parse import quote, urlencode
import datetime
import os
from requests import RequestException


def timestamp_to_date(timestamp):
    if timestamp is None:
        return None
    date = datetime.datetime.fromtimestamp(int(timestamp))
    return date.strftime('%Y-%m-%d %H:%M:%S')


# Warning this is a copy of IrmaScanStatus lib.irma.common.utils
# in order to get rid of this dependency
# KEEP SYNCHRONIZED


class IrmaScanStatus:
    """ All status codes and labels for IrmaScan
    """
    empty = 0
    ready = 10
    uploaded = 20
    launched = 30
    processed = 40
    finished = 50
    flushed = 60
    # cancel
    cancelling = 100
    cancelled = 110
    # errors
    error = 1000
    # Probes 101x
    error_probe_missing = 1010
    error_probe_na = 1011
    # FTP 102x
    error_ftp_upload = 1020

    label = {empty: "empty",
             ready: "ready",
             uploaded: "uploaded",
             launched: "launched",
             processed: "processed",
             finished: "finished",
             cancelling: "cancelling",
             cancelled: "cancelled",
             flushed: "flushed",
             error: "error",
             error_probe_missing: "probelist missing",
             error_probe_na: "probe(s) not available",
             error_ftp_upload: "ftp upload error"
             }


class IrmaError(Exception):
    """Error on cli script"""
    pass


class IrmaApiClient(object):
    """ Basic Api class that just deals with get and post requests
    """

    def __init__(self, url, submitter="cli", submitter_id=None,
                 max_tries=1, pause=3, verify=True,
                 cert=None, key=None, ca=None,
                 verbose=False, session=None):
        self.url = url
        self.submitter = submitter
        self.submitter_id = submitter_id
        self.verbose = verbose
        self.max_tries = max_tries
        self.pause = pause
        self.verify = verify
        # disable warning when verify is not set
        if self.verify is False:
            requests.packages.urllib3.disable_warnings()
        self.cert = cert
        self.key = key
        if verify is True and ca is not None:
            self.verify = ca
        self.session = session if session is not None else requests.Session()

    def get_call(self, route, **extra_args):
        nb_try = 0
        while nb_try < self.max_tries:
            nb_try += 1
            try:
                dec_extra_args = {}
                for (k, v) in extra_args.items():
                    try:
                        if type(v) == unicode or type(v) == str:
                            dec_extra_args[k] = v.encode("utf8")
                        else:
                            dec_extra_args[k] = v
                    except NameError:
                        # unicode does not exists in python3
                        # and str are encoded in utf8 by default
                        # so just pass
                        dec_extra_args[k] = v
                args = urlencode(dec_extra_args)
                resp = self.session.get(self.url + route + "?" + args,
                                        verify=self.verify,
                                        cert=(self.cert, self.key))

                return self._handle_resp(resp)
            except (IrmaError, RequestException) as e:
                if nb_try < self.max_tries:
                    if self.verbose:
                        print("Exception Raised {0} retry #{1}".format(e,
                                                                       nb_try))
                    time.sleep(self.pause)
                    continue
                else:
                    raise

    def post_call(self, route, **extra_args):
        nb_try = 0
        while nb_try < self.max_tries:
            nb_try += 1
            try:
                resp = self.session.post(self.url + route, verify=self.verify,
                                         cert=(self.cert, self.key),
                                         **extra_args)
                return self._handle_resp(resp)
            except (IrmaError, RequestException) as e:
                if nb_try < self.max_tries:
                    if self.verbose:
                        print("Exception Raised {0} retry #{1}".format(e,
                                                                       nb_try))
                    time.sleep(self.pause)
                    continue
                else:
                    raise
        raise ValueError

    def _handle_resp(self, resp):
        content = resp.content.decode("utf-8")
        if self.verbose:
            print("http code : {0}".format(resp.status_code))
            print("content : {0}".format(content))
        if resp.status_code == 200:
            if len(resp.content) > 0:
                return json.loads(content)
            else:
                return
        else:
            reason = "Error {0}".format(resp.status_code)
            try:
                data = json.loads(content)
                if 'message' in data and data['message'] is not None:
                    reason += ": {0}".format(data['message'])
            except Exception:
                pass
            raise IrmaError(reason)


class IrmaAboutApi(object):
    """ Probes Api
    """

    def __init__(self, apiclient):
        self._apiclient = apiclient
        return

    def get(self):
        route = '/about'
        res = self._apiclient.get_call(route)
        return res


class IrmaProbesApi(object):
    """ Probes Api
    """

    def __init__(self, apiclient):
        self._apiclient = apiclient
        return

    def list(self):
        route = '/probes'
        res = self._apiclient.get_call(route)
        return res['data']


class IrmaTagsApi(object):
    """ Tags Api
    """

    def __init__(self, apiclient):
        self._apiclient = apiclient
        self._tags_schema = IrmaTagSchema()
        return

    def list(self):
        route = '/tags'
        data = self._apiclient.get_call(route)
        res_list = []
        items = data.get('items', list())
        for res in items:
            res_obj = self._tags_schema.make_object(res)
            res_list.append(res_obj)
        return res_list

    def new(self, text):
        route = '/tags'
        headers = {'Content-type': 'application/json; charset=utf8'}
        params = {'text': text}
        res = self._apiclient.post_call(route,
                                        data=json.dumps(params),
                                        headers=headers)
        return res


class IrmaScansApi(object):
    """ IrmaScans Api
    """

    def __init__(self, apiclient):
        self._apiclient = apiclient
        self._scan_schema = IrmaScanSchema()
        self._results_schema = IrmaFileExtSchema()
        return

    def new(self):
        route = '/scans'
        data = self._apiclient.post_call(route)
        return self._scan_schema.make_object(data)

    def get(self, scan_id):
        route = '/scans/{0}'.format(scan_id)
        data = self._apiclient.get_call(route)
        return self._scan_schema.make_object(data)

    def list(self, limit=None, offset=None):
        route = '/scans'
        extra_args = {}
        if offset is not None:
            extra_args['offset'] = offset
        if limit is not None:
            extra_args['limit'] = limit
        data = self._apiclient.get_call(route, **extra_args)
        items = data.get('data', list())
        total = data.get('total', None)
        res_list = []
        for res in items:
            res_obj = self._scan_schema.make_object(res)
            res_list.append(res_obj)
        return total, res_list

    def launch(self, fileext_list, force, probe=None,
               mimetype_filtering=None, resubmit_files=None):
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        params = dict()
        params["files"] = fileext_list
        options = dict()
        options["force"] = force
        if mimetype_filtering is not None:
            options["mimetype_filtering"] = mimetype_filtering
        if resubmit_files is not None:
            options["resubmit_files"] = resubmit_files
        if probe is not None:
            options["probes"] = probe
        params["options"] = options
        route = "/scans/"
        data = self._apiclient.post_call(route,
                                         data=json.dumps(params),
                                         headers=headers)
        return self._scan_schema.make_object(data)

    def cancel(self, scan_id):
        route = '/scans/{0}/cancel'.format(scan_id)
        data = self._apiclient.post_call(route)
        return self._scan_schema.make_object(data)

    def results(self, scan_id):
        route = '/scans/{0}/results'.format(scan_id)
        data = self._apiclient.get_call(route)
        return self._scan_schema.make_object(data)

    def probe_results(self, fe_id, formatted=True):
        extra_args = {}
        if not formatted:
            extra_args['formatted'] = 'no'
        route = '/files_ext/{0}'.format(fe_id)
        data = self._apiclient.get_call(route, **extra_args)
        return self._results_schema.make_object(data)

    def quick(self, filepath, payload=None):
        route = '/scans/quick'
        file_data = open(filepath, 'rb').read()
        try:
            if type(filepath) is unicode:
                filepath = filepath.encode("utf8")
        except NameError:
            # Python3 strings are already unicode
            pass
        dec_filepath = quote(filepath)
        json_data = {"submitter": self._apiclient.submitter}
        if payload is not None:
            json_data.update(payload)
        if self._apiclient.submitter_id is not None:
            json_data.update({"submitter_id": self._apiclient.submitter_id})
        data = {
                "files": (dec_filepath, file_data, 'application/octet-stream'),
                "json": (None, json.dumps(json_data),
                         'application/json')}
        res = self._apiclient.post_call(route,
                                        files=data)
        return self._scan_schema.make_object(res)


class IrmaFilesApi(object):
    """ IrmaFiles Api
    """

    def __init__(self, apiclient):
        self._apiclient = apiclient
        self._results_schema = IrmaFileExtSchema()
        self._scan_schema = IrmaScanSchema()
        return

    def download(self, sha256, dest_filepath):
        route = '/files/{0}/download'.format(sha256)
        with open(dest_filepath, 'wb') as handle:
            res = self._apiclient.session.get(self._apiclient.url + route,
                                              verify=self._apiclient.verify,
                                              cert=(self._apiclient.cert,
                                                    self._apiclient.key),
                                              stream=True)
            if not res.ok:
                raise IrmaError("Error Downloading file")
            for block in res.iter_content(1024):
                handle.write(block)
        return

    def search(self, name=None, hash=None, tags=None, limit=None, offset=None):
        extra_args = {}
        if name is not None:
            extra_args['name'] = name
        if hash is not None:
            extra_args['hash'] = hash
        if offset is not None:
            extra_args['offset'] = offset
        if limit is not None:
            extra_args['limit'] = limit
        if tags is not None:
            tags = map(lambda x: str(x), tags)
            extra_args['tags'] = ",".join(tags)
        route = '/files'
        data = self._apiclient.get_call(route, **extra_args)
        res_list = []
        items = data.get('items', list())
        total = data.get('total', None)
        for res in items:
            res_obj = self._results_schema.make_object(res)
            res_list.append(res_obj)
        return (total, res_list)

    def tag_add(self, sha256, tagid):
        route = '/files/{0}/tags/{1}/add'.format(sha256, tagid)
        self._apiclient.get_call(route)
        return

    def tag_remove(self, sha256, tagid):
        route = '/files/{0}/tags/{1}/remove'.format(sha256, tagid)
        self._apiclient.get_call(route)
        return

    def results(self, sha256, limit=None, offset=None):
        route = '/files/{0}'.format(sha256)
        extra_args = {}
        if offset is not None:
            extra_args['offset'] = offset
        if limit is not None:
            extra_args['limit'] = limit
        data = self._apiclient.get_call(route, **extra_args)
        res_list = []
        items = data.get('items', list())
        total = data.get('total', None)
        for res in items:
            res_obj = self._results_schema.make_object(res)
            res_list.append(res_obj)
        return (total, res_list)

    def create(self, filepath, payload=None):
        with open(filepath, 'rb') as f:
            res = self.add_data(f.read(), filepath, payload)
        return res

    def add_data(self, data, filepath, payload=None):
        route = '/files_ext'
        try:
            if type(filepath) is unicode:
                filepath = filepath.encode("utf8")
        except NameError:
            # Python3 strings are already unicode
            pass
        dec_filepath = quote(filepath)
        json_data = {"submitter": self._apiclient.submitter}
        if self._apiclient.submitter_id is not None:
            json_data.update({"submitter_id": self._apiclient.submitter_id})
        if payload is not None:
            json_data.update(payload)
        data = {
                "files": (dec_filepath, data, 'application/octet-stream'),
                "json": (None, json.dumps(json_data),
                         'application/json')}

        res = self._apiclient.post_call(route,
                                        files=data)
        return self._results_schema.make_object(res)


class IrmaTokensApi(object):

    def __init__(self, apiclient):
        self._apiclient = apiclient
        return

    def new(self, scan_id):
        route = '/tokens'
        data = dict()
        data['scan_id'] = scan_id
        res = self._apiclient.post_call(route, data=data)
        return res

    def get(self, token_id):
        route = '/tokens/{}'.format(token_id)
        res = self._apiclient.get_call(route)
        return res

    def get_file(self, token_id, file_id, session=None):
        route = '/tokens/{}/files_ext/{}'.format(token_id, file_id)
        res = self._apiclient.get_call(route)
        return res

    def download_file(self, token_id, file_id, dest_filepath):
        route = '/tokens/{}/files_ext/{}/download'.format(token_id, file_id)
        with open(dest_filepath, 'wb') as handle:
            res = self._apiclient.session.get(self._apiclient.url + route,
                                              verify=self._apiclient.verify,
                                              cert=(self._apiclient.cert,
                                                    self._apiclient.key),
                                              stream=True)
            if not res.ok:
                raise IrmaError("Error Downloading file")
            for block in res.iter_content(1024):
                handle.write(block)
        return

# =============
#  Deserialize
# =============


class IrmaTag(object):
    """ IrmaTag
    Description for class

    :ivar id: id of the tag
    :ivar text: tag label
    """
    def __init__(self, id, text, **kwargs):
        self.id = id
        self.text = text

    def __repr__(self):
        ret = u"Tag {0} [{1}]".format(self.text, self.id)
        return ret


class IrmaTagSchema(Schema):

    class Meta:
        fields = ('text', 'id')

    def make_object(self, data):
        return IrmaTag(**data)


class IrmaFileInfoSchema(Schema):
    tags = fields.Nested(IrmaTagSchema, many=True)

    class Meta:
        fields = ('size', 'sha1', 'timestamp_first_scan',
                  'timestamp_last_scan', 'sha256', 'md5', 'mimetype',
                  'tags')

    def make_object(self, data):
        return IrmaFileInfo(**data)


class IrmaFileInfo(object):
    """ IrmaFileInfo
    Description for class

    :ivar timestamp_first_scan: timestamp when file was first scanned in IRMA
    :ivar timestamp_last_scan: timestamp when file was last scanned in IRMA
    :ivar size:    size in bytes
    :ivar md5:     md5 hexdigest
    :ivar sha1:    sha1 hexdigest
    :ivar sha256:  sha256 hexdigest
    :ivar mimetype: mimetype (based on python magic)
    :ivar tags:  list of tags
    """

    def __init__(self, size, timestamp_first_scan,
                 timestamp_last_scan, sha1, sha256, md5, mimetype, tags,
                 **kwargs):
        self.size = size
        self.sha1 = sha1
        self.timestamp_first_scan = timestamp_first_scan
        self.timestamp_last_scan = timestamp_last_scan
        self.sha256 = sha256
        self.md5 = md5
        self.mimetype = mimetype
        self.tags = []
        for t in tags:
            obj = IrmaTagSchema().make_object(t)
            self.tags.append(obj)

    @property
    def pdate_first_scan(self):
        try:
            return timestamp_to_date(self.timestamp_first_scan)
        except TypeError:
            return None

    @property
    def pdate_last_scan(self):
        try:
            return timestamp_to_date(self.timestamp_last_scan)
        except TypeError:
            return None

    def __repr__(self):
        ret = u"Size: {0}\n".format(self.size)
        ret += u"Sha1: {0}\n".format(self.sha1)
        ret += u"Sha256: {0}\n".format(self.sha256)
        ret += u"Md5: {0}s\n".format(self.md5)
        ret += u"First Scan: {0}\n".format(self.pdate_first_scan)
        ret += u"Last Scan: {0}\n".format(self.pdate_last_scan)
        ret += u"Mimetype: {0}\n".format(self.mimetype)
        ret += u"Tags: {0}\n".format(self.tags)
        return ret


class IrmaFileExt(object):
    """ IrmaFileExt
    Description for class

    :ivar status: int
        (0 means clean 1 at least one AV report this file as a virus)
    :ivar probes_finished: number of finished probes analysis for current file
    :ivar probes_total: number of total probes analysis for current file
    :ivar scan_id: id of the scan
    :ivar name: file name
    :ivar path: file path (as sent during upload or resubmit)
    :ivar id: id of this file_ext (specific results for this file and this
    scan)
     used to fetch probe_results through scan_proberesults helper function
    :ivar file_infos: IrmaFileInfo object
    :ivar probe_results: list of IrmaProbeResults objects
    """

    def __init__(self, status, probes_finished, probes_total,
                 scan_id, scan_date, name,
                 file_sha256, parent_file_sha256, id=None, result_id=None,
                 probe_results=None, file_infos=None, **kwargs):
        self.status = status
        self.probes_finished = probes_finished
        self.probes_total = probes_total
        self.scan_id = scan_id
        self.scan_date = scan_date
        self.name = name
        self.file_sha256 = file_sha256
        self.parent_file_sha256 = parent_file_sha256
        self.id = id or result_id
        if probe_results is not None:
            self.probe_results = probe_results
        if file_infos is not None:
            self.file_infos = IrmaFileInfoSchema().make_object(file_infos)

    @property
    def pscan_date(self):
        return timestamp_to_date(self.scan_date)

    def to_json(self):
        return IrmaFileExtSchema().dumps(self).data

    def __str__(self):
        ret = u"id: {0}\n".format(self.id)
        ret += u"Status: {0}\n".format(self.status)
        ret += u"Probes finished: {0}\n".format(self.probes_finished)
        ret += u"Probes Total: {0}\n".format(self.probes_total)
        ret += u"Scanid: {0}\n".format(self.scan_id)
        ret += u"Scan Date: {0}\n".format(self.pscan_date)
        ret += u"Filename: {0}\n".format(self.name)
        ret += u"SHA256: {0}\n".format(self.file_sha256)
        ret += u"ParentFile SHA256: {0}\n".format(self.parent_file_sha256)
        if hasattr(self, 'file_infos'):
            ret += u"FileInfo: \n{0}\n".format(self.file_infos)
        if hasattr(self, 'probe_results'):
            ret += u"Results: {0}\n".format(self.probe_results)
        return ret


class IrmaFileExtSchema(Schema):
    file_infos = fields.Nested(IrmaFileInfoSchema)

    class Meta:
        fields = ('status', 'probes_finished', 'probes_total', 'scan_id',
                  'name', 'parent_file_sha256', 'id',
                  'file_sha256', 'scan_date', 'file_infos', 'probe_results')

    def make_object(self, data):
        return IrmaFileExt(**data)


class IrmaScan(object):
    """ IrmaScan
    Description for class

    :ivar id: id of the scan
    :ivar status: int (one of IrmaScanStatus)
    :ivar probes_finished: number of finished probes analysis for current scan
    :ivar probes_total: number of total probes analysis for current scan
    :ivar date: scan creation date
    :ivar force: force a new analysis or not
    :ivar resubmit_files: files generated by the probes should be analyzed
        or not
    :ivar mimetype_filtering: probes list should be decided based on files
        mimetype or not
    :ivar results: list of IrmaFileExt objects
    """

    def __init__(self, id, status, probes_finished,
                 probes_total, date, force, resubmit_files,
                 mimetype_filtering, results=None, **kwargs):
        self.id = id
        self.status = status
        self.probes_finished = probes_finished
        self.probes_total = probes_total
        self.date = date
        self.force = force
        self.resubmit_files = resubmit_files
        self.mimetype_filtering = mimetype_filtering
        self.results = None
        if results is not None:
            self.results = []
            schema = IrmaFileExtSchema()
            for r in results:
                self.results.append(schema.make_object(r))

    def is_launched(self):
        return self.status == IrmaScanStatus.launched

    def is_finished(self):
        return self.status == IrmaScanStatus.finished

    @property
    def pstatus(self):
        return IrmaScanStatus.label[self.status]

    @property
    def pdate(self):
        return timestamp_to_date(self.date)

    def __repr__(self):
        ret = u"Scanid: {0}\n".format(self.id)
        ret += u"Status: {0}\n".format(self.pstatus)
        ret += u"Probes finished: {0}\n".format(self.probes_finished)
        ret += u"Probes Total: {0}\n".format(self.probes_total)
        ret += u"Date: {0}\n".format(self.pdate)
        ret += u"Options: Force [{0}] ".format(self.force)
        ret += u"Resubmit [{0}]\n".format(self.resubmit_files)
        ret += u"Mimetype [{0}] ".format(self.mimetype_filtering)
        ret += u"Results: {0}\n".format(self.results)
        return ret


class IrmaScanSchema(Schema):
    results = fields.Nested(IrmaFileExtSchema, many=True,
                            exclude=('probe_results', 'file_infos'))

    class Meta:
        fields = ('status', 'probes_finished', 'date',
                  'probes_total', 'date', 'id', 'force',
                  'resubmit_files', 'mimetype_filtering', 'results')

    def make_object(self, data):
        return IrmaScan(**data)
