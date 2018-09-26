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

import unittest
import os
import hashlib
import tempfile
from irmacl.apiclient import IrmaScanStatus, IrmaSRCodesApi
from irmacl.helpers import *

import requests


cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
FILENAMES = ["fish", "eicar.com"]
FILEPATHS = list(map(lambda x: os.path.join(SAMPLES_DIR, x), FILENAMES))
HASH = "7cddf3fa0f8563d49d0e272208290fe8fdc627e5cae0083d4b7ecf901b2ab6c8"
SESSION = requests.Session()


class IrmaAPISRCodesTests(unittest.TestCase):

    def setUp(self):
        self.skipTest("Waiting for core API support")
        api_client = IrmaApiClient(api_endpoint, submitter=submitter,
                                   max_tries=max_tries, pause=pause,
                                   verify=verify, cert=cert, key=key, ca=ca)
        self.cli = IrmaSRCodesApi(api_client)

    def test_srcode_new(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode = res["id"]
        self.assertEqual(len(srcode), 10)

    def test_srcode_get(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode = res["id"]
        res = self.cli.get(srcode)
        self.assertEqual(len(res["results"]), len(FILENAMES))

    def test_srcode_get_file(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode = res["id"]
        res = self.cli.get(srcode)
        results = res["results"]
        for r in results:
            if r["name"] == "eicar.com":
                virus_file = r
            else:
                clean_file = r
        self.assertEqual(virus_file["status"], 1)
        self.assertEqual(clean_file["status"], 0)

    def test_srcode_download_clean_file(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode = res["id"]
        res = self.cli.get(srcode)
        results = res["results"]
        for r in results:
            if r["name"] == "fish":
                clean_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        self.cli.download_file(srcode, clean_file["result_id"],
                               dst.name)
        h = hashlib.sha256()
        with open(dst.name, "rb") as f:
            h.update(f.read())
        os.unlink(dst.name)
        hashval = h.hexdigest()
        self.assertEqual(hashval, HASH)

    def test_srcode_download_virus_file(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode = res["id"]
        res = self.cli.get(srcode)
        results = res["results"]
        for r in results:
            if r["name"] == "eicar.com":
                virus_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        with self.assertRaises(IrmaError):
            self.cli.download_file(srcode, virus_file["result_id"],
                                   dst.name)

    def test_srcode_download_clean_file_wrong_srcode(self):
        probes = probe_list(session=SESSION)
        force = False
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode1 = res["id"]
        scan = scan_files(FILEPATHS, force, blocking=True, probe=probes,
                          session=SESSION)
        self.assertEqual(scan.status, IrmaScanStatus.finished)
        res = self.cli.new(scan.id)
        srcode2 = res["id"]
        res = self.cli.get(srcode2)
        results = res["results"]
        for r in results:
            if r["name"] == "fish":
                clean_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        with self.assertRaises(IrmaError):
            self.cli.download_file(srcode1, clean_file["result_id"],
                                   dst.name)


if __name__ == "__main__":
    unittest.main()
