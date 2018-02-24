# -*- coding: utf-8 -*-

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
import time
from irmacl.helpers import scan_files, scan_get, \
    scan_proberesults, file_search, probe_list

cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
ZIP_SAMPLE = "eicar.zip"
UTF8_SAMPLES = [u"☀.vir", u"فایل.exe", u"вирус.exe", u"ვირუსი.exe",
                u"परीक्षण.exe", u"病毒.exe"]
UTF8_PATHS = list(map(lambda x: os.path.join(SAMPLES_DIR, x), UTF8_SAMPLES))


class TestCornerCase(unittest.TestCase):

    def test_utf8(self):
        force = False
        scan = scan_files(UTF8_PATHS, force, blocking=True)
        for get_result in scan.results:
            res = scan_proberesults(get_result.id)
            self.assertIn(res.name, UTF8_SAMPLES)
        for filename in UTF8_SAMPLES:
            (_, res) = file_search(filename, limit=1)
            self.assertEqual(type(res), list)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0].name, filename)

    def test_zip(self):
        probelist = probe_list()
        probe = u'Unarchive'
        if probe not in probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        force = True
        sample = os.path.join(SAMPLES_DIR, ZIP_SAMPLE)
        scan = scan_files([sample], force, probe=[probe], blocking=True)
        self.assertEqual(len(scan.results), 2)
        self.assertEqual(scan.probes_finished, 1)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
