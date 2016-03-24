# Copyright (c) 2013-2015 QuarksLab.
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
import sys
import os
import re
pardir = os.path.abspath(os.path.join(__file__, os.path.pardir))
pardir = os.path.abspath(os.path.join(pardir, os.path.pardir))
sys.path.append(os.path.dirname(pardir))
from irma.helpers import probe_list, scan_new, scan_add, scan_get, scan_launch, \
    file_results
import time
import logging

logging.getLogger("requests").setLevel(logging.WARNING)
SCAN_TIMEOUT_SEC = 3000
BEFORE_NEXT_PROGRESS = 5
DEBUG = False
cwd = os.path.abspath(__file__)
EICAR_FILE = "samples/eicar.com"
EICAR_HASH = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
MAXTIME_SLOW_PROBE = 60
MAXTIME_NORMAL_PROBE = 20
MAXTIME_FAST_PROBE = 10
EICAR_RESULTS = [
    {"status": 1,
     "name": "eScan Antivirus for Linux Desktop",
     "results": "EICAR-Test-File \(not a virus\)\(DB\)",
     "version": "7.0-18",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "McAfee VirusScan Command Line scanner",
     "results": "EICAR test file",
     "version": "6.0.4.564",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "FSecure Antivirus for Linux Desktop",
     "results": "EICAR_Test_File \[FSE\]",
     "version": "11.00",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Clam AntiVirus Scanner",
     "results": "Eicar-Test-Signature",
     "version": "0.99",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 0,
     "name": "StaticAnalyzer",
     "results": "Not a PE file",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 1,
     "name": "AVG AntiVirus Free",
     "results": "EICAR_Test",
     "version": "13.0.3114",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Zoner Antivirus for Linux Desktop",
     "results": "EICAR.Test.File-NoVirus",
     "version": "1.3.0",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "McAfee VirusScan Daemon",
     "results": "EICAR test file",
     "version": "6.0.4.564",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "DrWeb Antivirus for Linux Desktop",
     "results": "EICAR Test File \(NOT a Virus!\)",
     "version": "10.1.0.0.1503311845",
     "duration": MAXTIME_SLOW_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Comodo Antivirus for Linux",
     "results": "Malware",
     "version": "1.1.268025.1",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "VirusBlokAda (Console Scanner)",
     "results": "EICAR-Test-File",
     "version": "3.12.26.4",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Bitdefender Antivirus Scanner for Unices",
     "results": "EICAR-Test-File \(not a virus\)",
     "version": "7.141118",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Avast Core Security",
     "results": "EICAR Test-NOT virus!!!",
     "version": "2.1.1",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 0,
     "name": "PEiD",
     "results": "Not a PE",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 0,
     "name": "TrID",
     "results": None,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 1,
     "name": "VirusTotal",
     "results": "detected by \d{1,2}/\d{2}",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "external"
     },
    {"status": -1,
     "name": "Unarchive",
     "results": None,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "tools"
     },
    {"status": 1,
     "name": "Sophos Anti-Virus",
     "results": "EICAR-AV-Test",
     "version": "5.19.0",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "GData Anti-Virus",
     "results": "Virus: EICAR-Test-File (not a virus) (Engine A)",
     "version": "4.2.14030.221",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "ESET NOD32 Antivirus Business Edition for Linux Desktop",
     "results": "Eicar test file",
     "version": "4.0.81",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     }, ]


##############################################################################
# Test Cases
##############################################################################
class EicarTestCase(unittest.TestCase):
    def setUp(self):
        # setup test
        cwd = os.path.abspath(os.path.dirname(__file__))
        self.filepath = os.path.join(cwd, EICAR_FILE)
        self.filename = os.path.basename(self.filepath)
        self.probelist = probe_list(verbose=DEBUG)
        assert os.path.exists(self.filepath)

    def tearDown(self):
        # do the teardown
        pass

    def _check_result(self, result, scanid, filelist,
                      range_finished, range_total):
        self.assertEqual(result.scan_id, scanid)
        self.assertTrue(result.name in filelist)
        self.assertIn(result.status, [0, 1])
        self.assertIsNotNone(result.result_id)
        self.assertIn(result.probes_total, range_total)
        self.assertIn(result.probes_finished, range_finished)
        return

    def _check_results(self, results, scanid, filelist,
                       nb_finished, nb_total,
                       none_infos=False, none_results=False):
        resname_list = sorted([r.name for r in results])
        self.assertEqual(resname_list, sorted(filelist))
        for result in results:
            self._check_result(result, scanid, filelist, nb_finished, nb_total)
            if none_infos is True:
                self.assertIsNone(result.file_infos)
            if none_results is True:
                self.assertIsNone(result.probe_results)
        return

    def _check_probe_result(self, probe_result, ref_results):
        for ref_res in ref_results:
            if ref_res["name"] == probe_result.name:
                self.assertEqual(probe_result.status,
                                 ref_res["status"],
                                 "%s status %s got %s" %
                                 (probe_result.name,
                                  ref_res["status"],
                                  probe_result.status)
                                 )
                self.assertEqual(probe_result.name,
                                 ref_res["name"],
                                 "%s name %s got %s" %
                                 (probe_result.name,
                                  ref_res["name"],
                                  probe_result.name)
                                 )
                self.assertEqual(probe_result.version,
                                 ref_res["version"],
                                 "%s version %s got %s" %
                                 (probe_result.name,
                                  ref_res["version"],
                                  probe_result.version)
                                 )
                self.assertEqual(probe_result.type,
                                 ref_res["type"],
                                 "%s type %s got %s" %
                                 (probe_result.name,
                                  ref_res["type"],
                                  probe_result.type)
                                 )
                if ref_res["results"] is not None:
                    self.assertIsNotNone(re.match(ref_res["results"],
                                                  probe_result.results),
                                         "%s results %s got %s" %
                                         (probe_result.name,
                                          ref_res["results"],
                                          probe_result.results)
                                         )
                else:
                    self.assertIsNone(probe_result.results,
                                      "%s results %s got %s" %
                                      (probe_result.name,
                                       ref_res["results"],
                                       probe_result.results)
                                      )
                self.assertLessEqual(probe_result.duration,
                                     ref_res["duration"],
                                     "%s duration %s got %s" %
                                     (probe_result.duration,
                                      ref_res["duration"],
                                      probe_result.results)
                                     )
                return
        self.assertFalse(True,
                         "Missing probe %s ref_result" % probe_result.name)

    def _test_scan_file(self,
                        filelist,
                        probelist,
                        force=False,
                        timeout=SCAN_TIMEOUT_SEC):
        nb_probes = len(probelist)
        nb_files = len(filelist)
        nb_jobs = nb_probes * nb_files
        filenames = map(lambda f: os.path.basename(f), filelist)
        scan = scan_new(verbose=DEBUG)
        self.assertIsNot(scan.id, None)
        scanid = scan.id
        self.assertIsNot(scan.date, None)
        self.assertEqual(len(scan.results), 0)

        scan = scan_add(scan.id, filelist, verbose=DEBUG)
        self._check_results(scan.results, scanid, filenames, [0], [0],
                            True, True)

        scan = scan_launch(scan.id, force, probelist, verbose=DEBUG)
        start = time.time()
        while True:
            scan = scan_get(scan.id)
            if scan.pstatus == "finished":
                break

            self._check_results(scan.results, scanid, filenames,
                                range(nb_probes + 1), range(nb_jobs + 1),
                                True, True)
            time.sleep(BEFORE_NEXT_PROGRESS)
            now = time.time()
            self.assertLessEqual(now, start + timeout, "Results Timeout")

        # Scan finished
        self._check_results(scan.results, scanid, filenames,
                            [nb_probes], [nb_probes], True, True)
        res = {}
        for result in scan.results:
            file_result = file_results(scanid, result.result_id,
                                       formatted=True, verbose=DEBUG)
            self.assertIn(file_result.status, [-1, 0, 1])
            self.assertEqual(file_result.probes_finished, nb_probes)
            self.assertEqual(file_result.probes_total, nb_probes)
            self.assertEqual(len(file_result.probe_results), nb_probes)
            res[result.name] = {}
            for pr in file_result.probe_results:
                res[result.name][pr.name] = pr
        return res

    def assertListContains(self, list1, list2):
        for l in list1:
            self.assertIn(l, list2)


class IrmaEicarTest(EicarTestCase):

    def check_eicar_results(self, reslist):
        for probe in reslist.keys():
            self._check_probe_result(reslist[probe], EICAR_RESULTS)

    def test_scan_avg(self):
        probe = 'AVGAntiVirusFree'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_avast(self):
        probe = 'AvastCoreSecurity'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_bitdefender(self):
        probe = 'BitdefenderForUnices'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_clamav(self):
        probe = 'ClamAV'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_comodo(self):
        probe = 'ComodoCAVL'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_drweb(self):
        probe = 'DrWeb'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_escan(self):
        probe = 'EScan'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_eset(self):
        probe = 'EsetNod32'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_fsecure(self):
        probe = 'FSecure'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_mcafeed(self):
        probe = 'McAfee-Daemon'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_mcafee(self):
        probe = 'McAfeeVSCL'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_peid(self):
        probe = 'PEiD'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_staticanalyzer(self):
        probe = 'StaticAnalyzer'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_trid(self):
        probe = 'TrID'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_virustotal(self):
        probe = 'VirusTotal'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        # dont raise on VT error cause of API limitations
        # to 4 requests per minute
        try:
            self.check_eicar_results(res[self.filename])
        except:
            raise unittest.SkipTest("Skipping Virustotal test")

    def test_scan_VirusBlokAda(self):
        probe = 'VirusBlokAda'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_zoner(self):
        probe = 'Zoner'
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_all_probes(self):
        filelist = [self.filepath]
        probelist = probe_list()
        # remove Virustotal from grouped scan as public API is limited
        # to 4 requests per minute
        try:
            probelist.remove('VirusTotal')
        except ValueError:
            pass
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

if __name__ == '__main__':
    unittest.main()
