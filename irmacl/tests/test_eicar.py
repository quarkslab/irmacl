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
import re
from irmacl.helpers import probe_list, scan_new, scan_add_files, scan_get, \
    scan_launch, scan_proberesults
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
MAXTIME_NORMAL_PROBE = 30
MAXTIME_FAST_PROBE = 10
NOT_CHECKED = "This value is not checked"
EICAR_RESULTS = [
    {"status": 1,
     "name": "AVG AntiVirus Free (Linux)",
     "results": "EICAR_Test",
     "version": "13.0.3114",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Avast Core Security (Linux)",
     "results": "EICAR Test-NOT virus!!!",
     "version": "2.1.1",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Bitdefender Antivirus Scanner (Linux)",
     "results": "EICAR-Test-File \(not a virus\)",
     "version": "7.141118",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Clam AntiVirus Scanner (Linux)",
     "results": "Eicar-Test-Signature",
     "version": "0.99.2",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Comodo Antivirus (Linux)",
     "results": "ApplicUnwnt",
     "version": "1.1.268025.1",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "DrWeb Antivirus (Linux)",
     "results": "EICAR Test File \(NOT a Virus!\)",
     "version": "10.1.0.1.1507091917",
     "duration": MAXTIME_SLOW_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Emsisoft Commandline Scanner (Windows)",
     "results": "EICAR-Test-File \(not a virus\) \(B\)",
     "version": "12.2.0.7060",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "eScan Antivirus (Linux)",
     "results": "EICAR-Test-File \(not a virus\)\(DB\)",
     "version": "7.0-18",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "ESET File Security (Linux)",
     "results": "Eicar test file",
     "version": "4.0.82",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "F-PROT Antivirus (Linux)",
     "results": "EICAR_Test_File \(exact\)",
     "version": "4.6.5.141",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus",
     },
    {"status": 1,
     "name": "FSecure Antivirus (Linux)",
     "results": "EICAR_Test_File \[FSE\]",
     "version": "11.00",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "GData Anti-Virus (Windows)",
     "results": "Virus: EICAR-Test-File \(not a virus\) \(Engine A\)",
     "version": "5.0.15051.292",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Kaspersky Anti-Virus (Windows)",
     "results": "EICAR-Test-File",
     "version": "16.0.0.694",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "McAfee VirusScan Command Line scanner (Linux)",
     "results": "EICAR test file",
     "version": "6.0.4.564",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "McAfee VirusScan Command Line scanner (Windows)",
     "results": "EICAR test file",
     "version": "6.0.4.564",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "McAfee VirusScan Daemon (Linux)",
     "results": "EICAR test file",
     "version": "6.0.4.564",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 0,
     "name": "PEiD PE Packer Identifier",
     "results": "Not a PE",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 1,
     "name": "Sophos Anti-Virus (Linux)",
     "results": "EICAR-AV-Test",
     "version": "5.21.0",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Sophos Endpoint Protection (Windows)",
     "results": "EICAR-AV-Test",
     "version": "10.6",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Dummy",
     "results": EICAR_HASH,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 0,
     "name": "PE Static Analyzer",
     "results": "Not a PE file",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": 1,
     "name": "TrID File Identifier",
     "results": NOT_CHECKED,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
    {"status": -1,
     "name": "Unarchive",
     "results": None,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "tools"
     },
    {"status": 1,
     "name": "VirusTotal",
     "results": "detected by \d{1,2}/\d{2}",
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "external"
     },
    {"status": 1,
     "name": "VirusBlokAda Console Scanner (Linux)",
     "results": "EICAR-Test-File",
     "version": "3.12.26.4",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Windefender Anti-Virus (Windows)",
     "results": "Virus:DOS/EICAR_Test_File",
     "version": "4.10.14393.0   ",
     "duration": MAXTIME_FAST_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "Zoner Antivirus (Linux)",
     "results": "EICAR.Test.File-NoVirus",
     "version": "1.3.0",
     "duration": MAXTIME_NORMAL_PROBE,
     "type": "antivirus"
     },
    {"status": 1,
     "name": "LIEF",
     "results": NOT_CHECKED,
     "version": None,
     "duration": MAXTIME_FAST_PROBE,
     "type": "metadata"
     },
]


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

    def _check_result(self, get_result, scanid, filelist,
                      range_finished, range_total):
        self.assertEqual(get_result.scan_id, scanid)
        self.assertTrue(get_result.name in filelist)
        self.assertIn(get_result.status, [0, 1])
        self.assertIsNotNone(get_result.result_id)
        self.assertIn(get_result.probes_total, range_total)
        self.assertIn(get_result.probes_finished, range_finished)
        return

    def _check_results(self, results, scanid, filelist,
                       nb_finished, nb_total,
                       none_infos=False, none_results=False):
        resname_list = sorted([r.name for r in results])
        self.assertEqual(resname_list, sorted(filelist))
        for get_result in results:
            self._check_result(get_result, scanid, filelist,
                               nb_finished, nb_total)
            if none_infos is True:
                self.assertFalse(hasattr(get_result, 'file_infos'))
            if none_results is True:
                self.assertFalse(hasattr(get_result, 'probe_results'))
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
                if (probe_result.version != ref_res["version"]):
                    logging.warning("Outdated version of %s: latest %s got %s"
                                    % (probe_result.name,
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
                if ref_res["results"] == NOT_CHECKED:
                    pass
                elif ref_res["results"] is not None:
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
                                     (probe_result.name,
                                      ref_res["duration"],
                                      probe_result.duration)
                                     )
                return
        self.assertFalse(True,
                         "Missing probe %s ref_result" % probe_result.name)

    def _test_scan_file(self,
                        filelist,
                        probelist,
                        force=True,
                        mimetype_filtering=None,
                        resubmit_files=None,
                        timeout=SCAN_TIMEOUT_SEC):
        nb_probes = len(probelist)
        nb_files = len(filelist)
        nb_jobs = nb_probes * nb_files
        filenames = list(map(lambda f: os.path.basename(f), filelist))
        scan = scan_new(verbose=DEBUG)
        self.assertIsNot(scan.id, None)
        scanid = scan.id
        self.assertIsNot(scan.date, None)
        self.assertEqual(len(scan.results), 0)

        scan = scan_add_files(scan.id, filelist, verbose=DEBUG)
        self._check_results(scan.results, scanid, filenames, [0], [0],
                            True, True)

        scan = scan_launch(scan.id, force=force, probe=probelist,
                           mimetype_filtering=mimetype_filtering,
                           resubmit_files=resubmit_files,
                           verbose=DEBUG)
        start = time.time()
        while not scan.is_finished():
            self._check_results(scan.results, scanid, filenames,
                                range(nb_probes + 1), range(nb_jobs + 1),
                                True, True)
            time.sleep(BEFORE_NEXT_PROGRESS)
            now = time.time()
            self.assertLessEqual(now, start + timeout, "Results Timeout")
            scan = scan_get(scan.id)

        # Scan finished
        self._check_results(scan.results, scanid, filenames,
                            [scan.probes_total], [scan.probes_total],
                            True, True)
        res = {}
        for get_result in scan.results:
            file_result = scan_proberesults(get_result.result_id,
                                            formatted=True, verbose=DEBUG)
            self.assertIn(file_result.status, [-1, 0, 1])
            self.assertEqual(file_result.probes_finished,
                             file_result.probes_total)
            self.assertEqual(len(file_result.probe_results),
                             file_result.probes_total)
            res[get_result.name] = {}
            for pr in file_result.probe_results:
                res[get_result.name][pr.name] = pr
        return res

    def assertListContains(self, list1, list2):
        for l in list1:
            self.assertIn(l, list2)


class IrmaEicarTest(EicarTestCase):

    def check_eicar_results(self, reslist):
        for probe in reslist.keys():
            self._check_probe_result(reslist[probe], EICAR_RESULTS)

    def _scan_eicar(self, probe):
        if probe not in self.probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [self.filepath]
        res = self._test_scan_file(filelist, probelist, force=True)
        self.check_eicar_results(res[self.filename])

    def test_scan_avg(self):
        self._scan_eicar('AVGAntiVirusFree')

    def test_scan_avast(self):
        self._scan_eicar('AvastCoreSecurity')

    def test_scan_bitdefender(self):
        self._scan_eicar('BitdefenderForUnices')

    def test_scan_clamav(self):
        self._scan_eicar('ClamAV')

    def test_scan_comodo(self):
        self._scan_eicar('ComodoCAVL')

    def test_scan_drweb(self):
        self._scan_eicar('DrWeb')

    def test_scan_dummy(self):
        self._scan_eicar('Dummy')

    def test_scan_emsisoft_windows(self):
        self._scan_eicar('ASquaredCmdWin')

    def test_scan_escan(self):
        self._scan_eicar('EScan')

    def test_scan_eset_file_security(self):
        self._scan_eicar('EsetFileSecurity')

    def test_scan_fprot(self):
        self._scan_eicar('FProt')

    def test_scan_fsecure(self):
        self._scan_eicar('FSecure')

    def test_scan_gdata_windows(self):
        self._scan_eicar('GDataWin')

    def test_scan_kaspersky_windows(self):
        self._scan_eicar('KasperskyWin')

    def test_scan_lief(self):
        self._scan_eicar('LIEF')

    def test_scan_mcafee(self):
        self._scan_eicar('McAfeeVSCL')

    def test_scan_mcafee_windows(self):
        self._scan_eicar('McAfeeVSCLWin')

    def test_scan_mcafeed(self):
        self._scan_eicar('McAfee-Daemon')

    def test_scan_peid(self):
        self._scan_eicar('PEiD')

    def test_scan_sophos(self):
        self._scan_eicar('Sophos')

    def test_scan_sophos_windows(self):
        self._scan_eicar('SophosWin')

    def test_scan_staticanalyzer(self):
        self._scan_eicar('StaticAnalyzer')

    def test_scan_trid(self):
        self._scan_eicar('TrID')

    def test_scan_virustotal(self):
        # dont raise on VT error cause of API limitations
        # to 4 requests per minute
        try:
            self._scan_eicar('VirusTotal')
        except Exception:
            raise unittest.SkipTest("Virustotal test Failed")

    def test_scan_virusblokada(self):
        self._scan_eicar('VirusBlokAda')

    def test_scan_windefender(self):
        self._scan_eicar('WinDefender')

    def test_scan_zoner(self):
        self._scan_eicar('Zoner')

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
