# -*- coding: utf-8 -*-
import unittest
import os
import requests
from irmacl.helpers import scan_files, \
    scan_proberesults, probe_list

cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
ZIP_SAMPLE = "zipbomb.zip"
SESSION = requests.Session()


class TestZipBomb(unittest.TestCase):

    def test_zipbomb(self):
        probelist = probe_list(session=SESSION)
        probe = u'Unarchive'
        if probe not in probelist:
            raise unittest.SkipTest("Skipping %s not present" % probe)
        force = True
        sample = os.path.join(SAMPLES_DIR, ZIP_SAMPLE)
        scan = scan_files([sample], force, probe=[probe], blocking=True,
                          session=SESSION)
        self.assertEqual(len(scan.results), 1)
        self.assertEqual(scan.probes_finished, 1)
        result = scan_proberesults(scan.results[0].result_id, session=SESSION)
        self.assertEqual(len(result.probe_results), 1)
        probe_result = result.probe_results[0]
        self.assertEqual(probe_result.status, -1)
        self.assertNotEqual(probe_result.error, None)
        self.assertEqual(probe_result.results, None)


if __name__ == "__main__":
    unittest.main()
