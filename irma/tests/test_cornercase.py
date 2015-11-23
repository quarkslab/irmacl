# -*- coding: utf-8 -*-
import unittest
import os
import time
from irma.helpers import scan_files, scan_get, \
    file_results, file_search

cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
UTF8_SAMPLES = [u"☀.vir", u"فایل.exe", u"вирус.exe", u"ვირუსი.exe",
                u"परीक्षण.exe", u"病毒.exe"]
UTF8_PATHS = map(lambda x: os.path.join(SAMPLES_DIR, x), UTF8_SAMPLES)


class TestCornerCase(unittest.TestCase):
    def _make_scan(self, filelist):
        force = True
        scan = scan_files(filelist, force, blocking=True)
        return scan

    def test_utf8(self):
        scan = self._make_scan(UTF8_PATHS)
        for result in scan.results:
            res = file_results(result.result_id)
            self.assertIn(res.name, UTF8_SAMPLES)
        for filename in UTF8_SAMPLES:
            (_, res) = file_search(filename, limit=1)
            self.assertEqual(type(res), list)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0].name, filename)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
