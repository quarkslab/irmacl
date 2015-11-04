import unittest
import os
import sys
import re
import time
from irma.apiclient import IrmaProbeResult, IrmaResults
pardir = os.path.abspath(os.path.join(__file__, os.path.pardir))
pardir = os.path.abspath(os.path.join(pardir, os.path.pardir))
sys.path.append(os.path.dirname(pardir))
from irma.irma import probe_list, scan_new, scan_add, scan_files, scan_get, \
    scan_launch, file_results, file_search, scan_cancel


cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
FILENAMES = ["fish", "ls"]
HASHES = ["7cddf3fa0f8563d49d0e272208290fe8fdc627e5cae0083d4b7ecf901b2ab6c8",
          "7c81309cc089f80525fd777788c8401ec9a37153e8b98dd8e9ef3231440653da",
          "3826e18a5dc849670744752fd27c4eec6136ac90",
          "c664bf0df003af91573a57128ce022efbaae6e0d",
          "07edba6f3f181bad9a56a87d4039487a",
          "4f428f95740ec935125766de5baa8a0d"]
FILEPATHS = map(lambda x: os.path.join(SAMPLES_DIR, x), FILENAMES)


class IrmaActionTests(unittest.TestCase):

    def _validate_uuid(self, uuid):
        regex = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                           re.IGNORECASE)
        return regex.match(uuid) is not None

    def _check_scan(self, scan, scanid, range_status, filelist,
                    range_finished, range_total, date):
        nb_files = len(filelist)
        self.assertEquals(scan.id, scanid)
        self.assertIn(scan.pstatus, range_status)
        self.assertEquals(type(scan.results), list)
        self.assertEquals(len(scan.results), nb_files)
        self.assertIn(scan.probes_finished, range_finished)
        self.assertIn(scan.probes_total, range_total)
        self.assertEquals(scan.date, date)

    def test_probe_list(self):
        probelist = probe_list()
        self.assertIs(type(probelist), list)
        self.assertNotEqual(len(probelist), 0)

    def test_scan_new(self):
        scan = scan_new()
        self.assertTrue(self._validate_uuid(scan.id))
        self._check_scan(scan, scan.id, ["empty"], [], [0], [0], scan.date)

    def test_scan_add(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        self.assertEqual(scan.pstatus, "ready")
        self._check_scan(scan, scanid, ["ready"], FILENAMES, [0], [0], date)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"], FILENAMES, [0], [0], date)

    def test_scan_launch(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = True
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan_launch(scan.id, force, probes)
        self._check_scan(scan, scanid, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date)

    def test_scan_files(self):
        force = True
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_files(FILEPATHS, force, probes)
        self._check_scan(scan, scan.id, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         scan.date)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scan.id, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         scan.date)

    def test_scan_get(self):
        force = True
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_files(FILEPATHS, force, probes)
        while scan.pstatus != "finished":
            time.sleep(1)
            scan = scan_get(scan.id)
        self._check_scan(scan, scan.id, ["finished"],
                         FILENAMES, [nb_jobs], [nb_jobs],
                         scan.date)

    def test_file_results_formatted(self):
        force = True
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while scan.pstatus != "finished":
            time.sleep(1)
            scan = scan_get(scan.id)
        for result in scan.results:
            self.assertTrue(self._validate_uuid(str(result.result_id)) or
                            result.result_id in range(len(FILENAMES)))
            res = file_results(scan.id, result.result_id)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), list)
            self.assertEqual(type(res.probe_results[0]), IrmaProbeResult)
            self.assertEqual(len(res.probe_results), len(probes))

    def test_file_results_not_formatted(self):
        force = True
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while scan.pstatus != "finished":
            time.sleep(1)
            scan = scan_get(scan.id)
        for result in scan.results:
            self.assertTrue(self._validate_uuid(str(result.result_id)) or
                            result.result_id in range(len(FILENAMES)))
            res = file_results(scan.id, result.result_id, formatted=False)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), list)
            self.assertEqual(type(res.probe_results[0]), IrmaProbeResult)
            self.assertEqual(len(res.probe_results), len(probes))

    def test_file_search_name(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while scan.pstatus != "finished":
            time.sleep(1)
            scan = scan_get(scan.id)
        for name in FILENAMES:
            res = file_search(name=name)
            self.assertEqual(type(res), list)
            self.assertTrue(len(res) > 0)
            self.assertEqual(type(res[0]), IrmaResults)
            res = file_search(name, limit=1)
            self.assertEqual(type(res), list)
            self.assertEqual(len(res), 1)

    def test_file_search_limit(self):
        res = file_search(limit=50)
        total = len(res)
        res = file_search(limit=total)
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), total)
        offset = total - total / 2
        limit = total / 2
        res = file_search(offset=offset, limit=limit)
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), limit)

    def test_file_search_hash(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while scan.pstatus != "finished":
            time.sleep(1)
            scan = scan_get(scan.id)
        for hash in HASHES:
            res = file_search(hash=hash)
            self.assertEqual(type(res), list)
            self.assertTrue(len(res) > 0)
            self.assertEqual(type(res[0]), IrmaResults)

if __name__ == "__main__":
    unittest.main()
