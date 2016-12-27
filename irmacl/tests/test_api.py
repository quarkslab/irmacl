import unittest
import os
import re
import time
from irmacl.apiclient import IrmaProbeResult, IrmaResults, IrmaError
from irmacl.helpers import probe_list, scan_new, scan_add, scan_files, \
    scan_get, scan_launch, file_results, file_search, scan_cancel


cwd = os.path.dirname(__file__)
SAMPLES_DIR = os.path.join(cwd, "samples")
FILENAMES = ["fish", "ls"]
HASHES = ["7cddf3fa0f8563d49d0e272208290fe8fdc627e5cae0083d4b7ecf901b2ab6c8",
          "71f30d658966bcc7ea162b4e0f20d2305d4a003e854305b524280f4c2a3b48a3",
          "3826e18a5dc849670744752fd27c4eec6136ac90",
          "8d50d7a3929a356542119aa858c492442655e097",
          "07edba6f3f181bad9a56a87d4039487a",
          "e718241e1cc6472d4f4bac20c59a0179"]
FILEPATHS = map(lambda x: os.path.join(SAMPLES_DIR, x), FILENAMES)


class IrmaAPITests(unittest.TestCase):

    def _validate_uuid(self, uuid):
        regex = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                           re.IGNORECASE)
        return regex.match(uuid) is not None

    def _check_scan(self, scan, scanid, range_status, filelist,
                    range_finished, range_total, date):
        nb_files = len(filelist)
        self.assertEqual(scan.id, scanid)
        self.assertIn(scan.pstatus, range_status)
        self.assertEqual(type(scan.results), list)
        self.assertEqual(len(scan.results), nb_files)
        self.assertIn(scan.probes_finished, range_finished)
        self.assertIn(scan.probes_total, range_total)
        self.assertEqual(scan.date, date)


class IrmaAPIScanTests(IrmaAPITests):

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
        self._check_scan(scan, scanid, ["cancelled"], FILENAMES, [0], [0],
                         date)

    def test_scan_launch(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = False
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_launch(scan.id, force, probes)
        self._check_scan(scan, scanid, ["ready", "uploaded",
                                        "launched", "finished"],
                         FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                         date)

    def test_scan_files(self):
        force = True
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_files(FILEPATHS, force, probe=probes)
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                         scan.date)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scan.id, ["cancelled"],
                         FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                         scan.date)

    def test_scan_get(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while not scan.is_finished():
            time.sleep(1)
            scan = scan_get(scan.id)
        self._check_scan(scan, scan.id, ["finished"],
                         FILENAMES, [scan.probes_total], [scan.probes_total],
                         scan.date)

    def test_file_results_formatted(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probe=probes)
        while not scan.is_finished():
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
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probe=probes, blocking=True)
        for result in scan.results:
            self.assertTrue(self._validate_uuid(str(result.result_id)) or
                            result.result_id in range(len(FILENAMES)))
            res = file_results(scan.id, result.result_id, formatted=False)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), list)
            self.assertEqual(type(res.probe_results[0]), IrmaProbeResult)
            self.assertEqual(len(res.probe_results), len(probes))


class IrmaAPIFileTests(IrmaAPITests):

    def test_file_search_name(self):
        force = False
        probes = probe_list()
        scan_files(FILEPATHS, force, probe=probes, blocking=True)
        for name in FILENAMES:
            data = file_search(name=name)
            self.assertEqual(type(data), tuple)
            (total, res) = file_search(name, limit=1)
            self.assertEqual(type(res), list)
            self.assertEqual(type(res[0]), IrmaResults)
            self.assertEqual(len(res), 1)
            self.assertEqual(type(total), int)

    def test_file_search_limit(self):
        (total, _) = file_search()
        if total > 10:
            offset = total - 10
            limit = 10
        else:
            offset = 0
            limit = total
        (_, res) = file_search(offset=offset, limit=limit)
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), limit)

    def test_file_search_hash(self):
        force = False
        probes = probe_list()
        scan_files(FILEPATHS, force, probe=probes, blocking=True)
        for hash in HASHES:
            (_, res) = file_search(hash=hash)
            self.assertTrue(len(res) > 0)
            self.assertEqual(type(res[0]), IrmaResults)

    def test_file_search_hash_name(self):
        with self.assertRaises(IrmaError):
            file_search(name="name", hash="hash")


if __name__ == "__main__":
    unittest.main()
