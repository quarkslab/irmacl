import unittest
import os
import re
import time
from irma.apiclient import IrmaProbeResult, IrmaResults, IrmaError
from irma.helpers import probe_list, scan_new, scan_add, scan_files, \
    scan_get, scan_launch, scan_proberesults, file_search, scan_cancel, \
    tag_list, file_tag_add, file_tag_remove


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
                    range_finished, range_total, date,
                    force, mimetype_filtering, resubmit_files):
        nb_files = len(filelist)
        self.assertEqual(scan.id, scanid)
        self.assertIn(scan.pstatus, range_status)
        self.assertEqual(type(scan.results), list)
        self.assertEqual(len(scan.results), nb_files)
        self.assertIn(scan.probes_finished, range_finished)
        self.assertIn(scan.probes_total, range_total)
        self.assertEqual(scan.date, date)
        self.assertEqual(scan.force, force)
        self.assertEqual(scan.mimetype_filtering, mimetype_filtering)
        self.assertEqual(scan.resubmit_files, resubmit_files)


class IrmaAPIScanTests(IrmaAPITests):

    def test_probe_list(self):
        probelist = probe_list()
        self.assertIs(type(probelist), list)
        self.assertNotEqual(len(probelist), 0)

    def test_scan_new(self):
        scan = scan_new()
        self.assertTrue(self._validate_uuid(scan.id))
        self._check_scan(scan, scan.id, ["empty"], [], [0], [0], scan.date,
                         False, False, False)

    def test_scan_add(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        self.assertEqual(scan.pstatus, "ready")
        self._check_scan(scan, scanid, ["ready"], FILENAMES, [0], [0], date,
                         False, False, False)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"], FILENAMES, [0], [0],
                         date, False, False, False)

    def test_scan_launch(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = False
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_launch(scan.id, force, probes)
        self._check_scan(scan, scanid, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, True)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, True)

    def test_scan_force(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = False
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_launch(scan.id, force, probe=probes)
        self._check_scan(scan, scanid, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, True)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, True)

    def test_mimetype_filtering(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = True
        mimetype_filtering = False
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_launch(scan.id, force, probes,
                           mimetype_filtering=mimetype_filtering)
        self._check_scan(scan, scanid, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, mimetype_filtering, True)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, mimetype_filtering, True)

    def test_resubmit_files(self):
        scan = scan_new()
        date = scan.date
        scanid = scan.id
        scan = scan_add(scan.id, FILEPATHS)
        force = True
        resubmit_files = False
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_launch(scan.id, force, probe=probes,
                           resubmit_files=resubmit_files)
        self._check_scan(scan, scanid, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, resubmit_files)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scanid, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         date, force, True, resubmit_files)

    def test_scan_files(self):
        force = True
        probes = probe_list()
        nb_jobs = len(FILENAMES) * len(probes)
        scan = scan_files(FILEPATHS, force, probe=probes)
        self._check_scan(scan, scan.id, ["ready", "uploaded", "launched"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         scan.date, True, True, True)
        scan = scan_cancel(scan.id)
        self._check_scan(scan, scan.id, ["cancelled"],
                         FILENAMES, range(nb_jobs), range(nb_jobs + 1),
                         scan.date, True, True, True)

    def test_scan_get(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while not scan.is_finished():
            time.sleep(1)
            scan = scan_get(scan.id)
        self._check_scan(scan, scan.id, ["finished"],
                         FILENAMES, [scan.probes_total], [scan.probes_total],
                         scan.date, True, True, True)

    def test_file_results_formatted(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes)
        while not scan.is_finished():
            time.sleep(1)
            scan = scan_get(scan.id)
        for get_result in scan.results:
            self.assertTrue(self._validate_uuid(str(get_result.result_id)))
            res = scan_proberesults(get_result.result_id)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), list)
            self.assertEqual(type(res.probe_results[0]), IrmaProbeResult)
            self.assertEqual(len(res.probe_results), res.probes_finished)

    def test_file_results_not_formatted(self):
        force = False
        probes = probe_list()
        scan = scan_files(FILEPATHS, force, probes, blocking=True)
        for get_result in scan.results:
            self.assertTrue(self._validate_uuid(str(get_result.result_id)))
            res = scan_proberesults(get_result.result_id, formatted=False)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), list)
            self.assertEqual(type(res.probe_results[0]), IrmaProbeResult)
            self.assertEqual(len(res.probe_results), res.probes_finished)


class IrmaAPIFileTests(IrmaAPITests):

    def test_file_search_name(self):
        force = False
        probes = probe_list()
        scan_files(FILEPATHS, force, probes, blocking=True)
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
        (total, res) = file_search(limit=total)
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), total)
        offset = total - total / 2
        limit = total / 2
        (_, res) = file_search(offset=offset, limit=limit)
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), limit)

    def test_file_search_hash(self):
        force = False
        probes = probe_list()
        scan_files(FILEPATHS, force, probes, blocking=True)
        for hash in HASHES:
            (_, res) = file_search(hash=hash)
            self.assertTrue(len(res) > 0)
            self.assertEqual(type(res[0]), IrmaResults)

    def test_file_search_hash_name(self):
        with self.assertRaises(IrmaError):
            file_search(name="name", hash="hash")


class IrmaAPITagTests(IrmaAPITests):
    taglist = None
    file_sha256 = HASHES[0]
    file_path = FILEPATHS[0]
    file_name = FILENAMES[0]
    get_result = None
    former_tag = []

    def setUp(self):
        if self.taglist is None:
            self.taglist = tag_list()
        if len(self.taglist) == 0:
            raise unittest.SkipTest("Skipping No tag found (please add some)")
        # Insure file is present (Force=False)
        scan = scan_files([self.file_path], False, blocking=True)
        self.get_result = scan_proberesults(scan.results[0].result_id)
        # Insure file got no tags for test
        self.former_tag = [x.id for x in self.get_result.file_infos.tags]
        if len(self.former_tag) != 0:
            for tagid in self.former_tag:
                file_tag_remove(self.file_sha256, tagid)
            self.get_result = scan_proberesults(scan.results[0].result_id)

    def tearDown(self):
        self.assertEqual(self.file_sha256, self.get_result.file_sha256)
        self.assertEqual(self.file_sha256, self.get_result.file_infos.sha256)
        self.get_result = scan_proberesults(self.get_result.result_id)
        for tag in self.get_result.file_infos.tags:
            file_tag_remove(self.file_sha256, tag.id)
        for tagid in self.former_tag:
            file_tag_add(self.file_sha256, tagid)

    def test_tag_list(self):
        for tag in tag_list():
            self.assertIn(tag.id, [x.id for x in self.taglist])
            self.assertIn(tag.text, [x.text for x in self.taglist])

    def test_file_tag_add_remove(self):
        for tag in self.taglist:
            file_tag_add(self.file_sha256, tag.id)
            get_result = scan_proberesults(self.get_result.result_id)
            self.assertIn(tag.id,
                          [x.id for x in get_result.file_infos.tags])
        for tag in self.taglist:
            file_tag_remove(self.file_sha256, tag.id)
            get_result = scan_proberesults(self.get_result.result_id)
            self.assertNotIn(tag.id,
                             [x.id for x in get_result.file_infos.tags])

    def test_file_search_tag(self):
        self.assertEqual(len(self.get_result.file_infos.tags), 0)
        tagged = []
        for tag in self.taglist:
            file_tag_add(self.file_sha256, tag.id)
            tagged.append(tag.id)
            (total, found) = file_search(name=self.file_name, tags=tagged)
            self.assertGreater(total, 0)
            self.assertIn(self.file_name, [x.name for x in found])

    def test_file_search_not_existing_tag(self):
        invalid_tagid = max([x.id for x in self.taglist]) + 1
        with self.assertRaises(IrmaError):
            file_search(tags=[invalid_tagid])

    def test_file_search_not_existing_tag_and_name(self):
        invalid_tagid = max([x.id for x in self.taglist]) + 1
        with self.assertRaises(IrmaError):
            file_search(name=self.file_name, tags=[invalid_tagid])

    def test_file_tag_twice(self):
        found = file_search(hash=self.file_sha256)
        self.assertNotEqual(len(found), 0)
        file_tag_add(self.file_sha256, self.taglist[0].id)
        (total, found) = file_search(hash=self.file_sha256)
        self.assertGreaterEqual(total, 1)
        with self.assertRaises(IrmaError):
            file_tag_add(self.file_sha256, self.taglist[0].id)

if __name__ == "__main__":
    unittest.main()
