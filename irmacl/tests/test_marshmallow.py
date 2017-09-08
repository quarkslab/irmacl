import unittest
from copy import deepcopy
from irmacl.apiclient import IrmaFileInfo, IrmaFileInfoSchema, \
    IrmaScan, IrmaScanSchema, \
    IrmaFileExt, IrmaFileExtSchema, \
    IrmaTag, IrmaTagSchema

file_infos_sample = \
    {
        u"mimetype": u"EICAR virus test files",
        u"sha1": u"3395856ce81f2b7382dee72602f798b642f14140",
        u"tags": [],
        u"timestamp_first_scan": 1464531950.52,
        u"timestamp_last_scan": 1488453424.26,
        u"sha256":
        u"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        u"md5": u"44d88612fea8a8f36de82e1278abb02f",
        u"size": 68
    }

probe_results_sample = \
    {
        u"status": 1,
        u"error": None,
        u"name": u"VirusBlokAda Console Scanner (Linux)",
        u"results": u"EICAR-Test-File",
        u"version": u"3.12.26.4",
        u"duration": 3.04,
        u"type": u"antivirus"
    }

results_summary_sample = \
    {
        u"result_id": u"d3347ebf-8589-488d-a867-3861237aef7d",
        u"status": 1,
        u"probes_finished": 1,
        u"scan_id": u"ae769a05-30a8-43f7-b97b-b97270916629",
        u"parent_file_sha256": None,
        u"name": u"eicar.com",
        u"scan_date": 1488453418,
        u"probes_total": 1,
        u"file_sha256":
            u"275a021bbfb6489e54d471899f7db9d1663fc6'"
            u"95ec2fe2a2c4538aabf651fd0f",
    }
results_sample = deepcopy(results_summary_sample)
results_sample['probe_results'] = [probe_results_sample]
results_sample['file_infos'] = dict(file_infos_sample)

scan_sample = \
    {
        u"status": 50,
        u"probes_finished": 1,
        u"force": True,
        u"mimetype_filtering": True,
        u"results": [results_summary_sample],
        u"resubmit_files": True,
        u"probes_total": 1,
        u"date": 1488453418,
        u"id": u"ae769a05-30a8-43f7-b97b-b97270916629"
    }

tag_sample = \
    {
        u"text": u"malware",
        u"id": 1
    }


class IrmaMarshmallowTests(unittest.TestCase):

    def test_tag_serialization(self):
        tag = IrmaTag(**tag_sample)
        tag_dumps = IrmaTagSchema().dump(tag).data
        self.assertDictEqual(tag_dumps, tag_sample)

    def test_tag_deserialization(self):
        tag1 = IrmaTag(**tag_sample)
        tag_dumps = IrmaTagSchema().dump(tag1).data
        tag2 = IrmaTag(**tag_dumps)
        self.assertDictEqual(tag1.__dict__, tag2.__dict__)

    def test_file_infos_serialization(self):
        file_info = IrmaFileInfo(**file_infos_sample)
        file_info_dumps = IrmaFileInfoSchema().dump(file_info).data
        self.assertDictEqual(file_info_dumps, file_infos_sample)

    def test_file_infos_deserialization(self):
        file_info1 = IrmaFileInfo(**file_infos_sample)
        file_info_dumps = IrmaFileInfoSchema().dump(file_info1).data
        file_info2 = IrmaFileInfo(**file_info_dumps)
        self.assertDictEqual(file_info1.__dict__, file_info2.__dict__)

    def test_scan_serialization(self):
        self.maxDiff = None
        scan = IrmaScan(**scan_sample)
        scan_dumps = IrmaScanSchema().dump(scan).data
        self.assertDictEqual(scan_dumps, scan_sample)

    def test_scan_deserialization(self):
        self.maxDiff = None
        scan1 = IrmaScan(**scan_sample)
        scan_dumps = IrmaScanSchema().dump(scan1).data
        scan2 = IrmaScan(**scan_dumps)
        dict1 = deepcopy(scan1.__dict__)
        res1 = dict1.pop('results')
        dict2 = deepcopy(scan2.__dict__)
        res2 = dict2.pop('results')
        self.assertDictEqual(dict1, dict2)
        self.assertEqual(len(res1), len(res2))
        for i in range(len(res1)):
            self.assertDictEqual(res1[i].__dict__, res2[i].__dict__)

    def test_results_serialization(self):
        self.maxDiff = None
        res = IrmaFileExt(**results_sample)
        res_dumps = IrmaFileExtSchema().dump(res).data
        self.assertDictEqual(res_dumps, results_sample)

    def test_results_deserialization(self):
        self.maxDiff = None
        res1 = IrmaFileExt(**results_sample)
        res_dumps = IrmaFileExtSchema().dump(res1).data
        res2 = IrmaFileExt(**res_dumps)
        dict1 = res1.__dict__.copy()
        dict1.pop("file_infos")
        dict1.pop("probe_results")
        probe_res1 = res1.probe_results
        file_infos1 = res1.file_infos
        dict2 = res2.__dict__.copy()
        probe_res2 = dict2.pop('probe_results')
        file_infos2 = dict2.pop('file_infos')
        self.assertDictEqual(dict1, dict2)
        self.assertDictEqual(file_infos1.__dict__, file_infos2.__dict__)
        self.assertEqual(len(probe_res1), len(probe_res2))
        for i in range(len(probe_res1)):
            self.assertDictEqual(probe_res1[i].__dict__,
                                 probe_res2[i].__dict__)


if __name__ == "__main__":
    unittest.main()
