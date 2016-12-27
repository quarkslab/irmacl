Irmacl: command-line tool for IRMA API
--------------------------------------

|docs|

IRMA is an asynchronous and customizable analysis system for suspicious files.
This repository is a subproject of IRMA and contains the source code for IRMA's
API client.

**This api client is only made for IRMA API version 1.0.**

Installation
````````````
.. code-block:: bash

   $ python setup.py install


Configuration file contains the API endpoint (full url) and some optional paramters (max number and
delay in second between retries)

.. code-block::

   [Server]
   api_endpoint=http://172.16.1.30/api/v1.1
   max_tries=3
   pause=1


and is searched in these locations in following order:

* current directory
* environment variable ("IRMA_CONF")
* user home directory
* global directory  ("/etc/irma")


Once you set up a working irma.conf settings file, you could run tests on your running IRMA server:

.. code-block:: bash

   $ python setup.py test


Pip Install
-----------

Install it directly with pip:

.. code-block:: bash

  $ pip install irmacl


Usage
-----

.. code-block:: python

   >>> from irmacl.helpers import *
   >>> probe_list()
   [u'AVGAntiVirusFree', u'AvastCoreSecurity', u'BitdefenderForUnices', u'ClamAV', u'ComodoCAVL', u'EScan', u'FSecure', u'GData', u'McAfee-Daemon', u'PEiD', u'Sophos', u'StaticAnalyzer', u'TrID', u'VirusBlokAda', u'VirusTotal', u'Zoner']

   >>> scan_files(["./irma/tests/samples/eicar.com"], force=True, blocking=True)
   Scanid: 9f7f2dc3-31c3-47ad-8aa6-e8b23dd71b5b
   Status: finished
   Probes finished: 16
   Probes Total: 16
   Date: 2015-11-24 10:55:15
   Results: [<irmacl.apiclient.IrmaResults object at 0x7fdd0430a3d0>]
   
   >>> scan = _
   >>> print scan.results[0]
   Status: 1
   Probes finished: 16
   Probes Total: 16
   Scanid: 9f7f2dc3-31c3-47ad-8aa6-e8b23dd71b5b
   Filename: eicar.com
   Resultid: 0
   FileInfo: 
   None
   Results: None

   >>> res = file_results(scan.id, 0)
   >>> print res
   Status: 1
   Probes finished: 16
   Probes Total: 16
   Scanid: 9f7f2dc3-31c3-47ad-8aa6-e8b23dd71b5b
   Filename: eicar.com
   Resultid: 0
   FileInfo: 
   Size: 68
   Sha1: 3395856ce81f2b7382dee72602f798b642f14140
   Sha256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
   Md5: 44d88612fea8a8f36de82e1278abb02fs
   First Scan: 2015-09-11 10:58:05
   Last Scan: 2015-11-24 10:55:26
   Id: 2482

   Results: [<irmacl.apiclient.IrmaProbeResult object at 0x7fdd0430af90>, ...]

   >>> print res.probe_results[0]
   Status: 1
   Name: Comodo Antivirus for Linux
   Category: antivirus
   Version: 1.1.268025.1
   Duration: 1.23s
   Results: Malware

   >>> file_search(name="eic")
   (2, [<irmacl.apiclient.IrmaResults object at 0x7fea53798e90>, <irmacl.apiclient.IrmaResults object at 0x7fea53751990>])

   >>> (total, res_list) = _
   >>> print res_list[0]
   Status: 1
   Probes finished: 16
   Probes Total: 16
   Scanid: a9a3d505-5205-4465-8760-3d8813d6e174
   Filename: eicar.com
   [...]

Results: [<irmacl.apiclient.IrmaProbeResult object at 0x7fea53738350>
Objects (apiclient.py)
-------

**class irmacl.apiclient.IrmaFileInfo(id, size, timestamp_first_scan, timestamp_last_scan, sha1, sha256, md5)**

   Bases: "object"

   IrmaFileInfo Description for class

   Variables:
      * **id** -- id

      * **timestamp_first_scan** -- timestamp when file was first
        scanned in IRMA

      * **timestamp_last_scan** -- timestamp when file was last
        scanned in IRMA

      * **size** -- size in bytes

      * **md5** -- md5 hexdigest

      * **sha1** -- sha1 hexdigest

      * **sha256** -- sha256 hexdigest

   pdate_first_scan

   pdate_last_scan

   raw()


**class irmacl.apiclient.IrmaScan(id, status, probes_finished, probes_total, date, results=[])**

   Bases: "object"

   IrmaScan Description for class

   Variables:
      * **id** -- id of the scan

      * **status** -- int (one of IrmaScanStatus)

      * **probes_finished** -- number of finished probes analysis
        for current scan

      * **probes_total** -- number of total probes analysis for
        current scan

      * **date** -- scan creation date

      * **results** -- list of IrmaResults objects

   is_finished()

   is_launched()

   pdate

   pstatus


**class irmacl.apiclient.IrmaProbeResult(**kwargs)**

   Bases: "object"

   IrmaProbeResult Description for class

   Variables:
      * **status** -- int probe specific (usually -1 is error, 0
        nothing found 1 something found)

      * **name** -- probe name

      * **type** -- one of IrmaProbeType ('antivirus', 'external',
        'database', 'metadata'...)

      * **version** -- probe version

      * **duration** -- analysis duration in seconds

      * **results** -- probe results (could be str, list, dict)

      * **error** -- error string (only relevant in error case when
        status == -1)

      * **external_url** -- remote url if available (only relevant
        when type == 'external')

      * **database** -- antivirus database digest (need unformatted
        results) (only relevant when type == 'antivirus')

      * **platform** -- 'linux' or 'windows' (need unformatted
        results)

   to_json()


**class irmacl.apiclient.IrmaResults(status, probes_finished, scan_id, name, probes_total, result_id, file_infos=None, probe_results=None)**

   Bases: "object"

   IrmaResults Description for class

   Variables:
      * **status** -- int (0 means clean 1 at least one AV report
        this file as a virus)

      * **probes_finished** -- number of finished probes analysis
        for current file

      * **probes_total** -- number of total probes analysis for
        current file

      * **scan_id** -- id of the scan

      * **name** -- filename

      * **result_id** -- id of specific results for this file and
        this scan used to fetch probe_results through file_results
        helper function

      * **file_infos** -- IrmaFileInfo object

      * **probe_results** -- list of IrmaProbeResults objects

   to_json()


Helpers (helpers.py)
-------

**irmacl.helpers.file_results(scan_id, result_idx, formatted=True, verbose=False)**

   Fetch a file results

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **result_idx** (*str*) -- the result id

      * **formatted** (*bool*) -- apply frontend formatters on
        results (optional default:True)

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return a IrmaResult object

   Return type:
      IrmaResults

**irmacl.helpers.file_search(name=None, hash=None, limit=None, offset=None, verbose=False)**

   Search a file by name or hash value

   Parameters:
      * **name** (*str*) -- name of the file ('*name*' will be
        searched)

      * **hash** (*str of (64, 40 or 32 chars)*) -- one of sha1, md5
        or sha256 full hash value

      * **limit** (*int*) -- max number of files to receive
        (optional default:25)

      * **offset** (*int*) -- index of first result (optional
        default:0)

   Returns:
      return tuple of total files and list of matching files already
      scanned

   Return type:
      tuple(int, list of IrmaResults)

**irmacl.helpers.probe_list(verbose=False)**

   List availables probes

   Parameters:
      **verbose** (*bool*) -- enable verbose requests (optional
      default:False)

   Returns:
      return probe list

   Return type:
      list

**irmacl.helpers.scan_add(scan_id, filelist, verbose=False)**

   Add files to an existing scan

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **filelist** (*list*) -- list of full path qualified files

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the updated scan object

   Return type:
      IrmaScan

**irmacl.helpers.scan_cancel(scan_id, verbose=False)**

   Cancel a scan

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**irmacl.helpers.scan_files(filelist, force, probe=None, blocking=False, verbose=False)**

   Wrapper around scan_new / scan_add / scan_launch

   Parameters:
      * **filelist** (*list*) -- list of full path qualified files

      * **force** (*bool*) -- if True force a new analysis of files
        if False use existing results

      * **probe** (*list*) -- probe list to use (optional default:
        None means all)

      * **blocking** (*bool*) -- wether or not the function call
        should block until scan ended

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**irmacl.helpers.scan_get(scan_id, verbose=False)**

   Fetch a scan (useful to track scan progress with scan.pstatus)

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**irmacl.helpers.scan_launch(scan_id, force, probe=None, verbose=False)**

   Launch an existing scan

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **force** (*bool*) -- if True force a new analysis of files
        if False use existing results

      * **probe** (*list*) -- probe list to use (optional default
        None means all)

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the updated scan object

   Return type:
      IrmaScan

**irmacl.helpers.scan_list(limit=None, offset=None, verbose=False)**

   List all scans

   Parameters:
      * **limit** (*int*) -- max number of files to receive
        (optional default:25)

      * **offset** (*int*) -- index of first result (optional
        default:0)

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return tuple of total scans and list of scans

   Return type:
      tuple(int, list of IrmaScan)

**irmacl.helpers.scan_new(verbose=False)**

   Create a new scan

   Parameters:
      **verbose** (*bool*) -- enable verbose requests (optional
      default:False)

   Returns:
      return the new generated scan object

   Return type:
      IrmaScan

Documentation
`````````````

The full IRMA documentation is available `on Read The Docs Website`_.


Getting help
````````````

Join the #qb_irma channel on irc.freenode.net. Lots of helpful people hang out there.


Contribute to IRMA
``````````````````

IRMA is an ambitious project. Make yourself known on the #qb_irma channel on
irc.freenode.net. We will be please to greet you and to find a way to get you
involved in the project.


.. |docs| image:: https://readthedocs.org/projects/irma/badge/
    :alt: Documentation Status
    :scale: 100%
    :target: https://irma.readthedocs.io
.. _on Read The Docs Website: https://irma.readthedocs.io
