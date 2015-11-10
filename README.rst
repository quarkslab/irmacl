IRMA: Incident Response & Malware Analysis
------------------------------------------

|docs|

IRMA is an asynchronous and customizable analysis system for suspicious files.
This repository is a subproject of IRMA and contains the source code for IRMA's
API client.

Installation
````````````
.. code-block:: bash

   $ python setup.py install


Configuration file contains only the API endpoint address (not the full url).

.. code-block::

   [Server]
   address=172.16.1.30


and is searched in these locations in following order:

* current directory
* environment variable ("IRMA_CONF")
* user home directory
* global directory  ("/etc/irma")


Once you set up a working irma.conf settings file, you could run tests on a running IRMA instance:

.. code-block:: bash

   $ python setup.py test

Usage
-----

.. code-block:: python

   >>> from irma.helpers import *
   >>> probe_list()
   [u'StaticAnalyzer', u'Unarchive', u'VirusBlokAda', u'VirusTotal']

   >>> scan = scan_new()
   >>> scan
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Status: empty
   Options: Force [False] Mimetype [False] Resubmit [False]
   Probes finished: 0
   Probes Total: 0
   Date: 1446711412
   Results: []

   >>> scan_add(scan.id, ["./irma/tests/samples/eicar.com"])
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Status: ready
   Options: Force [False] Mimetype [False] Resubmit [False]
   Probes finished: 0
   Probes Total: 0
   Date: 1446711412
   Results: [<irma.apiclient.IrmaResults object at 0x7f572aab53d0>]

   >>> scan_launch(scan.id, probe=None, force=True, mimetype_filtering=True, resubmit_files=True)
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Status: ready
   Options: Force [True] Mimetype [True] Resubmit [True]
   Probes finished: 0
   Probes Total: 0
   Date: 1446711412
   Results: [<irma.apiclient.IrmaResults object at 0x7f572aa62790>]

   >>> scan  = scan_get(scan.id)
   >>> scan
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Status: finished
   Options: Force [True] Mimetype [True] Resubmit [True]
   Probes finished: 2
   Probes Total: 2
   Date: 1446711412
   Results: [<irma.apiclient.IrmaResults object at 0x7f572aa62f90>]

   >>> scan.pstatus
   'finished'

   >>> print scan.results[0]
   Status: 1
   Probes finished: 2
   Probes Total: 2
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Filename: eicar.com
   ParentFile SHA256: None
   Resultid: 633beafb-358f-40c3-a969-4c78e39adc15
   FileInfo: 
   None
   Results: None

   >>> res = file_results("633beafb-358f-40c3-a969-4c78e39adc15")
   >>> print res
   Status: 1
   Probes finished: 2
   Probes Total: 2
   Scanid: 83e8a0a0-9669-45c3-bfa8-ffbcaa3f0aa7
   Filename: eicar.com
   ParentFile SHA256: None
   Resultid: 633beafb-358f-40c3-a969-4c78e39adc15
   FileInfo: 
   Size: 68
   Sha1: 3395856ce81f2b7382dee72602f798b642f14140
   Sha256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
   Md5: 44d88612fea8a8f36de82e1278abb02fs
   First Scan: 1446474373.06
   Last Scan: 1446711485.82
   Id: 46
   Mimetype: EICAR virus test files
   Tags: []

   Results: [<irma.apiclient.IrmaProbeResult object at 0x7f572aab5d10>, <irma.apiclient.IrmaProbeResult object at 0x7f572aab5f90>]
   
   >>> print res.probe_results[0]
   Status: 1
   Name: VirusBlokAda (Console Scanner)
   Category: antivirus
   Version: 3.12.26.4
   Duration: 1.88s
   Results: EICAR-Test-File


Objects (apiclient.py)
-------

**class IrmaScan(id, status, probes_finished, probes_total, date, results=[])**

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


**class IrmaProbeResult(**kwargs)**

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


**class IrmaResults(status, probes_finished, probes_total, scan_id, name,  result_id, file_infos=None, probe_results
=None)**

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


Helpers (helpers.py)
-------

**probe_list(verbose=False)**

   List availables probes

   Parameters:
      **verbose** (*bool*) -- enable verbose requests (optional
      default:False)

   Returns:
      return probe list

   Return type:
      list
      
**scan_new(verbose=False)**

   Create a new scan

   Parameters:
      **verbose** (*bool*) -- enable verbose requests (optional
      default:False)

   Returns:
      return the new generated scan object

   Return type:
      IrmaScan
      
**scan_add(scan_id, filelist, verbose=False)**

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

**scan_launch(scan_id, force, probe=None, verbose=False)**

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

**scan_get(scan_id, verbose=False)**

   Fetch a scan (useful to track scan progress with scan.pstatus)

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**scan_files(filelist, force, probe=None, verbose=False)**

   Wrapper around scan_new / scan_add / scan_launch

   Parameters:
      * **filelist** (*list*) -- list of full path qualified files

      * **force** (*bool*) -- if True force a new analysis of files
        if False use existing results

      * **probe** (*list*) -- probe list to use (optional default:
        None means all)

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**scan_cancel(scan_id, verbose=False)**

   Cancel a scan

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

**file_results(scan_id, result_idx, formatted=True, verbose=False)**

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

**file_search(name=None, hash=None, limit=None, offset=None, verbose=False)**

   Search a file by name or hash value

   Parameters:
      * **name** (*str*) -- name of the file ('*name*' will be
        searched)

      * **hash** (*str of (64, 40 or 32 chars)*) -- one of sha1, md5
        or sha256 full hash value

      * **limit** (*bool*) -- max number of files to receive
        (optional default:25)

      * **offset** (*bool*) -- index of first result (optional
        default:0)

   Returns:
      return matching files already scanned

   Return type:
      list of IrmaResults


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
    :target: https://irma.readthedocs.org
.. _on Read The Docs Website: https://irma.readthedocs.org
