IRMA: Incident Response & Malware Analysis
------------------------------------------

|docs|

IRMA is an asynchronous and customizable analysis system for suspicious files.
This repository is a subproject of IRMA and contains the source code for IRMA's
api client

Installation
````````````

```python

   $ python setup.py install
```

Configuration File contains only the API endpoint address (not the full url).

```
[Server]
address=172.16.1.30
```

and is searched in these locations in following order:

* current directory
* environment variable ("IRMA_CONF")
* user home directory
* global directory  ("/etc/irma")


Once you set up a working irma.conf settings file, you could run tests on a running IRMA instance

```python

   $ python setup.py test
```

Usage
-----

```python

>>> from irma.irma import *
>>> probe_list()
[u'AVGAntiVirusFree', u'AvastCoreSecurity', u'BitdefenderForUnices', u'ClamAV', u'ComodoCAVL', u'DrWeb', u'EScan', u'FSecure', u'GData', u'McAfee-Daemon', u'PEiD', u'Sophos', u'StaticAnalyzer', u'TrID', u'VirusBlokAda', u'VirusTotal', u'Zoner']

>>> scan = scan_new()
>>> print scan
Scanid: 0b7e7f96-00a3-4a4c-aa4d-91a73d7c1867
Status: empty
Probes finished: 0
Probes Total: 0
Date: 1446633817
Results: []

>>> scan_add(scan.id, ["./irma/tests/samples/eicar.com"])
Scanid: 0b7e7f96-00a3-4a4c-aa4d-91a73d7c1867
Status: ready
Probes finished: 0
Probes Total: 0
Date: 1446633817
Results: [<irma.apiclient.IrmaResults object at 0x7fcea1ec3850>]

>>> scan_launch(scan.id, True)
Scanid: 0b7e7f96-00a3-4a4c-aa4d-91a73d7c1867
Status: ready
Probes finished: 0
Probes Total: 17
Date: 1446633817
Results: [<irma.apiclient.IrmaResults object at 0x7fcea165c410>]

>>> scan = scan_get(scan.id)
>>> scan.pstatus
'finished'

>>> print scan.results[0]
Status: 1
Probes finished: 17
Probes Total: 17
Scanid: 0b7e7f96-00a3-4a4c-aa4d-91a73d7c1867
Filename: eicar.com
Resultid: 0
FileInfo: 
None
Results: None

>>> res = file_results(scan.id, 0)
>>> print res
Status: 1
Probes finished: 17
Probes Total: 17
Scanid: 0b7e7f96-00a3-4a4c-aa4d-91a73d7c1867
Filename: eicar.com
Resultid: 0
FileInfo: 
Size: 68
Sha1: 3395856ce81f2b7382dee72602f798b642f14140
Sha256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Md5: 44d88612fea8a8f36de82e1278abb02fs
First Scan: 1441961885.24
Last Scan: 1446633967.67
Id: 2482

Results: [<irma.apiclient.IrmaProbeResult object at 0x7fcea166be90>, <irma.apiclient.IrmaProbeResult object at 0x7fcea166b2d0>, <irma.apiclient.IrmaProbeResult object at 0x7fcea166b750>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1ec3950>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1ec3890>, <irma.apiclient.IrmaProbeResult object at 0x7fcea164ee90>, <irma.apiclient.IrmaProbeResult object at 0x7fcea164ef90>, <irma.apiclient.IrmaProbeResult object at 0x7fcea165c750>, <irma.apiclient.IrmaProbeResult object at 0x7fcea165c190>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1681bd0>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1681ad0>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1681350>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1681050>, <irma.apiclient.IrmaProbeResult object at 0x7fcea160f0d0>, <irma.apiclient.IrmaProbeResult object at 0x7fcea160f390>, <irma.apiclient.IrmaProbeResult object at 0x7fcea160f650>, <irma.apiclient.IrmaProbeResult object at 0x7fcea1681e90>]

>>> print res.probe_results[0]
Status: 1
Name: Comodo Antivirus for Linux
Category: antivirus
Version: 1.1.268025.1
Duration: 1.23s
Results: Malware

```


Objects
-------


class irma.apiclient.IrmaScan(id, status, probes_finished, probes_total, date, results=[])

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


class irma.apiclient.IrmaProbeResult(**kwargs)

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


class irma.apiclient.IrmaResults(status, probes_finished, probes_total, scan_id, name,  result_id, file_infos=None, probe_results
=None)

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


Functions
---------

irma.irma.file_results(scan_id, result_idx, formatted=True, verbose=False)

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

irma.irma.file_search(name=None, hash=None, limit=None, offset=None, verbose=False)

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

irma.irma.probe_list(verbose=False)

   List availables probes

   Parameters:
      **verbose** (*bool*) -- enable verbose requests (optional
      default:False)

   Returns:
      return probe list

   Return type:
      list

irma.irma.scan_add(scan_id, filelist, verbose=False)

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

irma.irma.scan_cancel(scan_id, verbose=False)

   Cancel a scan

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

irma.irma.scan_files(filelist, force, probe=None, verbose=False)

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

irma.irma.scan_get(scan_id, verbose=False)

   Fetch a scan (useful to track scan progress with scan.pstatus)

   Parameters:
      * **scan_id** (*str*) -- the scan id

      * **verbose** (*bool*) -- enable verbose requests (optional
        default:False)

   Returns:
      return the scan object

   Return type:
      IrmaScan

irma.irma.scan_launch(scan_id, force, probe=None, verbose=False)

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

irma.irma.scan_new(verbose=False)

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
    :target: https://irma.readthedocs.org
.. _on Read The Docs Website: https://irma.readthedocs.org
