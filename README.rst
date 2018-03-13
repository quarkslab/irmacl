Irmacl: command-line tool for IRMA API
--------------------------------------

|docs|

IRMA is an asynchronous and customizable analysis system for suspicious files.
This repository is a subproject of IRMA and contains the source code for IRMA's
API client.

**This api client is only made for IRMA API version 2.**

Installation
````````````
.. code-block:: console

   $ python setup.py install


Configuration file contains the API endpoint (full url) and some optional parameters (max number and
delay in second between retries)

.. code-block:: console

   [Server]
   api_endpoint=http://172.16.1.30/api/v2
   max_tries=3
   pause=1

Optionnally you could add some SSL configuration, ``ca`` key unser ``Server`` section
if you want to verify server's certificate, and ``Client`` section if you have enabled
client certificates.

.. code-block:: console

   [Server]
   api_endpoint=https://172.16.1.30/api/v2
   max_tries=3
   pause=1
   ca=<path to ca.crt>
   [Client]
   cert=<path to client.crt>
   key=<path to client.key>


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
   [u'Comodo', u'TrID']

   >>>  tag_list()
   [Tag malware [1], Tag clean [2], Tag suspicious [3]]

   >>>  scan_files(["./irma/tests/samples/eicar.com"], force=True, blocking=True)
   Scanid: b91c348b-1bc7-43fc-8363-983ef2e613e6
   Status: finished
   Probes finished: 2
   Probes Total: 2
   Date: 2018-03-13 11:42:01
   Options: Force [True] Resubmit [True]
   Mimetype [True]
   Results: [<irmacl.apiclient.IrmaFileExt object at 0x7fc50e8ee2d0>]

   >>> scan = _
   >>> print scan.results[0]
   id: 9098500f-6f06-4926-9558-c08608c3be23
   Status: 1
   Probes finished: 2
   Probes Total: 2
   Scanid: b91c348b-1bc7-43fc-8363-983ef2e613e6
   Scan Date: 2018-03-13 11:42:01
   Filename: eicar.txt
   SHA256: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
   ParentFile SHA256: None

   >>> print scan_proberesults("9098500f-6f06-4926-9558-c08608c3be23")
   id: 9098500f-6f06-4926-9558-c08608c3be23
   Status: 1
   Probes finished: 2
   Probes Total: 2
   Scanid: b91c348b-1bc7-43fc-8363-983ef2e613e6
   Scan Date: 2018-03-13 11:42:01
   Filename: eicar.txt
   SHA256: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
   ParentFile SHA256: None
   FileInfo:
   Size: 69
   Sha1: cf8bd9dfddff007f75adf4c2be48005cea317c62
   Sha256: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
   Md5: 69630e4574ec6798239b091cda43dca0s
   First Scan: 2018-03-13 11:42:00
   Last Scan: 2018-03-13 11:42:04
   Mimetype: EICAR virus test files
   Tags: []

   Results: {u'antivirus':{u'Comodo Antivirus (Linux)': {u'status': 1, u'duration': 1.42, u'version': u'1.1.268025.1', u'results': u'Malware', u'virus_database_version': u'2018-03-13'}},
             u'metadata': {u'TrID File Identifier': {u'status': 1, u'duration': 0.1, u'version': None, u'results': [{u'ext': u'.COM', u'ratio': u'100.0', u'desc': u'EICAR antivirus test file (7057/5)'}]}}}

   >>> file_result = _
   >>> print file_result.probe_results
   {u'antivirus': {u'Comodo Antivirus (Linux)': {u'duration': 1.42,
   u'results': u'Malware',
   u'status': 1,
   u'version': u'1.1.268025.1',
   u'virus_database_version': u'2018-03-13'}},
 u'metadata': {u'TrID File Identifier': {u'duration': 0.1,
   u'results': [{u'desc': u'EICAR antivirus test file (7057/5)',
     u'ext': u'.COM',
     u'ratio': u'100.0'}],
   u'status': 1,
   u'version': None}}}


Searching for scans

.. code-block:: python

   >>> scan_list()
   (2, [Scanid: bec16782-7cc1-4807-b83c-42e23ef483c4
    Status: finished
    Probes finished: 2
    Probes Total: 2
    Date: 2018-03-13 11:40:48
    Options: Force [True] Resubmit [True]
    Mimetype [True] Results: [<irmacl.apiclient.IrmaFileExt object at 0x7fc50ded6610>],
    Scanid: b91c348b-1bc7-43fc-8363-983ef2e613e6
    Status: finished
    Probes finished: 2
    Probes Total: 2
    Date: 2018-03-13 11:42:01
    Options: Force [True] Resubmit [True]
    Mimetype [True] Results: [<irmacl.apiclient.IrmaFileExt object at 0x7fc50ded6490>]])
   [...]


Searching for files

.. code-block:: python

   >>> file_search(name="ei")
   (1, [<irmacl.apiclient.IrmaResults at 0x7f3f250491d0>])

   >>> (total, res) = _
   >>> print res[0]
   Status: 1
   Probes finished: 1
   Probes Total: 1
   Scanid: 7ae6b759-b357-4680-8358-b134b564b1ca
   Filename: eicar.txt
   [...]

   >>> file_search(hash="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267")
   (1, [<irmacl.apiclient.IrmaFileExt at 0x7fc50df78d50>])

   >>> file_search(hash="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", tags=[1,2])
   (0, [])

   # looking for an unexisting tagid raise IrmaError
   >>> file_search(hash="131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", tags=[100])
   IrmaError: Error 402


Objects (apiclient.py)
-------

IrmaFileInfo
  IrmaFileInfo are the metadata information linked to a IrmaFile

IrmaScan
  IrmaScan keep tracks of the IrmaFileExt scanned together, probe list used and scan options.

IrmaFileExt
  IrmaFileExt object are scan results for a IrmaFile. One IrmaFileExt could be linked to only one IrmaScan.
  If you submit multiple times the same file and scan it each time, you create only one IrmaFile
  but create multiple IrmaFileExt all linked to the same IrmaFile.

IrmaTag
  Tag will be directly linked to IrmaFiles, each IrmaFileExt linked to this IrmaFile will
  be tagged indirectly.


Helpers (helpers.py)
-------
about(verbose=False)
  Retrieves information about the application

file_download(sha256, dest_filepath, verbose=False)
   Download file identified by sha256 to dest_filepath

file_results(sha256, limit=None, offset=None, verbose=False)
   List all results for a given file identified by sha256

file_search(name=None, hash=None, tags=None, limit=None, offset=None, verbose=False)
   Search a file by name or hash value

file_tag_add(sha256, tagid, verbose=False)
   Add a tag to a File

file_tag_remove(sha256, tagid, verbose=False)
   Remove a tag to a File

probe_list(verbose=False)
   List availables probes

data_upload(data, filename, verbose=False)
   Upload data, returns a fileext

file_upload(filepath, verbose=False)
   Upload file, returns a fileext

scan_cancel(scan_id, verbose=False)
   Cancel a scan

scan_data(data, filename, force, post_max_size_M=100, probe=None, mimetype_filtering=None, resubmit_files=None, blocking=False,blocking_timeout=60, verbose=False)
   Wrapper around scan_new / scan_add / scan_launch

scan_files(filelist, force, post_max_size_M=100, probe=None, mimetype_filtering=None, resubmit_files=None, blocking=False,blocking_timeout=60, verbose=False)
   Wrapper around scan_new / scan_add / scan_launch

scan_get(scan_id, verbose=False)
   Fetch a scan (useful to track scan progress with scan.pstatus)

scan_launch(file_id_list, force, probe=None, mimetype_filtering=None, resubmit_files=None, verbose=False)
   Launch an existing scan on Filext ids previously uploaded

scan_list(limit=None, offset=None, verbose=False)
   List all scans

scan_new(verbose=False)
   Create a new scan

scan_proberesults(fe_id, formatted=True, verbose=False)
   Fetch file probe results (for a given scan
      one scan <-> one fileext_id

tag_list(verbose=False)
   List all available tags

tag_new(text, verbose=False)
   Create a new tag

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
