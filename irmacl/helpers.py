# Copyright (c) 2013-2018 Quarkslab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import os
import time
import warnings
from irmacl.apiclient import IrmaApiClient, IrmaAboutApi, IrmaScansApi, \
    IrmaProbesApi, IrmaFilesApi, IrmaError, IrmaTagsApi, IrmaTokensApi
try:
    # Python 2 import
    from ConfigParser import ConfigParser, NoOptionError, NoSectionError
except ImportError:
    # Python 3 import
    from configparser import ConfigParser, NoOptionError, NoSectionError

conf_location = [os.curdir,
                 os.environ.get("IRMA_CONF", ""),
                 os.path.expanduser("~"),
                 "/etc/irma"]

config_file = None
for loc in conf_location:
    conf_tmp = os.path.join(loc, "irma.conf")
    if os.path.exists(conf_tmp):
        config_file = conf_tmp
        break

# Optional values in the config file
# Here are the defaults values
max_tries = 1
verify = True
pause = 3
cert = None
key = None
ca = None
submitter = "cli"
submitter_id = None

if config_file is None:
    warnings.warn("irma.conf config file not found, make sure to set "
                  "required parameters manually!", Warning)
else:
    config = ConfigParser()
    config.read(config_file)
    api_endpoint = config.get("Server", "api_endpoint")
    try:
        max_tries = config.getint("Server", "max_tries")
    except NoOptionError:
        pass

    try:
        pause = config.getint("Server", "pause")
    except NoOptionError:
        pass

    try:
        verify = config.getboolean("Server", "verify")
    except NoOptionError:
        pass

    try:
        ca = config.get("Server", "ca")
    except NoOptionError:
        pass

    try:
        cert = config.get("Client", "cert")
    except (NoOptionError, NoSectionError):
        pass

    try:
        key = config.get("Client", "key")
    except (NoOptionError, NoSectionError):
        pass

    try:
        submitter = config.get("Client", "submitter")
    except (NoOptionError, NoSectionError):
        pass

    try:
        submitter_id = config.get("Client", "submitter_id")
    except (NoOptionError, NoSectionError):
        pass


def get_cli(verbose=False, session=None):
    cli = IrmaApiClient(api_endpoint, submitter=submitter,
                        submitter_id=submitter_id, max_tries=max_tries,
                        pause=pause, verify=verify, cert=cert, key=key, ca=ca,
                        verbose=verbose, session=session)
    return cli


# =========
#  Helpers
# =========


def about(verbose=False, session=None):
    """Retrieves information about the application

    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return dictionary of information about the applcation
    :rtype: bool
    """
    cli = get_cli(verbose, session)
    aboutapi = IrmaAboutApi(cli)
    return aboutapi.get()


def file_download(sha256, dest_filepath, verbose=False, session=None):
    """Download file identified by sha256 to dest_filepath

    :param sha256: file sha256 hash value
    :type sha256: str of 64 chars
    :param dest_filepath: destination path
    :type dest_filepath: str
    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return tuple of total files and list of results for the given file
    :rtype: tuple(int, list of IrmaResults)
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    fileapi.download(sha256, dest_filepath)
    return


def file_results(sha256, limit=None, offset=None, verbose=False, session=None):
    """List all results for a given file identified by sha256

    :param sha256: file sha256 hash value
    :type sha256: str of 64 chars
    :param limit: max number of files to receive
        (optional default:25)
    :type limit: int
    :param offset: index of first result
        (optional default:0)
    :type offset: int
    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: tuple(int, list of IrmaResults)
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    (total, files_list) = fileapi.results(sha256, limit=limit, offset=offset)
    return (total, files_list)


def file_search(name=None, hash=None, tags=None, limit=None, offset=None,
                verbose=False, session=None):
    """Search a file by name or hash value

    :param name: name of the file ('*name*' will be searched)
    :type name: str
    :param hash: one of sha1, md5 or sha256 full hash value
    :type hash: str of (64, 40 or 32 chars)
    :param tags: list of tagid
    :type tags: list of int
    :param limit: max number of files to receive
        (optional default:25)
    :type limit: int
    :param offset: index of first result
        (optional default:0)
    :type offset: int
    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return tuple of total files and list of matching files already
        scanned
    :rtype: tuple(int, list of IrmaResults)
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    (total, files_list) = fileapi.search(name=name, hash=hash, tags=tags,
                                         limit=limit, offset=offset)
    return (total, files_list)


def file_tag_add(sha256, tagid, verbose=False, session=None):
    """Add a tag to a File

    :param sha256: file sha256 hash
    :type sha256: str of (64 chars)
    :param tagid: tag id
    :type tagid: int
    :return: No return
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    fileapi.tag_add(sha256, tagid)
    return


def file_tag_remove(sha256, tagid, verbose=False, session=None):
    """Remove a tag to a File

    :param sha256: file sha256 hash
    :type sha256: str of (64 chars)
    :param tagid: tag id
    :type tagid: int
    :return: No return
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    fileapi.tag_remove(sha256, tagid)
    return


def probe_list(verbose=False, session=None):
    """List availables probes

    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return probe list
    :rtype: list
    """
    cli = get_cli(verbose, session)
    probesapi = IrmaProbesApi(cli)
    probelist = probesapi.list()
    return probelist


def data_upload(data, filename, verbose=False, session=None):
    """Upload data returns a fileext

    :param data: data to scan
    :type data: raw string
    :param filename: filename associated to data
    :type filename: string
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the created file object
    :rtype: IrmaFile
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    file = fileapi.add_data(data, filename)
    return file


def file_upload(filepath, verbose=False, session=None):
    """Upload file to IRMA server

    :param filepath: full path qualified file
    :type filepath: str
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the updated scan object
    :rtype: IrmaFileExt
    """
    cli = get_cli(verbose, session)
    fileapi = IrmaFilesApi(cli)
    file = fileapi.create(filepath)
    return file


def scan_cancel(scan_id, verbose=False, session=None):
    """Cancel a scan

    :param scan_id: the scan id
    :type scan_id: str
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    cli = get_cli(verbose, session)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.cancel(scan_id)
    return scan


def scan_data(data, filename, force, post_max_size_M=100, probe=None,
              mimetype_filtering=None, resubmit_files=None,
              blocking=False, blocking_timeout=60,
              verbose=False, session=None):
    """Wrapper around scan_new / scan_add_data / scan_launch

    :param data: data to scan
    :type data: raw string
    :param filename: filename associated to data
    :type filename: string
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param post_max_size_M: POST data max size in Mb (multiple calls to the
    api will be done if total size is more than this limit, note that if
    one or more file is bigger than this limit it will raise an error)
    :type post_max_size_M: int
    :param probe: probe list to use
        (optional default: None means all)
    :type probe: list
    :param mimetype_filtering: enable probe selection based on mimetype
        (optional default:True)
    :type mimetype_filtering: bool
    :param resubmit_files: reanalyze files produced by probes
        (optional default:True)
    :type resubmit_files: bool
    :param blocking: wether or not the function call should block until
        scan ended
    :type blocking: bool
    :param blocking_timeout: maximum amount of time before timeout per file
        (only enabled while blocking is ON)
    :type blocking_timeout: int
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    file = data_upload(data, filename, verbose=verbose, session=session)
    scan = scan_launch([file.id], force, probe=probe,
                       mimetype_filtering=mimetype_filtering,
                       resubmit_files=resubmit_files,
                       verbose=verbose, session=session)
    if blocking:
        start = time.time()
        while not scan.is_finished():
            now = time.time()
            if now > (start + blocking_timeout):
                raise IrmaError("Timeout waiting for scan to finish")
            time.sleep(1)
            scan = scan_get(scan.id, verbose=verbose, session=session)
    return scan


def scan_files(filelist, force, probe=None,
               mimetype_filtering=None, resubmit_files=None,
               blocking=False, blocking_timeout=60,
               verbose=False, session=None):
    """Wrapper around file_upload / scan_launch

    :param filelist: list of full path qualified files
    :type filelist: list
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param probe: probe list to use
        (optional default: None means all)
    :type probe: list
    :param mimetype_filtering: enable probe selection based on mimetype
        (optional default:True)
    :type mimetype_filtering: bool
    :param resubmit_files: reanalyze files produced by probes
        (optional default:True)
    :type resubmit_files: bool
    :param blocking: wether or not the function call should block until
        scan ended
    :type blocking: bool
    :param blocking_timeout: maximum amount of time before timeout per file
        (only enabled while blocking is ON)
    :type blocking_timeout: int
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    file_ids = []
    for filepath in filelist:
        file = file_upload(filepath, verbose, session)
        file_ids.append(file.id)

    scan = scan_launch(file_ids, force, probe=probe,
                       mimetype_filtering=mimetype_filtering,
                       resubmit_files=resubmit_files,
                       verbose=verbose, session=session)
    total_timeout = blocking_timeout * len(filelist)
    if blocking:
        start = time.time()
        while not scan.is_finished():
            now = time.time()
            if now > (start + total_timeout):
                raise IrmaError("Timeout waiting for scan to finish")
            time.sleep(1)
            scan = scan_get(scan.id, verbose=verbose, session=session)
    return scan


def scan_get(scan_id, verbose=False, session=None):
    """Fetch a scan (useful to track scan progress with scan.pstatus)

    :param scan_id: the scan id
    :type scan_id: str
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    cli = get_cli(verbose, session)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.get(scan_id)
    return scan


def scan_launch(file_id_list, force, probe=None, mimetype_filtering=None,
                resubmit_files=None, verbose=False, session=None):
    """Launch an existing scan

    :param file_id_list: list of files id returned by upload_data or
    upload_files
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param probe: probe list to use
        (optional default None means all)
    :type probe: list
    :param mimetype_filtering: enable probe selection based on mimetype
        (optional default:True)
    :type mimetype_filtering: bool
    :param resubmit_files: reanalyze files produced by probes
        (optional default:True)
    :type resubmit_files: bool
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the updated scan object
    :rtype: IrmaScan
    """
    cli = get_cli(verbose, session)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.launch(file_id_list, force, probe=probe,
                          mimetype_filtering=mimetype_filtering,
                          resubmit_files=resubmit_files)
    return scan


def scan_list(limit=None, offset=None, verbose=False, session=None):
    """List all scans

    :param limit: max number of files to receive
        (optional default:25)
    :type limit: int
    :param offset: index of first result
        (optional default:0)
    :type offset: int
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return tuple of total scans and list of scans
    :rtype: tuple(int, list of IrmaScan)
    """
    cli = get_cli(verbose, session)
    scanapi = IrmaScansApi(cli)
    (total, scan_list) = scanapi.list(limit=limit, offset=offset)
    return (total, scan_list)


def scan_proberesults(fe_id, formatted=True, verbose=False, session=None):
    """Fetch file probe results (for a given scan
        one scan <-> one fe_id

    :param fe_id: the file_ext id
    :type fe_id: str
    :param formatted: apply frontend formatters on results
        (optional default:True)
    :type formatted: bool
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return a IrmaResult object
    :rtype: IrmaResults
    """
    cli = get_cli(verbose, session)
    scanapi = IrmaScansApi(cli)
    proberesults = scanapi.probe_results(fe_id,
                                         formatted=formatted)
    return proberesults


def tag_list(verbose=False, session=None):
    """List all available tags

    :return: list of existing tags
    :rtype: list of IrmaTag
    """
    cli = get_cli(verbose, session)
    tagapi = IrmaTagsApi(cli)
    taglist = tagapi.list()
    return taglist


def tag_new(text, verbose=False, session=None):
    """Create a new tag

    :param text: tag label (utf8 encoded)
    :type text: str
    :return: None
    """
    cli = get_cli(verbose, session)
    tagapi = IrmaTagsApi(cli)
    return tagapi.new(text)


def token_new(scan_id, verbose=False, session=None):
    """Create a new token

    :param scan_id: scan id
    :type text: str uuid
    :return: None
    """
    cli = get_cli(verbose, session)
    tokenapi = IrmaTokensApi(cli)
    return tokenapi.new(scan_id)
