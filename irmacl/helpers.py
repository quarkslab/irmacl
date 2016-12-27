# Copyright (c) 2013-2016 Quarkslab.
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
from apiclient import IrmaApiClient, IrmaScansApi, IrmaProbesApi, \
    IrmaFilesApi, IrmaError
from ConfigParser import ConfigParser, NoOptionError


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

if config_file is None:
    raise IrmaError("irma.conf config file not found")

config = ConfigParser()
config.read(config_file)
api_endpoint = config.get("Server", "api_endpoint")

# Optional values in the config file
# Here are the defaults values
max_tries = 1
verify = True
pause = 3

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

# =========
#  Helpers
# =========


def file_results(scan_id, result_idx, formatted=True, verbose=False):
    """Fetch a file results

    :param scan_id: the scan id
    :type scan_id: str
    :param result_idx: the result id
    :type result_idx: str
    :param formatted: apply frontend formatters on results
        (optional default:True)
    :type formatted: bool
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return a IrmaResult object
    :rtype: IrmaResults
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    file_results = scanapi.file_results(scan_id, result_idx,
                                        formatted=formatted)
    return file_results


def file_search(name=None, hash=None, limit=None, offset=None, verbose=False):
    """Search a file by name or hash value

    :param name: name of the file ('*name*' will be searched)
    :type name: str
    :param hash: one of sha1, md5 or sha256 full hash value
    :type hash: str of (64, 40 or 32 chars)
    :param limit: max number of files to receive
        (optional default:25)
    :type limit: int
    :param offset: index of first result
        (optional default:0)
    :type offset: int
    :return: return tuple of total files and list of matching files already
        scanned
    :rtype: tuple(int, list of IrmaResults)
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    fileapi = IrmaFilesApi(cli)
    (total, files_list) = fileapi.search(name=name, hash=hash, limit=limit,
                                         offset=offset)
    return (total, files_list)


def probe_list(verbose=False):
    """List availables probes

    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return probe list
    :rtype: list
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    probesapi = IrmaProbesApi(cli)
    probelist = probesapi.list()
    return probelist


def scan_add(scan_id, filelist, verbose=False):
    """Add files to an existing scan

    :param scan_id: the scan id
    :type scan_id: str
    :param filelist: list of full path qualified files
    :type filelist: list
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the updated scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.add(scan_id, filelist)
    return scan


def scan_cancel(scan_id, verbose=False):
    """Cancel a scan

    :param scan_id: the scan id
    :type scan_id: str
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.cancel(scan_id)
    return scan


def scan_files(filelist, force, probe=None, blocking=False, verbose=False):
    """Wrapper around scan_new / scan_add / scan_launch

    :param filelist: list of full path qualified files
    :type filelist: list
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param probe: probe list to use
        (optional default: None means all)
    :type probe: list
    :param blocking: wether or not the function call should block until
        scan ended
    :type blocking: bool
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    scan = scan_new(verbose=verbose)
    scan = scan_add(scan.id, filelist, verbose=verbose)
    scan = scan_launch(scan.id, force, probe=probe, verbose=verbose)
    if blocking:
        while not scan.is_finished():
            time.sleep(1)
            scan = scan_get(scan.id, verbose=verbose)
    return scan


def scan_get(scan_id, verbose=False):
    """Fetch a scan (useful to track scan progress with scan.pstatus)

    :param scan_id: the scan id
    :type scan_id: str
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.get(scan_id)
    return scan


def scan_launch(scan_id, force, probe=None, verbose=False):
    """Launch an existing scan

    :param scan_id: the scan id
    :type scan_id: str
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param probe: probe list to use
        (optional default None means all)
    :type probe: list
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the updated scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.launch(scan_id, force, probe)
    return scan


def scan_list(limit=None, offset=None, verbose=False):
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
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    (total, scan_list) = scanapi.list(limit=limit, offset=offset)
    return (total, scan_list)


def scan_new(verbose=False):
    """Create a new scan

    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the new generated scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(api_endpoint, max_tries=max_tries, pause=pause,
                        verify=verify, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.new()
    return scan
