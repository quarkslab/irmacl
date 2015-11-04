#!/usr/bin/env python

#
# Copyright (c) 2013-2015 QuarksLab.
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
import argparse
from apiclient import IrmaApiClient, IrmaScansApi, IrmaProbesApi, \
    IrmaFilesApi, IrmaError
from ConfigParser import ConfigParser

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
address = config.get("Server", "address")
API_ENDPOINT = "http://{0}/api/v1".format(address)

# =========
#  Helpers
# =========


def probe_list(verbose=False):
    """List availables probes

    :param verbose: enable verbose requests (optional default:False)
    :type verbose: bool
    :return: return probe list
    :rtype: list
    """
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    probesapi = IrmaProbesApi(cli)
    probelist = probesapi.list()
    return probelist


def scan_new(verbose=False):
    """Create a new scan

    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the new generated scan object
    :rtype: IrmaScan
    """
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.new()
    return scan


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
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.add(scan_id, filelist)
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
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.launch(scan_id, force, probe)
    return scan


def scan_files(filelist, force, probe=None, verbose=False):
    """Wrapper around scan_new / scan_add / scan_launch

    :param filelist: list of full path qualified files
    :type filelist: list
    :param force: if True force a new analysis of files
        if False use existing results
    :type force: bool
    :param probe: probe list to use
        (optional default: None means all)
    :type probe: list
    :param verbose: enable verbose requests
        (optional default:False)
    :type verbose: bool
    :return: return the scan object
    :rtype: IrmaScan
    """
    scan = scan_new(verbose)
    scan = scan_add(scan.id, filelist, verbose)
    scan = scan_launch(scan.id, force, probe, verbose)
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
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.cancel(scan_id)
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
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    scanapi = IrmaScansApi(cli)
    scan = scanapi.get(scan_id)
    return scan


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
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
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
    :type limit: bool
    :param offset: index of first result
        (optional default:0)
    :type offset: bool
    :return: return matching files already scanned
    :rtype: list of IrmaResults
    """
    cli = IrmaApiClient(API_ENDPOINT, verbose=verbose)
    fileapi = IrmaFilesApi(cli)
    files = fileapi.search(name=name, hash=hash, limit=limit, offset=offset)
    return files

# ================================================
#  Functions print values or raise (Called by UI)
# ================================================


def cmd_probe_list(verbose=False):
    res = probe_list(verbose)
    print "Available analysis : " + ", ".join(res)
    return


def cmd_scan_cancel(scan_id=None, verbose=False):
    scan = scan_cancel(scan_id, verbose)
    cancelled = scan.probes_total - scan.probes_finished
    print "Cancelled {0}/{1} jobs".format(cancelled, scan.probes_total)
    return


def cmd_scan_progress(scan_id=None, partial=False, verbose=False):
    scan = scan_get(scan_id, verbose)
    rate_total = 0
    if scan.is_launched():
        if scan.probes_total != 0:
            rate_total = scan.probes_finished * 100 / scan.probes_total
        if scan.probes_finished != 0:
            print("{0}/{1} jobs finished ".format(scan.probes_finished,
                                                  scan.probes_total) +
                  "({0}%)".format(rate_total))
    else:
        print "Scan status : {0}".format(scan.pstatus)
    if scan.is_finished() or partial:
        cmd_scan_results(scan_id=scan_id, verbose=verbose)
    return


def print_probe_result(probe_result, justify=12):
    name = probe_result.name
    print "\t%s" % (name.ljust(justify)),
    if probe_result.status <= 0:
        probe_res = probe_result.error
    else:
        probe_res = probe_result.results
    try:
        if type(probe_res) == list:
            print ("\n\t " + " " * justify).join(probe_res)
        elif probe_res is None:
            print ('clean')
        elif type(probe_res) == dict:
            print "[...]"
        else:
            print (probe_res.strip())
        return
    except:
        print probe_res


def cmd_scan_results(scan_id, verbose=False):
    scan = scan_get(scan_id, verbose)
    for result in scan.results:
        file_result = file_results(scan_id, result.result_id)
        print "[{0} (sha256: {1})]".format(file_result.name,
                                           file_result.file_infos.sha256)
        for pr in file_result.probe_results:
            print_probe_result(pr)
    return


def cmd_scan(filename=None, force=None, probe=None, verbose=False):
    scan = scan_files(filename, force, probe, verbose)
    print "scan_id {0} launched".format(scan.id)
    return

if __name__ == "__main__":
    # create the top-level parser
    desc = "command line interface for IRMA"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-v',
                        dest='verbose',
                        action='store_true',
                        help='verbose output')
    subparsers = parser.add_subparsers(help='sub-command help')

    # create the parser for the "list" command
    list_parser = subparsers.add_parser('list', help='list available analysis')
    list_parser.set_defaults(func=cmd_probe_list)

    # create the parser for the "scan" command
    scan_parser = subparsers.add_parser('scan',
                                        help='scan given filename list')
    scan_parser.add_argument('--force',
                             dest='force',
                             action='store_true',
                             help='force new analysis')
    scan_parser.add_argument('--probe',
                             nargs='+',
                             help='specify analysis list')
    scan_parser.add_argument('--filename',
                             nargs='+',
                             help='a filename to analyze',
                             required=True)
    scan_parser.set_defaults(func=cmd_scan)

    # create the parser for the "results" command
    res_parser = subparsers.add_parser('results',
                                       help='print scan results')
    res_parser.add_argument('--partial',
                            dest='partial',
                            action='store_true',
                            help='print results as soon as they are available')
    res_parser.add_argument('scan_id', help='scan_id returned by scan command')
    res_parser.set_defaults(func=cmd_scan_progress)

    # create the parser for the "cancel" command
    cancel_parser = subparsers.add_parser('cancel', help='cancel scan')
    cancel_parser.add_argument('scan_id',
                               help='scan_id returned by scan command')
    cancel_parser.set_defaults(func=cmd_scan_cancel)

    args = vars(parser.parse_args())
    func = args.pop('func')
    # with 'func' removed, args is now a kwargs with only
    # the specific arguments for each subfunction
    # useful for interactive mode.
    try:
        func(**args)
    except IrmaError, e:
        print "IrmaError: {0}".format(e)
    except Exception, e:
        import traceback
        print traceback.format_exc()
        raise IrmaError("Uncaught exception: {0}".format(e))
