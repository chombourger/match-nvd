#!/usr/bin/env python3
# -------------------------------------------------------------------------------------------------
# Match NVD/CPE entries against a user-provided package list
# Copyright (c) 2018, Mentor Graphics, a Siemens business
# -------------------------------------------------------------------------------------------------
# This file is released under the MIT license, see LICENSE
# -------------------------------------------------------------------------------------------------

import apt_pkg
import glob
import os
import json
import re

aliases  = {}
packages = {}

# -------------------------------------------------------------------------------------------------
def load_nvd(nvd_file):
# -------------------------------------------------------------------------------------------------
    nvd_data = None
    with open(nvd_file) as data:
        nvd_data = json.load(data)
    return nvd_data

# -------------------------------------------------------------------------------------------------
def load_aliases(aliases_file):
# -------------------------------------------------------------------------------------------------
    if os.path.exists(aliases_file) == False:
        return {}
    aliases_data = None
    with open(aliases_file) as data:
       aliases_data = json.load(data)
    return aliases_data

# -------------------------------------------------------------------------------------------------
def load_packages(pkg_file):
# -------------------------------------------------------------------------------------------------
    pkg_data = None
    with open(pkg_file) as data:
       pkg_data = json.load(data)
    return pkg_data

# -------------------------------------------------------------------------------------------------
# Check if a given CVE affects one of the integrated products
# -------------------------------------------------------------------------------------------------
def match_cve_by_product(cve):
# -------------------------------------------------------------------------------------------------
    try:
        vendor  = cve['affects']['vendor']['vendor_data'][0]
        product = vendor['product']['product_data'][0]
        name    = product['product_name']
        if name not in packages:
            return None
        return name
    except (KeyError, IndexError):
        return None

# -------------------------------------------------------------------------------------------------
# Check if the specified version matches with the installed version
# -------------------------------------------------------------------------------------------------
# my_ver: installed version
# test_ver: version expression to compare against
# -------------------------------------------------------------------------------------------------
def match_version(my_ver, test_ver):
# -------------------------------------------------------------------------------------------------
    e = '^' + test_ver.replace('*', '.*')
    p = re.compile(e)
    m = p.match(my_ver)
    if m is None:
        return False
    else:
        return True

# -------------------------------------------------------------------------------------------------
# Match the installed application against the specified CPE application entry
# -------------------------------------------------------------------------------------------------
# my_app: name of the installed application
# my_ver: version of the installed application
# product: CPE product name
# vendor: CPE vendor name
# version: CPE version (expression)
# update: CPE update
# edition: CPE edition
# lang: CPE language
# -------------------------------------------------------------------------------------------------
def match_application(my_app, my_ver, product, vendor, version, update, edition, lang):
# -------------------------------------------------------------------------------------------------
    if my_app != product:
        return False
    return match_version(my_ver, version)

# -------------------------------------------------------------------------------------------------
# Match the installed OS against the specified CPE OS entry
# -------------------------------------------------------------------------------------------------
# my_app: name of the installed application
# my_ver: version of the installed application
# product: CPE product name
# vendor: CPE vendor name
# version: CPE version (expression)
# update: CPE update
# edition: CPE edition
# lang: CPE language
# -------------------------------------------------------------------------------------------------
def match_os(my_app, my_ver, product, vendor, version, update, edition, lang):
# -------------------------------------------------------------------------------------------------
    if my_app != "linux_kernel":
        return False
    return match_version(my_ver, version)

# -------------------------------------------------------------------------------------------------
def evaluate_cpe23(my_app, my_ver, uri):
# -------------------------------------------------------------------------------------------------
    values  = uri.split(':')
    scheme  = values[0]
    proto   = values[1]
    part    = values[2]
    vendor  = values[3]
    product = values[4]
    version = values[5]
    update  = values[6]
    edition = values[7]
    lang    = values[8]
    if part == 'a':
        return match_application(my_app, my_ver, product, vendor, version, update, edition, lang)
    elif part == 'o':
        return match_os(my_app, my_ver, product, vendor, version, update, edition, lang)
    return False

# -------------------------------------------------------------------------------------------------
def evaluate_cpe22(my_app, my_ver, uri):
# -------------------------------------------------------------------------------------------------
    values  = uri.split(':')
    scheme  = values[0]
    part    = values[1]
    vendor  = values[2]
    product = values[3]
    version = values[4]
    update  = values[5]
    edition = values[6]
    lang    = values[7]
    if part == '/a':
        return match_application(my_app, my_ver, product, vendor, version, update, edition, lang)
    elif part == '/o':
        return match_os(product, vendor, vendor, version, update, edition, lang)
    return False

# -------------------------------------------------------------------------------------------------
def evaluate_cpe(my_app, my_ver, cpe):
# -------------------------------------------------------------------------------------------------
    if 'versionStartExcluding' in cpe:
        test_ver = cpe['versionEndIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp <= 0:
            return False
    if 'versionStartIncluding' in cpe:
        test_ver = cpe['versionEndIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp < 0:
            return False
    if 'versionEndExcluding' in cpe:
        test_ver = cpe['versionEndIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp >= 0:
            return False
    if 'versionEndIncluding' in cpe:
        test_ver = cpe['versionEndIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp > 0:
            return False
    if 'cpe23Uri' in cpe:
        return evaluate_cpe23(my_app, my_ver, cpe['cpe23Uri'])
    elif 'cpe22Uri' in cpe:
        return evaluate_cpe22(my_app, my_ver, cpe['cpe22Uri'])
    else:
        return False

# -------------------------------------------------------------------------------------------------
def evaluate_cpes(my_app, my_ver, cpes):
# -------------------------------------------------------------------------------------------------
    results = []
    for cpe in cpes:
        result = evaluate_cpe(my_app, my_ver, cpe)
        results.append(result)
    return results

# -------------------------------------------------------------------------------------------------
def evaluate_children(my_app, my_ver, children):
# -------------------------------------------------------------------------------------------------
    results = []
    for child in children:
        result = evaluate_node(my_app, my_ver, child)
        results.append(result)
    return results

# -------------------------------------------------------------------------------------------------
def evaluate_node(my_app, my_ver, node):
# -------------------------------------------------------------------------------------------------
    result = False
    if 'cpe' in node:
        result = evaluate_cpes(my_app, my_ver, node['cpe'])
    elif 'children' in node:
        result = evaluate_children(my_app, my_ver, node['children'])
    return result

# -------------------------------------------------------------------------------------------------
def evaluate_results(op, results):
# -------------------------------------------------------------------------------------------------
    if isinstance(results, list):
        if op == 'OR':
            for value in results:
                if value == True:
                    return True
            return False
        elif op == 'AND':
            for value in results:
                if value == False:
                    return False
            return True
    else:
        return results

# -------------------------------------------------------------------------------------------------
def match_configurations(my_app, my_ver, cve):
# -------------------------------------------------------------------------------------------------
    try:
        configurations = cve['configurations']
        for node in configurations['nodes']:
            op = node['operator']
            results = evaluate_node(my_app, my_ver, node)
            return evaluate_results(op, results)
        return True
    except KeyError:
        return False

# -------------------------------------------------------------------------------------------------
# Our main
# -------------------------------------------------------------------------------------------------

apt_pkg.init_system()

aliases  = load_aliases('aliases.json')
packages = load_packages('packages.json')

for name in aliases:
    if name in packages:
        pkg = packages[name]
        alias = aliases[name]
        packages[alias] = pkg

nvd_files = glob.glob('nvdcve-*.json')
for nvd_file in nvd_files:
    nvd = load_nvd(nvd_file)
    for entry in nvd['CVE_Items']:
        if 'cve' not in entry:
            continue
        cve  = entry['cve']
        name = match_cve_by_product(cve)
        if name is None:
            continue
        for app in packages[name]:
            result = match_configurations(name, app['version'], entry)
            id = cve['CVE_data_meta']['ID']
            status = 'Not affected'
            if result == True:
                status = 'Affected'
                if 'patches' in app:
                    patches = app['patches']
                    if id in patches:
                        status = 'Patched'
            print("| %-18s | %-18s | %-8s | %-20s |" % (id, name, app['version'], status))
