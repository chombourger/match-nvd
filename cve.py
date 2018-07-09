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

aliases        = {}
distribution   = {}
distro_name    = None
distro_version = None
do_debug       = False
matched_rules  = []
packages       = {}

# -------------------------------------------------------------------------------------------------
def debug(x):
# -------------------------------------------------------------------------------------------------
    if do_debug == True:
        print(x)

# -------------------------------------------------------------------------------------------------
def clear_matched_rules():
# -------------------------------------------------------------------------------------------------
    matched_rules.clear()

# -------------------------------------------------------------------------------------------------
def add_matched_rule(r):
# -------------------------------------------------------------------------------------------------
    matched_rules.append(r)

# -------------------------------------------------------------------------------------------------
def get_matched_rules():
# -------------------------------------------------------------------------------------------------
    return matched_rules

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
def load_distribution(distro_file):
# -------------------------------------------------------------------------------------------------
    if os.path.exists(distro_file) == False:
        return {}
    distro_data = None
    with open(distro_file) as data:
       distro_data = json.load(data)
    return distro_data

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
        matched_distro = None
        matched_pkgs   = []
        for vendor in cve['affects']['vendor']['vendor_data']:
            for product in vendor['product']['product_data']:
                name = product['product_name']
                # product matches an installed package?
                if name in packages:
                    debug('%s is an installed package' % (name))
                    for pkg in packages[name]:
                        debug(pkg)
                        matched_pkgs.append(pkg)
                # product matches our distribution?
                if distro_name is not None and name == distro_name:
                    debug('%s is our distribution' % (name))
                    matched_distro = distribution

        if len(matched_pkgs) > 0:
            return matched_pkgs
        if matched_distro is not None:
            return [ matched_distro ]

        # none of the above
        return None

    except KeyError:
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
    debug("app check criteria: '%s' version '%s' against: '%s' version '%s'" %
          (product, version, my_app, my_ver))
    if update != '*':
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
        if distro_name is None or product != distro_name:
            return False
        elif distro_version is not None:
            my_ver = distro_version
    return match_version(my_ver, version)

# -------------------------------------------------------------------------------------------------
def evaluate_versions(my_app, my_ver, part, product, cpe):
# -------------------------------------------------------------------------------------------------
    versions = []
    if my_app != product:
        debug('top-level product: %s, cpe for %s' % (my_app, product))
        if part == 'a':
            if product in packages:
                for app in packages[product]:
                    versions.append(app['version'])
                my_app = product
            else:
                debug('%s not installed' % (product))
                return False
        elif part == 'o':
            if distro_name is not None and product == distro_name:
                my_app = distro_name
                if distro_version is not None:
                    versions.append(distro_version)
                else:
                    debug('%s version not specified!' % (distro_name))
                    return False
            else:
                debug("our distribution isn't %s" % (product))
                return False
        else:
            debug("unsupported part '%s'!" % (part))
            return False
    else:
        versions.append(my_ver)
    debug("%s versions to check: %s" % (my_app, str(versions)))

    version_checks = []
    if 'versionStartExcluding' in cpe:
        test_ver = cpe['versionStartExcluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp <= 0:
            return False
        version_checks.append('version > %s' % test_ver)
    if 'versionStartIncluding' in cpe:
        test_ver = cpe['versionStartIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp < 0:
            return False
        version_checks.append('version >= %s' % test_ver)
    if 'versionEndExcluding' in cpe:
        test_ver = cpe['versionEndExcluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp >= 0:
            return False
        version_checks.append('version < %s' % test_ver)
    if 'versionEndIncluding' in cpe:
        test_ver = cpe['versionEndIncluding']
        cmp = apt_pkg.version_compare(my_ver, test_ver)
        if cmp > 0:
            return False
        version_checks.append('version <= %s' % test_ver)
    if len(version_checks) > 0:
        add_matched_rule(product + ': ' + ' && '.join(version_checks))

# -------------------------------------------------------------------------------------------------
def evaluate_cpe23(my_app, my_ver, cpe):
# -------------------------------------------------------------------------------------------------
    uri     = cpe['cpe23Uri']
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

    result = evaluate_versions(my_app, my_ver, part, product, cpe)
    if result == False:
        return False

    if part == 'a':
        result = match_application(my_app, my_ver, product, vendor, version, update, edition, lang)
    elif part == 'o':
        result = match_os(my_app, my_ver, product, vendor, version, update, edition, lang)

    if result == True:
        add_matched_rule(uri)
    return result

# -------------------------------------------------------------------------------------------------
def evaluate_cpe22(my_app, my_ver, cpe):
# -------------------------------------------------------------------------------------------------
    uri     = cpe['cpe22Uri']
    values  = uri.split(':')
    scheme  = values[0]
    part    = values[1].replace('/', '')
    vendor  = values[2]
    product = values[3]
    version = values[4]
    update  = values[5]
    edition = values[6]
    lang    = values[7]

    result = evaluate_versions(my_app, my_ver, part, product, cpe)
    if result == False:
        return False

    if part == 'a':
        result = match_application(my_app, my_ver, product, vendor, version, update, edition, lang)
    elif part == 'o':
        result = match_os(product, vendor, vendor, version, update, edition, lang)

    if result == True:
        add_matched_rule(uri)
    return result

# -------------------------------------------------------------------------------------------------
def evaluate_cpe(my_app, my_ver, cpe):
# -------------------------------------------------------------------------------------------------
    if 'cpe23Uri' in cpe:
        return evaluate_cpe23(my_app, my_ver, cpe)
    elif 'cpe22Uri' in cpe:
        return evaluate_cpe22(my_app, my_ver, cpe)
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
        debug('evaluate cpe against %s version %s' % (my_app, my_ver))
        result = evaluate_cpes(my_app, my_ver, node['cpe'])
    elif 'children' in node:
        debug('evaluate children')
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
        debug("%d configurations" % (len(configurations['nodes'])))
        for node in configurations['nodes']:
            op      = node['operator']
            results = evaluate_node(my_app, my_ver, node)
            debug("OP=%s, %d results: %s" % (op, len(results), results))
            if evaluate_results(op, results) == True:
                return True
        return False
    except KeyError:
        return False

# -------------------------------------------------------------------------------------------------
def print_matches(id, product, version, status):
# -------------------------------------------------------------------------------------------------
    matches = get_matched_rules()
    if len(matches) == 0:
        matches.append('')
    for m in matches:
        print("| %-16s | %-32s | %-8s | %-20s | %-56s |" % (id, product, version, status, m))
        id      = ''
        product = ''
        version = ''
        status  = ''

# -------------------------------------------------------------------------------------------------
# Our main
# -------------------------------------------------------------------------------------------------

apt_pkg.init_system()

aliases      = load_aliases('aliases.json')
distribution = load_aliases('distribution.json')
packages     = load_packages('packages.json')

if 'name' in distribution:
    distro_name = distribution['name']
if 'version' in distribution:
    distro_version = distribution['version']

for name in aliases:
    if name in packages:
        pkg = packages[name]
        alias = aliases[name]
        packages[alias] = pkg

for name in packages:
    for app in packages[name]:
        app['name'] = name

nvd_files = glob.glob('nvdcve-*.json')
for nvd_file in nvd_files:
    nvd = load_nvd(nvd_file)
    for entry in nvd['CVE_Items']:
        if 'cve' not in entry:
            continue
        cve  = entry['cve']
        id = cve['CVE_data_meta']['ID']
        matches = match_cve_by_product(cve)
        if matches is None:
            continue
        for app in matches:
            clear_matched_rules()
            name   = app['name']
            alias  = name
            if name in aliases:
                alias = aliases[name]
            result = match_configurations(alias, app['version'], entry)
            status = 'Not affected'
            if result == True:
                status = 'Affected'
                if 'patches' in app:
                    patches = app['patches']
                    if id in patches:
                        status = 'Patched'
            else:
                clear_matched_rules()
            print_matches(id, name, app['version'], status)
