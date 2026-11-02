"""NEW bounded parser for explicit Android application boolean declarations.

This is static configuration evidence, not a runtime exploit verifier. Unknown,
resource-referenced or unstructured values are deliberately left unknown.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_ANDROID = 'http://schemas.android.com/apk/res/android'
_ATTRS = ('debuggable', 'allowBackup', 'usesCleartextTraffic')


def manifest_inventory(text):
    """Permission-aware static inventory. Unknown defaults stay unknown.

    Decoded XML is authoritative for declarations only. AAPT output retains the
    existing boolean parser; component semantics require decoded XML and are
    explicitly incomplete for binary/string dumps.
    """
    result = {'schema': 'tbhm.android-manifest/1', 'status': 'unknown',
              'settings': application_booleans(text), 'components': [],
              'deep_links': [], 'issues': [], 'runtime_verified': False}
    if not isinstance(text, str) or len(text) > 2_000_000:
        result['issues'].append('manifest input size/type limit'); return result
    if not text.lstrip().startswith('<') or re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
        result['issues'].append('component inventory requires decoded XML; no assumptions from raw strings/AAPT'); return result
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result['issues'].append('invalid XML: '+str(exc)); return result
    apps = root.findall('application') if root.tag == 'manifest' else []
    if len(apps) != 1:
        result['issues'].append('exactly one application required'); return result
    app = apps[0]
    def attr(node, name): return node.get('{'+_ANDROID+'}'+name)
    def boolean(value): return {'true': True, 'false': False}.get(value)
    sdk = root.find('uses-sdk')
    target = attr(sdk, 'targetSdkVersion') if sdk is not None else None
    result['target_sdk'] = int(target) if target and target.isdigit() else None
    result['package'] = root.get('package', '')
    result['application_permission'] = attr(app, 'permission')
    result['network_security_config'] = attr(app, 'networkSecurityConfig')
    declarations = {attr(p, 'name'): attr(p, 'protectionLevel') for p in root.findall('permission') if attr(p, 'name')}
    for node in list(app)[:2000]:
        if node.tag not in {'activity', 'activity-alias', 'service', 'receiver', 'provider'}:
            continue
        name = attr(node, 'name') or '(unnamed)'
        exported = boolean(attr(node, 'exported'))
        enabled = boolean(attr(node, 'enabled'))
        if boolean(attr(app, 'enabled')) is False or enabled is False:
            exposure = 'disabled_by_declaration'
        elif exported is False:
            exposure = 'not_exported_by_declaration'
        elif exported is True:
            exposure = 'exported_by_declaration'
        else:
            exposure = 'unknown_default_or_resource'
        permission = attr(node, 'permission')
        if permission is None:
            permission = attr(app, 'permission')
        permissions = {'general': permission}
        if node.tag == 'provider':
            permissions.update({k: attr(node, k+'Permission') or permission for k in ('read', 'write')})
        review = 'review_permissions_and_runtime_authorization'
        if exposure == 'exported_by_declaration' and not any(permissions.values()):
            review = 'exported_without_declared_permission_review_required'
        component = {'kind': node.tag, 'name': name, 'exported': exported,
                     'exposure': exposure, 'enabled': enabled, 'permissions': permissions,
                     'permission_protection': {p: declarations.get(p, 'external_or_unknown') for p in permissions.values() if p},
                     'path_permissions_present': bool(node.findall('path-permission')),
                     'uri_grants_present': bool(node.findall('grant-uri-permission')) or attr(node, 'grantUriPermissions') == 'true',
                     'review': review, 'vulnerability_confirmed': False}
        if exported is None and node.findall('intent-filter') and (result['target_sdk'] or 0) >= 31:
            component['issue'] = 'Android 12+ target requires explicit exported on components with intent filters; installability unverified'
        result['components'].append(component)
        for intent in node.findall('intent-filter')[:100]:
            for data in intent.findall('data')[:100]:
                result['deep_links'].append({'component': name, 'scheme': attr(data, 'scheme'),
                    'host': attr(data, 'host'), 'path': attr(data, 'path') or attr(data, 'pathPrefix') or attr(data, 'pathPattern'),
                    'auto_verify_declared': attr(intent, 'autoVerify') == 'true', 'association_verified': False})
    result['status'] = 'partial' if len(list(app)) > 2000 else 'complete'
    result['meaning'] = 'Manifest declarations only. Permission names, exported status and deep links do not establish unauthorized access.'
    return result


def application_booleans(text):
    result = {key: None for key in _ATTRS}
    if not isinstance(text, str) or len(text) > 2_000_000:
        return result
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
        return result
    if text.lstrip().startswith('<'):
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return result
        apps = root.findall('application') if root.tag == 'manifest' else []
        if len(apps) != 1:
            return result
        for key in _ATTRS:
            value = apps[0].get('{'+_ANDROID+'}'+key)
            if value in {'true', 'false'}:
                result[key] = value == 'true'
        return result
    # aapt/aapt2 xmltree: bind an attribute to the current element by indentation.
    stack = []; seen = set(); applications = 0
    for line in text.splitlines():
        element = re.fullmatch(r'(\s*)E: ([\w.-]+)(?:\s+.*)?', line)
        if element:
            depth = len(element[1])
            while stack and stack[-1][0] >= depth:
                stack.pop()
            if element[2] == 'application' and [x[1] for x in stack] == ['manifest']:
                applications += 1
            stack.append((depth, element[2]))
            continue
        attr = re.fullmatch(r'\s*A: android:(debuggable|allowBackup|usesCleartextTraffic)'
                            r'(?:\(0x[0-9a-fA-F]+\))?=\(type 0x12\)(0x[0-9a-fA-F]+)\s*', line)
        if attr and [x[1] for x in stack] == ['manifest', 'application']:
            if attr[1] in seen:
                return {key: None for key in _ATTRS}
            seen.add(attr[1]); value = int(attr[2], 16)
            if value in (0, 1, 0xffffffff):
                result[attr[1]] = value != 0
    return result if applications == 1 else {key: None for key in _ATTRS}
