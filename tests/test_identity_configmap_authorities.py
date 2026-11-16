# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound ConfigMap cleanup and retained Istio authority controls."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('retained_maps',Path(__file__).parent/'workload-identities/retained_state.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)

class ConfigMapAuthorities(unittest.TestCase):
    def fixture(self):
        jar=b'actual image fixture bytes';digest=hashlib.sha256(jar).hexdigest()
        obj={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'ignite-extensions','namespace':'takserver','uid':'map','resourceVersion':'7'},'binaryData':{'ignite-extensions.jar':base64.b64encode(jar).decode()}}
        container={'name':'config','image':'example/config:locked'}
        deployment={'metadata':{'uid':'deployment'},'spec':{'template':{'spec':{'containers':[container]}}}}
        rs={'metadata':{'uid':'replicaset','ownerReferences':[{'kind':'Deployment','uid':'deployment','controller':True}]}}
        pod={'metadata':{'name':'config-pod','uid':'pod','ownerReferences':[{'kind':'ReplicaSet','uid':'replicaset','controller':True}]},'spec':{'containers':[copy.deepcopy(container)]},'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'config','ready':True,'state':{'running':{'startedAt':'fixed'}},'imageID':'containerd://sha256:'+'a'*64}]}}
        data={'deployment':deployment,'replicasets':{'items':[rs]},'pods':{'items':[pod]}}
        driver=SimpleNamespace(state={'deploymentUIDs':{'takserver-config':'deployment'}},get=lambda kind,*a,**k:data[kind],exec=lambda *a,**k:SimpleNamespace(returncode=0,stderr='',stdout=digest+'  /ignite-extensions.jar\n'))
        return obj,driver,data

    def test_literal_binary_is_bound_to_ready_deployment_chain_and_image(self):
        obj,driver,data=self.fixture();rec=R.ignite_binding(driver,obj)
        self.assertEqual(rec['imageBoundJarSHA256'],hashlib.sha256(b'actual image fixture bytes').hexdigest())
        # A rollout may replace the Pod and ReplicaSet while retaining the same image authority.
        data['pods']['items'][0]['metadata']['uid']='new-pod'
        data['replicasets']['items'][0]['metadata']['uid']='new-rs'
        data['pods']['items'][0]['metadata']['ownerReferences'][0]['uid']='new-rs'
        self.assertEqual(R.ignite_binding(driver,obj),rec)
        data['pods']['items'][0]['status']['containerStatuses'][0]['imageID']='containerd://sha256:'+'b'*64
        self.assertNotEqual(R.ignite_binding(driver,obj),rec)

    def test_name_only_payload_owner_chain_mount_and_image_substitutions_refused(self):
        mutations=[lambda o,d:d['deployment']['metadata'].update(uid='foreign'),
            lambda o,d:d['replicasets']['items'][0]['metadata']['ownerReferences'][0].update(uid='foreign'),
            lambda o,d:d['pods']['items'][0]['metadata']['ownerReferences'][0].update(uid='foreign'),
            lambda o,d:d['pods']['items'].append(copy.deepcopy(d['pods']['items'][0])),
            lambda o,d:d['pods']['items'][0]['status']['containerStatuses'][0].update(imageID='mutable:tag'),
            lambda o,d:d['pods']['items'][0]['spec']['containers'][0].update(volumeMounts=[{'mountPath':'/ignite-extensions.jar'}]),
            lambda o,d:d['pods']['items'][0]['spec']['containers'][0].update(image='foreign'),
            lambda o,d:d['pods']['items'][0]['status']['conditions'][0].update(status='False'),
            lambda o,d:o.update(data={'private':'payload'}),
            lambda o,d:o['binaryData'].update(other='cHJpdmF0ZQ=='),
            lambda o,d:o['metadata'].update(ownerReferences=[{'uid':'foreign'}]),
            lambda o,d:o['binaryData'].update({'ignite-extensions.jar':base64.b64encode(b'other').decode()})]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                obj,driver,data=self.fixture();mutate(obj,data)
                with self.assertRaises(ValueError):R.ignite_binding(driver,obj)

    def test_exec_errors_and_identity_race_are_refused(self):
        for result in [SimpleNamespace(returncode=1,stderr='',stdout=''),SimpleNamespace(returncode=0,stderr='warning',stdout=''),SimpleNamespace(returncode=0,stderr='',stdout='a'*64+'  /wrong/path\n')]:
            obj,driver,data=self.fixture();driver.exec=lambda *a,**k:result
            with self.assertRaises(ValueError):R.ignite_binding(driver,obj)
        obj,driver,data=self.fixture();old=driver.exec
        def changed(*a,**k):
            data['pods']['items'][0]['metadata']['uid']='replacement'
            return old(*a,**k)
        driver.exec=changed
        with self.assertRaisesRegex(ValueError,'during binary observation'):R.ignite_binding(driver,obj)

    def test_cleanup_requires_bound_token_and_rechecks_binary_before_delete(self):
        obj,driver,data=self.fixture();rec=R.resource_record(obj)
        self.assertFalse(R.cleanup_allowed(rec));rec.update(R.ignite_binding(driver,obj));self.assertTrue(R.cleanup_allowed(rec))
        rec['origin']={}
        driver.guard=lambda:None;driver.core_unchanged=lambda:None
        driver.kube=lambda *a:'{}' if a[1]=='namespace' else json.dumps(obj)
        with patch.object(R,'require_origin'),patch.object(R,'consumers_gone'),patch.object(R,'delete_record') as delete:
            R.conditional_delete(driver,rec);delete.assert_called_once_with(driver,rec);delete.reset_mock()
            obj['binaryData']['ignite-extensions.jar']=base64.b64encode(b'changed after snapshot').decode()
            with self.assertRaisesRegex(ValueError,'Ignite binary changed'):R.conditional_delete(driver,rec)
            delete.assert_not_called()

    def test_istio_crl_empty_or_nonempty_requires_exact_core_authority(self):
        for value in ('','public CRL'):
            source={'metadata':{'uid':'core-crl'},'data':{'ca-crl.pem':value}}
            obj={'kind':'ConfigMap','metadata':{'name':'istio-ca-crl','namespace':'takserver','uid':'copy','resourceVersion':'2','labels':{'istio.io/config':'true'}},'data':{'ca-crl.pem':value}}
            driver=SimpleNamespace(get=lambda *a,**k:source)
            rec=R.trust_binding(driver,obj);self.assertTrue(R.preserved_trust(driver,obj,[rec]));self.assertFalse(R.cleanup_allowed(rec))
            source['metadata']['uid']='replacement'
            with self.assertRaisesRegex(ValueError,'Core trust authority'):R.preserved_trust(driver,obj,[rec])
            source['metadata']['uid']='core-crl';source['data']['ca-crl.pem']='different'
            with self.assertRaises(ValueError):R.trust_binding(driver,obj)
            source['data']={}
            with self.assertRaises(ValueError):R.trust_binding(driver,obj)
        obj['metadata']['name']='istio-ca-root-cert';obj['data']={'root-cert.pem':''};source['data']={'root-cert.pem':''}
        with self.assertRaises(ValueError):R.trust_binding(driver,obj)

if __name__=='__main__':unittest.main()
