#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import requests
import os
import sys
"""
Purpose:
    Download dicoms from xnat and place them into
    a BIDs "like" directory structure.
    using the xnat rest API to download dicoms.
    see here for xnat REST API documentation: (https://wiki.xnat.org/display/XNAT16/Using+the+XNAT+REST+API)
TODO:
    better error checking
    add a log to write events to
    handle conditionals better
    find a better way to call the script instead of main()
    find a way to pass the password in besides writing it in json file.
    add json descriptors according to BIDs format.
    revise some ugly formating
    add check for quality of scan (e.g. usable?)
    don't copy if already completed? (or just have user be cognizant?)
    parallelize the processing stream (e.g. get all the data first, then download)
    Make main more modular (add more methods/possibly classes)
"""

import requests
import os
import sys

__all__ = ['xnat_init_session','xnat_query_subjects','xnat_query_sessions','xnat_query_scans','xnat_query_dicoms']

class xnat_init_session(object):
    """starts the xnat session and allows user to login to a particular project page"""
    def __init__(self,username,password,project):
        self.url_base = 'https://rpacs.icts.uiowa.edu/xnat/REST/projects/%s/' % project
        self.username = username
        self.password = password
        self.project = project

    def login(self):
        login_query = requests.get(self.url_base,auth=(self.username,self.password))

        if login_query.ok:
            cookie_info = login_query.cookies._cookies['rpacs.icts.uiowa.edu']['/xnat']['JSESSIONID']
        else:
            print('error')
        self.cookie = {cookie_info.name : cookie_info.value}


class xnat_query_subjects(object):
    """get the subject ids from xnat"""
    def __init__(self,cookie,url_base,project):
        self.cookie=cookie
        self.url_base=url_base
        self.project=project


    def get_subjects(self):
        subject_query = requests.get(self.url_base+'subjects', cookies=self.cookie)
        if subject_query.ok:
            subject_json = subject_query.json()
            subject_list_dict = subject_json['ResultSet']['Result']
            self.subject_ids = { x['label']:0 for x in subject_list_dict }


class xnat_query_sessions(object):
    """get the sessions from a particular subject"""
    def __init__(self,cookie,url_base,project,subject):
        self.cookie=cookie
        self.url_base=url_base
        self.subject=subject
        self.project=project

    def get_sessions(self,session_labels=None):
        session_query = requests.get(self.url_base+'subjects/%s/experiments' % (self.subject), cookies=self.cookie)
        if session_query.ok:
            session_json = session_query.json()
            session_list_dict = session_json['ResultSet']['Result']
            if session_labels is not None:
                num_sessions = int(session_json['ResultSet']['totalRecords'])
                num_labels = len(session_labels)
                if num_sessions != num_labels:
                    print('%s has the wrong number of sessions, expected: %s, found: %s' % (self.subject,str(num_labels),str(num_sessions)))
                else:
                    self.session_ids = { sess_label : {sess_dict['label']: 0} for sess_label,sess_dict in zip(session_labels,session_list_dict) }
            else:
                #not supported in this script
                self.session_ids = { x['label']: 0 for x in session_list_dict }


class xnat_query_scans(object):
    """get the scans from a particular session"""
    def __init__(self,cookie,url_base,project,subject,session):
        self.cookie=cookie
        self.url_base=url_base
        self.subject=subject
        self.session=session
        self.project=project

    def get_scans(self):
          scan_query = requests.get(self.url_base+'subjects/%s/experiments/%s/scans/' % (self.subject,self.session), cookies=self.cookie)
          if scan_query.ok:
              scan_json = scan_query.json()
              scan_list_dict = scan_json['ResultSet']['Result']
              self.scan_ids = { x['ID']:[{str(x['type']) },x['quality']] for x in scan_list_dict }
              #ID is a number like 1,3,300
              #type is a name like fMRI FLANKER, PU:Sag CUBE FLAIR, represented as a set?
              #quality specifies if the scan is usable

class xnat_query_dicoms(object):
    """get the dicoms from a particular scan"""
    def __init__(self,cookie,url_base,project,subject,session,scan):
        self.cookie=cookie
        self.url_base=url_base
        self.subject=subject
        self.session=session
        self.scan=scan

    def get_dicoms(self,out_dir):
        #http://stackoverflow.com/questions/4917284/extract-files-from-zip-without-keeping-the-structure-using-python-zipfile
        import zipfile
        import StringIO
        import shutil
        dicom_query = requests.get(self.url_base+'subjects/%s/experiments/%s/scans/%s/resources/DICOM/files?format=zip' % (self.subject,self.session,self.scan), cookies=self.cookie)
        if dicom_query.ok:
            dicom_zip = zipfile.ZipFile(StringIO.StringIO(dicom_query.content))
            for member in dicom_zip.namelist():
                filename = os.path.basename(member)
                if not filename:
                    continue
                source = dicom_zip.open(member)
                target = file(os.path.join(out_dir,filename), "wb")
                with source, target:
                    shutil.copyfileobj(source, target)


def parse_cmdline(args):
    """Parse command line arguments."""
    import argparse
    parser = argparse.ArgumentParser(
        description=(
            'download_xnat.py downloads xnat dicoms and saves them in BIDs compatible directory format'))

    #Required arguments
    requiredargs = parser.add_argument_group('Required arguments')
    requiredargs.add_argument('-i','--input_json',
                              dest='input_json',required=True,
                              help='json file defining inputs for this script.')
    parsed_args = parser.parse_args(args)

    return parsed_args

def parse_json(json_file):
    """Parse json file."""
    import json
    with open(json_file) as json_input:
        input_dict = json.load(json_input)
    mandatory_keys = ['username','scan_dict','out_dir','sessions','session_labels','project','subjects','password','scans']

    #are there any inputs in the json_file that are not supported?
    extra_inputs = list(set(input_dict.keys()) - set(mandatory_keys))
    if extra_inputs:
        print('option(s) not supported: %s' % str(extra_inputs))

    #are there missing mandatory inputs?
    missing_inputs = list(set(mandatory_keys) - set(input_dict.keys()))
    if missing_inputs:
        print('option(s) need to be specified in input file: %s' % str(missing_inputs))
        return 1

    return input_dict







def run_xnat():
    """Command line entry point."""
    print('start here!')
    args = parse_cmdline(sys.argv[1:])
    input_dict = parse_json(args.input_json)
    #assign variables to save space
    username = input_dict['username']
    password = input_dict['password']
    out_dir = input_dict['out_dir'] #not sure if this is needed
    project = input_dict['project']
    subjects = input_dict['subjects']
    session_labels = input_dict['session_labels']
    sessions = input_dict['sessions']
    scans = input_dict['scans']
    scan_dict = input_dict['scan_dict']
    base_dir = input_dict['out_dir']


    #create my session for xnat
    xnat_session = xnat_init_session(username,password,project)

    #log in to my session
    xnat_session.login()

    #get the list of subjects
    subject_query = xnat_query_subjects(xnat_session.cookie,xnat_session.url_base,project)
    subject_query.get_subjects()

    if subjects != "ALL": #if the subject list specifies who to download
      missing_xnat_subjects = list(set(subjects) - set([int(x) for x in subject_query.subject_ids.keys()]))

      if missing_xnat_subjects:
        subjects = list(set(subjects) - set(missing_xnat_subjects))
        print('xnat does not have data for these subjects: %s' % str(missing_xnat_subjects))
    else:
        subjects = [int(x) for x in subject_query.subject_ids.keys()] #use all the subjects otherwise


    for subject in subjects:
        session_query = xnat_query_sessions(xnat_session.cookie,xnat_session.url_base,project,subject)
        if session_labels == "None":
            print('no session labels, assuming there is only one session')
            session_labels_dummy=['dummy_session']
            subject_sessions = session_query.get_sessions(session_labels_dummy)
        else:
            session_query.get_sessions(session_labels)
            xnat_sessions = session_query.session_ids
            #example output
            # [sub140_session_query.session_ids[x].keys()[0] for x in sub140_session_query.session_ids.keys()]
            # ['post', 'pre']
            #sessions = [session_query.session_ids[x].keys()[0] for x in session_query.session_ids.keys()]
            if sessions != "ALL":
                #find all session that are not a part of the list
                pop_list=list(set(xnat_sessions.keys()) - set(sessions))
                for key in pop_list:
                    xnat_sessions.pop(key) #remove session from analysis
            subject_sessions = xnat_sessions
            subject_query.subject_ids[subject] = subject_sessions
        for session in subject_sessions: #where session is pre, post, etc
            #how to get the actual number which the session is loaded in xnat
            session_date = subject_sessions[session].keys()[0]
            scan_query = xnat_query_scans(xnat_session.cookie,xnat_session.url_base,project,subject,session_date)
            scan_query.get_scans()
            subject_sessions[session] = scan_query.scan_ids
            for scan in scan_query.scan_ids:
                #scan names are listed as a set type for some reason...
                #making it a list type to access scan name as a string.
                scan_name=list(scan_query.scan_ids[scan][0])[0]
                scan_usable=scan_ids['10'][1]
                #check to see if you defined the scan name (equivalent to scan type in
                # the REST API in the input json file)
                if scan_name in list(scan_dict) and scan_usable == 'usable':
                    BIDs_scan=scan_dict[scan_name]
                    #outdir without session: out_dir=base_dir+'sub-%s/%s/dcms/%s_%s' % (subject,BIDs_scan,scan,scan_name)
                    if session_labels == "None":
                        out_dir = base_dir+'sub-%s/%s/%s_%s' % (subject, BIDs_scan, scan, scan_name)
                    else:
                        out_dir = base_dir+'sub-%s/ses-%s/%s/%s_%s' % (subject, session, BIDs_scan, scan, scan_name)
                    if not os.path.exists(out_dir):
                        os.makedirs(out_dir)
                    dicom_query = xnat_query_dicoms(xnat_session.cookie,xnat_session.url_base,project,subject,session_date,scan)
                    dicom_query.get_dicoms(out_dir)

if __name__ == "__main__":
    import sys
    run_xnat()
