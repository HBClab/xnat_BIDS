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
    1) better error checking
    2) add a log to write events to
    3) handle conditionals better
    4) find a better way to call the script instead of main()
    5) add json descriptors according to BIDs format. (not available in API)
    6) revise some ugly formating
    7) don't copy if already completed? (or just have user be cognizant?)
    8) parallelize the processing stream (e.g. get all the data first, then download)
    9) Make main more modular (add more methods/possibly classes)
    10) Fix error where if a subject has a alpha character in their name I can't filter the subject.
    11) Add conversion script?
"""

import requests
import os
import sys

__all__ = ['xnat_init_session','xnat_query_subjects','xnat_query_sessions','xnat_query_scans','xnat_query_dicoms','subject_variables_dictionary']

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
            self.cookie = {cookie_info.name : cookie_info.value}
        else:
            print('error')
            return 1


    #def logout(self):
    #    logout_query = requests.delete(self.url_base,self.cookie)

    #    if logout_query.ok:
    #        print('logout successful')
    #    else:
    #        print('logout unsuccessful')
    #        return 1


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

    def filter_subjects(self,subjects):
        import re
        #catch and remove subjects with characters in the name

        if subjects != "ALL": #if the subject list specifies who to download
            missing_xnat_subjects = list(set(subjects) - set([int(x) for x in self.subject_ids.keys()]))

            if missing_xnat_subjects:
                self.filt_subject_ids = dict.fromkeys(list(set(subjects) - set(missing_xnat_subjects)))
                print('xnat does not have data for these subjects: %s' % str(missing_xnat_subjects))
            else:
                self.filt_subject_ids = dict.fromkeys(subjects)
        else:
            self.filt_subject_ids = dict.fromkeys([int(x) for x in self.subject_ids.keys()]) #use all the subjects otherwise


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
                    self.session_ids = {}
                else:
                    self.session_ids = { sess_label : {sess_dict['label']: 0} for sess_label,sess_dict in zip(session_labels,session_list_dict) }
            else:
                #not supported in this script
                self.session_ids = { x['label']: 0 for x in session_list_dict }

    def filter_sessions(self,sessions):
        #updates the session_ids dictionary
        if sessions != "ALL":
            #find all session that are not a part of the list
            pop_list=list(set(self.session_ids.keys()) - set(sessions))
            for key in pop_list:
                self.session_ids.pop(key) #remove session from analysis


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
              self.scan_ids = { x['ID']:[{str(x['series_description']) },x['quality']] for x in scan_list_dict }
              #ID is a number like 1,3,300
              #type is a name like fMRI FLANKER, PU:Sag CUBE FLAIR, represented as a set?
              #^use series_description instead of type to differentiate multiple
              #scans as the same type (e.g. DTI 64 dir versus DTI extra B0)
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

class subject_variables_dictionary(object):
    def __init__(self,sub_vars):
        self.sub_dict = {}
        with open(sub_vars) as sub_file:
            for line in sub_file:
                sub_entry = line.strip('\n').split(',')
                self.sub_dict[sub_entry[0]] = sub_entry[1:]

    def get_bids_var(self,sub_num):
        #assume the sub_num is not zero-padded
        #assume the entries are not zero-padded
        return "".join(self.sub_dict[sub_num])

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
    mandatory_keys = ['username','scan_dict','dcm_dir','sessions','session_labels','project','subjects','scans']
    optional_keys = ['subject_variables_csv','zero_pad','nii_dir']
    total_keys = mandatory_keys.extend(optional_keys)
    #are there any inputs in the json_file that are not supported?
    extra_inputs = list(set(input_dict.keys()) - set(total_keys))
    if extra_inputs:
        print('option(s) not supported: %s' % str(extra_inputs))

    #are there missing mandatory inputs?
    missing_inputs = list(set(mandatory_keys) - set(input_dict.keys()))
    if missing_inputs:
        print('option(s) need to be specified in input file: %s' % str(missing_inputs))
        return 1

    return input_dict

def run_xnat():
    import getpass
    """Command line entry point."""
    args = parse_cmdline(sys.argv[1:])
    input_dict = parse_json(args.input_json)
    #assign variables to save space
    username = input_dict['username']
    nii_dir = input_dict['nii_dir'] #not sure if this is needed
    project = input_dict['project']
    subjects = input_dict['subjects']
    session_labels = input_dict['session_labels']
    sessions = input_dict['sessions']
    scans = input_dict['scans']
    scan_dict = input_dict['scan_dict']
    dcm_dir = input_dict['dcm_dir']
    #optional entries
    sub_vars = input_dict.get('subject_variables_csv', False)
    BIDs_num_length = input_dict.get('zero_pad', False)

    #make the BIDs subject dictionary
    if not sub_vars:
        sub_vars_dict = subject_variables_dictionary(sub_vars)

    #get the password
    password = getpass.getpass()

    #create my session for xnat
    xnat_session = xnat_init_session(username,password,project)

    #log in to my session
    xnat_session.login()

    #get the list of subjects
    subject_query = xnat_query_subjects(xnat_session.cookie,xnat_session.url_base,project)
    #gives the object subject_query the dictionary subject_ids
    subject_query.get_subjects()
    #gives the object subject_query the dictionary filt_subject_ids
    subject_query.filter_subjects(subjects)
    #assign subjects the filtered dictionary
    subjects = subject_query.filt_subject_ids
    #number to use to name BIDS outdir (e.g. 005 instead of 5)
    if not BIDs_num_length:
        BIDs_num_length = len(max([str(x) for x in list(subjects)],key=len))
    for subject in subjects:
        #workaround for xnat session closing
        #xnat_session.logout()
        #xnat_session.login()
        #^^potentially not necessary, test first

        session_query = xnat_query_sessions(xnat_session.cookie,xnat_session.url_base,project,subject)
        if session_labels == "None":
            print('no session labels, assuming there is only one session')
            session_labels_dummy=['dummy_session']
            session_query.get_sessions(session_labels_dummy)
        else:
            session_query.get_sessions(session_labels)
        #check to see if dictionary is empty
        if not bool(session_query.session_labels):
            #skip if there are no sessions
            continue
        #filtering the sessions
        session_query.filter_sessions(sessions)
        subject_sessions = session_query.session_ids
        #update the master subject dictionary
        subjects[subject] = subject_sessions
        for session in subject_sessions: #where session is pre, post, etc
            #getting the session folder name in xnat (e.g. 20150524)
            session_date = subject_sessions[session].keys()[0]
            #scan_query object
            scan_query = xnat_query_scans(xnat_session.cookie,xnat_session.url_base,project,subject,session_date)
            #makes a dictionary of scan ids
            scan_query.get_scans()
            subject_sessions[session] = scan_query.scan_ids
            for scan in scan_query.scan_ids:
                #scan names are listed as a set type for some reason...
                #making it a list type to access scan name as a string.
                scan_name=list(scan_query.scan_ids[scan][0])[0]
                scan_usable=list(scan_query.scan_ids[scan])[1]
                #check to see if you defined the scan name (equivalent to scan type in
                # the REST API in the input json file)
                if scan_name in list(scan_dict) and scan_usable == 'usable':
                    BIDs_scan = scan_dict[scan_name][0]
                    BIDs_scan_suffix = scan_dict[scan_name][0]
                    BIDs_subject=str(subject).zfill(BIDs_num_length)
                    if not sub_vars:
                        BIDs_subject_info = sub_vars_dict.get_bids_var(str(subject))
                        BIDs_subject = "".join(BIDs_subject_info,BIDs_subject)

                    scan_name_no_spaces = scan_name.replace(" ","_")
                    if session_labels == "None":
                        print('Downloading Dicoms[subject: %s, scan %s' % (str(subject), scan_name))
                        #sub_dir = 'sub-%s/%s/%s_%s' % (BIDs_subject, BIDs_scan, scan, scan_name_no_spaces)
                        sub_dir = 'sub-%s/%s/sub-%s_%s' % (BIDs_subject, BIDs_scan, BIDs_subject, BIDs_scan_suffix)
                    else:
                        print('Downloading Dicoms[subject: %s, session: %s, scan %s' % (str(subject), session, scan_name))
                        #sub_dir = 'sub-%s/ses-%s/%s/%s_%s' % (BIDs_subject, session, BIDs_scan, scan, scan_name_no_spaces)
                        sub_dir = 'sub-%s/ses-%s/%s/sub-%s_ses-%s_%s' % (BIDs_subject, session, BIDs_scan, BIDs_subject, session, BIDs_scan_suffix)
                    out_dir = os.path.join(dcm_dir,sub_dir)
                    if not os.path.exists(out_dir):
                        os.makedirs(out_dir)
                    dicom_query = xnat_query_dicoms(xnat_session.cookie,xnat_session.url_base,project,subject,session_date,scan)
                    dicom_query.get_dicoms(out_dir)
    #Conversion option here.
    #convert_to_nifti(nii_dir,dcm_dir,sub_dir)


#def convert_to_nifti(nii_dir,dcm_dir,sub_dir):


if __name__ == "__main__":
    import sys
    run_xnat()
