## xnat_BIDS
[![Build Status](https://travis-ci.org/HBClab/xnat_BIDS.svg?branch=master)](https://travis-ci.org/HBClab/xnat_BIDS)

## Purpose:
Downloads the xnat dicoms in a BIDs like format that make conversion into a nifti bids as painless as possible

## How To:
You do the painful work up front to specify what scans fit into what BIDs like scan (see example json). and make a subject csv containing additional subject information that you would like to be a part of the BIDs naming format (e.g. scanner type, group assignment, treatment/non-treatment). See the example folder for a basic description on how to format the inputs

## Call the Script
you can call the script from the command line by adding xnat_BIDS.py to your $PATH variable, and simply type:
```
> xnat_BIDS.py -i your_json.json
```
### Requirements
requests module

everything else should come with a standard python install

More documentation to come...
