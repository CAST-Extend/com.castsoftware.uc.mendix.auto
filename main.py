import os

from cast.analysers import create_link, CustomObject, Bookmark
from cast.analysers import log
import cast.analysers.ua
import traceback

import xml.etree.ElementTree as ET

class OmNextAnalysisLevel(cast.analysers.ua.Extension):
    
    def _init_(self):
        log.debug ('In __init__ ... ')

    def start_analysis(self):
        log.debug ('In start_analysis ...OMNEXT ' + str(os.listdir(os.curdir))) 
        log.info ('In start_analysis ... OMNEXT' + str(os.listdir(os.curdir))) 
        
    def start_file(self, file):
        log.info ('In start_file ... ' + str(file))
        artifact_dct = {}
        self.violation_dct = {}  # key - guid, value - [saved_obj, quality rule 1, quality rule 2, ...]
        self.artifact_links_dct = {}  # key - guid, value - [calltype, caller, callee]
        
        self.file_obj = file
        self.file_path = self.file_obj.get_path()
        artifact_dct["parent_obj"] = self.file_obj
        artifact_dct["fullname"] = self.file_path
        log.debug("File path ..: " + self.file_path + str(os.path.exists(self.file_path)))
        
        elm_root = ET.parse(self.file_path)
        for artfct_tag in elm_root.iter(tag='artifact'):
            link_type = ""
            callee = ""
            print(artfct_tag)
            artifact_dct["guid"] = artfct_tag.attrib["guid"]
            self.violation_dct[artfct_tag.attrib["guid"]] = []
            for attribs in artfct_tag:
                if attribs.tag == "type":
                    artifact_dct["type"] = attribs.text
                if attribs.tag == "typeValue":
                    artifact_dct["typeValue"] = attribs.text
                if attribs.tag == "ruleID":
                    self.violation_dct[artfct_tag.attrib["guid"]].append(attribs.text)  
                if attribs.tag == "instance":
                    link_type = attribs.attrib["instanceOf"]
                    for link in attribs:
                        print ('link tag: ', link)
                        callee = link.attrib["callee"]
#                         if callee == "%ProjectRoot%": # Commented as we will not use it
#                             callee = self.file_obj

            saved_obj = self.save_object(artifact_dct)
            self.violation_dct[artfct_tag.attrib["guid"]].insert(0, saved_obj) 
            self.artifact_links_dct[artifact_dct["guid"]] = [link_type, saved_obj, callee]
            
        log.info  ("final artifact_links_dct: " + str(self.artifact_links_dct))

    def end_analysis(self):
         
        log.info ('In end_analysis ... OMNEXT :: BEGIN')
        log.info("------------------------------ LINK CREATION : BEGIN ------------------------------")
        self.create_links()
        log.info("------------------------------ LINK CREATION : END ------------------------------")
        
        log.info("------------------------------ SAVING VIOLATION : BEGIN ------------------------------")
        self.save_violation()
        log.info("------------------------------ SAVING VIOLATION : END ------------------------------")
        log.info ('In end_analysis ... OMNEXT :: END')
        

                
#         bk = Bookmark(pfile, current_line, 1, current_line, 0)
#         pfile.save_violation('Mendix_CustomMetrics.AvoidExcessiveCrossModuleAssociations', bk)        
#             
            
    def save_object(self, artifact_dct):
        log.info ('In save_object:  ' + str(artifact_dct))

        log.info("Trying to save_object with =>Guid: "+ str(artifact_dct["guid"]) +"\nObject type: "+ str(artifact_dct["type"]) +"\nObject value: "+ str(artifact_dct["typeValue"]) +"\nObject path: "+ str(artifact_dct["fullname"]) +"\nParent Object: "+ str(artifact_dct["parent_obj"]) )
        
        omnxt_obj = CustomObject()
        omnxt_obj.set_name(artifact_dct["typeValue"])
        omnxt_obj.set_fullname(artifact_dct["fullname"])
        omnxt_obj.set_type(artifact_dct["type"])
        omnxt_obj.set_parent(artifact_dct["parent_obj"])
        omnxt_obj.set_guid(artifact_dct["guid"]) 
        omnxt_obj.save()
        
        log.info ('Object created successfully... ' + str(omnxt_obj))
        return omnxt_obj

       
    def save_violation(self):
        try:
            for key, val in self.violation_dct.items():
                if val[1:]:
                    for violation in val[1:]:
                        bk = Bookmark(self.file_obj, 1, 1, 1, 1)
                        log.info(str(val[0]))
                        log.info('Mendix_CustomMetrics.' + str(violation))
                        val[0].save_violation('Mendix_CustomMetrics.' + violation, bk)
                        log.info ('Violation saved ... ' + str(violation))
        except Exception as e:
            e = traceback.format_exc(e)
            print (str(e))
            log.info (str(e))
        
    
    def create_links(self):
        
        for guid, clr_cle_lst in self.artifact_links_dct.items():
            log.info ('GUID ...' + str(guid) + "  " + str(clr_cle_lst))
#             if clr_cle_lst[2] != "%ProjectRoot%" or clr_cle_lst[2] != "":
            if not clr_cle_lst[2] in ("%ProjectRoot%", ""):
                create_link("callLink", #clr_cle_lst[0],
                            clr_cle_lst[1],
                            self.artifact_links_dct[clr_cle_lst[2]][1])
            
                log.info ('Link created ...')
            
            
        
