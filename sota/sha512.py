import hashlib 



class SOTA_Hasher():
    def __init__(self) -> None:
        pass
    
    def sha512(self,input):
        result = hashlib.sha512(input.encode()) 
        return result