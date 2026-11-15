"""Small bounded ELF32 little-endian ARM reader for the pinned offline files."""
import struct

class ELF32:
    def __init__(self,data):
        self.data=data
        if data[:7]!=b'\x7fELF\x01\x01\x01': raise ValueError('ELF32 LE required')
        h=struct.unpack_from('<HHIIIIIHHHHHH',data,16)
        typ,machine,version,entry,phoff,shoff,flags,ehsize,phent,phnum,shent,shnum,shstr=h
        if typ not in (2,3) or machine!=40 or ehsize!=52 or phent!=32 or shent!=40: raise ValueError('Unexpected ARM ELF header')
        self.type=typ
        self.programs=[struct.unpack('<IIIIIIII',self.read(phoff+i*phent,32)) for i in range(phnum)]
        headers=[struct.unpack('<IIIIIIIIII',self.read(shoff+i*shent,40)) for i in range(shnum)]
        names=self.read(headers[shstr][4],headers[shstr][5])
        self.sections=[]
        for x in headers:
            name=self.string(names,x[0]);self.sections.append({'name':name,'type':x[1],'flags':x[2],'address':x[3],
                'offset':x[4],'size':x[5],'link':x[6],'info':x[7],'align':x[8],'entry':x[9]})
        self.symbols={}
        for index,s in enumerate(self.sections):
            if s['type'] not in (2,11):continue
            if s['entry']!=16 or s['size']%16:raise ValueError('Symbol table width')
            st=self.sections[s['link']];strings=self.read(st['offset'],st['size']);items=[]
            for offset in range(s['offset'],s['offset']+s['size'],16):
                n,value,size,info,other,section=struct.unpack('<IIIBBH',self.read(offset,16))
                items.append({'name':self.string(strings,n),'value':value,'size':size,'info':info,'section':section})
            self.symbols[index]=items
    def read(self,offset,length):
        if offset<0 or length<0 or offset+length>len(self.data):raise ValueError('ELF read bounds')
        return self.data[offset:offset+length]
    @staticmethod
    def string(data,offset):
        end=data.find(b'\0',offset)
        if offset<0 or end<offset:raise ValueError('ELF string bounds')
        return data[offset:end].decode('ascii','replace')
