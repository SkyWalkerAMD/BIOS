#include "lab.h"
#ifndef EXPECT_AUTO
#define EXPECT_AUTO 0
#endif
#define REQUIRE(c,t) do{if(!(c)){trace("FAIL:" t "\n");finish(0);return ERR(7);}trace("OK:" t "\n");}while(0)
ES EA efi_main(HANDLE self,ST*st){
 if(!st||!st->bs||!tcg())return ERR(3);trace("BOOT_FIXTURE_BEGIN\n");
 uint64_t phase=0;ES e=read_u64(st,(C16*)L"Lab1904Phase",&phase);REQUIRE((e==0||e==ERR(14))&&phase<=1,"phase valid");event("BOOT_PHASE",phase);
 LAB_PROTOCOL*p=0;e=st->bs->locate_protocol(&lab_guid,0,(void**)&p);
 if(EXPECT_AUTO){REQUIRE(!e&&p&&p->signature==LAB_SIGNATURE,"FV driver present before any LoadImage");REQUIRE(p->unlocked==0,"new boot starts locked");e=p->operation(p,1);REQUIRE(!e,"unlock fixture");}
 else {REQUIRE(e==ERR(14)&&p==0,"RAM driver absent before external load on every boot");HANDLE loader=0;e=start_file(st,self,(C16*)L"\\LOADER.EFI",&loader);REQUIRE(!e,"loader returned success");LOADED*li=0;e=st->bs->handle_protocol(loader,&loaded_guid,(void**)&li);REQUIRE(FAILED(e),"returning application unloaded");e=st->bs->locate_protocol(&lab_guid,0,(void**)&p);REQUIRE(!e&&p,"driver survives loader return");}
 REQUIRE(p->boot_counter==phase+1,"NVRAM boot counter persisted");REQUIRE(p->unlocked==1,"RAM session survived same boot");
 LOADED*driver=0;e=st->bs->handle_protocol(p->owner,&loaded_guid,(void**)&driver);REQUIRE(!e&&driver&&driver->code_type==3&&driver->data_type==4,"driver LoadedImage uses boot-service memory");
 HANDLE checker=0;e=start_file(st,self,(C16*)L"\\CHECKER.EFI",&checker);REQUIRE(!e,"second application calls resident driver");REQUIRE(p->calls==2,"call count survived across applications");
 e=p->operation(p,2);REQUIRE(!e&&!p->unlocked,"explicit session reset relocks fixture");
 LOADED*li=0;FS*fs=0;FILEP*root=0;FILEP*file=0;e=st->bs->handle_protocol(self,&loaded_guid,(void**)&li);REQUIRE(!e&&li,"boot LoadedImage");e=st->bs->handle_protocol(li->device,&fs_guid,(void**)&fs);REQUIRE(!e&&fs&&!fs->open_volume(fs,&root)&&root,"boot filesystem readable");
 e=root->open(root,&file,(C16*)L"\\LAB-LOG.TXT",0x8000000000000003ULL,0);event("BOOT_FILE_WRITE_OPEN",e);if(!e&&file){char msg[]="UEFI lab real file write\r\n";UN n=sizeof(msg)-1;REQUIRE(!file->write(file,&n,msg)&&n==sizeof(msg)-1,"file write");REQUIRE(!file->flush(file),"file flush");file->close(file);}root->close(root);
 e=write_u64(st,(C16*)L"Lab1904Phase",phase+1);REQUIRE(!e,"phase persisted via UEFI SetVariable");finish(1);return 0;
}
