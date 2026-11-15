/* Generated from frozen actual .71 payloads; exact SMBIOS source gate is mandatory. */
typedef struct {unsigned get_id,write_id,method;const char *id,*body,*sha;UN bytes;} INV71_ITEM;
static const char inv71_body_0[]="{\"Model\":\"ROG MAXIMUS Z790 HERO\",\"Manufacturer\":\"ASUS\",\"BiosVersion\":\"3107\",\"UUID\":\"9b296595-55eb-e689-5fd2-08bfb8eeda44\"}";
static const char inv71_body_1[]="{\"Id\":\"DevType1_CPU0\",\"Name\":\"DevType1_CPU0\",\"Socket\":\"LGA1700\",\"Manufacturer\":\"Intel(R) Corporation\",\"Model\":\"Intel(R) Core(TM) i9-14900KS\",\"ProcessorType\":\"CPU\",\"ProcessorArchitecture\":\"x86\",\"TotalCores\":24,\"TotalEnabledCores\":24,\"TotalThreads\":32,\"Status\":{\"State\":\"Enabled\"}}";
static const char inv71_body_2[]="{\"Id\":\"DevType2_DIMM0\",\"Name\":\"DevType2_DIMM0\",\"DeviceLocator\":\"Controller0-DIMM0\",\"Status\":{\"State\":\"Absent\"},\"CapacityMiB\":0}";
static const char inv71_body_3[]="{\"Id\":\"DevType2_DIMM1\",\"Name\":\"DevType2_DIMM1\",\"DeviceLocator\":\"Controller0-DIMM1\",\"Manufacturer\":\"G Skill Intl\",\"SerialNumber\":\"885E87F9\",\"PartNumber\":\"F5-6400J3239G32G\",\"Status\":{\"State\":\"Enabled\"},\"CapacityMiB\":32768,\"MemoryDeviceType\":\"DDR5\",\"MemoryType\":\"DRAM\",\"BusWidthBits\":64,\"DataWidthBits\":64,\"AllowedSpeedsMHz\":[4800],\"OperatingSpeedMhz\":4800}";
static const char inv71_body_4[]="{\"Id\":\"DevType2_DIMM2\",\"Name\":\"DevType2_DIMM2\",\"DeviceLocator\":\"Controller1-DIMM0\",\"Status\":{\"State\":\"Absent\"},\"CapacityMiB\":0}";
static const char inv71_body_5[]="{\"Id\":\"DevType2_DIMM3\",\"Name\":\"DevType2_DIMM3\",\"DeviceLocator\":\"Controller1-DIMM1\",\"Manufacturer\":\"G Skill Intl\",\"SerialNumber\":\"DB50F2F5\",\"PartNumber\":\"F5-6400J3239G32G\",\"Status\":{\"State\":\"Enabled\"},\"CapacityMiB\":32768,\"MemoryDeviceType\":\"DDR5\",\"MemoryType\":\"DRAM\",\"BusWidthBits\":64,\"DataWidthBits\":64,\"AllowedSpeedsMHz\":[4800],\"OperatingSpeedMhz\":4800}";
static const INV71_ITEM inv71_items[6]={{1,1,2,"",inv71_body_0,"6c8def8855be8a919d111111bc11b226a9eb540730525b35e68ba4effe1d6186",sizeof(inv71_body_0)-1},
{7,2,1,"DevType1_CPU0",inv71_body_1,"bf874208853feaa3ca3043384947fd7f5211d28c827a8c7f128028088d57f0d3",sizeof(inv71_body_1)-1},
{8,3,1,"DevType2_DIMM0",inv71_body_2,"72cbc4a85cc29a66cd987ca21e3631b05de434a1a62fed234d7afb91d6f16fec",sizeof(inv71_body_2)-1},
{9,3,1,"DevType2_DIMM1",inv71_body_3,"e59208caad2eb74e0e57de2ed34dd0e681bfc3b65ba3002fe841e219c2a8cded",sizeof(inv71_body_3)-1},
{10,3,1,"DevType2_DIMM2",inv71_body_4,"46da44c3d7b028b191c77cf749ebf2f54d4434550b4267a2b0fc34627ec3bcc6",sizeof(inv71_body_4)-1},
{11,3,1,"DevType2_DIMM3",inv71_body_5,"7e2deb9d80731f1447257b550d1034ad4a3cbfe0120e852caedc1db95df49558",sizeof(inv71_body_5)-1}};
static const char inv71_uuid[]="9b296595-55eb-e689-5fd2-08bfb8eeda44";
