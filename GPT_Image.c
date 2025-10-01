#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <uchar.h>
#include <string.h>
#include <inttypes.h>

typedef struct{
    uint32_t time_lo;
    uint16_t time_mid;
    uint16_t time_hi_and_ver;
    uint8_t  clock_seq_hi_and_res;
    uint8_t  clock_seq_lo;
    uint8_t  node[6];
} __attribute__((packed)) GUID;

    typedef struct{
        uint8_t boot_indicator;
        uint8_t starting_chs[3];
        uint8_t os_type;
        uint8_t ending_chs[3];
        uint32_t starting_lba;
        uint32_t size_lba;
    } __attribute__((packed)) MBR_PARTITION;

    typedef struct{
        uint8_t boot_code[440];
        uint32_t mbr_signature;
        uint16_t unknown;
        MBR_PARTITION partition[4];
        uint16_t boot_signature;    
    } __attribute__((packed)) MASTER_BOOT_RECORD;

typedef struct{
    uint8_t signature[8];
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved_1;
    uint64_t my_lba;
    uint64_t alternate_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    GUID     disk_guid;
    uint64_t partition_table_lba;
    uint32_t number_of_entries;
    uint32_t size_of_entry;
    uint32_t partition_table_crc32;
    
    uint8_t reserved_2[512-92];
} __attribute__((packed)) GPT_Header;

    typedef struct{
        GUID partition_type_guid;
        GUID unique_guid;
        uint64_t starting_lba;
        uint64_t ending_lba;
        uint64_t attributes;
        char16_t name[36];      //UCS-2
    } __attribute__((packed)) GPT_Partition_Entry;

typedef struct{
    uint8_t  BS_jmpBoot[3];
    uint8_t  BS_OEMName[8];
    uint16_t BPB_BytsPerSec;
    uint8_t  BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t  BPB_NumFATs;
    uint16_t BPB_RootEntCnt;
    uint16_t BPB_TotSec16;
    uint8_t  BPB_Media;
    uint16_t BPB_FATSz16;
    uint16_t BPB_SecPerTrk;
    uint16_t BPB_NumHeads;
    uint32_t BPB_HiddSec;
    uint32_t BPB_TotSec32;
    uint32_t BPB_FATSz32;
    uint16_t BPB_ExtFlags;
    uint16_t BPB_FSVer;
    uint32_t BPB_RootClus;
    uint16_t BPB_FSInfo;
    uint16_t BPB_BkBootSec;
    uint8_t  BPB_Reserved[12];
    uint8_t  BS_DrvNum;
    uint8_t  BS_Reserved1;
    uint8_t  BS_BootSig;
    uint8_t  BS_VolID[4];
    uint8_t  BS_VolLab[11];
    uint8_t  BS_FilSysType[8];

    uint8_t  boot_code[510-90];  // Bootloader stub (legacy BIOS)
    uint16_t bootsector_sig;     // 0xAA55
} __attribute__((packed)) VBR;

    typedef struct{
        uint32_t FSI_LeadSig;
        uint8_t  FSI_Reserved1[480];
        uint32_t FSI_StrucSig;
        uint32_t FSI_Free_Count;
        uint32_t FSI_Nxt_Free;
        uint8_t  FSI_Reserved2[12];
        uint32_t FSI_TrailSig;
    } __attribute__ ((packed)) FSInfo;

typedef struct {
    uint8_t  DIR_Name[11];
    uint8_t  DIR_Attr;
    uint8_t  DIR_NTRes;
    uint8_t  DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
} __attribute__ ((packed)) FAT32_DIR_ENTRY;

    typedef enum{
        ATTR_READ_ONLY = 0x01,
        ATTR_HIDDEN    = 0x02,
        ATTR_SYSTEM    = 0x04,
        ATTR_VOLUME_ID = 0x08,
        ATTR_DIRECTORY = 0x10,
        ATTR_ARCHIVE   = 0x20,
        ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN |
                         ATTR_SYSTEM    | ATTR_VOLUME_ID       
    }FAT32_DIR_ATTR;

    typedef enum{
        TYPE_DIR,
        TYPE_FILE
    }File_Type;

typedef struct {
    uint8_t cookie[8];
    uint8_t features[4];
    uint8_t version[4];
    uint64_t data_offset;
    uint8_t timestamp[4];
    uint8_t creator_app[4];
    uint8_t creator_ver[4];
    uint8_t creator_OS[4];
    uint8_t original_size[8];
    uint8_t current_size[8];
    uint8_t disk_geometry[4];
    uint8_t disk_type[4];
    uint8_t checksum[4];
    Guid unique_id;
    uint8_t saved_state;
    uint8_t reserved[427];
} __attribute__ ((packed)) VHD;


typedef struct{
    char        *image_name;
    uint32_t    lba_size;
    uint32_t    esp_size;
    uint32_t    data_size;  
    char        **esp_file_paths;
    uint32_t    num_esp_file_paths;
    char        **data_files;
    uint32_t    num_data_files;
    bool        vhd;
    bool        help;
    bool        error;
}Options;

const GUID ESP_GUID = {0xC12A7328, 0xF81F, 0x11D2, 0xBA, 0x4B,
    {0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};

const GUID BASIC_DATA_GUID = {0xEBD0A0A2, 0xB9E5, 0x4433, 0x87, 0xC0, 
    {0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}} ;

enum{
    GPT_TABLE_ENTRY_SIZE = 128,
    NUMBER_OF_GPT_TABLE_ENTRIES = 128,
    GPT_TABLE_SIZE = 16384,     //As per UEFI Spec
ALIGNMENT = 1048576
};

char *image_name = "BOOT_IMAGE.img";

    uint64_t lba_size = 512;
    uint64_t esp_size = 1024*1024*33;
    uint64_t data_size = 1024*1024*1;
    uint64_t image_size = 0;
    uint64_t esp_size_lbas = 0, data_size_lbas = 0, image_size_lbas = 0,
             gpt_table_lbas = 0;
    uint64_t align_lba = 0, esp_lba = 0, data_lba = 0,
             fat32_fats_lba = 0, fat32_data_lba = 0;

inline uint64_t bytes_to_lbas(const uint64_t bytes){
    return (bytes / lba_size) + (bytes % lba_size > 0 ? 1 : 0);
}

void padding_lba(FILE *image){
    uint8_t zero_sector[512] = { 0 };
        for(uint8_t i = 0; i < (lba_size - sizeof(zero_sector)) / sizeof(zero_sector); i++){
            fwrite(zero_sector, sizeof(zero_sector), 1, image);
        }
}

uint64_t alignment_lba( const uint64_t lba){
    return lba - (lba % align_lba) + align_lba;
}

GUID new_guid(void){
    uint8_t rand_arr[16] = { 0 };

        for(uint8_t i = 0; i < sizeof(rand_arr); i++){
            rand_arr[i] = rand() % (UINT8_MAX + 1) ;
        }
    
     GUID result = {
            .time_lo = *(uint32_t *)&rand_arr[0],
            .time_mid = *(uint16_t *)&rand_arr[4],
            .time_hi_and_ver = *(uint16_t *)&rand_arr[6],
            .clock_seq_hi_and_res = rand_arr[8],
            .clock_seq_lo = rand_arr[9],
            .node = { rand_arr[10], rand_arr[11], rand_arr[12], rand_arr[13],
                      rand_arr[14],rand_arr[15] }
        };
        
            result.time_hi_and_ver &= ~(1 << 15);
            result.time_hi_and_ver |=  (1 << 14);
            result.time_hi_and_ver &= ~(1 << 13);
            result.time_hi_and_ver &= ~(1 << 12);

            result.clock_seq_hi_and_res |= (1 << 7);
            result.clock_seq_hi_and_res |= (1 << 6); 
            result.clock_seq_hi_and_res &= ~(1 << 5);

    return result;
}

    uint32_t crc32_table[256];

void create_crc32_table(void){
    uint32_t c = 0;

    for(int32_t n = 0; n < 256; n++){
        c = (uint32_t)n;
        for(uint8_t k = 0; k < 8; k++){
            if(c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc32_table[n] = c;
    }
}

uint32_t calculate_crc32(void *buf, int32_t len){
    static bool made_crc_table = false;
    
        uint8_t *bufp = buf;
        uint32_t c = 0xFFFFFFFFL;

        if(!made_crc_table){
            create_crc32_table();
            made_crc_table = true;
        }
        for(int32_t n = 0; n < len; n++){
            c = crc32_table[(c ^ bufp[n]) & 0xFF] ^ (c >> 8);
        }
    return c ^ 0xFFFFFFFFL;
}

void get_fat_dir_entry_time_date(uint16_t *in_time, uint16_t *in_date){
    time_t curr_time;
    curr_time = time(NULL);

        struct tm tm  = *localtime(&curr_time);
        *in_date = ((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday;

        if(tm.tm_sec == 60) tm.tm_sec = 59;
        *in_time = tm.tm_hour << 11 | tm.tm_min << 5 | (tm.tm_sec / 2);
}

bool write_protective_mbr(FILE *image){
    uint64_t mbr_image_lbas = image_size_lbas;
    if(mbr_image_lbas > 0xFFFFFFFF) mbr_image_lbas = 0x100000000;

    MASTER_BOOT_RECORD MBR = {
        .boot_code = { 0 },
        .mbr_signature = 0,
        .unknown = 0,
        .partition[0] = {
            .boot_indicator = 0,
            .starting_chs = { 0x00, 0x02, 0x00 },
            .os_type = 0xEE,  //Protective GPT
            .ending_chs = { 0xFF, 0xFF, 0xFF },
            .starting_lba = 0x00000001,
            .size_lba = mbr_image_lbas - 1,
        },
        .boot_signature = 0xAA55,
    };

    if(fwrite(&MBR, 1, sizeof(MBR), image) != sizeof(MBR))
        return false;

    padding_lba(image);

    return true;
}

bool write_gpt(FILE *image){
    GPT_Header primary_gpt = {
        .signature = { "EFI PART" },
        .revision = 0x00010000,
        .header_size = 92, 
        .header_crc32 = 0, //Written Below
        .reserved_1 = 0,
        .my_lba = 1,
        .alternate_lba = image_size_lbas - 1,
        .first_usable_lba = 1 + 1 + gpt_table_lbas,
        .last_usable_lba = image_size_lbas - 1 - gpt_table_lbas - 1,
        .disk_guid = new_guid(),
        .partition_table_lba = 2,
        .number_of_entries = 128,
        .size_of_entry = 128,
        .partition_table_crc32 = 0, //Written Below
        .reserved_2 = { 0 },
    };

    GPT_Partition_Entry GPT_Table[NUMBER_OF_GPT_TABLE_ENTRIES] = {
            //ESP
        {
            .partition_type_guid = ESP_GUID,
            .unique_guid = new_guid(),
            .starting_lba = align_lba,
            .ending_lba = esp_lba + esp_size_lbas,
            .attributes = 0,
            .name = u"EFI SYSTEM"
        },
            //BDP
        {
            .partition_type_guid = BASIC_DATA_GUID,
            .unique_guid = new_guid(),
            .starting_lba = data_lba,
            .ending_lba = data_lba + data_size_lbas,
            .attributes = 0,
            .name = u"BASIC DATA"
        }
    };
    
        primary_gpt.partition_table_crc32 = calculate_crc32(GPT_Table, sizeof(GPT_Table));
        primary_gpt.header_crc32 = calculate_crc32(&primary_gpt, primary_gpt.header_size);

            if(fwrite(&primary_gpt, 1, sizeof(primary_gpt), image) != sizeof(primary_gpt))
                return false;

            padding_lba(image);

            if(fwrite(&GPT_Table, 1, sizeof(GPT_Table), image) != sizeof(GPT_Table))
                return false;
            
            GPT_Header secondary_gpt = primary_gpt;
            secondary_gpt.header_crc32 = 0;
            secondary_gpt.partition_table_crc32 = 0;
            secondary_gpt.my_lba = primary_gpt.alternate_lba;
            secondary_gpt.alternate_lba = primary_gpt.my_lba;
            secondary_gpt.partition_table_lba = image_size_lbas - 1 - gpt_table_lbas;


        secondary_gpt.partition_table_crc32 = calculate_crc32(GPT_Table, sizeof(GPT_Table));
        secondary_gpt.header_crc32 = calculate_crc32(&secondary_gpt, secondary_gpt.header_size);

        fseek(image, secondary_gpt.partition_table_lba * lba_size, SEEK_SET);
 
            if(fwrite(&GPT_Table, 1, sizeof(GPT_Table), image) != sizeof(GPT_Table))
                return false;

            if(fwrite(&secondary_gpt, 1, sizeof(secondary_gpt), image) != sizeof(secondary_gpt))
                return false;

            padding_lba(image);

    return true;
}

bool write_esp(FILE *image){
    const uint8_t reserved_sectors = 32;

VBR vbr = {
    .BS_jmpBoot = { 0xEB, 0x00, 0x90 },
    .BS_OEMName = { "NAS OS  "},
    .BPB_BytsPerSec = lba_size,
    .BPB_SecPerClus = 1,
    .BPB_RsvdSecCnt = reserved_sectors,
    .BPB_NumFATs = 2,
    .BPB_RootEntCnt = 0,
    .BPB_TotSec16 = 0,
    .BPB_Media = 0xF8,
    .BPB_FATSz16 = 0,
    .BPB_SecPerTrk = 0,
    .BPB_NumHeads =0,
    .BPB_HiddSec = esp_lba - 1,
    .BPB_TotSec32 = esp_size_lbas,
    .BPB_FATSz32 = (align_lba - reserved_sectors) / 2,
    .BPB_ExtFlags = 0,
    .BPB_FSVer = 0,
    .BPB_RootClus = 2,
    .BPB_FSInfo = 1,
    .BPB_BkBootSec = 6,
    .BPB_Reserved = { 0 },
    .BS_DrvNum = 0x80,
    .BS_Reserved1 = 0,
    .BS_BootSig = 0x29,
    .BS_VolID = { 0 },
    .BS_VolLab = { "NO NAME    "},
    .BS_FilSysType = {"FAT32   "},

    .boot_code = { 0 },
    .bootsector_sig = 0xAA55
};

    FSInfo fsinfo = {
        .FSI_LeadSig = 0x41615252,
        .FSI_Reserved1 = { 0 },
        .FSI_StrucSig = 0x61417272,
        .FSI_Free_Count = 0xFFFFFFFF,
        .FSI_Nxt_Free = 5,
        .FSI_Reserved2 = { 0 },
        .FSI_TrailSig = 0xAA550000
    };

fat32_fats_lba = esp_lba + vbr.BPB_RsvdSecCnt;
fat32_data_lba = fat32_fats_lba + (vbr.BPB_NumFATs * vbr.BPB_FATSz32);

    fseek(image, esp_lba * lba_size, SEEK_SET);

        if(fwrite(&vbr, 1, sizeof(vbr), image) != sizeof(vbr)){
            fprintf(stderr,"Error: could not write _vbr_ to disk\n");
            return false;
        }

    padding_lba(image);

    if(fwrite(&fsinfo, 1, sizeof(fsinfo), image) != sizeof(fsinfo)){
        fprintf(stderr,"Error: could not write FAT32 info sector to image\n");
        return false;
    }

    padding_lba(image);

    fseek(image, (esp_lba + vbr.BPB_BkBootSec) * lba_size, SEEK_SET);  
    fseek(image, esp_lba * lba_size, SEEK_SET);
     
        if(fwrite(&vbr, 1, sizeof(vbr), image) != sizeof(vbr)){
            fprintf(stderr,"Error: could not write _vbr_ to disk\n");
            return false;
        }
    
    padding_lba(image); 

    
    if(fwrite(&fsinfo, 1, sizeof(fsinfo), image) != sizeof(fsinfo)){
        fprintf(stderr,"Error: could not write FAT32 info sector to image\n");
        return false;
    }

    padding_lba(image);

        for(uint8_t i = 0; i < vbr.BPB_NumFATs; i++){
            fseek(image, (fat32_fats_lba + (i * vbr.BPB_FATSz32)) * lba_size, SEEK_SET); 

            uint32_t cluster = 0;

            cluster = 0xFFFFFF00 | vbr.BPB_Media;
            fwrite(&cluster, sizeof(cluster), 1, image);

            cluster = 0xFFFFFFFF;
            fwrite(&cluster, sizeof(cluster), 1, image);

            cluster = 0xFFFFFFFF;
            fwrite(&cluster, sizeof(cluster), 1, image);

            cluster = 0xFFFFFFFF;
            fwrite(&cluster, sizeof(cluster), 1, image);

            cluster = 0xFFFFFFFF;
            fwrite(&cluster, sizeof(cluster), 1, image);
        }

    fseek(image, fat32_data_lba * lba_size, SEEK_SET);

        FAT32_DIR_ENTRY dir_ent = {
            .DIR_Name = { "EFI        "},
            .DIR_Attr = ATTR_DIRECTORY,             
            .DIR_NTRes = 0,
            .DIR_CrtTimeTenth = 0,
            .DIR_CrtTime = 0,
            .DIR_CrtDate = 0,
            .DIR_LstAccDate = 0,
            .DIR_FstClusHI = 0,
            .DIR_WrtTime = 0,
            .DIR_WrtDate = 0,
            .DIR_FstClusLO = 3,
            .DIR_FileSize = 0,
        };

    uint16_t create_time = 0, create_date = 0;
    get_fat_dir_entry_time_date(&create_time, &create_date);

    dir_ent.DIR_CrtTime = create_time;
    dir_ent.DIR_CrtDate = create_date;
    dir_ent.DIR_WrtTime = create_time;
    dir_ent.DIR_WrtDate = create_date;

    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    fseek(image, (fat32_data_lba + 1) * lba_size, SEEK_SET);
    memcpy(dir_ent.DIR_Name, ".          ", 11); 
    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    memcpy(dir_ent.DIR_Name, "..         ", 11);
    dir_ent.DIR_FstClusLO = 0;
    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    memcpy(dir_ent.DIR_Name, "BOOT       ", 11);
    dir_ent.DIR_FstClusLO = 4;
    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    fseek(image, (fat32_data_lba + 2) * lba_size, SEEK_SET); 
    memcpy(dir_ent.DIR_Name, ".          ", 11); 
    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    memcpy(dir_ent.DIR_Name, "..         ", 11);
    dir_ent.DIR_FstClusLO = 3;
    fwrite(&dir_ent, sizeof(dir_ent), 1, image);

    return true;
}
bool add_file_to_esp(char *file_name, FILE *image, File_Type type, uint32_t *parent_dir_cluster) {

    // First grab FAT32 filesystem info for VBR and File System info

    VBR vbr = { 0 };

    fseek(image, esp_lba * lba_size, SEEK_SET);

    fread(&vbr, sizeof vbr, 1, image);



    FSInfo fsinfo = { 0 };

    fseek(image, (esp_lba + 1) * lba_size, SEEK_SET);

    fread(&fsinfo, sizeof fsinfo, 1, image);



    // Get file size if file

    FILE *new_file = NULL;

    uint64_t file_size_bytes = 0, file_size_lbas = 0;

    if (type == TYPE_FILE) {

        new_file = fopen(file_name, "rb");

        if (!new_file) return false;



        fseek(new_file, 0, SEEK_END);

        file_size_bytes = ftell(new_file);

        file_size_lbas = bytes_to_lbas(file_size_bytes);

        rewind(new_file);

    }



    // Get next free cluster in FATs

    uint32_t next_free_cluster = fsinfo.FSI_Nxt_Free;

    const uint32_t starting_cluster = next_free_cluster;  // Starting cluster for new dir/file



    // Add new clusters to FATs

    for (uint8_t i = 0; i < vbr.BPB_NumFATs; i++) {

        fseek(image, (fat32_fats_lba + (i * vbr.BPB_FATSz32)) * lba_size, SEEK_SET);

        fseek(image, next_free_cluster * sizeof next_free_cluster, SEEK_CUR);



        uint32_t cluster = fsinfo.FSI_Nxt_Free;

        next_free_cluster = cluster;

        if (type == TYPE_FILE) {

            for (uint64_t lba = 0; lba < file_size_lbas - 1; lba++) {

                cluster++;  // Each cluster points to next cluster of file data

                next_free_cluster++;

                fwrite(&cluster, sizeof cluster, 1, image);

            }

        }



        // Write EOC marker cluster, this would be the only cluster added for a directory

        //   (type == TYPE_DIR)

        cluster = 0xFFFFFFFF;

        next_free_cluster++;

        fwrite(&cluster, sizeof cluster, 1, image);

    }



    // Update next free cluster in FS Info

    fsinfo.FSI_Nxt_Free = next_free_cluster;

    fseek(image, (esp_lba + 1) * lba_size, SEEK_SET);

    fwrite(&fsinfo, sizeof fsinfo, 1, image); 



    // Go to Parent Directory's data location in data region

    fseek(image, (fat32_data_lba + *parent_dir_cluster - 2) * lba_size, SEEK_SET);



    // Add new directory entry for this new dir/file at end of current dir_entrys 

    FAT32_DIR_ENTRY dir_entry = { 0 };



    fread(&dir_entry, 1, sizeof dir_entry, image);

    while (dir_entry.DIR_Name[0] != '\0')

        fread(&dir_entry, 1, sizeof dir_entry, image);



    // sizeof dir_entry = 32, back up to overwrite this empty spot

    fseek(image, -32, SEEK_CUR);    



    // Check name length for FAT 8.3 naming

    const char *dot_pos = strchr(file_name, '.');

    const uint32_t name_len = strlen(file_name);

    if ((!dot_pos && name_len > 11) || 

        (dot_pos && name_len > 12)  || 

        (dot_pos && dot_pos - file_name > 8)) {

        return false;   // Name is too long or invalid

    }



    // Convert name to FAT 8.3 naming

    // e.g. "FOO.BAR"  -> "FOO     BAR",

    //      "BA.Z"     -> "BA      Z  ",

    //      "ELEPHANT" -> "ELEPHANT   "

    memset(dir_entry.DIR_Name, ' ', 11);    // Start with all spaces, name/ext will be space padded



    if (dot_pos) {

        uint8_t i = 0;

        // Name 8 portion of 8.3

        for (i = 0; i < (dot_pos - file_name); i++)

            dir_entry.DIR_Name[i] = file_name[i];



        uint8_t j = i;

        while (i < 8) dir_entry.DIR_Name[i++] = ' ';



        if (file_name[j] == '.') j++;   // Skip dot to get to extension



        // Extension 3 portion of 8.3

        while (file_name[j])

            dir_entry.DIR_Name[i++] = file_name[j++];



        while (i < 11) dir_entry.DIR_Name[i++] = ' ';

    } else {

        memcpy(dir_entry.DIR_Name, file_name, name_len);

    }



    if (type == TYPE_DIR) 

        dir_entry.DIR_Attr = ATTR_DIRECTORY;



    uint16_t fat_time, fat_date;

    get_fat_dir_entry_time_date(&fat_time, &fat_date);

    dir_entry.DIR_CrtTime = fat_time;

    dir_entry.DIR_CrtDate = fat_date;

    dir_entry.DIR_WrtTime = fat_time;

    dir_entry.DIR_WrtDate = fat_date;



    dir_entry.DIR_FstClusHI = (starting_cluster >> 16) & 0xFFFF;

    dir_entry.DIR_FstClusLO = starting_cluster & 0xFFFF;



    if (type == TYPE_FILE)

        dir_entry.DIR_FileSize = file_size_bytes;



    fwrite(&dir_entry, 1, sizeof dir_entry, image);



    // Go to this new file's cluster's data location in data region

    fseek(image, (fat32_data_lba + starting_cluster - 2) * lba_size, SEEK_SET);



    // Add new file data

    // For directory add dir_entrys for "." and ".."

    if (type == TYPE_DIR) {

        memcpy(dir_entry.DIR_Name, ".          ", 11);  // "." dir_entry; this directory itself

        fwrite(&dir_entry, 1, sizeof dir_entry, image);



        memcpy(dir_entry.DIR_Name, "..         ", 11);  // ".." dir_entry; parent directory

        dir_entry.DIR_FstClusHI = (*parent_dir_cluster >> 16) & 0xFFFF;

        dir_entry.DIR_FstClusLO = *parent_dir_cluster & 0xFFFF;

        fwrite(&dir_entry, 1, sizeof dir_entry, image);

    } else {

        // For file, add file data

        uint8_t *file_buf = calloc(1, lba_size);

        for (uint64_t i = 0; i < file_size_lbas; i++) {

            // In case last lba is less than a full lba in size, use actual bytes read

            //   to write file to disk image

            size_t bytes_read = fread(file_buf, 1, lba_size, new_file);

            fwrite(file_buf, 1, bytes_read, image);

        }

        free(file_buf);

    }



    // Set dir_cluster for new parent dir, if a directory was just added

    if (type == TYPE_DIR)

        *parent_dir_cluster = starting_cluster;



    return true;

}



// =============================

// Add a file path to the EFI System Partition;

//   will add new directories if not found, and

//   new file at end of path

// =============================

bool add_path_to_esp(char *path, FILE *image) {

    // Parse input path for each name

    if (*path != '/') return false; // Path must begin with root '/'



    File_Type type = TYPE_DIR;

    char *start = path + 1; // Skip initial slash

    char *end = start;

    uint32_t dir_cluster = 2;   // Next directory's cluster location; start at root



    // Get next name from path, until reached end of path for file to add

    while (type == TYPE_DIR) {

        while (*end != '/' && *end != '\0') end++;



        if (*end == '/') type = TYPE_DIR;

        else             type = TYPE_FILE;  // Reached end of path



        *end = '\0';    // Null terminate next name in case of directory



        // Search for name in current directory's file data (dIR_ENTRYFAT32_DIR_ENTRY dir_entry = { 0 };

        bool found = false;

        fseek(image, (fat32_data_lba + dir_cluster - 2) * lba_size, SEEK_SET);

        do {

            fread(&dir_entry, 1, sizeof dir_entry, image);

            if (!memcmp(dir_entry.DIR_Name, start, strlen(start))) {

                // Found name in directory, save cluster for last directory found

                dir_cluster = (dir_entry.DIR_FstClusHI << 16) | dir_entry.DIR_FstClusLO;

                found = true;

                break;

            }

        } while (dir_entry.DIR_Name[0] != '\0');



        if (!found) {


            // Add new directory or file to last found directory


            // Add new directory or file to last found directory;


            //   if new directory, update current directory cluster to check/use


            //   for next new files 

            if (!add_file_to_esp(start, image, type, &dir_cluster))

                return false;

        }



        *end++ = '/';

        start = end;

    }



    // Show info to user


    printf("Added '%s'\n", path);


    printf("Added '%s' to EFI System Partition\n", path);



    return true;

}
/*
bool add_file_to_esp(char *file_name, FILE *image, File_Type type, uint32_t *parent_dir_cluster) {
    VBR vbr = { 0 };
    fseek(image, esp_lba * lba_size, SEEK_SET);
    fread(&vbr, sizeof vbr, 1, image);

    FSInfo fsinfo = { 0 };
    fseek(image, (esp_lba + 1) * lba_size, SEEK_SET);
    fread(&fsinfo, sizeof fsinfo, 1, image);

    FILE *new_file = NULL;
    uint64_t file_size_bytes = 0, file_size_lbas = 0;
    if (type == TYPE_FILE) {
        new_file = fopen(file_name, "rb");
        if (!new_file) return false;

        fseek(new_file, 0, SEEK_END);
        file_size_bytes = ftell(new_file);
        file_size_lbas = bytes_to_lbas(file_size_bytes);
        rewind(new_file);
    }

    uint32_t next_free_cluster = fsinfo.FSI_Nxt_Free;
    const uint32_t starting_cluster = next_free_cluster;

    for (uint8_t i = 0; i < vbr.BPB_NumFATs; i++) {
        fseek(image, (fat32_fats_lba + (i * vbr.BPB_FATSz32)) * lba_size, SEEK_SET);
        fseek(image, next_free_cluster * sizeof next_free_cluster, SEEK_CUR);

        uint32_t cluster = fsinfo.FSI_Nxt_Free;
        next_free_cluster = cluster;
        if (type == TYPE_FILE) {
            for (uint64_t lba = 0; lba < file_size_lbas - 1; lba++) {
                cluster++;
                next_free_cluster++;
                fwrite(&cluster, sizeof cluster, 1, image);
            }
        }

        cluster = 0xFFFFFFFF;
        next_free_cluster++;
        fwrite(&cluster, sizeof cluster, 1, image);
    }

    fsinfo.FSI_Nxt_Free = next_free_cluster;
    fseek(image, (esp_lba + 1) * lba_size, SEEK_SET);
    fwrite(&fsinfo, sizeof fsinfo, 1, image); 

    fseek(image, (fat32_data_lba + *parent_dir_cluster - 2) * lba_size, SEEK_SET);

    FAT32_DIR_ENTRY dir_entry = { 0 };

    fread(&dir_entry, 1, sizeof dir_entry, image);
    while (dir_entry.DIR_Name[0] != '\0')
        fread(&dir_entry, 1, sizeof dir_entry, image);

    fseek(image, -32, SEEK_CUR);    

    const char *dot_pos = strchr(file_name, '.');
    const uint32_t name_len = strlen(file_name);
    if ((!dot_pos && name_len > 11) || 
        (dot_pos && name_len > 12)  || 
        (dot_pos && dot_pos - file_name > 8)) {
        return false;
    }
    
    memset(dir_entry.DIR_Name, ' ', 11);

    if (dot_pos) {
        uint8_t i = 0;
        for (i = 0; i < (dot_pos - file_name); i++)
            dir_entry.DIR_Name[i] = file_name[i];

        uint8_t j = i;
        while (i < 8) dir_entry.DIR_Name[i++] = ' ';

        if (file_name[j] == '.') j++;

        while (file_name[j])
            dir_entry.DIR_Name[i++] = file_name[j++];

        while (i < 11) dir_entry.DIR_Name[i++] = ' ';
    } else {
        memcpy(dir_entry.DIR_Name, file_name, name_len);
    }

    if (type == TYPE_DIR) 
        dir_entry.DIR_Attr = ATTR_DIRECTORY;

    uint16_t fat_time, fat_date;
    get_fat_dir_entry_time_date(&fat_time, &fat_date);
    dir_entry.DIR_CrtTime = fat_time;
    dir_entry.DIR_CrtDate = fat_date;
    dir_entry.DIR_WrtTime = fat_time;
    dir_entry.DIR_WrtDate = fat_date;

    dir_entry.DIR_FstClusHI = (starting_cluster >> 16) & 0xFFFF;
    dir_entry.DIR_FstClusLO = starting_cluster & 0xFFFF;

    if (type == TYPE_FILE)
        dir_entry.DIR_FileSize = file_size_bytes;

    fwrite(&dir_entry, 1, sizeof dir_entry, image);

    fseek(image, (fat32_data_lba + starting_cluster - 2) * lba_size, SEEK_SET);

    if (type == TYPE_DIR) {
        memcpy(dir_entry.DIR_Name, ".          ", 11);
        fwrite(&dir_entry, 1, sizeof dir_entry, image);

        memcpy(dir_entry.DIR_Name, "..         ", 11);
        dir_entry.DIR_FstClusHI = (*parent_dir_cluster >> 16) & 0xFFFF;
        dir_entry.DIR_FstClusLO = *parent_dir_cluster & 0xFFFF;
        fwrite(&dir_entry, 1, sizeof dir_entry, image);
    } else {
        uint8_t *file_buf = calloc(1, lba_size);
        for (uint64_t i = 0; i < file_size_lbas; i++) {
            size_t bytes_read = fread(file_buf, 1, lba_size, new_file);
            fwrite(file_buf, 1, bytes_read, image);
        }
        free(file_buf);
    }

    if (type == TYPE_DIR)
        *parent_dir_cluster = starting_cluster;

    return true;
}

bool add_path_to_esp(char *path, FILE *image){
    if (*path != '/') return false;

        File_Type type = TYPE_DIR;
        char *start = path + 1;
        char *end = start;
        uint32_t dir_cluster = 2;

while (type == TYPE_DIR) {
    while (*end != '/' && *end != '\0') end++;

    if (*end == '/') type = TYPE_DIR;
    else             type = TYPE_FILE;

    *end = '\0';

    FAT32_DIR_ENTRY dir_entry = { 0 };
    bool found = false;
    fseek(image, (fat32_data_lba + dir_cluster - 2) * lba_size, SEEK_SET);
    do {
        fread(&dir_entry, 1, sizeof dir_entry, image);
        if (!memcmp(dir_entry.DIR_Name, start, strlen(start))) {
            dir_cluster = (dir_entry.DIR_FstClusHI << 16) | dir_entry.DIR_FstClusLO;
            found = true;
            break;
        }
    } while (dir_entry.DIR_Name[0] != '\0');

    if (!found) {
        if (!add_file_to_esp(start, image, type, &dir_cluster)){
            printf("yaha ruka!");
            return false;
        }
    }

        *end++ = '/';
        start = end;
    }

        printf("Added '%s'\n", path);

    return true;        
}
*/
bool add_disk_image_info_file(FILE *image) {
    char *file_buf = calloc(1, lba_size);
    snprintf(file_buf, 
             lba_size,
             "DISK_SIZE=%"PRIu64"\n", 
             image_size);

    FILE *fp = fopen("DSKIMG.INF", "wb");
    if (!fp) return false;

    fwrite(file_buf, strlen(file_buf), 1, fp);
    fclose(fp);
    free(file_buf);

    char path[25] = { 0 };
    strcpy(path, "/EFI/BOOT/DSKIMG.INF");
    if (!add_path_to_esp(path, image)) return false;

    return true;
}

Options get_opts(int argc, char *argv[]) {



    Options options = { 0 };





    for (int i = 1; i < argc; i++) {


        if (!strcmp(argv[i], "-h") ||


            !strcmp(argv[i], "--help")) {


            // Print help text and exit


            options.help = true;


            return options;


        }





        if (!strcmp(argv[i], "-i") ||


            !strcmp(argv[i], "--image-name")) {


            // Set name of image, instead of using default name


            if (++i >= argc) {


                options.error = true;


                return options;


            }





            options.image_name = argv[i];


            continue;


        }





        if (!strcmp(argv[i], "-l") ||


            !strcmp(argv[i], "--lba-size")) {


            // Set size of lba/disk sector, instead of default 512 bytes


            if (++i >= argc) {


                options.error = true;


                return options;


            }





            options.lba_size = strtol(argv[i], NULL, 10);





            if (options.lba_size != 512  &&


                options.lba_size != 1024 &&


                options.lba_size != 2048 &&


                options.lba_size != 4096) {


                // Error: invalid LBA size


                fprintf(stderr, "Error: Invalid LBA size, must be one of 512/1024/2048/4096\n");


                options.error = true;


                return options;


            }





            // Enforce minimum size of ESP per LBA size


            if ((options.lba_size == 512  && options.esp_size < 33)  ||


                (options.lba_size == 1024 && options.esp_size < 65)  ||


                (options.lba_size == 2048 && options.esp_size < 129) ||


                (options.lba_size == 4096 && options.esp_size < 257)) {





                fprintf(stderr, "Error: ESP Must be a minimum of 33/65/129/257 MiB for "


                                "LBA sizes 512/1024/2048/4096 respectively\n");


                options.error = true;


                return options;


            }


            continue;


        }





        if (!strcmp(argv[i], "-es") ||


            !strcmp(argv[i], "--esp-size")) {


            // Set size of EFI System Partition in Megabytes (MiB)


            if (++i >= argc) {


                options.error = true;


                return options;


            }





            // Enforce minimum size of ESP per LBA size


            options.esp_size = strtol(argv[i], NULL, 10);


            if ((options.lba_size == 512  && options.esp_size < 33)  ||


                (options.lba_size == 1024 && options.esp_size < 65)  ||


                (options.lba_size == 2048 && options.esp_size < 129) ||


                (options.lba_size == 4096 && options.esp_size < 257)) {





                fprintf(stderr, "Error: ESP Must be a minimum of 33/65/129/257 MiB for "


                                "LBA sizes 512/1024/2048/4096 respectively\n");


                options.error = true;


                return options;


            }





            continue;


        }





        if (!strcmp(argv[i], "-ds") ||


            !strcmp(argv[i], "--data-size")) {


            // Set size of EFI System Partition in Megabytes (MiB)


            if (++i >= argc) {


                options.error = true;


                return options;


            }





            options.data_size = strtol(argv[i], NULL, 10);


            continue;


        }





        if (!strcmp(argv[i], "-ae") ||


            !strcmp(argv[i], "--add-esp-files")) {


            // Add files to the EFI System Partition


            if (i + 2 >= argc) {


                // Need at least 2 more args for path & file, for this to work


                fprintf(stderr, "Error: Must include at least 1 path and 1 file to add to ESP\n");


                options.error = true;


                return options;


            }





            // Allocate memory for file paths


            options.esp_file_paths = malloc(10 * sizeof(char *));


            const int MAX_FILES = 10;





            for (i += 1; i < argc && argv[i][0] != '-'; i++) {


                // Grab next 2 args, 1st will be path to add, 2nd will be file to add to path


                const int MAX_LEN = 256;


                options.esp_file_paths[options.num_esp_file_paths] = calloc(1, MAX_LEN);





                // Get path to add


                strncpy(options.esp_file_paths[options.num_esp_file_paths], 


                        argv[i], 


                        MAX_LEN-1);





                // Ensure path starts and ends with a slash '/'


                if ((argv[i][0] != '/') ||


                    (argv[i][strlen(argv[i]) - 1] != '/')) {


                    fprintf(stderr, 


                            "Error: All file paths to add to ESP must start and end with slash '/'\n");


                    options.error = true;


                    return options;


                }





                // Concat file to add to path


                i++;


                char *slash = strrchr(argv[i], '/');


                if (!slash) {


                    // Plain file name, no folder path


                    strncat(options.esp_file_paths[options.num_esp_file_paths], 


                            argv[i], 


                            MAX_LEN-1);


                } else {


                    // Get only last name in path, no folders 


                    strncat(options.esp_file_paths[options.num_esp_file_paths], 


                            slash + 1,  // File name starts after final slash


                            MAX_LEN-1);


                }





                if (++options.num_esp_file_paths == MAX_FILES) {


                    fprintf(stderr, 


                            "Error: Number of ESP files to add must be <= %d\n",


                            MAX_FILES);


                    options.error = true;


                    return options;


                }


            }





            // Overall for loop will increment i; in order to get next option, decrement here


            i--;    


            continue;


        }
        



        if (!strcmp(argv[i], "-ad") ||


            !strcmp(argv[i], "--add-data-files")) {


            // Add files to the Basic Data Partition


            // Allocate memory for file paths


            options.data_files = malloc(10 * sizeof(char *));


            const int MAX_FILES = 10;





            for (i += 1; i < argc && argv[i][0] != '-'; i++) {


                // Grab next 2 args, 1st will be path to add, 2nd will be file to add to path


                const int MAX_LEN = 256;


                options.data_files[options.num_data_files] = calloc(1, MAX_LEN);





                // Get path to add


                strncpy(options.data_files[options.num_data_files], 


                        argv[i], 


                        MAX_LEN-1);





                if (++options.num_data_files == MAX_FILES) {


                    fprintf(stderr, 


                            "Error: Number of Data Parition files to add must be <= %d\n",


                            MAX_FILES);





                    options.error = true;


                    return options;


                }


            }





            // Overall for loop will increment i; in order to get next option, decrement here


            i--;    


            continue;


        }





        if (!strcmp(argv[i], "-v") ||


            !strcmp(argv[i], "--vhd")) {


            // Add a fixed Virtual Hard Disk Footer to the disk image;


            //   will also change the suffix to .vhd





            options.vhd = true; 


            continue;


        }


    }





    return options;


}
    
int main(int argc, char *argv[]){

        FILE *image = NULL, *file_ptr = NULL;

    Options options = get_opts(argc, argv);
    if(options.error){
        return EXIT_FAILURE;
    }

    if(options.help){
        //To Do:
        return EXIT_SUCCESS;
    }

    if(options.image_name){
        image_name = options.image_name;
    }

    if(options.lba_size){
        lba_size = options.lba_size;
    }

    if(options.esp_size){

                if((lba_size == 512  && options.esp_size < 33) ||
                   (lba_size == 1024 && options.esp_size < 65) ||
                   (lba_size == 2048 && options.esp_size < 129) ||
                   (lba_size == 4096  && options.esp_size < 257)){
                    
                    fprintf(stderr, "Error: Invalid ESP value\n");
                    return EXIT_FAILURE;
                }

        esp_size = options.esp_size * ALIGNMENT;
    }

    if(options.data_size){
        data_size = options.data_size * ALIGNMENT;
    }
        
        gpt_table_lbas = GPT_TABLE_SIZE / lba_size;
    const uint64_t padding = (ALIGNMENT * 2 + (lba_size * ((gpt_table_lbas * 2) + 1 + 2)));    

        image_size = esp_size + data_size + padding;
        image_size_lbas = bytes_to_lbas(image_size);

        align_lba = ALIGNMENT / lba_size;
        esp_lba = align_lba;

        esp_size_lbas = bytes_to_lbas(esp_size);
        data_size_lbas = bytes_to_lbas(data_size);

        data_lba = alignment_lba(esp_lba + esp_size_lbas);

         image = fopen(image_name, "wb+");
            if(!image){
                fprintf(stderr, "Error: could not open file %s\n", image_name);
                return EXIT_FAILURE;
            }

            printf("IMAGE_NAME : %s\n"
                   "LBA_SIZE   : %"PRIu64"\n"
                   "ESP_SIZE   : %"PRIu64"MB\n"
                   "DATA_SIZE  : %"PRIu64"MB\n"
                   "PADDING    : %"PRIu64"MB\n"
                   "IMAGE_SIZE : %"PRIu64"MB\n",
                   image_name,
                   lba_size,
                   esp_size / ALIGNMENT,
                   data_size / ALIGNMENT, 
                   padding / ALIGNMENT,
                   image_size / ALIGNMENT);

        srand(time(NULL));

        if(!write_protective_mbr(image)){
            fprintf(stderr, "Error: could not write Protective MBR to the disk");
            fclose(image);
            return EXIT_FAILURE; 
        }
        
        if(!write_gpt(image)){
            fprintf(stderr, "Error: could not write GPT Table to the disk");
            fclose(image);
            return EXIT_FAILURE;
        }

        if(!write_esp(image)){
            fprintf(stderr, "Error: could not write ESP to the disk");
            fclose(image);
            return EXIT_FAILURE;
        }

    file_ptr = fopen("BOOTX64.EFI", "rb");
        if(file_ptr){
            fclose(file_ptr);

                char *path = calloc(1, 25);
                strcpy(path, "/EFI/BOOT/BOOTX64.EFI");

            if(!add_path_to_esp(path, image)){
                fprintf(stderr, "Error: could add file to the path '%s'\n", path);
                free(path);
            }
        }

         if (!add_disk_image_info_file(image)) 
        fprintf(stderr, "Error: Could not add disk image info file to '%s'\n", image_name);

    if(options.num_esp_file_paths > 0){
        for(uint32_t i = 0; i < options.num_esp_file_paths; i++){
            if(!add_path_to_esp(options.esp_file_paths[i], image)){
                fprintf(stderr, "Error: could not add %s to ESP\n",
                        options.esp_file_paths[i]);
                }
                free(options.esp_file_paths[i]);
            }
        free(options.esp_file_paths);
    }

    fclose(image);

    return EXIT_SUCCESS;
}
