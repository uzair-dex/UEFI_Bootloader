#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <uchar.h>

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

char *image_name = "Boot_Image";

    uint64_t lba_size = 512;
    uint64_t esp_size = 1024*1024*33;
    uint64_t data_size = 1024*1024*1;
    uint64_t image_size = 0;
    uint64_t esp_size_lbas = 0, data_size_lbas = 0, image_size_lbas = 0;
    uint64_t align_lba = 0, esp_lba = 0, data_lba = 0;

inline uint64_t bytes_to_lbas(const uint64_t bytes){
    return (bytes / lba_size) + (bytes % lba_size > 0 ? 1 : 0);
}

void padding_lba(FILE *image){
    uint8_t zero_sector[512];
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
        .first_usable_lba = 1 + 1 + 32,
        .last_usable_lba = image_size_lbas - 1 - 32 - 1,
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
            secondary_gpt.partition_table_lba = image_size_lbas - 1 - 32;


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

int main(void){

    FILE *image = fopen(image_name, "wb+");
    if(!image){
            fprintf(stderr, "Error: could not open file %s\n", image_name);
        return EXIT_FAILURE;
    }
        
    const uint64_t padding = (ALIGNMENT * 2 + (lba_size * 67));    

        image_size = esp_size + data_size + padding;
        image_size_lbas = bytes_to_lbas(image_size);

        align_lba = ALIGNMENT / lba_size;
        esp_lba = align_lba;

        esp_size_lbas = bytes_to_lbas(esp_size);
        data_size_lbas = bytes_to_lbas(data_size);

        data_lba = alignment_lba(esp_lba + esp_size_lbas);
    
        srand(time(NULL));

        if(!write_protective_mbr(image)){
            fprintf(stderr, "Error: could not write Protective MBR to the disk");
            return EXIT_FAILURE; 
        }
        
        if(!write_gpt(image)){
            fprintf(stderr, "Error: could not write GPT Table to the disk");
            return EXIT_FAILURE;
        }

    return EXIT_SUCCESS;
}
