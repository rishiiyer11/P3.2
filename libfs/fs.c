#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

// def 
#define BLOCK_SIZE 4096
#define FS_SIGNATURE "ECS150FS"
#define FAT_EOC 0xFFFF
#define MAX_FILENAME 16
#define MAX_FILE_COUNT 128
#define MAX_FD 32

// fd struct
struct fd {
    int open;
    char filename[MAX_FILENAME];
    size_t off;
};

// glob
static struct superblock *super = NULL;
static uint16_t *fat = NULL;
static struct root *rdir = NULL;
static int mount = 0;
static struct fd table[MAX_FD];

// def block structures
struct __attribute__((packed)) superblock {
	uint8_t sig[8];
	uint16_t totBlck;
    uint16_t rootInd;
    uint16_t dataBlckStart;
    uint16_t dataBlckCnt;
    uint8_t fatBlckCnt;
    uint8_t pad[4079];
};

struct __attribute__((packed)) FAT {
	uint8_t fileName[16];
    uint32_t fileSize;
    uint16_t firstBlck;
    uint8_t pad[10];
};

struct __attribute__((packed)) root {
	struct FAT ent[128];
};

int fs_mount(const char *disk)
{
	if (mount) {
        return -1;
    }

    if (block_disk_open(disk) < 0) {
        return -1;
    }

    super = malloc(sizeof(struct superblock));
    if (!super) {
        block_disk_close();
        return -1;
    }

    if (block_read(0, super) < 0) {
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    if (memcmp(super->sig, FS_SIGNATURE, 8) != 0) {
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    int blckCnt = block_disk_count();
    if (blckCnt < 0 || super->totBlck != blckCnt) {
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    size_t fatSize = super->fatBlckCnt * BLOCK_SIZE;
    fat = malloc(fatSize);
    if (!fat) {
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    for (int i = 0; i < super->fatBlckCnt; i++) {
        if (block_read(i + 1, (uint8_t*)fat + i * BLOCK_SIZE) < 0) {
            free(fat);
            fat = NULL;
            free(super);
            super = NULL;
            block_disk_close();
            return -1;
        }
    }

    rdir = malloc(sizeof(struct root));
    if (!rdir) {
        free(fat);
        fat = NULL;
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    if (block_read(super->rootInd, rdir) < 0) {
        free(rdir);
        rdir = NULL;
        free(fat);
        fat = NULL;
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    mount = 1;
    return 0;
}

int fs_umount(void)
{
    if (!mount) {
        return -1;
    }
    
    for (int i = 0; i < MAX_FD; i++) {
        if (table[i].open) {
            return -1; 
        }
    }

    for (int i = 0; i < super->fatBlckCnt; i++) {
        if (block_write(i + 1, (uint8_t*)fat + i * BLOCK_SIZE) < 0) {
            return -1;
        }
    }

    if (block_write(super->rootInd, rdir) < 0) {
        return -1;
    }

    free(rdir);
    rdir = NULL;
    free(fat);
    fat = NULL;
    free(super);
    super = NULL;

    if (block_disk_close() < 0) {
        return -1;
    }

    mount = 0;
    return 0;
}

int fs_info(void)
{
	if (!mount) {
        return -1;
    }

    int file_count = 0;
    for (int i = 0; i < 128; i++) {
        if (rdir->ent[i].fileName[0] != '\0') {
            file_count++;
        }
    }

    int free_blocks = 0;
    for (int i = 0; i < super->dataBlckCnt; i++) {
        if (fat[i] == 0) {
            free_blocks++;
        }
    }

    // print info
    printf("totBlckCnt=%d\n", super->totBlck);
    printf("fatBlckCnt=%d\n", super->fatBlckCnt);
    printf("rdirBlck=%d\n", super->rootInd);
    printf("dataBlck=%d\n", super->dataBlckStart);
    printf("dataBlckCnt=%d\n", super->dataBlckCnt);
    printf("fat/free=%d/%d\n", free_blocks, super->dataBlckCnt);
    printf("rdir/free=%d/%d\n", 128 - file_count, 128);

    return 0;
}

int fs_create(const char *filename)
{
    if (!mount) {
        return -1;
    }

    if (!filename) {
        return -1;
    }

    // check filename
    if (strlen(filename) >= MAX_FILENAME) {
        return -1;
    }

    // check filename empty
    if (strlen(filename) == 0) {
        return -1;
    }

    // check file exists
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            return -1;
        }
    }

    // find empty entry in root
    int emptyEnt = -1;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] == '\0') {
            emptyEnt = i;
            break;
        }
    }

    if (emptyEnt == -1) {
        return -1;
    }

    // init file entry
    memset(&rdir->ent[emptyEnt], 0, sizeof(struct FAT));
    strcpy((char*)rdir->ent[emptyEnt].fileName, filename);
    rdir->ent[emptyEnt].fileSize = 0;
    rdir->ent[emptyEnt].firstBlck = FAT_EOC;

    return 0;
}

int fs_delete(const char *filename)
{
    if (!mount) {
        return -1;
    }

    if (!filename) {
        return -1;
    }

    // find file in root
    int fileEnt = -1;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            fileEnt = i;
            break;
        }
    }

    if (fileEnt == -1) {
        return -1;
    }

    // free FAT data blocks
    uint16_t currBlck = rdir->ent[fileEnt].firstBlck;
    while (currBlck != FAT_EOC && currBlck != 0) {
        uint16_t nextBlck = fat[currBlck];
        
        // mark free
        fat[currBlck] = 0;
        currBlck = nextBlck;
    }

    // clear file entry in root
    memset(&rdir->ent[fileEnt], 0, sizeof(struct FAT));

    return 0;
}

int fs_ls(void)
{
    if (!mount) {
        return -1;
    }

    printf("FS Ls:\n");
    
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0') {
            printf("file: %s, size: %u, data_blk: %u\n",
                   rdir->ent[i].fileName,
                   rdir->ent[i].fileSize,
                   rdir->ent[i].firstBlck);
        }
    }

    return 0;
}

int fs_open(const char *filename)
{
    if (!mount) {
        return -1;
    }

    if (!filename) {
        return -1;
    }

    // check if exists
    int exists = 0;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            exists = 1;
            break;
        }
    }

    if (!exists) {
        return -1;
    }

    // find fd
    int fd = -1;
    for (int i = 0; i < MAX_FD; i++) {
        if (!table[i].open) {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        return -1;
    }

    // init fd
    table[fd].open = 1;
    strcpy(table[fd].filename, filename);
    table[fd].off = 0;

    return fd;
}

int fs_close(int fd)
{
    if (!mount) {
        return -1;
    }

    if (fd < 0 || fd >= MAX_FD || !table[fd].open) {
        return -1;
    }

    // clear fd
    table[fd].open = 0;
    memset(table[fd].filename, 0, MAX_FILENAME);
    table[fd].off = 0;

    return 0;
}

int fs_stat(int fd)
{
    if (!mount) {
        return -1;
    }

    if (fd < 0 || fd >= MAX_FD || !table[fd].open) {
        return -1;
    }

    // find file in root
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, table[fd].filename) == 0) {
            return rdir->ent[i].fileSize;
        }
    }

    return -1;
}

int fs_lseek(int fd, size_t off)
{
    if (!mount) {
        return -1;
    }

    if (fd < 0 || fd >= MAX_FD || !table[fd].open) {
        return -1;
    }

    // Find the file in root directory to get file size
    int size = -1;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, table[fd].filename) == 0) {
            size = rdir->ent[i].fileSize;
            break;
        }
    }

    if (size == -1) {
        return -1;
    }

    // check offset > size
    if (off > (size_t)size) {
        return -1;
    }

    table[fd].off = off;
    return 0;
}

static int find_data_block_for_offset(const char *filename, size_t offset) {
    if (!mount || !filename) {
        return -1;
    }
    
    struct FAT *file_entry = NULL;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            file_entry = &rdir->ent[i];
            break;
        }
    }
    
    if (!file_entry || file_entry->firstBlck == FAT_EOC) {
        return -1;
    }
    
    size_t target_block_num = offset / BLOCK_SIZE;
    
    uint16_t current_block = file_entry->firstBlck;
    for (size_t i = 0; i < target_block_num; i++) {
        if (current_block >= super->dataBlckCnt || fat[current_block] == FAT_EOC) {
            return -1; 
        }
        current_block = fat[current_block];
    }
    
    return current_block;
}

static int allocate_new_block(void) {
    if (!mount) {
        return -1;
    }
    
    for (int i = 0; i < super->dataBlckCnt; i++) {
        if (fat[i] == 0) {
            fat[i] = FAT_EOC; 
            return i;
        }
    }
    
    return -1; 
}

static int extend_file_chain(const char *filename) {
    if (!mount || !filename) {
        return -1;
    }
    
    struct FAT *file_entry = NULL;
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            file_entry = &rdir->ent[i];
            break;
        }
    }
    
    if (!file_entry) {
        return -1;
    }
    
    int new_block = allocate_new_block();
    if (new_block < 0) {
        return -1; 
    }
    
    if (file_entry->firstBlck == FAT_EOC) {
        file_entry->firstBlck = new_block;
        return new_block;
    }
    
    uint16_t current_block = file_entry->firstBlck;
    while (fat[current_block] != FAT_EOC) {
        if (current_block >= super->dataBlckCnt) {
            return -1; 
        }
        current_block = fat[current_block];
    }
    
    fat[current_block] = new_block;
    return new_block;
}

static struct FAT* get_file_entry(const char *filename) {
    if (!mount || !filename) {
        return NULL;
    }
    
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (rdir->ent[i].fileName[0] != '\0' && 
            strcmp((char*)rdir->ent[i].fileName, filename) == 0) {
            return &rdir->ent[i];
        }
    }
    
    return NULL;
}

int fs_read(int fd, void *buf, size_t count)
{
    if (!mount) {
        return -1;
    }
    
    if (fd < 0 || fd >= MAX_FD || !table[fd].open) {
        return -1;
    }
    
    if (!buf) {
        return -1;
    }
    
    struct FAT *file_entry = get_file_entry(table[fd].filename);
    if (!file_entry) {
        return -1;
    }
    
    size_t file_size = file_entry->fileSize;
    size_t offset = table[fd].off;
    
    if (offset >= file_size) {
        return 0; 
    }
    
    if (offset + count > file_size) {
        count = file_size - offset;
    }
    
    size_t bytes_read = 0;
    uint8_t *user_buf = (uint8_t*)buf;
    
    while (bytes_read < count) {
        int data_block_index = find_data_block_for_offset(table[fd].filename, 
                                                         offset + bytes_read);
        if (data_block_index < 0) {
            break; 
        }

        int real_block = super->dataBlckStart + data_block_index;
        
        size_t block_offset = (offset + bytes_read) % BLOCK_SIZE;
        
        size_t bytes_in_block = BLOCK_SIZE - block_offset;
        size_t bytes_to_read = (count - bytes_read < bytes_in_block) ? 
                               count - bytes_read : bytes_in_block;
        
        uint8_t bounce_buffer[BLOCK_SIZE];
        if (block_read(real_block, bounce_buffer) < 0) {
            return -1;
        }
        
        memcpy(user_buf + bytes_read, bounce_buffer + block_offset, bytes_to_read);
        bytes_read += bytes_to_read;
    }
    
    table[fd].off += bytes_read;
    
    return bytes_read;
}

int fs_write(int fd, void *buf, size_t count)
{
    if (!mount) {
        return -1;
    }
    
    if (fd < 0 || fd >= MAX_FD || !table[fd].open) {
        return -1;
    }
    
    if (!buf) {
        return -1;
    }
    
    struct FAT *file_entry = get_file_entry(table[fd].filename);
    if (!file_entry) {
        return -1;
    }
    
    size_t offset = table[fd].off;
    const uint8_t *user_buf = (const uint8_t*)buf;
    size_t bytes_written = 0;
    
    while (bytes_written < count) {
        size_t current_offset = offset + bytes_written;
        size_t block_offset = current_offset % BLOCK_SIZE;
        
        int data_block_index = find_data_block_for_offset(table[fd].filename, current_offset);
        if (data_block_index < 0) {
            data_block_index = extend_file_chain(table[fd].filename);
            if (data_block_index < 0) {
                break;
            }
        }
        
        int real_block = super->dataBlckStart + data_block_index;
        
        size_t bytes_in_block = BLOCK_SIZE - block_offset;
        size_t bytes_to_write = (count - bytes_written < bytes_in_block) ? 
                                count - bytes_written : bytes_in_block;
        
        uint8_t bounce_buffer[BLOCK_SIZE];
        
        if (block_offset != 0 || bytes_to_write != BLOCK_SIZE) {
            if (block_read(real_block, bounce_buffer) < 0) {
                if (block_offset == 0) {
                    memset(bounce_buffer, 0, BLOCK_SIZE);
                } else {
                    return -1;
                }
            }
        }
        
        memcpy(bounce_buffer + block_offset, user_buf + bytes_written, bytes_to_write);
        
        if (block_write(real_block, bounce_buffer) < 0) {
            return -1;
        }
        
        bytes_written += bytes_to_write;
        
        size_t new_offset = offset + bytes_written;
        if (new_offset > file_entry->fileSize) {
            file_entry->fileSize = new_offset;
        }
    }
    
    table[fd].off += bytes_written;
    
    return bytes_written;
}

