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

// glob
static struct superblock *super = NULL;
static uint16_t *fat = NULL;
static struct root *rdir = NULL;
static int mount = 0;

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

    // write FAT to disk
    for (int i = 0; i < super->fatBlckCnt; i++) {
        if (block_write(i + 1, (uint8_t*)fat + i * BLOCK_SIZE) < 0) {
            return -1;
        }
    }

    // write root to disk
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