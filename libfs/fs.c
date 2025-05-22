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
        fprintf(stderr, "file sys mounted\n");
        return -1;
    }

    if (block_disk_open(disk) < 0) {
        fprintf(stderr, "can't open disk %s\n", disk);
        return -1;
    }

    super = malloc(sizeof(struct superblock));
    if (!super) {
        fprintf(stderr, "failed malloc for super\n");
        block_disk_close();
        return -1;
    }

    if (block_read(0, super) < 0) {
        fprintf(stderr, "failed read for super\n");
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    if (memcmp(super->sig, FS_SIGNATURE, 8) != 0) {
        fprintf(stderr, "inv file sys sig\n");
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    int blckCnt = block_disk_count();
    if (blckCnt < 0 || super->totBlck != blckCnt) {
        fprintf(stderr, "blck cnt mismatch\n");
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    size_t fatSize = super->fatBlckCnt * BLOCK_SIZE;
    fat = malloc(fatSize);
    if (!fat) {
        fprintf(stderr, "failed malloc for FAT\n");
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    for (int i = 0; i < super->fatBlckCnt; i++) {
        if (block_read(i + 1, (uint8_t*)fat + i * BLOCK_SIZE) < 0) {
            fprintf(stderr, "failed read for FAT\n");
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
        fprintf(stderr, "failed malloc for root\n");
        free(fat);
        fat = NULL;
        free(super);
        super = NULL;
        block_disk_close();
        return -1;
    }

    if (block_read(super->rootInd, rdir) < 0) {
        fprintf(stderr, " failed read for root\n");
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
        fprintf(stderr, "no file sys mounted\n");
        return -1;
    }

    free(rdir);
    rdir = NULL;
    free(fat);
    fat = NULL;
    free(super);
    super = NULL;

    if (block_disk_close() < 0) {
        fprintf(stderr, "failed close disk\n");
        return -1;
    }

    mount = 0;
    return 0;
}

int fs_info(void)
{
	if (!mount) {
        fprintf(stderr, "no file sys mounted\n");
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

    // print info (EDIT TO MAKE FIT REF PRGRM)
    printf("totBlckCnt=%d\n", super->totBlck);
    printf("fatBlckCnt=%d\n", super->fatBlckCnt);
    printf("rdirBlck=%d\n", super->rootInd);
    printf("dataBlck=%d\n", super->dataBlckStart);
    printf("dataBlckCnt=%d\n", super->dataBlckCnt);
    printf("fat/free=%d/%d\n", free_blocks, super->dataBlckCnt);
    printf("rdir/free=%d/%d\n", 128 - file_count, 128);

    return 0;
}
