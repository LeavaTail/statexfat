// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 LeavaTail
 */
#ifndef _STATEXFAT_H
#define _STATEXFAT_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <errno.h>

#include "list.h"
#include "nls.h"
#include "stack.h"
/**
 * Program Name, version, author.
 * displayed when 'usage' and 'version'
 */
#define PROGRAM_NAME     "statexfat"
#define PROGRAM_VERSION  "0.1.0"
#define PROGRAM_AUTHOR   "LeavaTail"
#define COPYRIGHT_YEAR   "2021"

/**
 * Debug code
 */
extern unsigned int print_level;
extern FILE *output;
#define PRINT_ERR      1
#define PRINT_WARNING  2
#define PRINT_INFO     3
#define PRINT_DEBUG    4

#define print(level, fmt, ...) \
	do { \
		if (print_level >= level) { \
			if (level == PRINT_DEBUG) \
			fprintf( output, "(%s:%u): " fmt, \
					__func__, __LINE__, ##__VA_ARGS__); \
			else \
			fprintf( output, "" fmt, ##__VA_ARGS__); \
		} \
	} while (0) \

#define pr_err(fmt, ...)   print(PRINT_ERR, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)  print(PRINT_WARNING, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)  print(PRINT_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) print(PRINT_DEBUG, fmt, ##__VA_ARGS__)
#define pr_msg(fmt, ...)   fprintf(output, fmt, ##__VA_ARGS__)

#define SECSIZE          512
#define DENTRY_LISTSIZE  1024
#define PATHNAME_MAX     4096
/*
 * exFAT definition
 */
#define ACTIVEFAT     0x0001
#define VOLUMEDIRTY   0x0002
#define MEDIAFAILURE  0x0004
#define CLEARTOZERO   0x0008

#define EXFAT_FIRST_CLUSTER  2
#define EXFAT_BADCLUSTER     0xFFFFFFF7
#define EXFAT_LASTCLUSTER    0xFFFFFFFF

/*
 * FAT/exFAT definition
 */
#define JMPBOOTSIZE       3
#define ORMNAMESIZE       8
#define VOLUME_LABEL_MAX  11
#define LONGNAME_MAX      13
#define ENTRY_NAME_MAX    15
#define MAX_NAME_LENGTH   255

struct device_info {
	int fd;
	size_t total_size;
	size_t sector_size;
	size_t cluster_size;
	uint16_t cluster_count;
	uint32_t fat_offset;
	uint32_t fat_length;
	uint32_t heap_offset;
	uint32_t root_offset;
	uint8_t *alloc_table;
	uint32_t alloc_cluster;
	uint16_t *upcase_table;
	size_t upcase_size;
	uint16_t *vol_label;
	uint8_t vol_length;
};

#define DIRECTORY_FILES  1024

struct exfat_dirinfo {
	uint32_t clu;
	char *name;
	size_t namelen;
	size_t datalen;
	uint8_t flags;
};

struct exfat_fileinfo {
	unsigned char *name;
	size_t namelen;
	size_t datalen;
	uint8_t cached;
	uint16_t attr;
	uint8_t flags;
	struct tm ctime;
	struct tm atime;
	struct tm mtime;
	uint16_t hash;
};

struct exfat_bootsec {
	unsigned char JumpBoot[JMPBOOTSIZE];
	unsigned char FileSystemName[ORMNAMESIZE];
	unsigned char MustBeZero[53];
	uint64_t  PartitionOffset;
	uint64_t VolumeLength;
	uint32_t FatOffset;
	uint32_t FatLength;
	uint32_t ClusterHeapOffset;
	uint16_t ClusterCount;
	uint32_t FirstClusterOfRootDirectory;
	uint32_t VolumeSerialNumber;
	uint16_t FileSystemRevision;
	uint16_t VolumeFlags;
	uint8_t BytesPerSectorShift;
	uint8_t SectorsPerClusterShift;
	uint8_t NumberOfFats;
	uint8_t DriveSelect;
	uint8_t PercentInUse;
	unsigned char Reserved[7];
	unsigned char BootCode[390];
	unsigned char BootSignature[2];
};

struct exfat_dentry {
	uint8_t EntryType;
	union {
		/* Allocation Bitmap Directory Entry */
		struct {
			uint8_t BitmapFlags;
			unsigned char Reserved[18];
			uint32_t FirstCluster;
			uint64_t DataLength;
		} __attribute__((packed)) bitmap;
		/* Up-case Table Directory Entry */
		struct {
			unsigned char Reserved1[3];
			uint32_t TableCheckSum;
			unsigned char Reserved2[12];
			uint32_t FirstCluster;
			uint32_t DataLength;
		} __attribute__((packed)) upcase;
		/* Volume Label Directory Entry */
		struct {
			uint8_t CharacterCount;
			uint16_t VolumeLabel[VOLUME_LABEL_MAX];
			unsigned char Reserved[8];
		} __attribute__((packed)) vol;
		/* File Directory Entry */
		struct {
			uint8_t SecondaryCount;
			uint16_t SetChecksum;
			uint16_t FileAttributes;
			unsigned char Reserved1[2];
			uint32_t CreateTimestamp;
			uint32_t LastModifiedTimestamp;
			uint32_t LastAccessedTimestamp;
			uint8_t Create10msIncrement;
			uint8_t LastModified10msIncrement;
			uint8_t CreateUtcOffset;
			uint8_t LastModifiedUtcOffset;
			uint8_t LastAccessdUtcOffset;
			unsigned char Reserved2[7];
		} __attribute__((packed)) file;
		/* Volume GUID Directory Entry */
		struct {
			uint8_t SecondaryCount;
			uint16_t SetChecksum;
			uint16_t GeneralPrimaryFlags;
			unsigned char VolumeGuid[16];
			unsigned char Reserved[10];
		} __attribute__((packed)) guid;
		/* Stream Extension Directory Entry */
		struct {
			uint8_t GeneralSecondaryFlags;
			unsigned char Reserved1;
			uint8_t NameLength;
			uint16_t NameHash;
			unsigned char Reserved2[2];
			uint64_t ValidDataLength;
			unsigned char Reserved3[4];
			uint32_t FirstCluster;
			uint64_t DataLength;
		} __attribute__((packed)) stream;
		/* File Name Directory Entry */
		struct {
			uint8_t GeneralSecondaryFlags;
			uint16_t FileName[ENTRY_NAME_MAX];
		} __attribute__((packed)) name;
		/* Vendor Extension Directory Entry */
		struct {
			uint8_t GeneralSecondaryFlags;
			unsigned char VendorGuid[16];
			unsigned char VendorDefined[14];
		} __attribute__((packed)) vendor;
		/* Vendor Allocation Directory Entry */
		struct {
			uint8_t GeneralSecondaryFlags;
			unsigned char VendorGuid[16];
			unsigned char VendorDefined[2];
			uint32_t FirstCluster;
			uint64_t DataLength;
		} __attribute__((packed)) vendor_alloc;
	} __attribute__((packed)) dentry;
} __attribute__ ((packed));

/* FAT/exFAT File Attributes */
#define ATTR_READ_ONLY       0x01
#define ATTR_HIDDEN          0x02
#define ATTR_SYSTEM          0x04
#define ATTR_VOLUME_ID       0x08
#define ATTR_DIRECTORY       0x10
#define ATTR_ARCHIVE         0x20
#define ATTR_LONG_FILE_NAME  (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)
/* FAT dentry type */
#define LAST_LONG_ENTRY      0x40
#define DENTRY_DELETED       0xE5
/* exFAT dentry type */
#define DENTRY_UNUSED        0x00
#define DENTRY_BITMAP        0x81
#define DENTRY_UPCASE        0x82
#define DENTRY_VOLUME        0x83
#define DENTRY_FILE          0x85
#define DENTRY_GUID          0xA0
#define DENTRY_STREAM        0xC0
#define DENTRY_NAME          0xC1
#define DENTRY_VENDOR        0xE0
#define DENTRY_VENDOR_ALLOC  0xE1

/* exFAT EntryType */
#define EXFAT_TYPECODE       0x1F
#define EXFAT TYPEIMPORTANCE 0x20
#define EXFAT_CATEGORY       0x40
#define EXFAT_INUSE          0x80

/* exFAT GeneralSecondaryFlags */
#define ALLOC_POSIBLE         0x01
#define ALLOC_NOFATCHAIN      0x02

/* TimeStamp */
#define FAT_DAY      0
#define FAT_MONTH    5
#define FAT_YEAR     9
#define EXFAT_DSEC   0
#define EXFAT_MINUTE 5
#define EXFAT_HOUR   11
#define EXFAT_DAY    16
#define EXFAT_MONTH  21
#define EXFAT_YEAR   25

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static inline bool is_power2(unsigned int n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

extern struct device_info info;

/* General function */
int get_sector(void *, off_t, size_t);
int get_cluster(void *, off_t);
int get_clusters(void *, off_t, size_t);
int set_sector(void *, off_t, size_t);
int set_cluster(void *, off_t);
int set_clusters(void *, off_t, size_t);
int print_cluster(uint32_t);
void hexdump(void *, size_t);
void gen_rand(char *, size_t);

/* exFAT */
int exfat_check_filesystem(struct exfat_bootsec *);
int exfat_lookup(struct exfat_dirinfo *, char *);
int exfat_stat(struct exfat_dirinfo *, char *, struct exfat_dentry *);

#endif /* _STATEXFAT_H */
