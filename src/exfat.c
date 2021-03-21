// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 LeavaTail
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>

#include "statexfat.h"

/* Generic function prototype */
static uint32_t exfat_concat_cluster_fast(uint32_t, void **);
static size_t exfat_get_filesize_fast(uint32_t);

/* Boot sector function prototype */
static int exfat_load_bitmap_cluster(struct exfat_dentry);
static int exfat_load_upcase_cluster(struct exfat_dentry);
static int exfat_load_volume_label(struct exfat_dentry);

/* FAT-entry function prototype */
static uint32_t exfat_get_fat(uint32_t);

/* Directory chain function prototype */
static size_t exfat_get_filesize_fast(uint32_t clu);
static int exfat_load_entry_fast(uint32_t);
static int exfat_change_directory(struct exfat_dirinfo *di, const char *name);

/* File function prototype */
static uint32_t exfat_calculate_tablechecksum(unsigned char *, uint64_t);
static uint16_t exfat_calculate_namehash(uint16_t *, uint8_t);

/* File Name function prototype */
static uint16_t exfat_convert_upper(uint16_t);
static void exfat_convert_upper_character(uint16_t *, size_t, uint16_t *);

/*************************************************************************************************/
/*                                                                                               */
/* GENERIC FUNCTION                                                                              */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_concat_cluster_fast - Contatenate cluster @data with next_cluster (Only Check FAT)
 * @clu:                       index of the cluster
 * @data:                      The cluster (Output)
 *
 * @retrun:                    cluster count (@clu has next cluster)
 *                             0             (@clu doesn't have next cluster, or failed to realloc)
 */
static uint32_t exfat_concat_cluster_fast(uint32_t clu, void **data)
{
	int i;
	void *tmp;
	size_t allocated = exfat_get_filesize_fast(clu);

	if (!(tmp = realloc(*data, info.cluster_size * allocated)))
		return 0;

	*data = tmp;

	for (i = 1; i < allocated; i++) {
		clu = exfat_get_fat(clu);
		get_cluster(*data + info.cluster_size * i, clu);
	}

	return allocated;
}

/**
 * exfat_concat_cluster - Contatenate cluster @data with next_cluster
 * @f:                    file information pointer
 * @clu:                  index of the cluster
 * @data:                 The cluster (Output)
 *
 * @retrun:               cluster count (@clu has next cluster)
 *                        0             (@clu doesn't have next cluster, or failed to realloc)
 */
static uint32_t exfat_concat_cluster(struct exfat_dirinfo *di, void **data)
{
	int i;
	void *tmp;
	uint32_t clu = di->clu;
	uint32_t tmp_clu = clu;
	size_t allocated = 0;
	size_t cluster_num = (di->datalen + (info.cluster_size - 1)) / info.cluster_size;

	/* NO_FAT_CHAIN */
	if (di->flags & ALLOC_NOFATCHAIN) {
		if (!(tmp = realloc(*data, info.cluster_size * cluster_num)))
			return 0;
		*data = tmp;
		get_clusters(*data + info.cluster_size, clu + 1, cluster_num - 1);
		return cluster_num;
	}

	/* FAT_CHAIN */
	for (allocated = 0; tmp_clu; allocated++)
		tmp_clu = exfat_get_fat(tmp_clu);

	if (!(tmp = realloc(*data, info.cluster_size * allocated)))
		return 0;
	*data = tmp;

	for (i = 1; i < allocated; i++) {
		clu = exfat_get_fat(clu);
		get_cluster(*data + info.cluster_size * i, clu);
	}

	return allocated;
}

/**
 * exfat_check_filesystem - Whether or not exFAT filesystem
 * @b:                      boot sector pointer
 *
 * @return:                 0 (Image is exFAT filesystem)
 *                          -EINVAL (Image isn't exFAT filesystem)
 */
int exfat_check_filesystem(struct exfat_bootsec *b)
{
	if (strncmp((char *)b->FileSystemName, "EXFAT   ", 8))
		return -EINVAL;

	if ((b->BytesPerSectorShift < 9) || (b->BytesPerSectorShift > 12))
		return -EINVAL;

	if (b->SectorsPerClusterShift > (25 - b->BytesPerSectorShift))
		return -EINVAL;

	info.fat_offset = b->FatOffset;
	info.heap_offset = b->ClusterHeapOffset;
	info.root_offset = b->FirstClusterOfRootDirectory;
	info.sector_size  = 1 << b->BytesPerSectorShift;
	info.cluster_size = (1 << b->SectorsPerClusterShift) * info.sector_size;
	info.cluster_count = b->ClusterCount;
	info.fat_offset = b->FatOffset;
	info.fat_length = b->NumberOfFats * b->FatLength * info.sector_size;
	exfat_load_entry_fast(info.root_offset);

	return 0;
}

/*************************************************************************************************/
/*                                                                                               */
/* BOOT SECTOR FUNCTION                                                                          */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_load_bitmap_cluster - function to load Allocation Bitmap
 * @d:                         directory entry about allocation bitmap
 *
 * @return                      0 (success)
 *                             -1 (bitmap was already loaded)
 */
static int exfat_load_bitmap_cluster(struct exfat_dentry d)
{
	if (info.alloc_cluster)
		return -1;

	pr_debug("Get: allocation table: cluster 0x%x, size: 0x%lx\n",
			d.dentry.bitmap.FirstCluster,
			d.dentry.bitmap.DataLength);
	info.alloc_cluster = d.dentry.bitmap.FirstCluster;
	info.alloc_table = malloc(info.cluster_size);
	get_cluster(info.alloc_table, d.dentry.bitmap.FirstCluster);
	pr_info("Allocation Bitmap (#%u):\n", d.dentry.bitmap.FirstCluster);

	return 0;
}

/**
 * exfat_load_upcase_cluster - function to load Upcase table
 * @d:                         directory entry about Upcase table
 *
 * @return                      0 (success)
 *                             -1 (bitmap was already loaded)
 */
static int exfat_load_upcase_cluster(struct exfat_dentry d)
{
	uint32_t checksum = 0;
	uint64_t len;

	if (info.upcase_size)
		return -1;

	info.upcase_size = d.dentry.upcase.DataLength;
	len = (info.upcase_size + info.cluster_size - 1) / info.cluster_size;
	info.upcase_table = malloc(info.cluster_size * len);
	pr_debug("Get: Up-case table: cluster 0x%x, size: 0x%x\n",
			d.dentry.upcase.FirstCluster,
			d.dentry.upcase.DataLength);
	get_clusters(info.upcase_table, d.dentry.upcase.FirstCluster, len);
	checksum = exfat_calculate_tablechecksum((unsigned char *)info.upcase_table, info.upcase_size);
	if (checksum != d.dentry.upcase.TableCheckSum)
		pr_warn("Up-case table checksum is difference. (dentry: %x, calculate: %x)\n",
				d.dentry.upcase.TableCheckSum,
				checksum);

	return 0;
}

/**
 * exfat_load_volume_label - function to load volume label
 * @d:                       directory entry about volume label
 *
 * @return                    0 (success)
 *                           -1 (bitmap was already loaded)
 */
static int exfat_load_volume_label(struct exfat_dentry d)
{
	if (info.vol_length)
		return -1;

	info.vol_length = d.dentry.vol.CharacterCount;
	if (info.vol_length) {
		info.vol_label = malloc(sizeof(uint16_t) * info.vol_length);
		pr_debug("Get: Volume label: size: 0x%x\n",
				d.dentry.vol.CharacterCount);
		memcpy(info.vol_label, d.dentry.vol.VolumeLabel,
				sizeof(uint16_t) * info.vol_length);
	}

	return 0;
}

/*************************************************************************************************/
/*                                                                                               */
/* FAT-ENTRY FUNCTION                                                                            */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_get_fat - Whether or not cluster is continuous
 * @clu:           index of the cluster want to check
 *
 * @retrun:        next cluster (@clu has next cluster)
 *                 0            (@clu doesn't have next cluster)
 */
static uint32_t exfat_get_fat(uint32_t clu)
{
	uint32_t ret;
	size_t entry_per_sector = info.sector_size / sizeof(uint32_t);
	uint32_t fat_index = (info.fat_offset +  clu / entry_per_sector) * info.sector_size;
	uint32_t *fat;
	uint32_t offset = (clu) % entry_per_sector;

	fat = malloc(info.sector_size);
	get_sector(fat, fat_index, 1);
	/* validate index */
	if (clu == EXFAT_BADCLUSTER) {
		ret = 0;
		pr_err("cluster: %u is bad cluster.\n", clu);
	} else if (clu == EXFAT_LASTCLUSTER) {
		ret = 0;
		pr_debug("cluster: %u is the last cluster of cluster chain.\n", clu);
	} else if (clu < EXFAT_FIRST_CLUSTER || clu > info.cluster_count + 1) {
		ret = 0;
		pr_debug("cluster: %u is invalid.\n", clu);
	} else {
		ret = fat[offset];
		if (ret == EXFAT_LASTCLUSTER)
			ret = 0;
		else
			pr_debug("cluster: %u has chain. next is 0x%x.\n", clu, fat[offset]);
	}

	free(fat);
	return ret;
}

/*************************************************************************************************/
/*                                                                                               */
/* DIRECTORY FUNCTION                                                                            */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_get_filesize_fast - Get DataLength from cluster count (Only check FAT)
 * @clu:                     index of the cluster
 *
 * @return                   cluster count
 */
static size_t exfat_get_filesize_fast(uint32_t clu)
{
	size_t allocated;

	for (allocated = 0; clu; allocated++)
		clu = exfat_get_fat(clu);

	return allocated;
}

/**
 * exfat_load_extra_entry_fast - function to load extra entry (Only check meta entry)
 * @clu:                         index of the cluster
 *
 * @return                       0 (success)
 *                               1 (already traverse)
 */
static int exfat_load_entry_fast(uint32_t clu)
{
	int i;
	void *data;
	size_t cluster_num = 1;
	struct exfat_dentry d;
	size_t entries = info.cluster_size / sizeof(struct exfat_dentry);

	data = malloc(info.cluster_size);
	get_cluster(data, clu);
	
	cluster_num = exfat_concat_cluster_fast(clu, &data);
	entries = (cluster_num * info.cluster_size) / sizeof(struct exfat_dentry);

	for (i = 0; i < entries; i++) {
		d = ((struct exfat_dentry *)data)[i];
		switch (d.EntryType) {
			case DENTRY_BITMAP:
				exfat_load_bitmap_cluster(d);
				break;
			case DENTRY_UPCASE:
				exfat_load_upcase_cluster(d);
				break;
			case DENTRY_VOLUME:
				exfat_load_volume_label(d);
				break;
		}
	}

	free(data);
	return 0;
}

/**
 * exfat_traverse_directory - function to traverse one directory
 * @clu:                      index of the cluster want to check
 *
 * @return                    0 (success)
 *                           -1 (failed to read)
 *
 * NOTE: Need to Allocate/Free @data after this
 */
static int exfat_traverse_directory(struct exfat_dirinfo *dirinfo, const char *name, void *data, size_t dentry_num)
{
	int i, offset, src_len, dist_len;
	uint8_t remaining;
	uint16_t src_uniname[MAX_NAME_LENGTH] = {0};
	uint16_t dist_uniname[MAX_NAME_LENGTH] = {0};
	uint16_t uppername[MAX_NAME_LENGTH] = {0};
	uint16_t namehash = 0;
	struct exfat_dentry d, s, n;

	src_len = utf8s_to_utf16s((unsigned char *)name, strlen(name), src_uniname);
	exfat_convert_upper_character(src_uniname, src_len, uppername);
	namehash = exfat_calculate_namehash(uppername, src_len);

	for (offset = 0; offset < dentry_num; offset++) {
		d = ((struct exfat_dentry *)data)[offset];
		switch (d.EntryType) {
			case DENTRY_FILE:
				remaining = d.dentry.file.SecondaryCount;
				/* Stream entry */
				s = ((struct exfat_dentry *)data)[offset + 1];
				while ((!(s.EntryType & EXFAT_INUSE)) && (s.EntryType != DENTRY_UNUSED))
					s = ((struct exfat_dentry *)data)[++offset + 1];

				if (s.EntryType != DENTRY_STREAM) {
					offset += remaining;
					continue;
				}

				if (s.dentry.stream.NameLength != src_len || s.dentry.stream.NameHash != namehash) {
					offset += remaining;
					continue;
				}

				/* Filename entry */
				n = ((struct exfat_dentry *)data)[offset + 2];
				while ((!(n.EntryType & EXFAT_INUSE)) && (n.EntryType != DENTRY_UNUSED)) {
					pr_debug("This entry was deleted (0x%x).\n", n.EntryType);
					n = ((struct exfat_dentry *)data)[++offset + 2];
				}

				if (n.EntryType != DENTRY_NAME) {
					offset += remaining;
					continue;;
				}

				dist_len = s.dentry.stream.NameLength;
				for (i = 0; i < remaining - 1; i++) {
					dist_len = MIN(ENTRY_NAME_MAX,
							s.dentry.stream.NameLength - i * ENTRY_NAME_MAX);
					memcpy(dist_uniname + i * ENTRY_NAME_MAX,
							(((struct exfat_dentry *)data)[offset + 2 + i]).dentry.name.FileName,
							dist_len * sizeof(uint16_t));
				}

				if (!memcmp(src_uniname, dist_uniname, src_len))
					return offset;
		}
	}

	return -1;
}

/**
 * exfat_traverse_directory - function to traverse one directory
 * @clu:                      index of the cluster want to check
 *
 * @return                    0 (success)
 *                           -1 (failed to read)
 */
static int exfat_change_directory(struct exfat_dirinfo *dirinfo, const char *dir)
{
	int i;
	void *data;
	struct exfat_dentry s;
	size_t cluster_num = 1;
	size_t dentry_num = info.cluster_size / sizeof(struct exfat_dentry);

	data = malloc(info.cluster_size);
	get_cluster(data, dirinfo->clu);

	cluster_num = exfat_concat_cluster(dirinfo, &data);
	dentry_num = (cluster_num * info.cluster_size) / sizeof(struct exfat_dentry);

	if ((i = exfat_traverse_directory(dirinfo, dir, data, dentry_num)) < 0)
		return -1;

	s = ((struct exfat_dentry *)data)[++i];
	while ((!(s.EntryType & EXFAT_INUSE)) && (s.EntryType != DENTRY_UNUSED))
		s = ((struct exfat_dentry *)data)[++i];

	dirinfo->clu = s.dentry.stream.FirstCluster;
	dirinfo->datalen = s.dentry.stream.DataLength;
	dirinfo->flags = s.dentry.stream.GeneralSecondaryFlags;

	free(data);
	return dirinfo->clu;
}

/*************************************************************************************************/
/*                                                                                               */
/* FILE FUNCTION                                                                                 */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_calculate_Tablechecksum - Calculate Up-case table Checksum
 * @entry:                         points to an in-memory copy of the directory entry set
 * @count:                         the number of secondary directory entries
 *
 * @return                         Checksum
 */
static uint32_t exfat_calculate_tablechecksum(unsigned char *table, uint64_t length)
{
	uint32_t checksum = 0;
	uint64_t index;

	for (index = 0; index < length; index++)
		checksum = ((checksum & 1) ? 0x80000000 : 0) + (checksum >> 1) + (uint32_t)table[index];

	return checksum;
}

/**
 * exfat_calculate_namehash - Calculate name hash
 * @name:                     points to an in-memory copy of the up-cased file name
 * @len:                      Name length
 *
 * @return                    NameHash
 */
static uint16_t exfat_calculate_namehash(uint16_t *name, uint8_t len)
{
	unsigned char* buffer = (unsigned char *)name;
	uint16_t bytes = (uint16_t)len * 2;
	uint16_t hash = 0;
	uint16_t index;

	for (index = 0; index < bytes; index++)
		hash = ((hash & 1) ? 0x8000 : 0) + (hash >> 1) + (uint16_t)buffer[index];

	return hash;
}

/*************************************************************************************************/
/*                                                                                               */
/* FILE NAME FUNCTION                                                                            */
/*                                                                                               */
/*************************************************************************************************/
/**
 * exfat_convert_upper - convert character to upper-character
 * @c:                   character in UTF-16
 *
 * @return:              upper character
 */
static uint16_t exfat_convert_upper(uint16_t c)
{
	return info.upcase_table[c] ? info.upcase_table[c] : c;
}

/**
 * exfat_convert_upper_character - convert string to upper-string
 * @src:                           Target characters in UTF-16
 * @len:                           Target characters length
 * @dist:                          convert result in UTF-16 (Output)
 */
static void exfat_convert_upper_character(uint16_t *src, size_t len, uint16_t *dist)
{
	int i;

	for (i = 0; i < len; i++)
		dist[i] = exfat_convert_upper(src[i]);
}

/*************************************************************************************************/
/*                                                                                               */
/* OPERATIONS FUNCTION                                                                           */
/*                                                                                               */
/*************************************************************************************************/

/**
 * exfat_lookup - function interface to lookup pathname
 * @clu:          directory cluster index
 * @name:         file name
 *
 * @return:       cluster index
 *                -1 (Not found)
 */
int exfat_lookup(struct exfat_dirinfo *dir, char *name)
{
	int i = 0, depth = 0;
	char *path[MAX_NAME_LENGTH] = {};

	if (!name) {
		pr_err("invalid pathname.\n");
		return -1;
	}

	/* Absolute path */
	if (name[0] != '/') {
		pr_err("Filename is have to Absolute path, But (%s) is not.\n", name);
		return -1;
	}

	/* Separate pathname by slash */
	path[depth] = strtok(name, "/");
	while (path[depth] != NULL) {
		if (depth >= MAX_NAME_LENGTH) {
			pr_err("Pathname is too depth. (> %d)\n", MAX_NAME_LENGTH);
			return -1;
		}
		path[++depth] = strtok(NULL, "/");
	}
	for (i = 0; path[i] && i < depth - 1; i++) {
		pr_debug("Lookup %s to %d\n", path[i], dir->clu);
		if (!exfat_change_directory(dir, path[i])) {
			pr_err("%s is Not Found\n", path[i]);
			return -1;
		}
		dir->name = path[i];
		dir->namelen = strlen(path[i]);
	}

	dir->name = path[i];
	dir->namelen = strlen(path[i]);

	return 0;
}

/**
 * exfat_stat - function interface to lookup pathname
 * @clu:        directory cluster index
 * @name:       file name
 *
 * @return:     cluster index
 *              -1 (Not found)
 */
int exfat_stat(struct exfat_dirinfo *dirinfo, char *filename, struct exfat_dentry *dist)
{
	int i;
	void *data;
	struct exfat_dentry d, s;
	size_t cluster_num = 1;
	size_t dentry_num = info.cluster_size / sizeof(struct exfat_dentry);

	data = malloc(info.cluster_size);
	get_cluster(data, dirinfo->clu);

	cluster_num = exfat_concat_cluster(dirinfo, &data);
	dentry_num = (cluster_num * info.cluster_size) / sizeof(struct exfat_dentry);

	if ((i = exfat_traverse_directory(dirinfo, filename, data, dentry_num)) < 0) {
		pr_err("%s is Not Found\n", filename);
		return -1;
	}

	d = ((struct exfat_dentry *)data)[i];
	s = ((struct exfat_dentry *)data)[++i];
	while ((!(s.EntryType & EXFAT_INUSE)) && (s.EntryType != DENTRY_UNUSED))
		s = ((struct exfat_dentry *)data)[++i];

	dirinfo->clu = s.dentry.stream.FirstCluster;
	dirinfo->datalen = s.dentry.stream.DataLength;
	dirinfo->flags = s.dentry.stream.GeneralSecondaryFlags;

	memcpy(dist++, &d, sizeof(struct exfat_dentry));
	memcpy(dist, &s, sizeof(struct exfat_dentry));
	free(data);

	pr_msg("SecondaryCount: %0x\n", d.dentry.file.SecondaryCount);
	pr_msg("SetChecksum: %02x\n", d.dentry.file.SetChecksum);
	pr_msg("FileAttributes: %02x\n", d.dentry.file.FileAttributes);
	pr_msg("Reserved1: %x%x\n", d.dentry.file.Reserved1[0], d.dentry.file.Reserved1[1]);
	pr_msg("CreateTimestamp: %04x\n", d.dentry.file.CreateTimestamp);
	pr_msg("LastModifiedTimestamp: %04x\n", d.dentry.file.LastModifiedTimestamp);
	pr_msg("LastAccessedTimestamp: %04x\n", d.dentry.file.LastAccessedTimestamp);
	pr_msg("Create10msIncrement: %0x\n", d.dentry.file.Create10msIncrement);
	pr_msg("LastModified10msIncrement: %0x\n", d.dentry.file.LastModified10msIncrement);
	pr_msg("CreateUtcOffset: %0x\n", d.dentry.file.CreateUtcOffset);
	pr_msg("LastModifiedTimestamp: %0x\n", d.dentry.file.LastModifiedTimestamp);
	pr_msg("LastAccessdUtcOffset: %0x\n", d.dentry.file.LastAccessdUtcOffset);
	pr_msg("GenericSecondaryFlags: %0x\n", s.dentry.stream.GeneralSecondaryFlags);
	pr_msg("Reserved1: %0x\n", s.dentry.stream.Reserved1);
	pr_msg("NameLength: %0x\n", s.dentry.stream.NameLength);
	pr_msg("NameHash: %02x\n", s.dentry.stream.NameHash);
	pr_msg("Reserved2: %x%x\n", s.dentry.stream.Reserved2[0], s.dentry.stream.Reserved2[1]);
	pr_msg("ValidDataLength: %08lx\n", s.dentry.stream.ValidDataLength);
	pr_msg("Reserved3: %x%x%x%x\n", s.dentry.stream.Reserved3[0], s.dentry.stream.Reserved3[1],
			s.dentry.stream.Reserved3[2], s.dentry.stream.Reserved3[3]);
	pr_msg("FirstCluster: %04x\n", s.dentry.stream.FirstCluster);
	pr_msg("DataLength: %08lx\n", s.dentry.stream.DataLength);

	return 0;
}
