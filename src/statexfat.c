// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 LeavaTail
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "statexfat.h"
FILE *output = NULL;
unsigned int print_level = PRINT_WARNING;
struct device_info info;
/**
 * Special Option(no short option)
 */
enum
{
	GETOPT_HELP_CHAR = (CHAR_MIN - 2),
	GETOPT_VERSION_CHAR = (CHAR_MIN - 3)
};

/* option data {"long name", needs argument, flags, "short name"} */
static struct option const longopts[] =
{
	{"all", no_argument, NULL, 'a'},
	{"byte", required_argument, NULL, 'b'},
	{"cluster", required_argument, NULL, 'c'},
	{"directory", required_argument, NULL, 'd'},
	{"entry", required_argument, NULL, 'e'},
	{"force", required_argument, NULL, 'f'},
	{"interactive", no_argument, NULL, 'i'},
	{"load", required_argument, NULL, 'l'},
	{"output", required_argument, NULL, 'o'},
	{"quiet", no_argument, NULL, 'q'},
	{"ro", no_argument, NULL, 'r'},
	{"save", required_argument, NULL, 's'},
	{"upper", required_argument, NULL, 'u'},
	{"verbose", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, GETOPT_HELP_CHAR},
	{"version", no_argument, NULL, GETOPT_VERSION_CHAR},
	{0,0,0,0}
};

/**
 * usage - print out usage
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s [OPTION]... FILE\n", PROGRAM_NAME);
	fprintf(stderr, "dump FAT/exFAT filesystem information.\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "  -a, --all\tTrverse all directories.\n");
	fprintf(stderr, "  -b, --byte=offset\tdump the any byte after dump filesystem information.\n");
	fprintf(stderr, "  -c, --cluster=index\tdump the cluster index after dump filesystem information.\n");
	fprintf(stderr, "  -d, --direcotry=path\tread directory entry from path.\n");
	fprintf(stderr, "  -e --entry=index\tread raw directory entry in current directory.\n");
	fprintf(stderr, "  -f, --fource\twrite foucibly even if filesystem image has already mounted.\n");
	fprintf(stderr, "  -i, --interactive\tprompt the user operate filesystem.\n");
	fprintf(stderr, "  -l, --load=file\tLoad Main boot region and FAT region from file.\n");
	fprintf(stderr, "  -o, --output=file\tsend output to file rather than stdout.\n");
	fprintf(stderr, "  -q, --quiet\tSuppress message about Main boot Sector.\n");
	fprintf(stderr, "  -r, --ro\tread only mode. \n");
	fprintf(stderr, "  -s, --save=file\tSave Main boot region and FAT region in file.\n");
	fprintf(stderr, "  -u, --upper\tconvert into uppercase latter by up-case Table.\n");
	fprintf(stderr, "  -v, --verbose\tVersion mode.\n");
	fprintf(stderr, "  --help\tdisplay this help and exit.\n");
	fprintf(stderr, "  --version\toutput version information and exit.\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "  %s /dev/sda\tdump FAT/exFAT filesystem information.\n", PROGRAM_NAME);
	fprintf(stderr, "  %s -c 2 /dev/sda\tdump FAT/exFAT filesystem information and cluster #2.\n", PROGRAM_NAME);
	fprintf(stderr, "\n");
}

/**
 * version        - print out program version
 * @command_name:   command name
 * @version:        program version
 * @author:         program authoer
 */
static void version(const char *command_name, const char *version, const char *author)
{
	fprintf(stdout, "%s %s\n", command_name, version);
	fprintf(stdout, "\n");
	fprintf(stdout, "Written by %s.\n", author);
}

/**
 * get_sector - Get Raw-Data from any sector
 * @data:       Sector raw data (Output)
 * @index:      Start bytes
 * @count:      The number of sectors
 *
 * @return       0 (success)
 *              -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int get_sector(void *data, off_t index, size_t count)
{
	size_t sector_size = info.sector_size;

	pr_debug("Get: Sector from 0x%lx to 0x%lx\n", index , index + (count * sector_size) - 1);
	if ((pread(info.fd, data, count * sector_size, index)) < 0) {
		pr_err("read: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/**
 * set_sector - Set Raw-Data from any sector
 * @data:       Sector raw data
 * @index:      Start bytes
 * @count:      The number of sectors
 *
 * @return       0 (success)
 *              -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int set_sector(void *data, off_t index, size_t count)
{
	size_t sector_size = info.sector_size;

	pr_debug("Set: Sector from 0x%lx to 0x%lx\n", index, index + (count * sector_size) - 1);
	if ((pwrite(info.fd, data, count * sector_size, index)) < 0) {
		pr_err("write: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/**
 * get_cluster - Get Raw-Data from any cluster
 * @data:        cluster raw data (Output)
 * @index:       Start cluster index
 *
 * @return        0 (success)
 *               -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int get_cluster(void *data, off_t index)
{
	return get_clusters(data, index, 1);
}

/**
 * set_cluster - Set Raw-Data from any cluster
 * @data:        cluster raw data
 * @index:       Start cluster index
 *
 * @return        0 (success)
 *               -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int set_cluster(void *data, off_t index)
{
	return set_clusters(data, index, 1);
}

/**
 * get_clusters - Get Raw-Data from any cluster
 * @data:         cluster raw data (Output)
 * @index:        Start cluster index
 * @num:          The number of clusters
 *
 * @return         0 (success)
 *                -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int get_clusters(void *data, off_t index, size_t num)
{
	size_t clu_per_sec = info.cluster_size / info.sector_size;
	off_t heap_start = info.heap_offset * info.sector_size;

	if (index < 2 || index + num > info.cluster_count) {
		pr_err("invalid cluster index %lu.\n", index);
		return -1;
	}

	return get_sector(data,
			heap_start + ((index - 2) * info.cluster_size),
			clu_per_sec * num);
}

/**
 * set_clusters - Set Raw-Data from any cluster
 * @data:         cluster raw data
 * @index:        Start cluster index
 * @num:          The number of clusters
 *
 * @return         0 (success)
 *                -1 (failed to read)
 *
 * NOTE: Need to allocate @data before call it.
 */
int set_clusters(void *data, off_t index, size_t num)
{
	size_t clu_per_sec = info.cluster_size / info.sector_size;
	off_t heap_start = info.heap_offset * info.sector_size;

	if (index < 2 || index + num > info.cluster_count) {
		pr_err("invalid cluster index %lu.\n", index);
		return -1;
	}

	return set_sector(data,
			heap_start + ((index - 2) * info.cluster_size),
			clu_per_sec * num);
}

/**
 * hexdump - Hex dump of a given data
 * @data:    Input data
 * @size:    Input data size
 */
void hexdump(void *data, size_t size)
{
	unsigned long skip = 0;
	size_t line, byte = 0;
	size_t count = size / 0x10;
	const char zero[0x10] = {0};

	for (line = 0; line < count; line++) {
		if ((line != count - 1) && (!memcmp(data + line * 0x10, zero, 0x10))) {
			switch (skip++) {
				case 0:
					break;
				case 1:
					pr_msg("*\n");
					/* FALLTHROUGH */
				default:
					continue;
			}
		} else {
			skip = 0;
		}

		pr_msg("%08lX:  ", line * 0x10);
		for (byte = 0; byte < 0x10; byte++) {
			pr_msg("%02X ", ((unsigned char *)data)[line * 0x10 + byte]);
		}
		putchar(' ');
		for (byte = 0; byte < 0x10; byte++) {
			char ch = ((unsigned char *)data)[line * 0x10 + byte];
			pr_msg("%c", isprint(ch) ? ch : '.');
		}
		pr_msg("\n");
	}
}

/**
 * gen_rand - generate random string of any characters
 * @data:     Output data (Output)
 * @len:      data length
 */
void gen_rand(char *data, size_t len)
{
	int i;
	const char strset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for (i = 0; i < len; i++)
		data[i] = strset[rand() % (sizeof(strset) - 1)];
	data[i] = '\0';
}

/**
 * pseudo_check_filesystem - virtual function to check filesystem
 * @boot:                    boot sector pointer
 *
 * return:                    0 (succeeded in obtaining filesystem)
 *                           -1 (failed)
 */
static int check_filesystem(const char *filename)
{
	int fd;
	struct stat s;
	struct exfat_bootsec boot;
	size_t count = 0;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		pr_err("open: %s\n", strerror(errno));
		return -1;
	}

	if (fstat(fd, &s) < 0) {
		pr_err("stat: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	info.fd = fd;
	info.total_size = s.st_size;

	count = pread(info.fd, &boot, SECSIZE, 0);
	if (count < 0) {
		pr_err("read: %s\n", strerror(errno));
		return -1;
	}

	if (!exfat_check_filesystem(&boot))
		return 0;

	pr_err("%s isn't exFAT filesystem.\n", filename);
	return -1;
}

/**
 * main   - main function
 * @argc:   argument count
 * @argv:   argument vector
 */
int main(int argc, char *argv[])
{
	int opt;
	int longindex;
	int ret = 0;
	struct exfat_dirinfo dir = { 0 };
	struct exfat_dentry d[2] = { 0 };

	while ((opt = getopt_long(argc, argv,
					"v",
					longopts, &longindex)) != -1) {
		switch (opt) {
			case 'v':
				print_level = PRINT_INFO;
				break;
			case GETOPT_HELP_CHAR:
				usage();
				exit(EXIT_SUCCESS);
			case GETOPT_VERSION_CHAR:
				version(PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_AUTHOR);
				exit(EXIT_SUCCESS);
			default:
				usage();
				exit(EXIT_FAILURE);
		}
	}

#ifdef STATEXFAT_DEBUG
	print_level = PRINT_DEBUG;
#endif

	if (optind != argc - 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	output = stdout;

	ret = check_filesystem(argv[optind]);
	if (ret < 0)
		goto out;

	dir.clu = info.root_offset;
	ret = exfat_lookup(&dir, argv[optind + 1]);
	if (ret < 0)
		goto cleanup;

	ret = exfat_stat(&dir, dir.name, d);
	if (ret < 0)
		goto cleanup;

cleanup:
	free(info.vol_label);
	free(info.upcase_table);
	free(info.alloc_table);
	close(info.fd);

out:
	return ret;
}
