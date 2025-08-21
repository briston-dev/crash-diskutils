#include <asm-generic/errno-base.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "defs.h"

#define LOG_FILE "/tmp/crash_scsi_dump.log"
#define MAX_LOG_LENGTH 1024
#define MAX_DESC_LENGTH 128
#define NVME_PREFIX "nvme"
#define SCSI_PREFIX "sd"
#define NVME_PREFIX_LENGTH 4
#define SCSI_PREFIX_LENGTH 2

#define get_atomic_value(addr, buf) get_field(addr, "atomic_t", "counter", buf)
#define get_refcnt_value(addr, buf) get_field(addr + MEMBER_OFFSET("refcount_t", "refs"), "atomic_t", "counter", buf)

#define list_for_each(pos, head)                        \
    for (get_field(head, "list_head", "next", &pos);    \
        pos != head;                                   \
        get_field(pos, "list_head", "next", &pos))

#define for_each_device_safe(host, device, tmp) \
    for (device = (host)->devices, tmp = device ? device->next : NULL; \
        device != NULL; \
        device = tmp, tmp = device ? device->next : NULL)

#define for_each_target_safe(host, target, tmp) \
    for (target = (host)->targets, tmp = target ? target->next : NULL; \
        target != NULL; \
        target = tmp, tmp = target ? target->next : NULL)

#define for_each_host_safe(class, host, tmp) \
    for (host = (class)->hosts, tmp = host ? host->next : NULL; \
        host != NULL; \
        host = tmp, tmp = host ? host->next : NULL)

#define for_each_gendisk_safe(class, gendisk, tmp) \
    for (gendisk = (class)->gendisks, tmp = gendisk ? gendisk->next : NULL; \
        gendisk != NULL; \
        gendisk = tmp, tmp = gendisk ? gendisk->next : NULL)

#define for_each_request_safe(gendisk, request, tmp) \
    for (request = (gendisk)->requests, tmp = request ? request->next : NULL; \
        request != NULL; \
        request = tmp, tmp = request ? request->next : NULL)

#define log_format(...) log_message(__func__, __LINE__, __VA_ARGS__)
void log_message(const char *function, int line, const char *format, ...) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *time_info = localtime(&now);
    char time_buffer[20];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);

    char message_buffer[MAX_LOG_LENGTH];

    va_list args;
    va_start(args, format);
    vsnprintf(message_buffer, sizeof(message_buffer), format, args);
    va_end(args);

    message_buffer[sizeof(message_buffer) - 1] = '\0';

    fprintf(log_file, "[%s] [%s:%d] %s\n", time_buffer, function, line, message_buffer);

    fflush(log_file);
    fclose(log_file);
}

static void logfile_cleanup()
{
    if (access(LOG_FILE, F_OK) != 0){
        return;
    }

    if (remove(LOG_FILE) != 0)
    {
        fprintf(fp, "Failed to delete log file: %s", LOG_FILE);
    }
    return;
}


unsigned long g_cur_jiff = 0;

/**
 * struct nvme_device_info - Placeholder for future NVMe device diagnostics (INCOMPLETE)
 * @nvme_device_addr: Address of source struct nvme_dev in vmcore
 *
 * CURRENTLY IMPLEMENTED AS PLACEHOLDER ONLY
 * ----------------------------------------
 *
 * Until fully implemented, this structure exists to maintain:
 * 1. Structural parity with SCSI device diagnostics
 * 2. Framework for attaching NVMe-specific data later
 *
 * Do not rely on current implementation for production diagnostics
 * as it captures minimal useful information.
 */

struct nvme_device_info{
    unsigned long nvme_device_addr;
};

/**
 * struct scsi_device_info - Stores parsed scsi_device information from vmcore
 * @next: Pointer to next scsi_device_info in device linked list
 * @gendisk_info: Pointer to associated gendisk_info structure (from block class)
 * @host_no: Host number in H:C:T:L notation
 * @sdev_id: Target ID (T) in H:C:T:L notation
 * @sdev_lun: Logical Unit Number (L) in H:C:T:L notation
 * @sdev_channel: Channel number (C) in H:C:T:L notation
 * @sdev_state: Parsed value of device state
 * @sdev_type: Parsed value of device type
 * @sdev_addr: Address of source struct scsi_device in vmcore
 * @io_request_cnt: Parsed value of I/O request counter
 * @io_done_cnt: Parsed value of completed I/O requests counter
 * @io_err_cnt: Parsed value of I/O error counter
 * @request_queue_addr: Address of request_queue structure in vmcore
 * @rev: Parsed revision information string
 * @model: Parsed device model string
 * @vendor: Parsed vendor identification string
 * @scsi_type: Parsed device type description string
 */
struct scsi_device_info{
    struct scsi_device_info *next;
    struct gendisk_info* gendisk_info;
    unsigned int host_no;
    unsigned int sdev_id;
    unsigned int sdev_lun;
    unsigned int sdev_channel;
    unsigned int sdev_state;
    unsigned char sdev_type;
    unsigned long sdev_addr;
    unsigned long io_request_cnt;
    unsigned long io_done_cnt;
    unsigned long io_err_cnt;
    unsigned long request_queue_addr;
    char rev[MAX_DESC_LENGTH];
    char model[MAX_DESC_LENGTH];
    char vendor[MAX_DESC_LENGTH];
    char scsi_type[MAX_DESC_LENGTH];
};

/**
 * struct scsi_target_info - Stores parsed scsi_target information from vmcore
 * @next: Pointer to next scsi_target_info in linked list (for target list management)
 * @target_busy: Value from 'target_busy' member of struct scsi_target
 * @target_block: Value from 'target_block' member of struct scsi_target
 * @target_state: Value from 'target_state' member of struct scsi_target
 * @target_id: Value from 'id' member of struct scsi_target (SCSI target ID)
 * @target_channel: Value from 'channel' member of struct scsi_target (SCSI channel number)
 * @scsi_target_addr: virtual address of source struct scsi_target in vmcore
 * @target_name: Device name from scsi_target.dev.kobj.name string
 */
struct scsi_target_info{
    struct scsi_target_info *next;
    long target_busy;
    long target_block;
    long target_state;
    unsigned int target_id;
    unsigned int target_channel;
    unsigned long scsi_target_addr;
    char target_name[MAX_DESC_LENGTH];
};

/**
 * struct scsi_host_info - Stores parsed SCSI host information from vmcore
 * @next: Pointer to next scsi_host_info in linked list (used for managing multiple hosts)
 * @devices: Head pointer to linked list of SCSI devices attached to this host
 * @devices_tail: Tail pointer to linked list of SCSI devices
 * @targets: Head pointer to linked list of SCSI targets associated with this host
 * @targets_tail: Tail pointer to linked list of SCSI targets
 * @host_busy: Parsed value of 'host_busy' member from struct Scsi_Host
 * @host_block: Parsed value of 'host_block' member from struct Scsi_Host
 * @host_failed: Parsed value of 'host_failed' member from struct Scsi_Host
 * @host_self_block: Parsed value of 'host_self_block' member from struct Scsi_Host
 * @host_state: Parsed value of 'host_state' member from struct Scsi_Host
 * @eh_deadline: Parsed value of 'eh_deadline' member from struct Scsi_Host
 * @cmd_per_lun: Parsed value of 'cmd_per_lun' member from struct Scsi_Host
 * @nr_hw_queue: Parsed value of 'nr_hw_queue' member from struct Scsi_Host
 * @max_lun: Parsed value of 'max_lun' member from struct Scsi_Host
 * @scsi_host_addr: virtual address of source struct Scsi_Host in vmcore
 * @shost_data: Parsed value of 'shost_data' member from struct Scsi_Host
 * @hostdata: Parsed value of 'hostdata' member from struct Scsi_Host
 * @taints: Parsed value of 'taints' member from struct Scsi_Host
 * @host_name: Host adapter name string (e.g., "scsi_host0")
 * @work_q_name: Work queue name string associated with the host
 * @driver_name: Name string of the underlying driver module
 * @hostt_version: Version string of the SCSI host template (HBA driver version)
 */
struct scsi_host_info{
    struct scsi_host_info *next;
    struct scsi_device_info *devices;
    struct scsi_device_info *devices_tail;
    struct scsi_target_info *targets;
    struct scsi_target_info *targets_tail;
    int host_busy;
    int host_block;
    int host_failed;
    int host_self_block;
    int host_state;
    int eh_deadline;
    int cmd_per_lun;
    unsigned int nr_hw_queue;
    unsigned long max_lun;
    unsigned long scsi_host_addr;
    unsigned long shost_data;
    unsigned long hostdata;
    unsigned long taints;
    char host_name[MAX_DESC_LENGTH];
    char work_q_name[MAX_DESC_LENGTH];
    char driver_name[MAX_DESC_LENGTH];
    char hostt_version[MAX_DESC_LENGTH];
};

/**
 * struct shost_class_info - Container for global SCSI host class management
 * @hosts: Head pointer to linked list of all discovered scsi_host_info instances
 * @hosts_tail: Tail pointer to linked list
 * @shost_class_addr: Physical/virtual address of kernel's global shost_class structure
 */
struct shost_class_info{
    struct scsi_host_info *hosts;
    struct scsi_host_info *hosts_tail;
    unsigned long shost_class_addr;
};

struct shost_class_info g_shost_info = {0};

 void add_host_to_class(struct shost_class_info *class, struct scsi_host_info *host) {
    if (!class || !host) return;

    host->next = NULL;

    if (class->hosts_tail) {
        class->hosts_tail->next = host;
        class->hosts_tail = host;
    } else {
        class->hosts = host;
        class->hosts_tail = host;
    }
}

void add_target_to_host(struct scsi_host_info *host, struct scsi_target_info *target) {
    if (!host || !target) return;

    target->next = NULL;

    if (host->targets_tail) {
        host->targets_tail->next = target;
        host->targets_tail = target;
    } else {
        host->targets = target;
        host->targets_tail = target;
    }
}

void add_device_to_host(struct scsi_host_info *host, struct scsi_device_info *device) {
    if (!host || !device) return;

    device->next = NULL;

    if (host->devices_tail) {
        host->devices_tail->next = device;
        host->devices_tail = device;
    } else {
        host->devices = device;
        host->devices_tail = device;
    }
}

/**
 * struct cmnd_info - Stores SCSI or NVMe command metadata
 * @opcode: Command operation code (SCSI OPCODE or NVMe OPC)
 * @alloc_time: Time of command allocation (jiffies or nanoseconds)
 * @cmnd_addr: Address of source command structure in vmcore
 *
 * Note: Reserved space for command detail union (SCSI vs NVMe)
 */
struct cmnd_info{
    int opcode;
    unsigned long alloc_time;
    unsigned long cmnd_addr;
};

/**
 * struct bio_info - Stores block I/O layer information
 * @sector: Starting sector number of I/O operation
 * @bio_addr: Address of source struct bio in vmcore
 */
struct bio_info{
    unsigned long sector;
    unsigned long bio_addr;
};

/**
 * struct request_info - Stores I/O request metadata
 * @next: Pointer to next request_info in linked list
 * @cmnd: Command metadata for SCSI/NVMe
 * @bio: Block I/O layer metadata
 * @timeout: Request timeout value in system units
 * @start_time_ns: Request start timestamp (nanoseconds)
 * @request_addr: Address of source request structure in vmcore
 */
struct request_info{
    struct request_info *next;
    struct cmnd_info    cmnd;
    struct bio_info     bio;
    unsigned int timeout;
    unsigned long statr_time_ns;
    unsigned long   request_addr;
};


/**
 * struct gendisk_info - Stores generic disk information from vmcore
 * @next: Pointer to next gendisk_info in linked list
 * @requests: Head pointer to associated request_info list
 * @request_tail: Tail pointer to request_info list (optimizes appending)
 * @scsi_device_info: Pointer to SCSI device when applicable
 * @nvme_device_info: Pointer to NVMe device when applicable
 * @elevator_type: I/O scheduler type used in request_queue (e.g., "mq-deadline")
 * @disk_name: Block device name (e.g., "sda", "nvme0n1")
 * @disk_type: Device type translated from disk name (e.g., DISK_TYPE_HDD)
 * @request_queue_addr: Address of associated request_queue in vmcore
 * @gendisk_addr: Address of source struct gendisk in vmcore
 *
 * This structure captures critical block layer information while
 * maintaining links to both the underlying transport device (SCSI/NVMe)
 * and the associated I/O requests.
 */
struct gendisk_info{
    struct gendisk_info *next;
    struct request_info *requests;
    struct request_info *request_tail;
    union{
        struct scsi_device_info *scsi_device_info;
        struct nvme_device_info *nvme_device_info;
    };
    char elevator_type[MAX_DESC_LENGTH];
    char disk_name[MAX_DESC_LENGTH];
    int disk_type;
    unsigned long request_queue_addr;
    unsigned long gendisk_addr;
};

/**
 * struct block_class_info - Container for global block device management
 * @gendisks: Head pointer to gendisk_info linked list
 * @gendisk_tail: Tail pointer for efficient list operations
 * @block_class_addr: Address of global block_class structure in vmcore
 *
 * Corresponds to the kernel's global block_class instance defined
 * in the block subsystem core (block/genhd.c). Acts as the root
 * container for all detected block devices.
 */
struct block_class_info{

    struct gendisk_info *gendisks;
    struct gendisk_info *gendisk_tail;
    unsigned long block_class_addr;
};

struct block_class_info g_block_class_info = {0};

void add_request_to_gendisk(struct gendisk_info *gendisk, struct request_info *req)
{
    if (!gendisk || !req) return;

    req->next = NULL;

    if (gendisk->request_tail) {
        gendisk->request_tail->next = req;
        gendisk->request_tail = req;
    } else {
        gendisk->requests = req;
        gendisk->request_tail = req;
    }
}

void add_gendisk_to_class(struct block_class_info *class, struct gendisk_info *gendisk)
{
    if (!class || !gendisk) return;

    gendisk->next = NULL;

    if (class->gendisk_tail) {
        class->gendisk_tail->next = gendisk;
        class->gendisk_tail = gendisk;
    } else {
        class->gendisks = gendisk;
        class->gendisk_tail = gendisk;
    }
}

void split_list(struct request_info *head,
               struct request_info **front_ref,
               struct request_info **back_ref) {
    struct request_info *slow = head;
    struct request_info *fast = head->next;

    while (fast != NULL) {
        fast = fast->next;
        if (fast != NULL) {
            slow = slow->next;
            fast = fast->next;
        }
    }

    *front_ref = head;
    *back_ref = slow->next;
    slow->next = NULL;
}

struct request_info *merge_lists(struct request_info *a, struct request_info *b) {
    struct request_info dummy;
    struct request_info *tail = &dummy;
    dummy.next = NULL;

    while (1) {
        if (a == NULL) {
            tail->next = b;
            break;
        } else if (b == NULL) {
            tail->next = a;
            break;
        }

        if (a->cmnd.alloc_time <= b->cmnd.alloc_time) {
            tail->next = a;
            a = a->next;
        } else {
            tail->next = b;
            b = b->next;
        }

        tail = tail->next;
    }

    return dummy.next;
}

void merge_sort(struct request_info **head_ref) {
    struct request_info *head = *head_ref;
    struct request_info *a;
    struct request_info *b;

    if (head == NULL || head->next == NULL) {
        return;
    }

    split_list(head, &a, &b);

    merge_sort(&a);
    merge_sort(&b);

    *head_ref = merge_lists(a, b);
}


struct request_info *find_tail(struct request_info *head) {
    if (head == NULL) return NULL;

    while (head->next != NULL) {
        head = head->next;
    }
    return head;
}

void sort_requests_by_alloc_time(struct gendisk_info *disk) {
    if (!disk || !disk->requests || !disk->requests->next) {
        return;
    }

    merge_sort(&disk->requests);
    disk->request_tail = find_tail(disk->requests);
}

/**
 * get_field - Retrieve a structure field value from vmcore memory
 * @base_addr: Base address of target structure in vmcore
 * @struct_name: Name of kernel structure type (for offset calculation)
 * @field_name: Name of field to extract
 * @buf: Buffer to store retrieved value
 *
 * Return: 0 on success, negative error code on failure
 */
static int get_field(unsigned long base_addr, char* struct_name,
                    char* field_name, void* buf){
    unsigned long offset = MEMBER_OFFSET(struct_name, field_name);
    if (offset == -1){
        fprintf(fp, "member %s dont exist in struct %s\n", field_name, struct_name);
        return FALSE;
    }
    if (!readmem(base_addr + offset, KVADDR, buf, MEMBER_SIZE(struct_name, field_name), struct_name, FAULT_ON_ERROR)){
        return FALSE;
    }
    return TRUE;
}

/**
 * get_string - retrieve a kernel string from vmcore memory
 * @src_addr: Kernel virtual address of the source string in vmcore
 * @buf: User-space buffer to store the retrieved string
 * @buf_size: Size of the destination buffer
 *
 * This function reads a null-terminated string from kernel memory space
 * into user-space buffer. Special considerations for crash tool context:
 *
 * 1. Operates in user-space: Cannot directly access kernel addresses
 * 2. Uses crash tool APIs: Relies on readmem()
 *
 * Return: Number of bytes copied (excluding null terminator) on success,
 *         - On buffer full: Returns buf_size - 1 (string truncated)
 */
static int get_string(unsigned long src_addr, char *buf, unsigned long buf_size){
    int pos = 0;
    char tmp_val = 0;

    while(pos + 1 < buf_size
        && readmem(src_addr + pos, KVADDR,
                 &tmp_val, sizeof(char), "char", FAULT_ON_ERROR)
        && tmp_val != '\0'){
            buf[pos++] = tmp_val;
        }
        buf[pos] = '\0';
        return pos;
}

const char *scsi_command_names[256] = {
    [0x00] = "TUR",
    [0x03] = "REQ-SENSE",
    [0x08] = "READ(6)",
    [0x0a] = "WRITE(6)",
    [0x12] = "INQUIRY",
    [0x16] = "RESERVE(6)",
    [0x17] = "RELEASE(6)",
    [0x25] = "READ-CAP(10)",
    [0x28] = "READ(10)",
    [0x2a] = "WRITE(10)",
    [0x35] = "SYNC CACHE",
    [0x41] = "WR SAME",
    [0x56] = "RESERVE(10)",
    [0x57] = "RELEASE(10)",
    [0x88] = "READ(16)",
    [0x8a] = "WRITE(16)",
    [0xa0] = "REPORT LUNS",
    [0xa8] = "READ(12)",
    [0xaa] = "WRITE(12)",
};

static inline const char *scsi_opcode_to_string(unsigned long opcode) {
    return strlen(scsi_command_names[opcode]) ? scsi_command_names[opcode] : "OPCODE_UNKOWN";
}

/**
 * enum disk_type - Device type classification for block devices
 * @UNKNOWN: Undetermined or unsupported device type
 * @SCSI: Device using SCSI protocol (including SATA, SAS)
 * @NVME: Device using NVMe protocol (NVM Express)
 * @DISK_TYPE_NR: Boundary marker for enum values
 */
enum disk_type{
    UNKOWN,
    SCSI,
    NVME,
    DISK_TYPE_NR,
};

static inline int get_disk_type_by_name(char *disk_name_addr){

    if (strlen(disk_name_addr) > NVME_PREFIX_LENGTH
        && !strncmp(disk_name_addr, NVME_PREFIX, NVME_PREFIX_LENGTH)){
        return NVME;
    }else if(strlen(disk_name_addr) > SCSI_PREFIX_LENGTH
            && !strncmp(disk_name_addr, SCSI_PREFIX, SCSI_PREFIX_LENGTH)){
        return SCSI;
    } else {
        return UNKOWN;
    }
};

static void get_scsi_type_string(unsigned char sdev_type, char *type){
    unsigned long device_type_addr = symbol_value("scsi_device_types");

    log_format("device type addr 0x%lx\n", device_type_addr);
    readmem(device_type_addr + sdev_type * sizeof(unsigned long),
             KVADDR, &device_type_addr, sizeof(unsigned long), "unsigned long", FAULT_ON_ERROR);
    get_string(device_type_addr, type, MAX_DESC_LENGTH);
}

static void get_scsi_cmnd_opcode(unsigned long scsi_cmnd_addr, int *opcode){
    unsigned long cmnd_addr = 0;
    get_field(scsi_cmnd_addr, "scsi_cmnd", "cmnd", &cmnd_addr);
    readmem(cmnd_addr, KVADDR, opcode, sizeof(char), "char", FAULT_ON_ERROR);
}

/**
 * HZ determination:
 *   Uses machdep->hz from crash tool's machine-dependent data
 *   - This value is initialized during crash session setup
 *   - Falls back to 250 if machdep->hz is 0
 * Critical Warning: HZ Value May Be Inaccurate
 */
static inline double get_scsi_cmnd_age(struct request_info *req){
    unsigned int hz = machdep->hz;
    return ( ((double)g_cur_jiff - req->cmnd.alloc_time ) /(hz ? hz : 250));
}

static unsigned long get_class_klist_list_addr(unsigned long shost_class){
    long subsys_private_offset = 0;
    long klist_devices_offset = 0;
    unsigned long klist_devices_addr = 0, subsys_private_addr = 0;

    if ((subsys_private_offset = MEMBER_OFFSET("class", "p")) >= 0){
        if( (klist_devices_offset = MEMBER_OFFSET("subsys_private","klist_devices")) >= 0){
            get_field(shost_class, "class", "p", &subsys_private_addr);
            klist_devices_addr = subsys_private_addr + klist_devices_offset;
        } else {
            log_format("struct subsys_private do not have klist_devices");
        }
    } else {
        if ( (klist_devices_offset = MEMBER_OFFSET("class", "klist_devices")) >=0 ){
            log_format("struct class member klist_devices offset: 0x%lx\n", klist_devices_offset);
        } else {
            log_format("something wrong, dont find scsi device list\n");
        }
    }

    return klist_devices_addr;
}

static unsigned long get_device_elevator_name(unsigned long request_queue_addr){
    unsigned long elevator_queue_addr = 0;
    unsigned long elevator_type_addr = 0;
    unsigned long elevator_name_addr = 0;

    /* NVMe disks do not have a request_queue */
    get_field(request_queue_addr, "request_queue", "elevator", &elevator_queue_addr);
    if (0 == elevator_queue_addr){
        return elevator_queue_addr;
    }

    if (MEMBER_EXISTS("elevator_queue", "elevator_type")){
        get_field(elevator_queue_addr, "elevator_queue", "elevator_type", &elevator_type_addr);
        elevator_name_addr = elevator_type_addr + MEMBER_OFFSET("elevator_type", "elevator_name");
    }
    else if (MEMBER_EXISTS("elevator_queue", "type")){
        get_field(elevator_queue_addr, "elevator_queue", "type", &elevator_type_addr);
        elevator_name_addr = elevator_type_addr + MEMBER_OFFSET("elevator_type", "elevator_name");
    } else {
        fprintf(fp, "request queue type unkown");
    }

    return elevator_name_addr;
}

static unsigned int get_sbitmap_depth(unsigned long sbitmap_addr, unsigned int idx){
    unsigned int depth = 0;
    unsigned int tags_shift = 0, tags_depth = 0, tags_map_nr = 0;

    get_field(sbitmap_addr, "sbitmap", "shift", &tags_shift);
    get_field(sbitmap_addr, "sbitmap", "depth", &tags_depth);
    get_field(sbitmap_addr, "sbitmap", "map_nr", &tags_map_nr);
    if (STRUCT_EXISTS("blk_mq_bitmap_tags")){
        fprintf(fp, "blk mq bitmap tags exist, error\n");
    } else {
        depth = 1 << tags_shift;
        if (idx == tags_map_nr - 1){
            depth = tags_depth - depth * idx;
        }
    }

    return depth;
}

static unsigned long get_bio_sector(unsigned long bio_addr){
    unsigned long sector = 0;
    unsigned long bi_iter_addr = 0;

    if (MEMBER_EXISTS("bio", "bi_sector")){
        get_field(bio_addr, "bio", "bi_sector", &sector);
    }else{
        bi_iter_addr = bio_addr + MEMBER_OFFSET("bio", "bi_iter");
        get_field(bi_iter_addr, "bvec_iter", "bi_sector", &sector);
    }
    return sector;
}

static int is_vaild_request(unsigned long request_addr, unsigned long queue_addr){
    int ret = FALSE;
    unsigned long request_q_addr = 0;
    unsigned long request_refcnt = 0;
    get_field(request_addr, "request", "q", &request_q_addr);
    if(request_q_addr  == queue_addr){
        get_refcnt_value(request_addr + MEMBER_OFFSET("request", "ref"), &request_refcnt);
        if(request_refcnt){
            ret = TRUE;
        }
    }else{
        log_format("request.q 0x%lx not equal to request queue addr 0x%lx\n",
                     request_q_addr, queue_addr);
    }
    return ret;
}

static void scsi_cmnd_parse_base_info(struct request_info *req)
{
    get_field(req->request_addr, "request", "timeout", &req->timeout);

    if (req->cmnd.cmnd_addr){
        get_scsi_cmnd_opcode(req->cmnd.cmnd_addr, &req->cmnd.opcode);
        get_field(req->cmnd.cmnd_addr, "scsi_cmnd", "jiffies_at_alloc", &req->cmnd.alloc_time);
    }else{
        log_format("request 0x%lx cnmd addr is null\n", req->request_addr);
    }

    if (req->bio.bio_addr){
        req->bio.sector = get_bio_sector(req->bio.bio_addr);
    }else{
        log_format("request 0x%lx bio addr is null\n", req->request_addr);
    }
}

static void request_parse_cmnd_info(struct request_info *req, int disk_type)
{
    get_field(req->request_addr, "request", "bio", &req->bio.bio_addr);
    get_field(req->request_addr, "request", "special", &req->cmnd.cmnd_addr);

    if (SCSI == disk_type){
        scsi_cmnd_parse_base_info(req);
    } else if(NVME == disk_type){
        //todo
    }
}

static void sbitmap_parse_request_info(struct gendisk_info* gendisk, unsigned long tags_addr, unsigned long offset, unsigned long rqs_addr)
{
    struct request_info *tmp = 0;
    unsigned int map_nr = 0, map_idx = 0, depth = 0, depth_idx = 0;
    unsigned long sbitmap_map_addr = 0;
    unsigned long request_addr = 0;
    unsigned long map_addr = 0;
    unsigned long word_clear = 0, word = 0;
    unsigned long tags_sb_addr = tags_addr + MEMBER_OFFSET("sbitmap_queue", "sb");
    unsigned long sbitmap_word_size = STRUCT_SIZE("sbitmap_word");

    get_field(tags_sb_addr, "sbitmap", "map", &sbitmap_map_addr);
    get_field(tags_sb_addr, "sbitmap", "map_nr", &map_nr);

    for (map_idx = 0; map_idx < map_nr; map_idx++){
        map_addr = sbitmap_map_addr + sbitmap_word_size * map_idx;
        get_field(map_addr, "sbitmap_word", "word", &word);
        if (MEMBER_EXISTS("sbitmap_word", "cleared")){
            get_field(map_addr, "sbitmap_word", "cleared", &word_clear);
            word &= (~word_clear);
            log_format("word after clear 0x%lx\n", word);
        }

        depth = get_sbitmap_depth(tags_sb_addr, map_idx);
        for (depth_idx = 0; depth_idx < depth; depth_idx++){
            if (word & 1){
                readmem(rqs_addr + offset * sizeof(unsigned long), KVADDR,
                        &request_addr, sizeof(unsigned long), "unsigned long", FAULT_ON_ERROR);
                if(request_addr == 0){
                    log_format("bitmap set but request is null request_queue addr 0x%lx, "
                                "sbitmap_queue addr 0x%lx, rqs 0x%lx"
                                "tag map idx %d rqs offset %ld\n",
                                gendisk->request_queue_addr, tags_addr, rqs_addr, map_idx, offset);
                    continue;
                }
                if(is_vaild_request(request_addr, gendisk->request_queue_addr)){
                    tmp = calloc(1, sizeof(*tmp));
                    tmp->request_addr = request_addr;
                    request_parse_cmnd_info(tmp, gendisk->disk_type);
                    add_request_to_gendisk(gendisk, tmp);
                }
            }
            word >>= 1;
            offset++;
        }
    }
}

static void mq_tags_parse_request_info(struct gendisk_info *gendisk, unsigned long tags_addr)
{
    unsigned int nr_reserved_tags = 0;
    unsigned long rqs_addr = 0;
    unsigned long breserved_tags_addr = tags_addr + MEMBER_OFFSET("blk_mq_tags", "breserved_tags");
    unsigned long bitmap_tags = tags_addr + MEMBER_OFFSET("blk_mq_tags", "bitmap_tags");

    get_field(tags_addr, "blk_mq_tags", "nr_reserved_tags", &nr_reserved_tags);
    get_field(tags_addr, "blk_mq_tags", "rqs", &rqs_addr);
    sbitmap_parse_request_info(gendisk, breserved_tags_addr, 0, rqs_addr);
    sbitmap_parse_request_info(gendisk, bitmap_tags, nr_reserved_tags, rqs_addr);
    return;
}

static int gendisk_parse_request_info(struct gendisk_info *gendisk){
    int ret = 0, idx = 0;
    unsigned long hctx = 0;
    unsigned long hctx_tags = 0;
    unsigned long nr_hw_queues = 0;
    unsigned long hctx_sched_tags = 0;
    unsigned long queue_hw_ctx_addr = 0;

    if (FALSE == MEMBER_EXISTS("request_queue", "mq_ops")){
        fprintf(fp, "member mq_ops not exist in request_queue");
        ret = -ENODEV;
        goto out;
    }

    get_field(gendisk->request_queue_addr, "request_queue", "nr_hw_queues", &nr_hw_queues);
    get_field(gendisk->request_queue_addr, "request_queue", "queue_hw_ctx", &queue_hw_ctx_addr);

    for (idx = 0; idx <nr_hw_queues; idx++){
        readmem(queue_hw_ctx_addr + idx * sizeof(unsigned long),
                KVADDR, &hctx, sizeof(unsigned long),
                "unsigned long", FAULT_ON_ERROR);
        log_format("get hctx addr 0x%xlx, queue_hw_ctx_addr 0x%lx\n", hctx, queue_hw_ctx_addr);
        get_field(hctx, "blk_mq_hw_ctx", "tags", &hctx_tags);
        get_field(hctx, "blk_mq_hw_ctx", "sched_tags", &hctx_sched_tags);
        if (hctx_tags)
            mq_tags_parse_request_info(gendisk, hctx_tags);
        if (hctx_sched_tags)
            mq_tags_parse_request_info(gendisk, hctx_sched_tags);
    }

out:
    return ret;
}

static int gendisk_parse_base_info(struct gendisk_info *gendisk)
{
    int ret = 0;
    unsigned long disk_name_addr = 0;
    unsigned long device_elevator_name_addr = 0;

    //先判断是否有request queue分配，分区情况下queue可能为0
    get_field(gendisk->gendisk_addr, "gendisk", "queue", &gendisk->request_queue_addr);
    if (!gendisk->request_queue_addr) {
        log_format("gendisk addr 0x%lx request queue is NULL\n", gendisk->gendisk_addr);
        ret = -ENODEV;
        goto out;
    }

    disk_name_addr = gendisk->gendisk_addr + MEMBER_OFFSET("gendisk", "disk_name");
    get_string(disk_name_addr, gendisk->disk_name, MAX_DESC_LENGTH);
    gendisk->disk_type = get_disk_type_by_name(gendisk->disk_name);
    log_format("get disk type %d, gendisk disk name %s\n", gendisk->disk_type, gendisk->disk_name);

    device_elevator_name_addr = get_device_elevator_name(gendisk->request_queue_addr);
    if (device_elevator_name_addr){
        get_string(device_elevator_name_addr, gendisk->elevator_type, MAX_DESC_LENGTH);
        log_format("elevator name addr: 0x%lx, name: %s\n", device_elevator_name_addr, gendisk->elevator_type);
    }


out:
    return ret;
}

static int block_class_parse_gendisk_info(struct block_class_info *block_class)
{
    int ret = 0;
    struct gendisk_info *tmp = 0;
    unsigned long klist_addr = 0, gendisk_addr = 0;
    unsigned long list_head_next = 0, list_head_base_addr = 0;
    unsigned long hd_struct_addr = 0, device_addr = 0;
    unsigned long klist_knode_offset = MEMBER_OFFSET("klist_node", "n_node");
    unsigned long klist_list_head_offset = MEMBER_OFFSET("klist", "k_list");
    unsigned long knode_class_offset = MEMBER_OFFSET("device", "knode_class");
    unsigned long hd_struct_dev_offset = MEMBER_OFFSET("hd_struct", "__dev");
    unsigned long gendisk_part_offset = MEMBER_OFFSET("gendisk", "part0");

    klist_addr = get_class_klist_list_addr(block_class->block_class_addr);
    list_head_base_addr = klist_addr + klist_list_head_offset;

    list_for_each(list_head_next, list_head_base_addr){
        device_addr = list_head_next - klist_knode_offset - knode_class_offset;
        hd_struct_addr = device_addr - hd_struct_dev_offset;
        gendisk_addr = hd_struct_addr - gendisk_part_offset;

        tmp = calloc(1, sizeof(*tmp));
        tmp-> gendisk_addr = gendisk_addr;
        if ((ret = gendisk_parse_base_info(tmp)) < 0){
            log_format("parse gendisk 0x%lx base info failed, errno :%d\n",
                     tmp->gendisk_addr, ret);
            ret = -EINVAL;
            goto out;
        }
        add_gendisk_to_class(&g_block_class_info, tmp);
    }

out:
    return ret;
}

static int block_class_parse_info(){
    int ret = 0;
    g_block_class_info.block_class_addr = symbol_value("block_class");
    ret = block_class_parse_gendisk_info(&g_block_class_info);
    return ret;
}

static void block_class_cleanup_info()
{
    log_format("cleanup gendisk info\n");
    struct gendisk_info *cur_disk, *tmp_disk;
    struct request_info *cur_req, *tmp_req;

    for_each_gendisk_safe(&g_block_class_info, cur_disk, tmp_disk){
        for_each_request_safe(cur_disk, cur_req, tmp_req){
            free(cur_req);
        }
        cur_disk->request_tail = NULL;

        if (cur_disk->scsi_device_info){
            cur_disk->scsi_device_info->gendisk_info = NULL;
        }

        free(cur_disk);
    }
}

static void gendisk_scsi_req_dump(struct gendisk_info *gendisk){
    int idx = 1;
    struct request_info *req, *tmp;
    fprintf(fp, "%-10s %-20s %-20s %-18s %-10s %-20s %-20s %-10s\n",
        "NO.", "REQUEST", "BIO", "SCSI CMND", "OPCODE", "CMMAND Age(s)","CMMAND Age(Jiffies)", "SECTOR");
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");
    for_each_request_safe(gendisk, req, tmp){
        if (req->cmnd.cmnd_addr){
            fprintf(fp, "%-3d %-3s 0x%-18lx 0x%-20lx 0x%-20lx %-14s %-10.3f(%ld) 0x%-15lx\n",
                        idx++, "", req->request_addr, req->bio.bio_addr, req->cmnd.cmnd_addr,
                        scsi_opcode_to_string(req->cmnd.opcode),
                         get_scsi_cmnd_age(req),
                        g_cur_jiff - req->cmnd.alloc_time,
                    req->bio.sector );
        }else{
            fprintf(fp, "%-3d %-3s 0x%-18lx 0x%-20lx 0x%-20s %-14s %-12s 0x%-15lx\n",
                idx++, "", req->request_addr, req->bio.bio_addr,
                "not exist ","not exist", "not exist", req->bio.sector);
        }
    }
    if (idx == 1){
        fprintf(fp, "<<< NO I/O REQUESTS FOUND ON THE DEVICE! >>>");
    }
}

static void gendisk_scsi_cmnd_dump(struct gendisk_info *gendisk)
{
    int idx = 1;
    struct request_info *req, *tmp;
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");
    for_each_request_safe(gendisk, req, tmp){
        fprintf(fp, "|-%d scsi_cmnd 0x%lx on scsi_device 0x%lx request: 0x%lx, req timeout jiffies %d"
                " cmnd jiffies_at_alloc: %ld\n",
                idx++,
                req->cmnd.cmnd_addr,
                gendisk->scsi_device_info->sdev_addr,
                req->request_addr,
                req->timeout,
                req->cmnd.alloc_time
            );
    }
    if (idx == 1){
        fprintf(fp, "<<< NO SCSI CMND FOUND ON THE DEVICE! >>>\n");
    }
}

static void gendisk_scsi_info_dump(struct gendisk_info *gendisk, int with_request)
{
    fprintf(fp, "\n==========================================================="
                 "============================================================\n");
    fprintf(fp, "### DEVICE: %s\n", gendisk->disk_name);
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");
    fprintf(fp, "gendisk       : 0x%-24lx    |    scsi_device : 0x%lx\n",
            gendisk->gendisk_addr, gendisk->scsi_device_info->sdev_addr);
    fprintf(fp, "request_queue : 0x%-24lx    |    H:C:T:L     : %d:%d:%d:%d\n",
            gendisk->request_queue_addr, gendisk->scsi_device_info->host_no,
            gendisk->scsi_device_info->sdev_channel, gendisk->scsi_device_info->sdev_id,
            gendisk->scsi_device_info->sdev_lun);
    fprintf(fp, "elevator_name : %-24s       |    Vendor/Model : %s\n",
            gendisk->elevator_type, gendisk->scsi_device_info->vendor);
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");

    if (with_request){
            gendisk_scsi_req_dump(gendisk);
    }
}

static void gendisk_nvme_info_dump(struct gendisk_info *gendisk, int with_request)
{
    fprintf(fp, "\n==========================================================="
                 "============================================================\n");
    fprintf(fp, "### DEVICE: %s\n", gendisk->disk_name);
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");
    fprintf(fp, "gendisk       : 0x%-24lx    |    nvme_device : 0x%s\n",
            gendisk->gendisk_addr, "-NA-");
    fprintf(fp, "request_queue : 0x%-24lx    |    H:C:T:L     : %d:%d:%d:%d\n",
            gendisk->request_queue_addr, 0,0,0,0);
    fprintf(fp, "elevator_name : %-24s       |    Vendor/Model : %s%s\n",
            gendisk->elevator_type, "-NA-","-NA-");
    fprintf(fp, "-----------------------------------------------------------"
        "-----------------------------------------------------------\n");

    if (with_request){
            fprintf(fp, "todo nvme cmnd dump\n");
    }
}

static void block_hierarchy_dump(int with_req){
    int ret = 0;
    struct gendisk_info *gendisk;
    struct gendisk_info *tmp;

    fprintf(fp, "===================================================================="
        "====================================================================\n");
    fprintf(fp, "block_class_addr :0x%lx\n", g_block_class_info.block_class_addr);
    for_each_gendisk_safe(&g_block_class_info, gendisk, tmp){
        if(SCSI == gendisk->disk_type){
            if ((ret = gendisk_parse_request_info(gendisk)) < 0){
                fprintf(fp, "parse device %s cmnd failed, gendisk addr 0x%lx, "
                        "request queue addr 0x%lx\n",
                        gendisk->disk_name, gendisk->gendisk_addr,
                        gendisk->request_queue_addr);
                continue;
            }
            gendisk_scsi_info_dump(gendisk, with_req);
        } else {
            //TODO NVME INFO DUMP
        }

    }
}

static void scsi_device_parse_channel_info(struct scsi_device_info *scsi_device){
    unsigned long scsi_host_addr = scsi_device->sdev_addr + MEMBER_OFFSET("scsi_device", "host");

    get_field(scsi_host_addr, "Scsi_Host", "host_no", &scsi_device->host_no);
    get_field(scsi_device->sdev_addr, "scsi_device", "id", &scsi_device->sdev_id);
    get_field(scsi_device->sdev_addr, "scsi_device", "channel", &scsi_device->sdev_channel);
    get_field(scsi_device->sdev_addr, "scsi_device", "lun", &scsi_device->sdev_lun);
}

static void scsi_device_parse_iocnt(struct scsi_device_info *scsi_device){
    unsigned long io_request_atomic_addr = scsi_device->sdev_addr + MEMBER_OFFSET("scsi_device" , "iorequest_cnt");
    unsigned long io_done_atomic_addr = scsi_device->sdev_addr + MEMBER_OFFSET("scsi_device", "iodone_cnt");
    unsigned long io_err_cnt_atomic_addr = scsi_device->sdev_addr + MEMBER_OFFSET("scsi_device", "ioerr_cnt");

    get_atomic_value(io_request_atomic_addr, &scsi_device->io_request_cnt);
    get_atomic_value(io_done_atomic_addr, &scsi_device->io_done_cnt);
    get_atomic_value(io_err_cnt_atomic_addr, &scsi_device->io_err_cnt);

    return;
}

static void scsi_device_parse_desc_info(struct scsi_device_info *scsi_device){
    unsigned long scsi_vendor_addr = 0;
    unsigned long scsi_model_addr = 0;
    unsigned long scsi_rev_addr = 0;

    get_field(scsi_device->sdev_addr, "scsi_device", "vendor", &scsi_vendor_addr);
    get_field(scsi_device->sdev_addr, "scsi_device", "model", &scsi_model_addr);
    get_field(scsi_device->sdev_addr, "scsi_device", "rev", &scsi_rev_addr);

    get_string(scsi_rev_addr, scsi_device->rev, MAX_DESC_LENGTH);
    get_string(scsi_model_addr, scsi_device->model, MAX_DESC_LENGTH);
    get_string(scsi_vendor_addr, scsi_device->vendor, MAX_DESC_LENGTH);

    return;
}

static void scsi_device_parse_base_info(struct scsi_device_info *scsi_device){
    get_field(scsi_device->sdev_addr, "scsi_device", "request_queue", &scsi_device->request_queue_addr);
    get_field(scsi_device->sdev_addr, "scsi_device", "sdev_state", &scsi_device->sdev_state);
    get_field(scsi_device->sdev_addr, "scsi_device", "type", &scsi_device->sdev_type);
    get_scsi_type_string(scsi_device->sdev_type, scsi_device->scsi_type);
    return;
}

static int scsi_host_parse_device_info(struct scsi_host_info *scsi_host){
    int ret = 0;
    long device_offset = 0, siblings_offset = 0;
    struct scsi_device_info *tmp_device = 0;
    unsigned long device_list_base_addr = 0, list_head_next = 0;
    unsigned long scsi_dev_addr = 0;

    device_offset = MEMBER_OFFSET("Scsi_Host", "__devices");
    siblings_offset = MEMBER_OFFSET("scsi_device", "siblings");
    if (device_offset < 0|| siblings_offset <0) {
        log_format("get device_offset 0x%ld, siblings_offset 0x%ld\n", device_offset, siblings_offset);
        ret = -ENODEV;
        goto out;
    }

    device_list_base_addr = scsi_host->scsi_host_addr + device_offset;
    list_for_each(list_head_next, device_list_base_addr){
        scsi_dev_addr = list_head_next - siblings_offset;
        tmp_device = calloc(1, sizeof(*tmp_device));
        tmp_device->sdev_addr = scsi_dev_addr;

        scsi_device_parse_base_info(tmp_device);
        scsi_device_parse_channel_info(tmp_device);
        scsi_device_parse_desc_info(tmp_device);
        scsi_device_parse_iocnt(tmp_device);
        add_device_to_host(scsi_host, tmp_device);
        log_format("add scsi_device 0x%lx request queue 0x%lx to scsi host 0x%lx info\n",
                     tmp_device->sdev_addr, tmp_device->request_queue_addr, scsi_host->scsi_host_addr);
    }

out:
    return ret;
}

static void scsi_target_parse_name(struct scsi_target_info *scsi_target)
{
    unsigned long scsi_target_device_offset = 0;
    unsigned long device_kobj_offset = 0;
    unsigned long kobj_name_addr = 0;

    scsi_target_device_offset = MEMBER_OFFSET("scsi_target", "dev");
    device_kobj_offset = MEMBER_OFFSET("device", "kobj");
    kobj_name_addr = scsi_target->scsi_target_addr + scsi_target_device_offset + device_kobj_offset;
    get_field(kobj_name_addr, "kobject", "name", &kobj_name_addr);
    get_string(kobj_name_addr, scsi_target->target_name, MAX_DESC_LENGTH);

    return;
}

static void scsi_target_parse_base_info(struct scsi_target_info *scsi_target)
{
    unsigned long target_busy_offset = 0;
    unsigned long target_block_offset = 0;

    target_busy_offset = MEMBER_OFFSET("scsi_target", "target_busy");
    target_block_offset = MEMBER_OFFSET("scsi_target", "target_blocked");

    scsi_target_parse_name(scsi_target);
    get_field(scsi_target->scsi_target_addr, "scsi_target", "id", &scsi_target->target_id);
    get_field(scsi_target->scsi_target_addr, "scsi_target", "state", &scsi_target->target_state);
    get_field(scsi_target->scsi_target_addr, "scsi_target", "channel", &scsi_target->target_channel);
    get_atomic_value(scsi_target->scsi_target_addr + target_block_offset, &scsi_target->target_block);
    get_atomic_value(scsi_target->scsi_target_addr + target_busy_offset, &scsi_target->target_busy);

    return;
}

static int scsi_host_parse_target_info(struct scsi_host_info *scsi_host)
{
    int ret = 0;
    long target_offset = 0, siblings_offset = 0;
    struct scsi_target_info *tmp_tgt = 0;
    unsigned long target_list_base_addr = 0, list_head_next = 0;
    unsigned long scsi_target_addr = 0;

    target_offset = MEMBER_OFFSET("Scsi_Host", "__targets");
    siblings_offset = MEMBER_OFFSET("scsi_target", "siblings");
    if (target_offset < 0|| siblings_offset <0) {
        log_format("get target_offset 0x%ld, siblings_offset 0x%ld\n",
                    target_offset, siblings_offset);
        ret =  -ENODEV;
        goto out;
    }

    target_list_base_addr = scsi_host->scsi_host_addr + target_offset;
    list_for_each(list_head_next, target_list_base_addr){
        scsi_target_addr = list_head_next - siblings_offset;
        tmp_tgt = calloc(1, sizeof(*tmp_tgt));
        tmp_tgt->scsi_target_addr = scsi_target_addr;

        scsi_target_parse_base_info(tmp_tgt);
        add_target_to_host(scsi_host, tmp_tgt);
        log_format("add scsi_target 0x%lx to scsi host 0x%lx info\n",
                     tmp_tgt->scsi_target_addr, scsi_host->scsi_host_addr);
    }

out:
    return ret;
}

static inline void scsi_host_parse_base_info(struct scsi_host_info *scsi_host){
    unsigned long hostt_module_addr;
    unsigned long host_name_addr = 0;
    unsigned long host_busy_addr = 0;
    unsigned long host_block_addr = 0;
    unsigned long module_version_addr = 0;

    host_busy_addr = scsi_host->scsi_host_addr + MEMBER_OFFSET("Scsi_Host", "host_busy");
    host_block_addr = scsi_host->scsi_host_addr + MEMBER_OFFSET("Scsi_Host", "host_blocked");

    host_name_addr = scsi_host->scsi_host_addr + MEMBER_OFFSET("Scsi_Host", "shost_gendev");
    host_name_addr += MEMBER_OFFSET("device", "kobj");
    get_field(host_name_addr, "kobject", "name", &host_name_addr);
    log_format("shost_gendev addr 0x%lx\n", host_name_addr);
    get_string(host_name_addr, scsi_host->host_name, MAX_DESC_LENGTH);
    log_format("kobject name 0x%lx", host_name_addr);

    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "hostt", &hostt_module_addr);
    get_field(hostt_module_addr, "scsi_host_template", "module", &hostt_module_addr);
    get_field(hostt_module_addr, "module", "taints", &scsi_host->taints);
    get_field(hostt_module_addr, "module", "version", &module_version_addr);

    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "max_lun", &scsi_host->max_lun);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "shost_data", &scsi_host->shost_data);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "shost_state", &scsi_host->host_state);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "host_failed", &scsi_host->host_failed);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "eh_deadline", &scsi_host->eh_deadline);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "cmd_per_lun", &scsi_host->cmd_per_lun);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "nr_hw_queues", &scsi_host->nr_hw_queue);
    get_field(scsi_host->scsi_host_addr, "Scsi_Host", "host_self_blocked", &scsi_host->host_self_block);

    get_string(hostt_module_addr + MEMBER_OFFSET("module", "name"), scsi_host->driver_name, MAX_DESC_LENGTH);
    get_string(module_version_addr, scsi_host->hostt_version, MAX_DESC_LENGTH);
    log_format("host state 0x%d\n", scsi_host->host_state);

    get_atomic_value(host_busy_addr, &scsi_host->host_busy);
    get_atomic_value(host_block_addr, &scsi_host->host_block);
    //TODO
    //get_field(scsi_host->scsi_host_addr, "Scsi_Host", "hostdata", &scsi_host->hostdata);

}

static int shost_class_parse_scsi_host_info(struct shost_class_info *shost_class_info){
    int ret = 0;
    struct scsi_host_info *tmp_host = 0;
    unsigned long list_head_base_addr = 0, list_head_next = 0;
    unsigned long device_addr = 0, klist_addr = 0;
    unsigned long scsi_host_addr = 0, device_knode_addr = 0;

    unsigned long knode_node_offset = MEMBER_OFFSET("klist_node", "n_node");
    unsigned long klist_list_head_offset =  MEMBER_OFFSET("klist", "k_list");
    unsigned long device_knode_class_offset = MEMBER_OFFSET("device", "knode_class");
    unsigned long shost_dev_offset = MEMBER_OFFSET("Scsi_Host", "shost_dev");


    if (0 == (klist_addr = get_class_klist_list_addr(shost_class_info->shost_class_addr)))
    {
        ret = -ENODEV;
        goto out;
    }

    list_head_base_addr = klist_addr + klist_list_head_offset;
    list_for_each(list_head_next, list_head_base_addr)
    {
        device_knode_addr = list_head_next;
        device_addr = device_knode_addr - knode_node_offset - device_knode_class_offset;
        scsi_host_addr = device_addr - shost_dev_offset;
        tmp_host = calloc(1, sizeof(*tmp_host));
        tmp_host->scsi_host_addr = scsi_host_addr;
        scsi_host_parse_base_info(tmp_host);
        add_host_to_class(&g_shost_info, tmp_host);
        log_format("get scsi host addr 0x%lx\n", tmp_host->scsi_host_addr);

        if((ret = scsi_host_parse_device_info(tmp_host)) < 0){
            log_format("parse tmp host 0x%lx device failed\n", tmp_host);
            break;
        }

        if ((ret = scsi_host_parse_target_info(tmp_host)) < 0){
            log_format("parse tmp host 0x%lx target failed\n", tmp_host);
            break;
        }
    }

out:
    return ret;
}

static int shost_class_parse_info(){
    int ret = 0;
    g_shost_info.shost_class_addr =  symbol_value("shost_class");
    ret = shost_class_parse_scsi_host_info(&g_shost_info);
    return ret;
}

static void link_device_to_gendisk()
{
    int find_gendisk = FALSE;
    struct scsi_device_info *device, *tmp_device;
    struct scsi_host_info   *host, *tmp_host;
    struct gendisk_info     *gendisk, *tmp_gendisk;

    for_each_host_safe(&g_shost_info, host, tmp_host){
        for_each_device_safe(host, device, tmp_device){
            find_gendisk = 0;
            for_each_gendisk_safe(&g_block_class_info, gendisk, tmp_gendisk){
                if (gendisk->request_queue_addr == device->request_queue_addr){
                    gendisk->scsi_device_info = device;
                    device->gendisk_info = gendisk;
                    find_gendisk = TRUE;
                }
            }
            if (FALSE == find_gendisk){
                tmp_gendisk = calloc(1, sizeof(*tmp_gendisk));
                tmp_gendisk->request_queue_addr = device->request_queue_addr;
                tmp_gendisk->scsi_device_info = device;
                device->gendisk_info = tmp_gendisk;
                log_format("no gendisk bound to device 0x%lx request queue 0x%lx\n",
                         device->sdev_addr, device->request_queue_addr);
            }
        }
    }
}

static void shost_class_cleanup_info()
{
    struct scsi_host_info *cur_host, *tmp_host;
    struct scsi_device_info *cur_dev, *tmp_dev;
    struct scsi_target_info *cur_tgt, *tmp_tgt;

    for_each_host_safe(&g_shost_info, cur_host, tmp_host){
        for_each_device_safe(cur_host, cur_dev, tmp_dev){
            if (cur_dev->gendisk_info){
                log_format("free virtual request_queue 0x%lx gendisk info addr\n",
                         cur_dev->request_queue_addr);
                free(cur_dev->gendisk_info);
            }
            free(cur_dev);
        }

        for_each_target_safe(cur_host, cur_tgt, tmp_tgt){
            free(cur_tgt);
        }

        log_format("free host addr 0x%lx\n", cur_host->scsi_host_addr);
        free(cur_host);
    }
}

const char * const host_state_strs[8] = {
    "SHOST_UNKOWN",
    "SHOST_CREATED",
    "SHOST_RUNNING",
    "SHOST_CANCEL",
    "SHOST_DEL",
    "SHOST_RECOVERY",
    "SHOST_CANCEL_RECOVERY",
    "SHOST_DEL_RECOVERY",
};

static const char *host_state_to_str(unsigned int state){
    if (state > 1 && state < 7)
        return host_state_strs[state];

    return "SHOST_UNKOWN";
}

static void shost_head_info_dump(struct scsi_host_info *host){
    fprintf(fp, "%-10s    %-22s %-24s %-24s %-24s\n", "HOST NAME", "DRIVER NAME", "Scsi_Host",
            "shost_data", "hostdata");
    fprintf(fp, "--------------------------------------------------"
            "-------------------------------------------------\n");
    fprintf(fp, "%-10s %-22s %12lx %24lx %24lx\n",
        host->host_name, host->driver_name, host->scsi_host_addr, host->shost_data, host->hostdata);
}

static void shost_detail_info_dump()
{
    struct scsi_host_info *host;
    struct scsi_host_info *tmp;
    for_each_host_safe(&g_shost_info, host, tmp){
        fprintf(fp, "===================================================================="
            "====================================================================\n");
        shost_head_info_dump(host);
        fprintf(fp, "  Driver version        : %s\n", host->hostt_version);
        fprintf(fp, "  Taints bitmask        : 0x%lx\n", host->taints);
        fprintf(fp, "\n");
        fprintf(fp, "  host_busy             : %d\n", host->host_busy);
        fprintf(fp, "  host_blocked          : %d\n", host->host_block);
        fprintf(fp, "  host_failed           : %d\n", host->host_failed);
        fprintf(fp, "  host_self_blocked     : %d\n", host->host_self_block & 0x10);
        fprintf(fp, "  shost_state           : %s(%d)\n", host_state_to_str(host->host_state),
                                                    host->host_state);
        fprintf(fp, "  eh_deadline           : %d\n", host->eh_deadline);
        fprintf(fp, "  max_lun               : %ld\n", host->max_lun);
        fprintf(fp, "  cmd_per_lun           : %d\n",host->cmd_per_lun );
        fprintf(fp, "  work_q_name           : %s\n", host->work_q_name);
        fprintf(fp, "  nr_hw_queues          : %d\n", host->nr_hw_queue);
    }
}

const char * const target_state_strs[6] = {
    "STARGET_UNKOWN",           /* = 0 */
    "STARGET_CREATED",          /* = 1 */
    "STARGET_RUNNING",          /* = 2 */
    "STARGET_REMOVE",           /* = 3 */
    "STARGET_CREATED_REMOVE",   /* = 4 */
    "STARGET_DEL",              /* = 5 */
};
static const char* scsi_target_state_str(unsigned int state){
    if (state >= 1 && state <=5) {
        return target_state_strs[state];
    }

    return "STARGET_UNKOWN";
}

static inline void scsi_target_info_dump(struct scsi_target_info *target)
{
    fprintf(fp, "%-24s %-18lx    %-8d %-4d     %-16s     %-ld     %-ld\n",
        target->target_name, target->scsi_target_addr, target->target_channel,
        target->target_id, scsi_target_state_str(target->target_state),
        target->target_busy, target->target_block);
}

static void scsi_target_dump()
{
    struct scsi_host_info *host, *tmp_host;
    struct scsi_target_info *target, *tmp_target;

    fprintf(fp, "===================================================================="
        "====================================================================\n");
    for_each_host_safe(&g_shost_info, host, tmp_host){
            /* dump 存在device的 scsi host */
        if (host->targets){
            fprintf(fp, "===================================================================="
                    "====================================================================\n");
            shost_head_info_dump(host);
            fprintf(fp, "--------------------------------------------------------------------"
                "--------------------------------------------------------------------\n");
            fprintf(fp, "%-24s %-18s    %-8s %-4s     %-16s     %-10s     %-10s\n",
                "TARGET DEVICE", "scsi_target", "CHANNEL", "ID", "DEVICE STATE",
                "TARGET_BUSY", "TARGET_BLOCK");
            fprintf(fp, "--------------------------------------------------------------------"
                "--------------------------------------------------------------------\n");
            /* 循环dump scsi device*/
            for_each_target_safe(host, target, tmp_target){
                scsi_target_info_dump(target);
            }
        }
    }
}

const char * const state_strs[10] = {
    "SDEV_UNKOWN",           /* = 0 */
    "SDEV_CREATED",          /* = 1 */
    "SDEV_RUNNING",          /* = 2 */
    "SDEV_CANCEL",           /* = 3 */
    "SDEV_DEL",              /* = 4 */
    "SDEV_QUIESCE",          /* = 5 */
    "SDEV_OFFLINE",          /* = 6 */
    "SDEV_TRANSPORT_OFFLINE",/* = 7 */
    "SDEV_BLOCK",            /* = 8 */
    "SDEV_CREATED_BLOCK"     /* = 9 */
};
static const char* scsi_device_state_str(unsigned int state){
    if (state >= 1 && state <= 9) {
        return state_strs[state];
    }

    return "SDEV_UNKOWN";
}

static inline void scsi_device_info_dump(struct scsi_device_info *device){

    fprintf(fp, "%-12s %-18lx %3d:%3d:%3d:%3d %-12s %-16s %10ld %10ld (%6ld) %12ld\n",
        strlen(device->gendisk_info->disk_name) ? device->gendisk_info->disk_name : device->scsi_type,
        device->sdev_addr,
        device->host_no,
        device->sdev_id,
        device->sdev_channel,
        device->sdev_lun,
        device->vendor,
        scsi_device_state_str(device->sdev_state),
        device->io_request_cnt,
        device->io_done_cnt,
        device->io_request_cnt - device->io_done_cnt,
        device->io_err_cnt);
}

static void device_dump_cmnd(unsigned long device_addr)
{
    int ret = 0;
    struct gendisk_info *gendisk = 0, *tmp = 0;

    for_each_gendisk_safe(&g_block_class_info, gendisk, tmp){
        if (gendisk->scsi_device_info
            &&((gendisk->scsi_device_info->sdev_addr == device_addr
            || gendisk->nvme_device_info->nvme_device_addr == device_addr)
            || !device_addr)){
            if (NULL == gendisk->requests){
                fprintf(fp, "\nParsing device 0x%lx reqeust. This may take a while\n",
                    gendisk->scsi_device_info->sdev_addr);
                if ((ret = gendisk_parse_request_info(gendisk)) < 0){
                    fprintf(fp, "parse device %s cmnd failed, gendisk addr 0x%lx, "
                            "request queue addr 0x%lx\n",
                        gendisk->disk_name, gendisk->gendisk_addr,
                         gendisk->request_queue_addr);
                    return;
                }
            }

            if(SCSI == gendisk->disk_type){
                gendisk_scsi_cmnd_dump(gendisk);
            } else {
                gendisk_nvme_info_dump(gendisk, TRUE);
            }
        }

    }
}

static void device_dump_request(unsigned long device_addr)
{
    int ret = 0;
    struct gendisk_info *gendisk = 0, *tmp = 0;

    for_each_gendisk_safe(&g_block_class_info, gendisk, tmp){
        if (gendisk->scsi_device_info &&(gendisk->scsi_device_info->sdev_addr == device_addr
            || gendisk->nvme_device_info->nvme_device_addr == device_addr)){
            if (NULL == gendisk->requests){
                fprintf(fp, "Parsing device 0x%lx reqeust. This may take a while\n",
                    gendisk->scsi_device_info->sdev_addr);
                if ((ret = gendisk_parse_request_info(gendisk)) < 0){
                    fprintf(fp, "parse device %s cmnd failed, gendisk addr 0x%lx, request queue addr 0x%lx\n",
                        gendisk->disk_name, gendisk->gendisk_addr, gendisk->request_queue_addr);
                    return;
                }
            }
            if(SCSI == gendisk->disk_type){
                gendisk_scsi_info_dump(gendisk, TRUE);
            } else {
                gendisk_nvme_info_dump(gendisk, TRUE);
            }
        }

    }

}

static void shost_info_dump(struct scsi_host_info *host){
    struct scsi_device_info *device;
    struct scsi_device_info *tmp;
    /* dump 存在device的 scsi host */
    if (host->devices){
        fprintf(fp, "===================================================================="
                "====================================================================\n");
        shost_head_info_dump(host);
        fprintf(fp, "--------------------------------------------------------------------"
            "--------------------------------------------------------------------\n");
        fprintf(fp, "%-12s %-18s %-16s %-24s     %-16s     %10s     %10s  %6s  %12s\n",
            "DEV NAME", "scsi_device", "H:C:T:L", "Vendor/Model",
            "DEVICE STATE", "IOREQ-CNT", "IODONE-CNT(DIFF)", "", "IOERR-CNT");
        fprintf(fp, "--------------------------------------------------------------------"
            "--------------------------------------------------------------------\n");
        /* 循环dump scsi device*/
        for_each_device_safe(host, device, tmp){
            scsi_device_info_dump(device);
        }
    }
}

static void scsi_hierarchy_dump()
{
    struct scsi_host_info *host;
    struct scsi_host_info *tmp;
    fprintf(fp, "===================================================================="
        "====================================================================\n");
    fprintf(fp, "shost_class :0x%lx\n", g_shost_info.shost_class_addr);
    for_each_host_safe(&g_shost_info, host, tmp){
        shost_info_dump(host);
    }
}

static void system_parse_base_info(){
    get_symbol_data("jiffies", sizeof(unsigned long), &g_cur_jiff);
}

static char *help_info[] = {
    "usage: sdinfo",
    "scsi device(sd) information",
    "sdinfo [-c device_addr] [-C] [-q device_addr] [-Q] [-d] [-s] [-t]",
    "optional arguments:",
    "-c [device_addr]",
    "               show device SCSI commands",
    "-C",
    "               show SCSI commands for all devices (may take a while)",
    "-q [device_addr]",
    "               show device IO request, SCSI commands for request_queue",
    "-Q",
    "               show all devices IO request, SCSI commands for request_queue (may take a while)",
    "-d",
    "               show all scsi device info",
    "-s",
    "               show all scsi hosts info",
    "-t",
    "               show all scsi targets info"
};

static void print_scsi_info(void){
    int arg = 0;
    unsigned long device_addr = 0;

    while ((arg = getopt(argcnt, args, "dsc:Cq:Qt")) != EOF ){
        switch (arg){
            case 'd':
                scsi_hierarchy_dump();
                break;
            case 's':
                shost_detail_info_dump();
                break;
            case 'c':
                device_addr = stol(optarg, FAULT_ON_ERROR, NULL);
                device_dump_cmnd(device_addr);
                break;
            case 'C':
                fprintf(fp, "dumping cmnd for all devices. This may take a while\n");
                device_dump_cmnd(0);
                break;
            case 'q':
                device_addr = stol(optarg, FAULT_ON_ERROR, NULL);
                device_dump_request(device_addr);
                break;
            case 't':
                scsi_target_dump();
                break;
            case 'Q':
                log_format("print request info\n");
                fprintf(fp, "\ndumping request for all devices. This may take a while\n\n");
                block_hierarchy_dump(TRUE);
                break;
            default:
                log_format("error args\n");
                cmd_usage(pc->curcmd, SYNOPSIS);
                break;
        }

    }

    return;
}

static struct command_table_entry scsi_command_table[] = {
    {"sdinfo", print_scsi_info, help_info, 0},
};

void __attribute__((constructor)) scsi_info_init(){
    system_parse_base_info();
    block_class_parse_info();
    shost_class_parse_info();
    link_device_to_gendisk();
    register_extension(scsi_command_table);
    return;
}

void __attribute__((destructor)) scsi_info_fini(){
    block_class_cleanup_info();
    shost_class_cleanup_info();
    logfile_cleanup();
    return;
}