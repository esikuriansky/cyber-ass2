#ifndef KBLOCKERH
#define KBLOCKERH

#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>   /* Specifically, a module */
#include <net/sock.h> 
#include <linux/spinlock_types.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/path.h>
#include <linux/list.h>
#include <linux/skbuff.h> 
#include <linux/kernel.h>   /* We're doing kernel work */
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <asm/uaccess.h>    /* for copy_from_user */
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/delay.h>

#define CR0_WP  0x00010000

#define PROCFS_MAX_SIZE 1024
#define NETLINK_USER 31
#define PROCFS_NAME "KBlocker"
#define TIME_BUFFER_SIZE 50

#define MAX_PATH_LENGTH 200

// HASH RELATED
#define HASH_BUFFER_SIZE 64

// HISTORY
#define MAX_HISTORY			10
#define HISTORY_ENTRY_SIZE  250



// Hook 
asmlinkage long (*original_sys_execve)(const char __user *, const char __user *const __user *,
    const char __user *const __user *);

asmlinkage long hook_sys_execve(const char __user *f, const char __user *const __user *,
    const char __user *const __user *);

// Declarations , kblocker.c
ssize_t procfile_write(struct file *file, const char *buffer, size_t len, loff_t * off);
ssize_t procfile_read(struct file * file, char *buffer, size_t len, loff_t * off);

// Hash list functions.
int delete_hash(char *);
int add_hash(char *);
void free_list(void);
int is_hash_in_blacklist(char *);

char * get_full_path(char *, char **, int);

//History
struct mutex history_mutex;
static char * loaded_exec_str = "%s, %s: %s was loaded with pid %d\n[!] (%s)\n";
static char * loaded_py_str = "%s, %s: %s was loaded under python with pid %d\n[!] (%s)\n";
static char * blocked_str = "%s, %s: %s was blocked due to configuration. pid %d\n[!] (%s)\n";

// Proc file print variables 
static char *lastevents_header = "KBlocker - Last Events:\n";
static char *config_header = "KBlocker Current Configuration:\n";
static char *exec_block_enabled = "Executable Blocking Mode - Enabled\n";
static char *exec_block_disabled = "Executable Blocking Mode - Disabled\n";
static char *pscripts_enabled = "Python Scripts Blocking Mode - Enabled\n";
static char *pscripts_disabled = "Python Scripts Blocking Mode - Disabled\n";
static char *blocked_hashes = "SHA256 hashes to block: \n";


// History 
static struct 
{
    char events[MAX_HISTORY][HISTORY_ENTRY_SIZE];
    int next_index;
} history;

// Config struct w
struct config  
{
    int exec_monitor;
    int pscripts_monitor;
    int exec_block;
    int pscripts_block;
} cfg = { 1, 1, 1, 1};


// Proc file operations 
static struct file_operations file_ops = {  
    .owner = THIS_MODULE,
    .write = procfile_write,
    .read = procfile_read,
};

// Hash blacklist structures
struct {
	struct hash_node* head;
} blacklist;

struct hash_node
{
	char hash[HASH_BUFFER_SIZE];
	struct hash_node* next;
};


// NetLink 
static void nl_hash_response_msg(struct sk_buff *skb);
static void nl_hash_request_msg(char * filename);

struct semaphore sema;


struct netlink_kernel_cfg nl_cfg = {
        .input = nl_hash_response_msg,
};

#endif