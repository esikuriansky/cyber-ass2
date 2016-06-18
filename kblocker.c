/*
Source: http://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module/3334782#3334782
*/
#include "kblocker.h"

MODULE_LICENSE("GPL");


static struct proc_dir_entry *proc_file;     // This structure hold information about the /proc file
static char procfs_buffer[PROCFS_MAX_SIZE];  // The buffer used to store characters for this module
static unsigned long procfs_buffer_size = 0; // The size of the buffer

//Hooking related
char fullpath[MAX_PATH_LENGTH];
void ** system_call_table;
void ** orig_execve;
void * ptr_to_execve = NULL;
unsigned long cr0;

// Helper buffer for d_path 
char aux_buff[100];
char time_buffer[TIME_BUFFER_SIZE];

//Helper printing buffer
char print_help_buffer[HISTORY_ENTRY_SIZE];

// Lock
DEFINE_SPINLOCK(lock);

// NetLink
struct sock *nl_sk = NULL;
int user_program_pid = -1; 
char hash_ans[HASH_BUFFER_SIZE];

static int finished = 0 ;
static int read_offset = 0;
static int can_proceed = 0;   // Busy wait for answer


static void nl_hash_response_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;

    if( user_program_pid == -1)
    {   
        nlh = (struct nlmsghdr *)skb->data;
        user_program_pid = nlh->nlmsg_pid;  /*pid of sending process */
        printk(KERN_INFO "[*] KBlocker recieved init msg. Pid is : %d\n", user_program_pid);
    }
    else
    {
        msg_size = strlen(msg);
        nlh = (struct nlmsghdr *)skb->data;
        printk(KERN_INFO "[*] KBlocker received msg payload: %s\n", (char *)nlmsg_data(nlh)); 
        strncpy(hash_ans, (char *)nlmsg_data(nlh), HASH_BUFFER_SIZE);
        up(&sema);
    }
    // nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    // NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    // strncpy(nlmsg_data(nlh), msg, msg_size);

    // res = nlmsg_unicast(nl_sk, skb_out, pid);
    // if (res < 0)
    //     printk(KERN_INFO "Error while sending back to user\n");

}

static void nl_hash_request_msg(char * filename)
{

    struct nlmsghdr *nlh;
    int msg_size = strlen(filename);
    struct sk_buff *skb_out = nlmsg_new(msg_size, 0);

    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return -1;
    }
    
    int res;

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), filename, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, user_program_pid);

    if ( res < 0 )
        printk(KERN_INFO "Error while sending back to user\n");

    // nlmsg_end(skb_out, nlh);
}

int update_config()
{
    int length = (int) (strchr(procfs_buffer, ' ') - procfs_buffer);

    if( strncmp(procfs_buffer, "ExecMon", length) == 0)
    {
        if(strncmp(procfs_buffer+length, " 1\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ExecMon was set to 1");
            cfg.exec_monitor = 1;
            return 1;
        }
        else if(strncmp(procfs_buffer+length, " 0\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ExecMon was set to 0");
            cfg.exec_monitor = 0;
            return 1;
        }
    }
    else if( strncmp(procfs_buffer, "ExecBlock", length) == 0)
    {
       if(strncmp(procfs_buffer+length, " 1\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ExecBlock was set to 1");
            cfg.exec_block = 1;
            return 1;
        }
        else if(strncmp(procfs_buffer+length, " 0\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ExecBlock was set to 0");
            cfg.exec_block = 0;
            return 1;
        }
    }
    else if( strncmp(procfs_buffer, "ScriptMon", length) == 0)
    {
       if(strncmp(procfs_buffer+length, " 1\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ScriptMon was set to 1");
            cfg.pscripts_monitor = 1;
            return 1;
        }
        else if(strncmp(procfs_buffer+length, " 0\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ScrpitMon was set to 0");
            cfg.pscripts_monitor = 0;
            return 1;
        }
    }
    else if( strncmp(procfs_buffer, "ScriptBlock", length) == 0)
    {
        if(strncmp(procfs_buffer+length, " 1\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ScriptBlock was set to 1");
            cfg.pscripts_block = 1;
            return 1;
        }
        else if(strncmp(procfs_buffer+length, " 0\n", 3) == 0)
        {
            printk(KERN_INFO "[*] ScriptBlock was set to 0");
            cfg.pscripts_block = 0;
            return 1;
        }
    }
    else if( strncmp(procfs_buffer, "AddHash", length) == 0)
    {
        int ret = add_hash(&procfs_buffer[8]);
        if(ret == -1)
        {
            printk(KERN_ERR "[!] Could not add hash !\n");   
            return -1;
        }
        printk(KERN_INFO "[*] Added hash: %s \n", &procfs_buffer[8]);
        return 1;
    }
    else if( strncmp(procfs_buffer, "DelHash", length) == 0)
    {
        printk(KERN_INFO "[*] Removing hash: %s\n", &procfs_buffer[8]);   
        int ret = delete_hash(&procfs_buffer[8]);
        if(ret == -1)
        {
            printk(KERN_ERR "[!] Hash does not exist !\n");   
            return -1;
        }
        return 1;
    }

    return -1;
}


int add_hash(char * hash)
{
    struct hash_node* old_head = blacklist.head;
    struct hash_node* new_node = (struct hash_node *) kmalloc(sizeof(struct hash_node), GFP_KERNEL);

    if(!new_node)
        return -1;

    // printk(KERN_INFO "[*] Got hash %s\n", hash);
    // return 1;

    //Copy hash
    strncpy(new_node->hash, hash, HASH_BUFFER_SIZE);

    // Update new head 
    blacklist.head = new_node;
    new_node->next = old_head;
    return 1;
}

int delete_hash(char * hash)
{

    struct hash_node* curr = blacklist.head;
    struct hash_node* prev = NULL; 

    while( curr != NULL )
    {
        // compare hashes 
        printk(KERN_INFO "[*] Comparing \n");
        printk(KERN_INFO "[*] %s  \n", curr->hash);
        printk(KERN_INFO "[*] %s  \n", hash);
        printk(KERN_INFO "[*] compare is : %d\n", strncmp(curr->hash, hash, HASH_BUFFER_SIZE));

        if( strncmp(curr->hash, hash, HASH_BUFFER_SIZE) == 0)
        {
            if( prev == NULL)
            {
                blacklist.head = curr->next;
            }
            else
            {
                prev->next = curr->next;
            }

            kfree(curr);
            return 1;
        }

        prev = curr;
        curr = curr->next;
    }

    return -1;
}

void free_list(void)
{
    struct hash_node* curr = blacklist.head;
    struct hash_node* to_free;

    while(curr != NULL)
    {
        to_free = curr;
        curr = curr->next;
        kfree(to_free);
    }
}


int is_hash_in_blacklist(char * hash)
{
    struct hash_node * curr = blacklist.head;

    while(curr != NULL)
    {
        if( strncmp(curr->hash, hash, HASH_BUFFER_SIZE) == 0)
            return 1;
        curr = curr->next;
    }   

    return 0;
}

/*
 * procfile_write - handling  input received from  the user
 * @file: 
 * @buffer: the input buffer from the user
 * @len:  size of user input 
 * @off: 
*/
ssize_t procfile_write(struct file *file, const char *buffer, size_t len, loff_t * off)
{
    unsigned long flags;

    if ( len > PROCFS_MAX_SIZE ) 
        procfs_buffer_size = PROCFS_MAX_SIZE;
    else
        procfs_buffer_size = len; 

    spin_lock_irqsave(&lock, flags);
        
    if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }

    int feature = update_config();

    if (feature == -1){
        spin_unlock_irqrestore(&lock, flags);
        printk(KERN_INFO "[*] Writing request is not valid! \n");
        return -EFAULT;
    }
    spin_unlock_irqrestore(&lock, flags);
    return procfs_buffer_size;
}

/*
 * procfile_read - handling  input received from  the user
 * @file: 
 * @buffer: the output buffer to return to the user
 * @len:  size of output
 * @off: 
*/
ssize_t procfile_read(struct file * file, char *buffer, size_t size, loff_t * off)
{
    int ret = 0;
    unsigned long flags;

    spin_lock_irqsave(&lock, flags);

    if(finished)
    {
        finished = 0;
        read_offset = 0;
        spin_unlock_irqrestore(&lock, flags);
        return 0;
    }


    /* * * * * * * * * * * * *
     *  Print 10 latest events
     * * * * * * * * * * * * */
     mutex_lock(&history_mutex);
     

    if(copy_to_user(buffer, lastevents_header, strlen(lastevents_header)))
    {
        mutex_unlock(&history_mutex);
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }

    read_offset += strlen(lastevents_header);
    
    int last_index = history.next_index > MAX_HISTORY ? MAX_HISTORY : history.next_index;
    int i;

    for(i = 0; i < history.next_index; i++)
    {
        int event_length = strlen(history.events[i]);
        if(copy_to_user(buffer + read_offset, history.events[i], event_length))
        {
            mutex_unlock(&history_mutex);
            spin_unlock_irqrestore(&lock, flags);
            return -EFAULT;
        }
        read_offset += event_length;
    }


     mutex_unlock(&history_mutex);
    /* * * * * * * * * * * * * 
     *   Print Configuration 
     * * * * * * * * * * * * */ 

     if(copy_to_user(buffer + read_offset, config_header, strlen(config_header)))
    {
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }
    read_offset += strlen(config_header);

    char *to_send;

    if(cfg.exec_block)
        to_send = exec_block_enabled;
    else
        to_send = exec_block_disabled;
        
    if( copy_to_user(buffer + read_offset, to_send, strlen(to_send)) )
    {
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }
    read_offset += strlen(to_send);

    if(cfg.pscripts_block)
        to_send = pscripts_enabled;
    else
        to_send = pscripts_disabled;

    if( copy_to_user(buffer+read_offset, to_send, strlen(to_send)) )
    {
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }

    read_offset += strlen(to_send);
    

     /* * * * * * * * * * * * * 
     *   Print blocked sha1's 
     * * * * * * * * * * * * */ 

    if( copy_to_user(buffer+read_offset, blocked_hashes, strlen(blocked_hashes)))
    {
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }

    read_offset += strlen(blocked_hashes);
    ret = read_offset;

    struct hash_node * curr = blacklist.head;

    while(curr != NULL)
    {
        if( copy_to_user(buffer+read_offset, curr->hash, HASH_BUFFER_SIZE)) 
        {
            spin_unlock_irqrestore(&lock, flags);
            return -EFAULT;
        }
        read_offset += HASH_BUFFER_SIZE;
        if( copy_to_user(buffer+read_offset, "\n", 1)) 
        {
            spin_unlock_irqrestore(&lock, flags);
            return -EFAULT;
        }
        read_offset += 1;
        curr = curr->next;
    }

    ret = read_offset;

    finished = 1;

    spin_unlock_irqrestore(&lock, flags);
    // return strlen(to_send);
    return ret;

}

unsigned long **find_sys_call_table(void)  
{
 
    unsigned long ptr;
    unsigned long *p;
  
    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
        p = (unsigned long *) ptr;
    
        if (p[__NR_close] == (unsigned long) sys_close){
        return (unsigned long **) p;
    }
  }
   return NULL;
}

char * get_timestamp(void)
{
    
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;

    do_gettimeofday(&time);
    local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
    rtc_time_to_tm(local_time, &tm);

    // printk("%02d/%02d/%04d %02d:%02d:%02d\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    snprintf(time_buffer, TIME_BUFFER_SIZE, "%02d/%02d/%04d %02d:%02d:%02d", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec );
    return time_buffer;
}

// Type -> 0 = pscripts, 1 = executable
char * get_full_path(char * path, char ** argv, int type)
{
    int path_len = strlen(path);

    if( type == 0)
    {
        strncpy(fullpath, path , path_len);
        strncpy(fullpath+path_len, "/", 1);
        strncpy(fullpath+path_len+1, argv[1], strlen(argv[1]));
        fullpath[path_len + strlen(argv[1]) + 1] = 0;
    }
    else if (type == 1)
    {
        strncpy(fullpath, path , path_len);
        strncpy(fullpath+path_len, argv[0]+1, strlen(argv[0]+1));
        fullpath[path_len + strlen(argv[0]+1)] = 0;
    }
    return fullpath;
}

void add_history_entry(char * entry)
{
    mutex_lock(&history_mutex);
    int next_index = history.next_index % MAX_HISTORY;
    strncpy(history.events[next_index], print_help_buffer, HISTORY_ENTRY_SIZE);
    history.next_index += 1;
    mutex_unlock(&history_mutex);
}

asmlinkage long hook_sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
{
    if( strncmp(argv[0], "dmesg", 5) == 0 || strncmp(argv[0], "sleep", 5) == 0 )
        goto end;

    // Get path details
    // struct fs_struct * fs = current->fs;
    struct path pwd = current->fs->pwd;
    struct path root = current->fs->root;   
    char * path = d_path(&pwd, aux_buff, sizeof(aux_buff));
    int path_len = strlen(path);
    int blocked = 0;
    char * exec_type;
    char * full_path;
    char * to_print;
    int was_pscript = 0;
    int was_exec = 0;

    if(strncmp(argv[0], "python", 6) == 0)
    {   
        // Was a python script.
        if((!cfg.pscripts_monitor && !cfg.pscripts_block) || user_program_pid == -1)
            goto end;

        exec_type = "SCRIPT";   
        was_pscript = 1;

        if( strncmp(argv[1], "/", 1) == 0 )
            full_path = argv[1];                        // agrv[1] contains full path to file
        else
            full_path = get_full_path(path, argv ,0);   // Must build full path 


        nl_hash_request_msg(full_path);        
        down(&sema); 

        if(cfg.pscripts_block)
        {
            if(is_hash_in_blacklist(hash_ans))
            {
                to_print =  blocked_str;
                blocked = 1;    
            }
        }
        if( cfg.pscripts_monitor && !blocked)   
        {
            // Add to history and report to dmesg.
            to_print = loaded_py_str;
        }
    }
    else if( strncmp(argv[0], "./", 2) == 0)
    {

        if((!cfg.exec_monitor && ! cfg.exec_block) || user_program_pid == -1)
            goto end;

        exec_type = "Executable"; 

        was_exec = 1;                                       // Executable was ran in local file. 
        full_path = get_full_path(path, argv, 1);           // Must build full path from relative.

        nl_hash_request_msg(full_path);        
        down(&sema);

        if(cfg.exec_block)
        {
            if(is_hash_in_blacklist(hash_ans))
            {
                to_print = blocked_str;
                blocked = 1;
            }
        }
        if(cfg.exec_monitor && !blocked)
        {
            to_print = loaded_exec_str;
        }
    }
    else
    {
        goto end;
    }

    if( blocked || (cfg.exec_monitor && was_exec) || (cfg.pscripts_monitor && was_pscript))
    {
        snprintf(print_help_buffer, HISTORY_ENTRY_SIZE, to_print, get_timestamp(), exec_type, full_path, current->pid, hash_ans);
        add_history_entry(print_help_buffer);
        printk(KERN_INFO "[!] %s", print_help_buffer);    
    }
    
    if(blocked)
        return 0;

    end:   ;
    return original_sys_execve(filename, argv, envp);
}

int set_my_execve(void)
{
    cr0 = read_cr0();  
    write_cr0(cr0 & ~CR0_WP);
    printk(KERN_INFO "[*] Read only disabled . \n");

    ptr_to_execve = memchr(system_call_table[__NR_execve], 0xE8, 200);

    if ( !ptr_to_execve )
    {
            printk(KERN_INFO "[!] Stub swap failed ! \n");
            return -1;
    }

    ptr_to_execve++;
    original_sys_execve = (void *) ptr_to_execve + *(int32_t *) ptr_to_execve + 4;
    *(int32_t *) ptr_to_execve = (void *) hook_sys_execve - ptr_to_execve - 4;

    write_cr0(cr0);
    return 0;
}

void restore_execve(void)
{
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    *(int32_t *) ptr_to_execve = (void *) original_sys_execve - ptr_to_execve - 4;
    write_cr0(cr0);
}

int set_procfile(void)
{
    /*
    * create the /proc file 
    */
    proc_file = proc_create(PROCFS_NAME, 0646, NULL, &file_ops);

    if (proc_file == NULL) {
        // remove_proc_entry(PROCFS_NAME, &proc_root);
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",PROCFS_NAME);
        return -1;
    }

    printk(KERN_INFO "[*] /proc/%s created.\n", PROCFS_NAME); 
}

static int __init kblocker_init(void)
{

    printk("[*] Entering: %s\n", __FUNCTION__);
    mutex_init(&history_mutex);

    sema_init(&sema, 0);

    int succ;
    succ = set_procfile();
    if(succ == -1)
        return -ENOMEM;

    system_call_table = (void **) find_sys_call_table();

    if(!system_call_table)
    {
        printk(KERN_ALERT "[*] Error ! Failed to locate system call table.\n");
        return -EFAULT; //bad address
    }
    
    succ = set_my_execve();
    if( succ == -1 )
        return -EFAULT;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &nl_cfg);

    if (!nl_sk) {
        printk(KERN_ALERT "[*] Error ! NetLink : Failed to creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit kblocker_exit(void)
{

    printk(KERN_INFO "[*] Exiting Kmonitor module.\n");
    // remove_proc_entry(PROCFS_NAME, &proc_root);
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "[*] /proc/%s removed.\n", PROCFS_NAME); 

    // nl_hash_request_msg("terminate");

    // free blacklist
    free_list();

    netlink_kernel_release(nl_sk);
    restore_execve();
}

module_init(kblocker_init); module_exit(kblocker_exit);

   // printk(KERN_INFO "[TSTAMP] time is  : %s\n", time_buffer); 
   //      printk(KERN_INFO "[EXECVE] pwd path is  : %s\n", path);    
   //      printk(KERN_INFO "[EXECVE] filename : %s\n", filename);
   //      printk(KERN_INFO "[EXECVE] argv[0] : %s\n", argv[0]);
   //      printk(KERN_INFO "[EXECVE] argv[1] : %s\n", argv[1]);
   //      printk(KERN_INFO "[EXECVE] envp: %s\n", envp);