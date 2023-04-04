/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include <linux/slab.h>	// kmalloc, krealloc, kfree
#include "aesd_ioctl.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif


int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Ritika Ramchandani"); 
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    
    struct aesd_dev* dev;

    dev = container_of(inode -> i_cdev, struct aesd_dev, cdev);

    filp -> private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev* dev;
    size_t entry_byte_offset;
    struct aesd_buffer_entry *read_entry;
    size_t num_bytes_read;

    //PDEBUG("read %zu bytes with offset %lld",count,*f_pos); todo

    // Check if any of inputs are invalid 
    if(filp == NULL || buf == NULL)
    {
        return -EINVAL;
    }

    // Get device pointer
    dev = filp -> private_data;

    // Get interruptible lock
    if (mutex_lock_interruptible(&(dev -> dev_lock)))
    {
        return -ERESTARTSYS;
    }

    // Get entry at the specified offset from the circular buffer
    read_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&(dev -> aesd_cb), *f_pos, &entry_byte_offset);

    if(read_entry == NULL)
    {
        goto exit_gracefully;
    }

    // Check if required count is within the bounds of the entry or not
    if((read_entry -> size - entry_byte_offset) < count)
    {
        num_bytes_read = read_entry -> size - entry_byte_offset;
    }
    else
    {
        num_bytes_read = count;
    }

    // Copy the entry from the specified offset to the user-provided buffer
    if(copy_to_user(buf, read_entry -> buffptr + entry_byte_offset, num_bytes_read))
    {
        retval = -EFAULT;
        goto exit_gracefully;
    }

    PDEBUG("Reading form f_pos = %d and filp -> f_pos = %d\n", f_pos, filp -> f_pos);
    PDEBUG("Number of bytes read = %d\n", num_bytes_read);

    *f_pos += num_bytes_read;

    retval = num_bytes_read;

exit_gracefully:
    mutex_unlock(&dev -> dev_lock);
    
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("Write begin\n");
    
    ssize_t retval = -ENOMEM;
    struct aesd_dev* dev;
    char* temp_buf; 
    const char* entry_to_rm;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    // Check if any of inputs are invalid 
    if(filp == NULL || buf == NULL)
    {
        return -EINVAL;
    }

    // Get device pointer
    dev = filp -> private_data;
		
    //kmalloc a buffer to copy from user space
    temp_buf = kmalloc(count, GFP_KERNEL);

    if(temp_buf == NULL)
    {
        PDEBUG("Unable to kmalloc a buffer to store the input data\n");
        goto exit_gracefully;
    }

    if(copy_from_user(temp_buf, buf, count))
    {
        retval = -EFAULT;
        PDEBUG("Unable to copy from user\n");
        goto exit_with_free;
    }  

    // Get interruptible lock
    if (mutex_lock_interruptible(&(dev -> dev_lock)))
    {
        return -ERESTARTSYS;
    }

    // If last write was completed, create a buffer
    if(dev -> prev_wr_completed)
    {
        dev -> buf_element.buffptr = kmalloc(count, GFP_KERNEL);
        dev -> buf_element.size = 0;

        if(dev -> buf_element.buffptr == NULL)
        {
            PDEBUG("Unable to kmalloc a buffer for the circular buffer entry\n");
            goto exit_with_free;
        }

        memcpy(dev -> buf_element.buffptr, temp_buf, count);
    }
    else // Reallocate the buffer that already exists to accomodate the new data
    {
        dev -> buf_element.buffptr = krealloc(dev -> buf_element.buffptr, (dev -> buf_element.size + count), GFP_KERNEL);
        if(dev -> buf_element.buffptr == NULL)
        {
            PDEBUG("Unable to krealloc a buffer for the circular buffer entry\n");
            goto exit_with_free;
        }

        memcpy((dev -> buf_element.buffptr + dev -> buf_element.size), temp_buf, count);
    }

    dev -> buf_element.size += count;

    // If last char is \n, add entry to circular buffer (aesdsocket sends '\n' as the last character)
    if((dev -> buf_element.buffptr[(dev -> buf_element.size) - 1]) == '\n')
    {
        entry_to_rm = aesd_circular_buffer_add_entry(&(dev -> aesd_cb), &(dev -> buf_element));

        if(entry_to_rm != NULL)
        {
            kfree(entry_to_rm);
        }

        dev -> prev_wr_completed = true;
    }
    else
    {
        dev -> prev_wr_completed = false;
    }

    retval = count;

exit_with_free:
    kfree(temp_buf);
exit_gracefully:
    mutex_unlock(&(dev -> dev_lock));
    
    return retval;
}


loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev* dev;
    loff_t cb_size = 0;
    struct aesd_buffer_entry* entry_ptr = NULL;
    uint8_t index = 0;
    loff_t retval;

    // Check if the inputs are valid
    if(filp == NULL)
    {
        PDEBUG("Invalid file pointer\n");
        return -EINVAL;
    }

    // Get device pointer
    dev = filp -> private_data;

    // Get interruptible lock
    if (mutex_lock_interruptible(&(dev -> dev_lock)))
    {
        return -ERESTARTSYS;
    }

    // Adding all AESD circular buffer entries
    AESD_CIRCULAR_BUFFER_FOREACH(entry_ptr, &(aesd_device.aesd_cb), index)
    {
        if(entry_ptr -> buffptr != NULL)
        {
            cb_size += entry_ptr -> size;
        }
    }

    retval = fixed_size_llseek(filp, off, whence, cb_size);

    if(retval == -EINVAL)
    {
        PDEBUG("Invalid \"whence\" value\n");
    }

    mutex_unlock(&(dev -> dev_lock));
    
    return retval;

}


static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    struct aesd_dev* dev;
    int i;

    // Check for valid inputs
    if(filp == NULL)
    {
        PDEBUG("Invalid file pointer\n");
        return -EINVAL;
    }

    // Get device pointer
    dev = filp -> private_data;

    // Get interruptible lock
    if (mutex_lock_interruptible(&(dev -> dev_lock)))
    {
        return -ERESTARTSYS;
    }

    int total_num_entries = dev -> aesd_cb.in_offs - dev -> aesd_cb.out_offs;

    if(total_num_entries <= 0)
    {
        total_num_entries += AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    PDEBUG("Total number of entries is %d\n", total_num_entries);

    if((write_cmd > total_num_entries) || (write_cmd_offset > (dev -> aesd_cb.entry[write_cmd].size - 1)))
    {
        PDEBUG("Invalid input values for write_cmd / write_cmd_offset\n");
        return -EINVAL;
    }

    for(i = 0; i < write_cmd; i++)
    {
        filp -> f_pos += (dev -> aesd_cb.entry[i].size);
    }

    filp -> f_pos += write_cmd_offset;

    PDEBUG("filp -> f_pos is %zu\n", filp -> f_pos);

    mutex_unlock(&(dev -> dev_lock));
    
    return 0;
}



long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    // Reference : scull example
	int retval = 0;

    // Check for valid inputs
    if(filp == NULL)
    {
        PDEBUG("Invalid file pointer\n");
        return -EINVAL;
    }
    
	/*
	 * Extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) 
	 */

	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

    switch(cmd)
    {
        case AESDCHAR_IOCSEEKTO:
        {
            struct aesd_seekto seekto;
            if(copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
            {
                retval = -EFAULT;
            }
            else
            {
                retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
            }

            break;
        }
        default:  /* redundant, as cmd was checked against MAXNR */
        {
		    PDEBUG("Inside default case - string did not match the AESDCHAR_IOCSEEKTO command\n");
            return -ENOTTY;
            break;
        }
    }

    PDEBUG("Value of retval is %d\n", retval);
    PDEBUG("Value filp -> pos is %zu\n", filp -> f_pos);

    return retval;
}


struct file_operations aesd_fops = {
    .owner =            THIS_MODULE,
    .read =             aesd_read,
    .write =            aesd_write,
    .open =             aesd_open,
    .release =          aesd_release,
    .llseek =           aesd_llseek,
    .unlocked_ioctl =   aesd_ioctl
};


static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&(aesd_device.aesd_cb));

    // Initialize the AESD specific portion of the device
    mutex_init(&aesd_device.dev_lock);
    
    // Initialize boolen variable to false since there was no prev write
    aesd_device.prev_wr_completed = false;

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }

    PDEBUG("Initialized\n");
    return result;

}

void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry* entry_ptr = NULL;
    uint8_t index = 0;
    
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    // Freeing AESD circular buffer entries
    AESD_CIRCULAR_BUFFER_FOREACH(entry_ptr, &(aesd_device.aesd_cb), index)
    {
        if(entry_ptr -> buffptr != NULL)
        {
            kfree(entry_ptr -> buffptr);
        }
    }

    // Destroy the mutex
    mutex_destroy(&aesd_device.dev_lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
