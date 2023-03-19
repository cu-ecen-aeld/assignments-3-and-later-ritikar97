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

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

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

    read_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&(dev -> aesd_cb), *f_pos, &entry_byte_offset);

    if(read_entry == NULL)
    {
        goto exit_gracefully;
    }

    if((read_entry -> size - entry_byte_offset) < count)
    {
        
        num_bytes_read = read_entry -> size - entry_byte_offset;
        
    }
    else
    {
        num_bytes_read = count;
    }

    if(copy_to_user(buf, read_entry -> buffptr + entry_byte_offset, num_bytes_read))
    {
        retval = -EFAULT;
        goto exit_gracefully;
    }

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

    // Get interruptible lock
    if (mutex_lock_interruptible(&(dev -> dev_lock)))
    {
        return -ERESTARTSYS;
    }
		
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
    else
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

    // If last char is \n, add entry to circular buffer
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


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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
