/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Anastasis Stathopoulos >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));
	/* ? */
	
	if (sensor->msr_data[state->type]->last_update > state->buf_timestamp)
        return 1;
    

	/* The following return is bogus, just for the stub to compile */
	return 0; /* ? */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	unsigned long flags;
	uint32_t data;
	unsigned int decimal, fractional;
   	unsigned char sign;
	long data_value;	
	debug("Just entered UPDATE\n");
	long *lookup[N_LUNIX_MSR] = { lookup_voltage, lookup_temperature, lookup_light };
	
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	/* ? */
	/* Why use spinlocks? See LDD3, p. 119 */
	
	/*
	 * Any new data available?
	 */
	/* ? */
	
	sensor = state->sensor;
	
	//disables interrupts before taking the spinlock
	spin_lock_irqsave(&sensor->lock, flags);    
	
	if(!lunix_chrdev_state_needs_refresh(state)){
		spin_unlock_irqrestore(&sensor->lock, flags);
		return -EAGAIN;
	}
	data = sensor->msr_data[state->type]->values[0];
	state->buf_timestamp = sensor->msr_data[state->type]->last_update;
	
	spin_unlock_irqrestore(&sensor->lock, flags);
	
	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	data_value = lookup[state->type][data];
	sign = (int) data_value >= 0 ? ' ' : '-';
    decimal = data_value / 1000;
    fractional = data_value % 1000;
	sprintf(state->buf_data,"%c%d.%d\n", sign, decimal , fractional);	
	
	state->buf_lim = strnlen(state->buf_data, 20);

    up(&state->lock);
	
	debug("Leaving UPDATE\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	int ret;
	struct lunix_chrdev_state_struct *state;
	dev_t minor;
	int type;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;
	
	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	 minor = iminor(inode);
	 type = minor%8;
	 if(type >= N_LUNIX_MSR) {
		ret = -ENODEV;								 //No such device 
		debug("leaving, with ret = %d\n", ret);
		return ret;
	 }
	
	/* Allocate a new Lunix character device private state structure */
	/* ? */
	state = kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	if(!state) {
		ret = -EFAULT;        						 //Bad address
		debug("leaving, with ret = %d\n", ret);
		return ret;
	}
	
	state->type = type;
	state->buf_lim = 0;
	state->buf_timestamp = 0;
	state->sensor = &lunix_sensors[(minor >> 3)];
	
	sema_init(&state->lock, 1);
	filp->private_data = state;
	
	
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;
	int ret_from_update = 1;
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	
	/* Lock? */
	/* down_interruptible -> user-process waiting on a semaphore 
	 * can be interrupted by the user.
	 * if interrupted it returns a nonzero value
	 * and the caller does not hold the semaphore
	 */
	if (down_interruptible(&state->lock)) {
        ret = -ERESTARTSYS;
        return ret;
    }
	
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	 
	 if (*f_pos >= state->buf_lim)  
        *f_pos=0;
				
	if (*f_pos == 0) {
		while ((ret_from_update = lunix_chrdev_state_update(state)) == -EAGAIN) {
			/* ? */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			
			up(&state->lock);
			
			if (filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				return ret; 
			}	
			debug("Reading: going to sleep\n");
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) {
				ret = -ERESTARTSYS;
				return ret;
			}
			/* loop, but first reacquire the lock */
			if (down_interruptible(&state->lock)) {
				ret = -ERESTARTSYS;
				return ret;
			}
		}	
	}				
	
	debug("READ: ret = %d\n", ret);
	/* End of file */
	/* ? */
	
	
	/* Determine the number of cached bytes to copy to userspace */
	/* ? */
	
		
	if (state->buf_lim < *f_pos + cnt)
        cnt = state->buf_lim - *f_pos;
    
	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)){
        debug("Copy to user failed\n");
        ret = -EFAULT;
        goto out;
    }
    
	*f_pos += cnt;
    ret = cnt;

	/* Auto-rewind on EOF mode? */
	/* ? */

	
out:
	/* Unlock? */
	debug("Returning from READ with ret = %d\n", ret); 
    up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	
	/* cdev_add? */
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
