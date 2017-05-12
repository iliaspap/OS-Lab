/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	int host_fd = -1;
	
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out=0, num_in=0;
	
	debug("Entering");

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	
	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(int));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	
	spin_lock_irq(&crdev->lock);
	
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	
	spin_unlock_irq(&crdev->lock);
    
	/* If host failed to open() return -ENODEV. */
	/* ?? */
	if(crof->host_fd < 0){
		debug("Host failed to open() the crypto device!");
		ret = -ENODEV;
	}	

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out=0, num_in=0;
	
	debug("Entering");

	/**
	 * Send data to the host.
	 **/
	/* ?? */
	
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(int));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */	
	spin_lock_irq(&crdev->lock);
	
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	
	while ((virtqueue_get_buf(crdev->vq, &len) == NULL))
		/* do nothing */;
	
	spin_unlock_irq(&crdev->lock);
	
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg, output_msg_sg, input_msg_sg, 
		   session_key_sg, session_op_sg, host_return_val_sg, session_id_sg, cryp_op_sg, src_sg, dst_sg, iv_sg,
	                   *sgs[8];
					   
#define MSG_LEN 100
	unsigned char output_msg[MSG_LEN], input_msg[MSG_LEN], iv[16] = "abcdefghijklmno";
	unsigned int num_out, num_in,
	             syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL, ioctl_cmd = cmd,
	             len;
	unsigned char *session_key;
	struct session_op *sess= NULL, *sess_ptr = NULL;
	struct crypt_op *cryp = NULL, *cryp_ptr = NULL;
	void *key_ptr=NULL, *iv_ptr, *src_ptr, *dst_ptr = NULL;
	__u32 *ses_id;
	long host_return_val;

	debug("Entering");

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;
	
	sg_init_one(&ioctl_cmd_sg, &ioctl_cmd, sizeof(ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;
	
	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		sess_ptr = (struct session_op *) arg;
		sess = (struct session_op *)kmalloc(sizeof(struct session_op), GFP_KERNEL);
		if(copy_from_user(sess, sess_ptr , sizeof(struct session_op))){
            debug("Copy from user failed!");
            ret = -EFAULT;
            return ret;
        }
		
		printk("To keylen einai = %d\n", sess->keylen);
		
		key_ptr = sess->key;
		sess->key = (unsigned char *)kmalloc(sess->keylen*sizeof(unsigned char), GFP_KERNEL);

		if(copy_from_user(sess->key, key_ptr, sess->keylen*sizeof(unsigned char))){
			debug("Copy from user failed!");
            ret = -EFAULT;
            return ret;
        }
		printk("To key einai = %s\n", sess->key);
		
		sg_init_one(&session_key_sg, sess->key, sess->keylen*sizeof(unsigned char));
		sgs[num_out++] = &session_key_sg;
		
		sg_init_one(&session_op_sg, sess, sizeof(struct session_op));
		sgs[num_out + num_in++] = &session_op_sg;
		
		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;
		
		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		
		ses_id = (__u32 *)kmalloc(sizeof(__u32), GFP_KERNEL);
		if(copy_from_user(ses_id, (void *) arg, sizeof(__u32))){
            debug("Copy from user for ses_id failed");
            ret = -EFAULT;
            return ret;
        }

		sg_init_one(&session_id_sg, ses_id, sizeof(ses_id));
		sgs[num_out++] = &session_id_sg;

		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;
		
		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		
		cryp_ptr = (struct crypt_op *) arg;
		cryp = (struct crypt_op *)kmalloc(sizeof(struct crypt_op), GFP_KERNEL);
		if(copy_from_user(cryp, (void *) arg, sizeof(struct crypt_op))){
            debug("Copy from user for crypt_op failed!");
            ret = -EFAULT;
            return ret;
        }
		printk("To cryplen einai = %d\n", cryp->len);
		
		src_ptr = cryp->src;
		cryp->src = (unsigned char *)kmalloc(cryp->len*sizeof(unsigned char), GFP_KERNEL);

        if(copy_from_user(cryp->src, src_ptr, cryp->len*sizeof(unsigned char))){
            debug("Copy from user for SOURCE failed!");
            ret = -EFAULT;
            return ret;
        }

		iv_ptr = cryp->iv;
        cryp->iv = (unsigned char *)kmalloc(16*sizeof(unsigned char), GFP_KERNEL);

        if(copy_from_user(cryp->iv, iv_ptr, 16*sizeof(unsigned char))){
            debug("Copy from user for IV failed!");
            ret = -EFAULT;
            return ret;
        }
		
		cryp->dst = (unsigned char *)kmalloc(cryp->len*sizeof(unsigned char), GFP_KERNEL);
		dst_ptr = cryp->dst;	
		
		sg_init_one(&cryp_op_sg, cryp, sizeof(struct crypt_op));
        sgs[num_out++] = &cryp_op_sg;
				
		sg_init_one(&src_sg, cryp->src, cryp->len*sizeof(unsigned char));
		sgs[num_out++] = &src_sg;
				
		sg_init_one(&iv_sg, cryp->iv, 16*sizeof(unsigned char));
		sgs[num_out++] = &iv_sg;

		sg_init_one(&dst_sg, cryp->dst, cryp->len*sizeof(unsigned char));
		sgs[num_out + num_in++] = &dst_sg;	

		sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
		sgs[num_out + num_in++] = &host_return_val_sg;
		
		
		break;

	default:
		debug("Unsupported ioctl command");

	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	
	spin_lock_irq(&crdev->lock);
	
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	
	spin_unlock_irq(&crdev->lock);
	
	if(cmd == CIOCGSESSION){
		if(copy_to_user(sess_ptr, sess, sizeof(struct session_op))){
				debug("Copy to user for SES failed!");
				ret = -EFAULT;
				return ret;
		}
		sess_ptr->key = key_ptr;
	}
	
	if(cmd == CIOCCRYPT){
		if(copy_to_user(cryp_ptr->dst, dst_ptr, cryp->len*sizeof(unsigned char))){
				debug("Copy to user for DEST failed!");
				ret = -EFAULT;
				return ret;
		}
		
	}	
	

	debug("Leaving ioctl with return value %ld", host_return_val);
	return host_return_val;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
