/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type, *ioctl_cmd;
	int *cfd_ptr;
	struct session_op *sess;
	__u32 *ses_id_ptr;
	struct crypt_op *cryp;
	long *host_return_val;
	
	DEBUG_IN();

	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	} 

	DEBUG("I have got an item from VQ :)");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		/* ?? */
		cfd_ptr = elem.in_sg[0].iov_base;
		*cfd_ptr = open("/dev/crypto", O_RDWR);
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		/* ?? */
		cfd_ptr = elem.out_sg[1].iov_base;
		if (close(*cfd_ptr) < 0) 
            DEBUG("Problem with close(cfd)");
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		/* ?? */
		
		cfd_ptr = elem.out_sg[1].iov_base;
		ioctl_cmd = elem.out_sg[2].iov_base;
		
		switch (*ioctl_cmd) {
		case CIOCGSESSION:
			DEBUG("CIOCGSESSION");
			
			sess = (struct session_op *) elem.in_sg[0].iov_base;
			sess->key = elem.out_sg[3].iov_base;
			
			host_return_val = elem.in_sg[1].iov_base;

			*host_return_val = ioctl(*cfd_ptr, CIOCGSESSION, sess);
			if(*host_return_val)				
				DEBUG("Error: ioctl(CIOCGSESSION)");
			
			printf("To kleidi einai = %s\n", sess->key);
			printf("To host_return_val = %ld", *host_return_val);
			break;
			
		case CIOCFSESSION:
			DEBUG("CIOCCRYPT");
			
			ses_id_ptr = (__u32 *) elem.out_sg[3].iov_base;
			host_return_val = elem.in_sg[0].iov_base;
			
			*host_return_val = ioctl(*cfd_ptr, CIOCFSESSION, ses_id_ptr);
			if(*host_return_val)	
				DEBUG("Error: ioctl(CIOCGSESSION)");
			
			break;
			
		case CIOCCRYPT:
			DEBUG("CIOCRYPT");
			
			cryp = (struct crypt_op *) elem.out_sg[3].iov_base;
			
			cryp->src = elem.out_sg[4].iov_base;
			
			cryp->iv = elem.out_sg[5].iov_base;
			
			cryp->dst =  elem.in_sg[0].iov_base;
			
			host_return_val = elem.in_sg[1].iov_base;
			*host_return_val = ioctl(*cfd_ptr, CIOCCRYPT, cryp);
			if(*host_return_val)				
				DEBUG("Error: ioctl(CIOCCRYPT)");
			
			break;

		default:
			DEBUG("Unknown ioctl_cmd");
		}	
		
		break;

	default:
		DEBUG("Unknown syscall_type");
	}
	
	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
