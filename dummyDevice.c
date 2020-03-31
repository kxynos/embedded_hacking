#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>

#define DEVICE_NAME "dummy"
#define MAJOR_NUM 42
#define NUM_DEVICES 4
#
static struct class *dummy_class;

static int dummy_open(struct inode *inode, struct file *file)
{    
pr_info("%s\n", __func__);    
return 0;
}

static int dummy_release(struct inode *inode, struct file *file)
{   
pr_info("%s\n", __func__);    
return 0;
}

static ssize_t dummy_read(struct file *file, char *buffer, size_t length, loff_t * offset){
    pr_info("%s %u\n", __func__, length);
    return 0;
}

static ssize_t dummy_write(struct file *file, const char *buffer, size_t length, loff_t * offset)
{    
pr_info("%s %u\n", __func__, length);    
return length;

}

struct file_operations dummy_fops = {
    .owner = THIS_MODULE,    
    .open = dummy_open,
    .release = dummy_release,
    .read = dummy_read,
    .write = dummy_write,
};

int __init dummy_init(void){
    int ret;
    int i;
    printk("Dummy loaded\n");
    ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &dummy_fops);
    if (ret != 0)
        return ret;
    dummy_class = class_create(THIS_MODULE, DEVICE_NAME);
    for (i = 0; i < NUM_DEVICES; i++) {
        device_create(dummy_class, NULL,
                  MKDEV(MAJOR_NUM, i), NULL, "dummy%d", i);
    }
    return 0;
}

void __exit dummy_exit(void){
    int i;
    for (i = 0; i < NUM_DEVICES; i++) {
        device_destroy(dummy_class, MKDEV(MAJOR_NUM, i));
    }    

class_destroy(dummy_class);    
unregister_chrdev(MAJOR_NUM, DEVICE_NAME);   
printk("Dummy unloaded\n");
}

module_init(dummy_init);
module_exit(dummy_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Simmonds");
MODULE_DESCRIPTION("A dummy driver");
