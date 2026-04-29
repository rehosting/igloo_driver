#include "portal_internal.h"
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/file.h>
#include "portal_devfs.h"


struct portal_anonfs_create_req {
    char name[32];
    int hf_id;
    struct igloo_dev_ops ops;
};

struct portal_anonfs_entry {
    int hf_id;
    struct file_operations fops;
    int (*python_release)(struct inode *, struct file *);
};

static struct proto igloo_dummy_proto = {
    .name       = "IGLOO_SOCK",
    .owner      = THIS_MODULE,
    .obj_size   = sizeof(struct sock),
};

static int igloo_anonfs_proxy_release(struct inode *inode, struct file *file) {
    struct portal_anonfs_entry *pe = file->private_data;
    int ret = 0;
    
    if (pe) {
        if (pe->python_release) {
            ret = pe->python_release(inode, file);
        }
        kfree(pe); 
    }
    return ret;
}

void handle_op_anonfs_create_file(portal_region *mem_region) {
    struct portal_anonfs_create_req *req = (void *)PORTAL_DATA(mem_region);
    struct portal_anonfs_entry *pe;
    int fd;

    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return;
    }

    req->name[31] = '\0';
    pe->hf_id = req->hf_id;
    pe->python_release = req->ops.release;

    // Use the shared converter to wire up Python trampolines
    igloo_convert_ops_to_fops(&req->ops, &pe->fops, false);
    
    // Route release through our cleanup proxy
    pe->fops.release = igloo_anonfs_proxy_release;

    fd = anon_inode_getfd(req->name, &pe->fops, pe, O_RDWR);
    
    if (fd < 0) {
        kfree(pe);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return;
    }

    mem_region->header.size = cpu_to_le64(fd);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_NUM);
}

/* =========================================================================
 * 2. SOCKFS (True Kernel Sockets)
 * ========================================================================= */

// Defines the Python Trampolines for Socket-Specific Operations
struct igloo_proto_ops {
    int (*bind)(struct socket *sock, struct sockaddr *myaddr, int sockaddr_len);
    int (*connect)(struct socket *sock, struct sockaddr *vaddr, int sockaddr_len, int flags);
    int (*sendmsg)(struct socket *sock, struct msghdr *m, size_t total_len);
    int (*recvmsg)(struct socket *sock, struct msghdr *m, size_t total_len, int flags);
    int (*release)(struct socket *sock);
};

struct portal_sockfs_create_req {
    int hf_id;
    int family;
    int type;
    int protocol;
    struct igloo_proto_ops ops;
};

struct portal_sockfs_entry {
    int hf_id;
    struct proto_ops pops;
    int (*python_release)(struct socket *);
};

static int igloo_sockfs_proxy_release(struct socket *sock) {
    struct portal_sockfs_entry *pe = sock->sk ? sock->sk->sk_user_data : NULL;
    int ret = 0;
    
    if (pe) {
        if (pe->python_release) {
            ret = pe->python_release(sock);
        }
        kfree(pe); 
    }
    return ret;
}

void handle_op_sockfs_create_socket(portal_region *mem_region) {
    struct portal_sockfs_create_req *req = (void *)PORTAL_DATA(mem_region);
    struct portal_sockfs_entry *pe;
    struct socket *sock;
    struct file *sfile; // ADD THIS
    int fd;

    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) goto fail;

    pe->hf_id = req->hf_id;
    pe->python_release = req->ops.release;

    // 1. Map socket protocol operations to our Python FFI pointers
    pe->pops.family = req->family;
    pe->pops.bind = req->ops.bind;
    pe->pops.connect = req->ops.connect;
    pe->pops.sendmsg = req->ops.sendmsg;
    pe->pops.recvmsg = req->ops.recvmsg;
    pe->pops.release = igloo_sockfs_proxy_release;
    
    // 2. Allocate a true kernel socket object
    sock = sock_alloc();
    if (!sock) {
        kfree(pe);
        goto fail;
    }

    sock->type = req->type;
    sock->ops = &pe->pops; 
    
    // Allocate the internal networking struct to hold our private data pointer
    sock->sk = sk_alloc(&init_net, req->family, GFP_KERNEL, &igloo_dummy_proto, 1);
    if (sock->sk) {
        sock->sk->sk_user_data = pe; 
    }

    // 3. Map the socket object to a process file descriptor safely
    fd = get_unused_fd_flags(O_RDWR);
    if (unlikely(fd < 0)) {
        sock_release(sock);
        kfree(pe);
        goto fail;
    }

    sfile = sock_alloc_file(sock, O_RDWR, NULL);
    if (IS_ERR(sfile)) {
        put_unused_fd(fd);
        kfree(pe);
        // Note: sock_alloc_file handles releasing the sock on error in most kernels
        goto fail;
    }

    fd_install(fd, sfile);

    mem_region->header.size = fd;
    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;

fail:
    mem_region->header.op = HYPER_RESP_WRITE_FAIL;
}