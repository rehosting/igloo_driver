#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/igloo.h>
#include <linux/unistd.h>
#include <linux/socket.h>
#include <linux/ipv6.h>
#include <net/inet_sock.h>

void igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address);
void igloo_sock_release(struct socket *sock);


/**
 * Called from __sys_bind_socket in net/socket.c
 */
void igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address){
	if (!igloo_do_hc) {
		return;
	}
	// Bind successfully occured. Hypercall to tell us
	// the bind details.
	// First hypercall to tell us process name.
	int hrv = 1;
	int i;
	
	if (address->ss_family == AF_INET) {
		// IPv4: hypercall 200
		struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
		short port = addr_in->sin_port;
		short is_stream = (sock->type == SOCK_STREAM);
	
		// report procname + address
		while (hrv == 1) {
			// Read current->comm to ensure it's paged in and try again
			for (i=0; i<strlen(current->comm); i++) {
				asm volatile("" : : "r" (current->comm[i]) : "memory");
			}
			hrv = igloo_hypercall2(IGLOO_IPV4_SETUP, (unsigned long)current->comm,  (unsigned long)addr_in->sin_addr.s_addr);
		}
	
		igloo_hypercall2(IGLOO_IPV4_BIND, (unsigned long)port, (unsigned long)is_stream);
	
	} else if (address->ss_family == AF_INET6) {
		// IPv6: hypercall 201
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
		short port = addr_in6->sin6_port;
		short is_stream = (sock->type == SOCK_STREAM);
	
		while (hrv == 1) {
			// Read current->comm and addr_in6->sin6_addr to ensure it's paged in and try again
			for (i=0; i<strlen(current->comm); i++) {
				asm volatile("" : : "r" (current->comm[i]) : "memory");
			}
			for (i=0; i<16; i++) {
				asm volatile("" : : "r" (addr_in6->sin6_addr.s6_addr[i]) : "memory");
			}
			hrv = igloo_hypercall2(IGLOO_IPV6_SETUP, (unsigned long)current->comm, (unsigned long)&addr_in6->sin6_addr);
		}
	
		igloo_hypercall2(IGLOO_IPV6_BIND, (unsigned long)port, (unsigned long)is_stream);
	}
}

/**
 * Called from sock_release in net/socket.c
 */
void igloo_sock_release(struct socket *sock){
    if (!igloo_do_hc){
	    return;
    }
	struct sock *sk = sock->sk;

	if (sk) {
		int e;
		unsigned short port;

		if (sk->sk_family == AF_INET) {
			char buffer[23];
			struct inet_sock *inet = inet_sk(sk);
			port = ntohs(inet->inet_sport);      
			if (port != 0){
				__be32 ip = inet->inet_saddr;          
				short is_stream = (sk->sk_type == SOCK_STREAM);
				snprintf(buffer, sizeof(buffer), "%pI4:%u", &ip, port);
				e = igloo_hypercall2(IGLOO_IPV4_RELEASE, (unsigned long)&buffer, (unsigned long)is_stream); 
			}
		}
		else if (sk->sk_family == AF_INET6) {
			char buffer[49];
			struct inet_sock *inet = inet_sk(sk);
			struct ipv6_pinfo *ipv6_s = inet6_sk(sk);
			port = ntohs(inet->inet_sport);

			if (port != 0){
				struct in6_addr *ip6 = &ipv6_s->saddr;
				short is_stream = (sk->sk_type == SOCK_STREAM);

				snprintf(buffer, sizeof(buffer), "[%pI6c]:%u", ip6, port);
				
				e = igloo_hypercall2(IGLOO_IPV6_RELEASE, (unsigned long)&buffer, (unsigned long)is_stream);
			}
		}
	}
}