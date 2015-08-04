/*
 * Copyright (C) 2014 Giuseppe Lettieri. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $FreeBSD: readp/sys/dev/netmap/netmap_pipe.c 261909 2014-02-15 04:53:04Z luigi $ */

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/socket.h> /* sockaddrs */
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/refcount.h>
#include <sys/uio.h>


#elif defined(linux)

#include "bsd_glue.h"

#elif defined(__APPLE__)

#warning OSX support is only partial
#include "osx_glue.h"

#else

#error	Unsupported platform

#endif /* unsupported */

/*
 * common headers
 */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include "jsonlr.h"

#ifdef WITH_NMCONF

#define NM_CBDATASIZ 1024
#define NM_CBDATAMAX 4

/* simple buffers for incoming/outgoing data on read()/write() */

struct nm_confbuf_data {
	struct nm_confbuf_data *chain;
	u_int size;
	char data[];
};

/* prepare for a write of req_size bytes;
 * returns a pointer to a buffer that can be used for writing,
 * or NULL if not enough space is available;
 * By passing in avl_size, the caller declares that it is
 * willing to accept a buffer with a smaller size than requested.
 */
static void*
netmap_confbuf_pre_write(struct netmap_confbuf *cb, u_int req_size, u_int *avl_size)
{
	struct nm_confbuf_data *d, *nd;
	u_int s = 0, b;
	void *ret;

	d = cb->writep;
	/* get the current available space */
	if (d)
		s = d->size - cb->next_w;
	if (s > 0 && (s >= req_size || avl_size)) {
		b = cb->next_w;
		goto out;
	}
	/* we need to expand the buffer, if possible */
	if (cb->n_data >= NM_CBDATAMAX)
		return NULL;
	s = NM_CBDATASIZ;
	if (req_size > s && avl_size == NULL)
		s = req_size;
	nd = malloc(sizeof(*d) + s, M_DEVBUF, M_NOWAIT);
	if (nd == NULL)
		return NULL;
	nd->size = s;
	nd->chain = NULL;
	if (d) {
		/* the caller is not willing to do a short write
		 * and the available space in the current chunk
		 * is not big enough. Truncate the chunk and
		 * move to the next one.
		 */
		d->size = cb->next_w;
		d->chain = nd;
	}
	cb->n_data++;
	if (cb->readp == NULL) {
		/* this was the first chunk, 
		 * initialize all pointers
		 */
		cb->readp = cb->writep = nd;
	}
	d = nd;
	b = 0;
out:
	if (s > req_size)
		s = req_size;
	if (avl_size)
		*avl_size = s;
	ret = d->data + b;
	return ret;
}

static void
netmap_confbuf_post_write(struct netmap_confbuf *cb, u_int size)
{
	if (cb->next_w == cb->writep->size) {
		cb->writep = cb->writep->chain;
		cb->next_w = 0;
	}
	cb->next_w += size;

}

/* prepare for a read of size bytes;
 * returns a pointer to a buffer which is at least size bytes big.
 * Note that, on return, size may be smaller than asked for;
 * if size is 0, no other bytes can be read.
 */
static void*
netmap_confbuf_pre_read(struct netmap_confbuf *cb, u_int *size)
{
	struct nm_confbuf_data *d;
	u_int n;

	d = cb->readp;
	n = cb->next_r;
	for (;;) {
		if (d == NULL) {
			*size = 0;
			return NULL;
		}
		if (d->size > n) {
			/* there is something left to read
			 * in this chunk
			 */
			u_int s = d->size - n;
			void *ret = d->data + n;
			if (*size < s)
				s = *size;
			else
				*size = s;
			return ret;
		}
		/* chunk exausted, move to the next one */
		d = d->chain;
		n = 0;
	}
}

static void
netmap_confbuf_post_read(struct netmap_confbuf *cb, u_int size)
{
	if (cb->next_r == cb->readp->size) {
		struct nm_confbuf_data *ocb = cb->readp;
		cb->readp = cb->readp->chain;
		cb->next_r = 0;
		free(ocb, M_DEVBUF);
		cb->n_data--;
	}
	cb->next_r += size;
}

struct netmap_jp_stream {
	struct _jp_stream stream;
	struct netmap_confbuf *cb;
};

static int
netmap_confbuf_peek(struct _jp_stream *jp)
{
	struct netmap_jp_stream *n = (struct netmap_jp_stream *)jp;
	struct netmap_confbuf *cb = n->cb;
	u_int s = 1;
	void *p = netmap_confbuf_pre_read(cb, &s);
	if (p == NULL)
		return 0;
	return *(char *)p;
}

static void
netmap_confbuf_consume(struct _jp_stream *jp)
{
	struct netmap_jp_stream *n = (struct netmap_jp_stream *)jp;
	struct netmap_confbuf *cb = n->cb;
	netmap_confbuf_post_read(cb, 1);
}

static void
netmap_confbuf_destroy(struct netmap_confbuf *cb)
{
	struct nm_confbuf_data *d = cb->readp;

	while (d) {
		struct nm_confbuf_data *nd = d->chain;
		free(d, M_DEVBUF);
		d = nd;
	}
	memset(cb, 0, sizeof(*cb));
}

void
netmap_config_init(struct netmap_config *c)
{
	NM_MTX_INIT(c->mux);
}

void
netmap_config_uninit(struct netmap_config *c)
{
	int i;
	
	(void)netmap_config_parse(c);
	for (i = 0; i < 2; i++)
		netmap_confbuf_destroy(c->buf + i);
	NM_MTX_DESTROY(c->mux);
}

#define NETMAP_CONFIG_POOL_SIZE (1<<12)

int
netmap_config_parse(struct netmap_config *c)
{
	char *pool;
	uint32_t pool_len = NETMAP_CONFIG_POOL_SIZE;
	struct netmap_jp_stream njs = {
		.stream = {
			.peek = netmap_confbuf_peek,
			.consume = netmap_confbuf_consume,
		},
		.cb = &c->buf[0],
	};
	struct _jpo r;
	int error = 0;

	pool = malloc(pool_len, M_DEVBUF, M_ZERO);
	if (pool == NULL)
		return ENOMEM;
	r = jslr_parse(&njs.stream, pool, pool_len);
	if (r.ty == JPO_ERR) {
		D("parse error: %d", r.ptr);
		netmap_confbuf_destroy(njs.cb);
		goto out;
	}
	D("parse OK: ty %u len %u ptr %u", r.ty, r.len, r.ptr);
	/* now we should take global lock and interpret the commands */
out:
	free(pool, M_DEVBUF);
	return error;
}

int
netmap_config_write(struct netmap_config *c, struct uio *uio)
{
	int ret = 0;
	struct netmap_confbuf *i = &c->buf[0],
			      *o = &c->buf[1];

	NM_MTX_LOCK(c->mux);

	netmap_confbuf_destroy(o);

	while (uio->uio_resid > 0) {
		int s = uio->uio_resid;
		void *p = netmap_confbuf_pre_write(i, s, &s);
		if (p == NULL) {
			ND("NULL p from confbuf_pre_write");
			ret = ENOMEM;
			goto out;
		}
		ND("s %d", s);
		ret = uiomove(p, s, uio);
		if (ret)
			goto out;
		netmap_confbuf_post_write(i, s);
	}

out:
	NM_MTX_UNLOCK(c->mux);
	return ret;
}

int
netmap_config_read(struct netmap_config *c, struct uio *uio)
{
	int ret = 0;
	struct netmap_confbuf *o = &c->buf[1];

	NM_MTX_LOCK(c->mux);

	ret = netmap_config_parse(c);
	if (ret)
		goto out;

	while (uio->uio_resid > 0) {
		int s = uio->uio_resid;
		void *p = netmap_confbuf_pre_read(o, &s);
		if (p == NULL) {
			goto out;
		}
		ret = uiomove(p, s, uio);
		if (ret)
			goto out;
		netmap_confbuf_post_read(o, s);
	}

out:
	NM_MTX_UNLOCK(c->mux);

	return ret;
}


static int
netmap_interp_list_interp(struct netmap_interp *ip,
		struct _jpo jpo, const char *pool,
		struct netmap_confbuf *out)
{
	return 0;
}


int
netmap_interp_list_init(struct netmap_interp_list *il, u_int nelem)
{
	il->up.interp = netmap_interp_list_interp;
	il->minelem = nelem;
	il->list = malloc(sizeof(*il->list) * nelem, M_DEVBUF, M_ZERO);
	if (il->list == NULL)
		return ENOMEM;
	il->nelem = nelem;
	return 0;
}

void
netmap_interp_list_uninit(struct netmap_interp_list *il)
{
	free(il->list, M_DEVBUF);
	memset(il, 0, sizeof(*il));
}

int
netmap_interp_list_add(struct netmap_interp_list *il, const char *name,
		struct netmap_interp *ip)
{
	struct netmap_interp_list_elem *e, *newlist;

	if (il->nextfree >= il->nelem) {
		u_int newnelem = il->nelem * 2;
		newlist = realloc(il->list, sizeof(*il->list) * newnelem, M_DEVBUF, M_ZERO);
		if (newlist == NULL)
			return ENOMEM;
		il->list = newlist;
		il->nelem = newnelem;
	}
	e = &il->list[il->nextfree++];
	strncpy(e->name, name, NETMAP_CONFIG_MAXNAME);
	e->ip = ip;
	return 0;
}

static int
_netmap_interp_list_search(struct netmap_interp_list *il, const char *name)
{
	int i;
	for (i = 0; i < il->nelem; i++) {
		struct netmap_interp_list_elem *e = &il->list[i];
		if (strncmp(name, e->name, NETMAP_CONFIG_MAXNAME) == 0)
			break;
	}
	return i;
}

int
netmap_interp_list_del(struct netmap_interp_list *il, const char *name)
{
	int i = _netmap_interp_list_search(il, name);
	struct netmap_interp_list_elem *e1, *e2;
	if (i == il->nelem)
		return ENOENT;
	e1 = &il->list[i];
	e2 = &il->list[il->nextfree];
	strncpy(e1->name, e2->name, NETMAP_CONFIG_MAXNAME);
	e1->ip = e2->ip;
	il->nextfree--;
	if (il->nelem > il->minelem && il->nextfree < il->nelem / 2) {
		struct netmap_interp_list_elem *newlist;
		u_int newnelem = il->nelem / 2;
		if (newnelem < il->minelem)
			newnelem = il->minelem;
		newlist = realloc(il->list, newnelem, M_DEVBUF, M_ZERO);
		if (newlist == NULL) {
			D("out of memory when trying to release memory?");
			return 0; /* not fatal */
		}
		il->list = newlist;
		il->nelem = newnelem;
	}
	return 0;
}

struct netmap_interp *
netmap_interp_list_search(struct netmap_interp_list *il, const char *name)
{
	int i = _netmap_interp_list_search(il, name);
	if (i == il->nelem)
		return NULL;
	return il->list[i].ip;
}

#endif /* WITH_NMCONF */
