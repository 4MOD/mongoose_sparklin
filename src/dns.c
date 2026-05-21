#include "dns.h"
#include "log.h"
#include "str.h"
#include "timer.h"
#include "url.h"
#include "util.h"

/* lwip fallback DNS: when Mongoose's UDP DNS socket times out (e.g. on
 * Thread/NAT64 where the BSD socket source address is link-local and NAT64
 * cannot route the response back), we retry using lwip's internal DNS API
 * which uses the OMR (ULA) address and succeeds where the socket path fails.
 * For A-only hosts we synthesize the NAT64 address from the /96 prefix
 * that is embedded in the configured DNS64 server address. */
#ifdef MG_LWIP_DNS_FALLBACK
#  include "lwip/netdb.h"
#  include "lwip/sockets.h"
#  include "lwip/dns.h"
#endif

struct dns_data {
  struct dns_data *next;
  struct mg_connection *c;
  uint64_t expire;
  uint16_t txnid;
#ifdef MG_LWIP_DNS_FALLBACK
  char name[256];  /* hostname copy for lwip fallback resolution */
#endif
};

static void mg_sendnsreq(struct mg_connection *, struct mg_str *, int,
                         struct mg_dns *, bool);

static void mg_dns_free(struct mg_connection *c, struct dns_data *d) {
  LIST_DELETE(struct dns_data,
              (struct dns_data **) &c->mgr->active_dns_requests, d);
  free(d);
}

void mg_resolve_cancel(struct mg_connection *c) {
  struct dns_data *tmp, *d = (struct dns_data *) c->mgr->active_dns_requests;
  for (; d != NULL; d = tmp) {
    tmp = d->next;
    if (d->c == c) mg_dns_free(c, d);
  }
}

static size_t mg_dns_parse_name_depth(const uint8_t *s, size_t len, size_t ofs,
                                      char *to, size_t tolen, size_t j,
                                      int depth) {
  size_t i = 0;
  if (tolen > 0 && depth == 0) to[0] = '\0';
  if (depth > 5) return 0;
  // MG_INFO(("ofs %lx %x %x", (unsigned long) ofs, s[ofs], s[ofs + 1]));
  while (ofs + i + 1 < len) {
    size_t n = s[ofs + i];
    if (n == 0) {
      i++;
      break;
    }
    if (n & 0xc0) {
      size_t ptr = (((n & 0x3f) << 8) | s[ofs + i + 1]);  // 12 is hdr len
      // MG_INFO(("PTR %lx", (unsigned long) ptr));
      if (ptr + 1 < len && (s[ptr] & 0xc0) == 0 &&
          mg_dns_parse_name_depth(s, len, ptr, to, tolen, j, depth + 1) == 0)
        return 0;
      i += 2;
      break;
    }
    if (ofs + i + n + 1 >= len) return 0;
    if (j > 0) {
      if (j < tolen) to[j] = '.';
      j++;
    }
    if (j + n < tolen) memcpy(&to[j], &s[ofs + i + 1], n);
    j += n;
    i += n + 1;
    if (j < tolen) to[j] = '\0';  // Zero-terminate this chunk
    // MG_INFO(("--> [%s]", to));
  }
  if (tolen > 0) to[tolen - 1] = '\0';  // Make sure make sure it is nul-term
  return i;
}

static size_t mg_dns_parse_name(const uint8_t *s, size_t n, size_t ofs,
                                char *dst, size_t dstlen) {
  return mg_dns_parse_name_depth(s, n, ofs, dst, dstlen, 0, 0);
}

size_t mg_dns_parse_rr(const uint8_t *buf, size_t len, size_t ofs,
                       bool is_question, struct mg_dns_rr *rr) {
  const uint8_t *s = buf + ofs, *e = &buf[len];

  memset(rr, 0, sizeof(*rr));
  if (len < sizeof(struct mg_dns_header)) return 0;  // Too small
  if (len > 512) return 0;  //  Too large, we don't expect that
  if (s >= e) return 0;     //  Overflow

  if ((rr->nlen = (uint16_t) mg_dns_parse_name(buf, len, ofs, NULL, 0)) == 0)
    return 0;
  s += rr->nlen + 4;
  if (s > e) return 0;
  rr->atype = (uint16_t) (((uint16_t) s[-4] << 8) | s[-3]);
  rr->aclass = (uint16_t) (((uint16_t) s[-2] << 8) | s[-1]);
  if (is_question) return (size_t) (rr->nlen + 4);

  s += 6;
  if (s > e) return 0;
  rr->alen = (uint16_t) (((uint16_t) s[-2] << 8) | s[-1]);
  if (s + rr->alen > e) return 0;
  return (size_t) (rr->nlen + rr->alen + 10);
}

bool mg_dns_parse(const uint8_t *buf, size_t len, struct mg_dns_message *dm) {
  const struct mg_dns_header *h = (struct mg_dns_header *) buf;
  struct mg_dns_rr rr;
  size_t i, n, ofs = sizeof(*h);
  memset(dm, 0, sizeof(*dm));

  if (len < sizeof(*h)) return 0;                // Too small, headers dont fit
  if (mg_ntohs(h->num_questions) > 1) return 0;  // Sanity
  if (mg_ntohs(h->num_answers) > 10) return 0;   // Sanity
  dm->txnid = mg_ntohs(h->txnid);

  for (i = 0; i < mg_ntohs(h->num_questions); i++) {
    if ((n = mg_dns_parse_rr(buf, len, ofs, true, &rr)) == 0) return false;
    // MG_INFO(("Q %lu %lu %hu/%hu", ofs, n, rr.atype, rr.aclass));
    ofs += n;
  }
  for (i = 0; i < mg_ntohs(h->num_answers); i++) {
    if ((n = mg_dns_parse_rr(buf, len, ofs, false, &rr)) == 0) return false;
    // MG_INFO(("A -- %lu %lu %hu/%hu %s", ofs, n, rr.atype, rr.aclass,
    // dm->name));
    mg_dns_parse_name(buf, len, ofs, dm->name, sizeof(dm->name));
    ofs += n;

    if (rr.alen == 4 && rr.atype == 1 && rr.aclass == 1) {
      dm->addr.is_ip6 = false;
      memcpy(&dm->addr.ip, &buf[ofs - 4], 4);
      dm->resolved = true;
      break;  // Return success
    } else if (rr.alen == 16 && rr.atype == 28 && rr.aclass == 1) {
      dm->addr.is_ip6 = true;
      memcpy(&dm->addr.ip6, &buf[ofs - 16], 16);
      dm->resolved = true;
      break;  // Return success
    }
  }
  return true;
}

static void dns_cb(struct mg_connection *c, int ev, void *ev_data,
                   void *fn_data) {
  struct dns_data *d, *tmp;
  if (ev == MG_EV_POLL) {
    uint64_t now = *(uint64_t *) ev_data;
    for (d = (struct dns_data *) c->mgr->active_dns_requests; d != NULL;
         d = tmp) {
      tmp = d->next;
      // MG_DEBUG ("%lu %lu dns poll", d->expire, now));
      if (now > d->expire) {
#ifdef MG_LWIP_DNS_FALLBACK
        /* lwip fallback: Mongoose's UDP DNS socket times out on Thread/NAT64
         * because BSD socket source-address selection may pick a link-local
         * fe80:: address that NAT64 cannot route responses back to.
         * lwip's internal getaddrinfo() uses the OMR address directly.
         * For A-only hosts we synthesize the NAT64-mapped IPv6 address from
         * the /96 prefix embedded in the configured dns6 server address. */
        bool fallback_ok = false;
        if (d->name[0] != '\0') {
          struct addrinfo hints, *res = NULL;
          memset(&hints, 0, sizeof(hints));
          hints.ai_family   = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          if (getaddrinfo(d->name, NULL, &hints, &res) == 0 && res != NULL) {
            uint16_t saved_port = d->c->rem.port;
            struct addrinfo *ai;
            uint8_t ipv4_bytes[4];
            bool got_inet6 = false, got_inet = false;
            for (ai = res; ai != NULL; ai = ai->ai_next) {
              if (ai->ai_family == AF_INET6 && !got_inet6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ai->ai_addr;
                memset(&d->c->rem, 0, sizeof(d->c->rem));
                d->c->rem.is_ip6 = true;
                memcpy(d->c->rem.ip6, &sa6->sin6_addr, 16);
                d->c->rem.port   = saved_port;
                got_inet6 = true;
                break;
              } else if (ai->ai_family == AF_INET && !got_inet) {
                struct sockaddr_in *sa4 = (struct sockaddr_in *) ai->ai_addr;
                memcpy(ipv4_bytes, &sa4->sin_addr.s_addr, 4);
                got_inet = true;
              }
            }
            freeaddrinfo(res);
            if (!got_inet6 && got_inet) {
              /* Synthesize NAT64 address: first 12 bytes of the configured
               * dns6 server = /96 NAT64 prefix; last 4 bytes = IPv4 addr. */
              const ip_addr_t *nat64_dns = dns_getserver(0);
              if (nat64_dns != NULL && IP_IS_V6_VAL(*nat64_dns)) {
                const ip6_addr_t *pfx = ip_2_ip6(nat64_dns);
                memset(&d->c->rem, 0, sizeof(d->c->rem));
                d->c->rem.is_ip6 = true;
                memcpy(d->c->rem.ip6,      pfx->addr, 12);
                memcpy(d->c->rem.ip6 + 12, ipv4_bytes, 4);
                d->c->rem.port   = saved_port;
                got_inet6 = true;
              }
            }
            if (got_inet6 && d->c->is_resolving) {
              MG_DEBUG(("%lu DNS lwip fallback: resolved %s", d->c->id, d->name));
              mg_connect_resolved(d->c);
              mg_dns_free(c, d);
              fallback_ok = true;
            }
          }
        }
        if (!fallback_ok) mg_error(d->c, "DNS timeout");
#else
        mg_error(d->c, "DNS timeout");
#endif
      }
    }
  } else if (ev == MG_EV_READ) {
    struct mg_dns_message dm;
    int resolved = 0;
    if (mg_dns_parse(c->recv.buf, c->recv.len, &dm) == false) {
      MG_ERROR(("Unexpected DNS response:"));
      mg_hexdump(c->recv.buf, c->recv.len);
    } else {
      MG_VERBOSE(("%s %d", dm.name, dm.resolved));
      for (d = (struct dns_data *) c->mgr->active_dns_requests; d != NULL;
           d = tmp) {
        tmp = d->next;
        // MG_INFO(("d %p %hu %hu", d, d->txnid, dm.txnid));
        if (dm.txnid != d->txnid) continue;
        if (d->c->is_resolving) {
          if (dm.resolved) {
            char buf[100];
            dm.addr.port = d->c->rem.port;  // Save port
            d->c->rem = dm.addr;            // Copy resolved address
            MG_DEBUG(("%lu %s is %s", d->c->id, dm.name,
                      mg_ntoa(&d->c->rem, buf, sizeof(buf))));
            mg_connect_resolved(d->c);
#if MG_ENABLE_IPV6
          } else if (dm.addr.is_ip6 == false && dm.name[0] != '\0' &&
                     c->mgr->use_dns6 == false) {
            struct mg_str x = mg_str(dm.name);
            mg_sendnsreq(d->c, &x, c->mgr->dnstimeout, &c->mgr->dns6, true);
#endif
          } else {
            mg_error(d->c, "%s DNS lookup failed", dm.name);
          }
        } else {
          MG_ERROR(("%lu already resolved", d->c->id));
        }
        mg_dns_free(c, d);
        resolved = 1;
      }
    }
    if (!resolved) MG_ERROR(("stray DNS reply"));
    c->recv.len = 0;
  } else if (ev == MG_EV_CLOSE) {
    for (d = (struct dns_data *) c->mgr->active_dns_requests; d != NULL;
         d = tmp) {
      tmp = d->next;
      mg_error(d->c, "DNS error");
      mg_dns_free(c, d);
    }
  }
  (void) fn_data;
}

static bool mg_dns_send(struct mg_connection *c, const struct mg_str *name,
                        uint16_t txnid, bool ipv6) {
  struct {
    struct mg_dns_header header;
    uint8_t data[256];
  } pkt;
  size_t i, n;
  memset(&pkt, 0, sizeof(pkt));
  pkt.header.txnid = mg_htons(txnid);
  pkt.header.flags = mg_htons(0x100);
  pkt.header.num_questions = mg_htons(1);
  for (i = n = 0; i < sizeof(pkt.data) - 5; i++) {
    if (name->ptr[i] == '.' || i >= name->len) {
      pkt.data[n] = (uint8_t) (i - n);
      memcpy(&pkt.data[n + 1], name->ptr + n, i - n);
      n = i + 1;
    }
    if (i >= name->len) break;
  }
  memcpy(&pkt.data[n], "\x00\x00\x01\x00\x01", 5);  // A query
  n += 5;
  if (ipv6) pkt.data[n - 3] = 0x1c;  // AAAA query
  // memcpy(&pkt.data[n], "\xc0\x0c\x00\x1c\x00\x01", 6);  // AAAA query
  // n += 6;
  return mg_send(c, &pkt, sizeof(pkt.header) + n);
}

static void mg_sendnsreq(struct mg_connection *c, struct mg_str *name, int ms,
                         struct mg_dns *dnsc, bool ipv6) {
  struct dns_data *d = NULL;
  if (dnsc->url == NULL) {
    mg_error(c, "DNS server URL is NULL. Call mg_mgr_init()");
  } else if (dnsc->c == NULL) {
    dnsc->c = mg_connect(c->mgr, dnsc->url, NULL, NULL);
    if (dnsc->c != NULL) {
      dnsc->c->pfn = dns_cb;
      // dnsc->c->is_hexdumping = 1;
    }
  }
  if (dnsc->c == NULL) {
    mg_error(c, "resolver");
  } else if ((d = (struct dns_data *) calloc(1, sizeof(*d))) == NULL) {
    mg_error(c, "resolve OOM");
  } else {
    struct dns_data *reqs = (struct dns_data *) c->mgr->active_dns_requests;
    char buf[100];
    d->txnid = reqs ? (uint16_t) (reqs->txnid + 1) : 1;
    d->next = (struct dns_data *) c->mgr->active_dns_requests;
    c->mgr->active_dns_requests = d;
    d->expire = mg_millis() + (uint64_t) ms;
    d->c = c;
    c->is_resolving = 1;
#ifdef MG_LWIP_DNS_FALLBACK
    if (name->len < sizeof(d->name)) {
      memcpy(d->name, name->ptr, name->len);
      d->name[name->len] = '\0';
    }
#endif
    MG_VERBOSE(("%lu resolving %.*s @ %s, txnid %hu", c->id, (int) name->len,
                name->ptr, mg_ntoa(&dnsc->c->rem, buf, sizeof(buf)), d->txnid));
    if (!mg_dns_send(dnsc->c, name, d->txnid, ipv6)) {
      mg_error(dnsc->c, "DNS send");
    }
  }
}

void mg_resolve(struct mg_connection *c, const char *url) {
  struct mg_str host = mg_url_host(url);
  c->rem.port = mg_htons(mg_url_port(url));
  if (mg_aton(host, &c->rem)) {
    // host is an IP address, do not fire name resolution
    mg_connect_resolved(c);
  } else {
    // host is not an IP, send DNS resolution request
    struct mg_dns *dns = c->mgr->use_dns6 ? &c->mgr->dns6 : &c->mgr->dns4;
    mg_sendnsreq(c, &host, c->mgr->dnstimeout, dns, c->mgr->use_dns6);
  }
}
