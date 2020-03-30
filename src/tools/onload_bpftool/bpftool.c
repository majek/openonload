/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <net/if.h>

#include <ci/tools.h>
#include <onload/oobpf.h>
#ifndef	__aligned_u64
/* Not present on vanilla kernels < 4.15 */
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif
#include <linux/bpf.h>


#define TRY(x)                                                  \
  do {                                                          \
    int _rc = (x);                                              \
    if( _rc < 0 ) {                                             \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              _rc, errno, strerror(errno));                     \
      exit(EXIT_FAILURE);                                       \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(EXIT_FAILURE);                                       \
    }                                                           \
  } while( 0 )


static bool should_quote_string(const char* str, int len)
{
  int i;

  for( i = 0; i < len; ++i ) {
    char c = str[i];
    if( c == '\0' )
      break;
    else if( c == '\\' || c == '\"' || c == ' ' )
      return true;
    else if( ' ' <= c && c <= '~' )
      continue;
    else
      return true;
  }

  return false;
}


static void print_escaped_string(FILE* f, const char* str, int len)
{
  int i;

  for( i = 0; i < len; ++i ) {
    char c = str[i];
    if( c == '\0')
      break;
    switch( c ) {
    case '\t': fprintf(f, "\\t");  break;
    case '\r': fprintf(f, "\\r");  break;
    case '\n': fprintf(f, "\\n");  break;
    case '\"': fprintf(f, "\\\""); break;
    case '\\': fprintf(f, "\\\\"); break;
    default:
      if( ' ' <= c && c <= '~' )
        fputc(c, f);
      else
        fprintf(f, "\\x%02x", c & 0xFF);
    }
  }
}


#define ATTACH_POINT_SYNTAX     "{ xdp_ingress }"
#define ATTACH_POINT_DEFINITION "ATTACH_POINT := " ATTACH_POINT_SYNTAX
static const char* format_attach_point(enum oo_bpf_attach_point attach_point)
{
  switch( attach_point ) {
  case OO_BPF_ATTACH_XDP_INGRESS:
    return "xdp_ingress";
  case OO_BPF_ATTACH_MAX:
    break;
  }
  return "<unrecognized attach point>";
}


static enum oo_bpf_attach_point parse_attach_point(const char* str)
{
  if( !strcmp(str, "xdp_ingress") )
    return OO_BPF_ATTACH_XDP_INGRESS;

  return OO_BPF_ATTACH_MAX;
}


#define ATTACHMENT_SYNTAX     "ATTACH_POINT [dev IFNAME] [stack STACKNAME]"
#define ATTACHMENT_DEFINITION "ATTACHMENT := " ATTACHMENT_SYNTAX
static void parse_attachment_error(void)
{
    fprintf(stderr, "Expected " ATTACHMENT_SYNTAX "\n");
    fprintf(stderr, "\n");
    fprintf(stderr, ATTACH_POINT_DEFINITION "\n");
}


static void print_attachment(FILE* f,
                             const struct oo_bpf_prog_attach_arg* attach)
{
  char ifname[IF_NAMESIZE];

  fprintf(f, "%s", format_attach_point(attach->attach_point));
  if( attach->ifindex != 0 )
    fprintf(f, " dev %s", if_indextoname(attach->ifindex, ifname));
  if( attach->stack[0] != '\0' ) {
    bool quote = should_quote_string(attach->stack, sizeof(attach->stack));
    fprintf(f, " stack ");
    if( quote )
      fprintf(f, "\"");
    print_escaped_string(f, attach->stack, sizeof(attach->stack));
    if( quote )
      fprintf(f, "\"");
  }
}


static int parse_attachment(int argc, char** argv,
                            struct oo_bpf_prog_attach_arg* attach)
{
  int consumed = 0;
  bool have_ifname = false;
  bool have_stackname = false;

  if( argc < 1 ) {
    parse_attachment_error();
    return -1;
  }

  memset(attach, 0, sizeof(*attach));

  /* Parse ATTACH_POINT */
  attach->attach_point = parse_attach_point(argv[consumed]);
  if( attach->attach_point == OO_BPF_ATTACH_MAX ) {
    fprintf(stderr, "Error: Bad ATTACH_POINT, try " ATTACH_POINT_SYNTAX "\n");
    return -1;
  }
  ++consumed;

  /* Parse [dev IFNAME] [stack STACKNAME] */
  while( argc - consumed >= 1 ) {
    if( !strcmp(argv[consumed], "dev") && !have_ifname ) {
      if( argc - consumed < 2 ) {
        fprintf(stderr, "Expected dev IFNAME\n");
        return -1;
      }
      const char* ifname = argv[consumed + 1];
      attach->ifindex = if_nametoindex(ifname);
      if( attach->ifindex == 0 ) {
        fprintf(stderr, "Error: Unrecognized IFNAME %s\n", ifname);
        return -1;
      }
      have_ifname = true;
      consumed += 2;
    }
    else if( !strcmp(argv[consumed], "stack") && !have_stackname ) {
      if( argc - consumed < 2 ) {
        fprintf(stderr, "Expected stack STACKNAME\n");
        return -1;
      }
      strncpy(attach->stack, argv[consumed + 1], sizeof(attach->stack));
      have_stackname = true;
      consumed += 2;
    }
    else break;
  }

  return consumed;
}


static int parse_attachments(int argc, char** argv, const char* prefix,
                             struct oo_bpf_prog_attach_arg** attaches_out,
                             int* attach_cnt_out)
{
  int rc;

  int consumed = 0;

  struct oo_bpf_prog_attach_arg* attaches = NULL;
  struct oo_bpf_prog_attach_arg* new_attaches = NULL;
  int attach_cnt = 0;

  while( argc - consumed > 0 ) {
    if( prefix ) {
      if( strcmp(argv[consumed], prefix ) )
        break;
      ++consumed;
    }
    new_attaches = realloc(attaches, (attach_cnt + 1) *
                                     sizeof(struct oo_bpf_prog_attach_arg));
    if( new_attaches == NULL ) {
      free(attaches);
      return -1;
    }
    attaches = new_attaches;
    rc = parse_attachment(argc - consumed, argv + consumed,
                          &attaches[attach_cnt]);
    if( rc < 0 )
      return -1;
    consumed += rc;
    ++attach_cnt;
  }

  *attaches_out = attaches;
  *attach_cnt_out = attach_cnt;

  return consumed;
}


#define PROG_LIST_ARGUMENTS ""
static int cmd_prog_list(int argc, char** argv)
{
  int rc;
  int drv_fd;
  int prog_fd;

  int capacity;
  int count;
  struct oo_bpf_prog_attach_arg* attaches = NULL;

  int i;
  struct oo_bpf_prog_info info;

  TRY(drv_fd = open(OO_BPF_DEVICE, O_RDWR));
  TRY(oo_bpf_check_version(drv_fd));

  /* Get all attachments, retrying until a coherent snapshot is obtained */
  do {
    TRY(capacity = oo_bpf_prog_get_all(drv_fd, 0, NULL));

    free(attaches);
    TEST(attaches = malloc(sizeof(struct oo_bpf_prog_attach_arg) * capacity));
    TRY(count = oo_bpf_prog_get_all(drv_fd, capacity, attaches));
  } while( count > capacity );

  /* Print each attachment.
   * The same program may be installed at multiple attachments.
   * These will be printed as multiple entries. */
  for( i = 0; i < count; ++i ) {
    print_attachment(stdout, &attaches[i]);
    printf("\n");

    prog_fd = oo_bpf_prog_get_by_attachment(drv_fd, &attaches[i]);
    if( prog_fd < 0 ) {
      fprintf(stderr, "\terror getting attachment %d: %s\n",
              i, strerror(errno));
      continue;
    }

    memset(&info, 0, sizeof(info));
    rc = oo_bpf_prog_get_info(prog_fd, &info);
    if( rc < 0 ) {
      fprintf(stderr, "\terror getting program info %d: %s\n",
              i, strerror(errno));
    }
    else {
      printf("\txlated %dB  jited %dB  maps %d\n",
             info.xlated_prog_len,
             info.jited_prog_len,
             info.nr_map_ids);
    }

    close(prog_fd);
  }

  free(attaches);

  close(drv_fd);
  return 0;
}


#define TMPFILE "/tmp/onload_bpftool_XXXXXX"
static void print_disassembly(void* jit, size_t length)
{
  int rc = 1;

  char cmd[] = "objdump -D -b binary -m i386:x86-64 " TMPFILE;
  char* tmpfile = cmd + strlen(cmd) - strlen(TMPFILE);

  int jitfd = mkstemp(tmpfile);
  if( jitfd < 0 )
    goto fail;
  if( write(jitfd, jit, length) != length )
    goto fail_unlink;

  rc = system(cmd);

fail_unlink:
  close(jitfd);
  unlink(tmpfile);

fail:
  /* Fall back to a hex dump if the objdump attempt did not work out */
  if( rc != 0 )
    ci_hex_dump(ci_log_stdout, jit, length, 0);

  return;
}
#undef TMPFILE


#define PROG_DUMP_ARGUMENTS "{ xlated | jited } ATTACHMENT"
static int cmd_prog_dump(int argc, char** argv)
{
  int rc;
  int drv_fd;
  int prog_fd;

  bool dump_jit;
  struct oo_bpf_prog_attach_arg attach;

  /* Parse mode ("xlated" | "jited") */
  const char* mode = argc >= 1 ? argv[0] : NULL;
  if( mode && ! strcmp(mode, "xlated") )
    dump_jit = false;
  else if( mode && ! strcmp(mode, "jited") )
    dump_jit = true;
  else {
    fprintf(stderr, "Error: expected 'xlated' or 'jited', got: %s\n", mode);
    return 1;
  }
  argc--; argv++;

  /* Parse attachment */
  rc = parse_attachment(argc, argv, &attach);
  if( rc < 0 )
    return 1;
  if( rc < argc ) {
    parse_attachment_error();
    return 1;
  }
  argc -= rc; argv += rc;

  /* Get program */
  TRY(drv_fd = open(OO_BPF_DEVICE, O_RDWR));
  TRY(oo_bpf_check_version(drv_fd));

  prog_fd = oo_bpf_prog_get_by_attachment(drv_fd, &attach);
  if( prog_fd < 0 ) {
    rc = 1;
    if( errno == ENOENT )
      fprintf(stderr, "Error: no program is attached here\n");
    else
      fprintf(stderr, "Error: %s\n", strerror(errno));
    goto fail;
  }

  /* Get program info */
  struct oo_bpf_prog_info info;
  memset(&info, 0, sizeof(info));
  TRY(rc = oo_bpf_prog_get_info(prog_fd, &info));

  /* Get program instructions */
  size_t ebpf_size = info.xlated_prog_len;
  size_t jit_size  = info.jited_prog_len;
  struct bpf_insn* ebpf = malloc(ebpf_size);
  size_t ebpf_insn_cnt = ebpf_size / sizeof(struct bpf_insn);
  void* jit = malloc(jit_size);

  memset(&info, 0, sizeof(info));
  info.xlated_prog_len = ebpf_size;
  info.xlated_prog_insns = (uintptr_t)ebpf;
  info.jited_prog_len = jit_size;
  info.jited_prog_insns = (uintptr_t)jit;

  TRY(rc = oo_bpf_prog_get_info(prog_fd, &info));

  if( ! dump_jit ) {
    /* Dump eBPF, in a format that's halfway between bpftools prog dump's
     * default and opcodes mode. No nice disassembly here sadly. */
    int i = 0;
    while( i < ebpf_insn_cnt ) {
      union {
        struct bpf_insn insn;
        uint8_t bytes[8];
      } insn;
      insn.insn = ebpf[i];
      fprintf(stdout, "%4d: (%02x) %02x %02x %02x %02x %02x %02x %02x", i,
              insn.bytes[0], insn.bytes[1], insn.bytes[2], insn.bytes[3],
              insn.bytes[4], insn.bytes[5], insn.bytes[6], insn.bytes[7]);
      /* The (BPF_LD | BPF_IMM | BPF_DW) instruction takes up two bpf_insn
       * slots. */
      if( insn.bytes[0] == (BPF_LD | BPF_IMM | BPF_DW) &&
          i + 1 < ebpf_insn_cnt ) {
        ++i;
        insn.insn = ebpf[i];
        fprintf(stdout, " %02x %02x %02x %02x %02x %02x %02x %02x",
                insn.bytes[0], insn.bytes[1], insn.bytes[2], insn.bytes[3],
                insn.bytes[4], insn.bytes[5], insn.bytes[6], insn.bytes[7]);
      }
      fprintf(stdout, "\n");
      ++i;
    }
  } else {
    /* Dump JIT */
    print_disassembly(jit, jit_size);
  }

  free(ebpf);
  free(jit);
  close(prog_fd);

fail:
  close(drv_fd);

  return rc;
}


/* Used to allow abbreviated keywords in the command-line parameters of the
 * "load" subcommand, for compatibility with iproute2's command line */
static bool matches(const char* arg, const char* keyword)
{
  return strncmp(arg, keyword, strlen(arg)) == 0;
}


/* Do a retry loop loading a prog, increasing the verifier log buffer size
 * each time - we don't know how much space we're going to need */
static int load_prog_verbose(int drv, struct oo_bpf_elf* elf,
                             const char* section)
{
  struct oo_bpf_elf_load_attrs load_attrs;
  char* log_buf = NULL;
  size_t buf_size = 65536;
  int retry;
  int prog_fd;
  int saved_errno;

  memset(&load_attrs, 0, sizeof(load_attrs));
  load_attrs.struct_size = sizeof(load_attrs);
  load_attrs.log_level = 2;

  for( retry = 0; retry < 10; ++retry ) {
    log_buf = malloc(buf_size);
    if( ! log_buf ) {
      errno = ENOMEM;
      return -1;
    }
    log_buf[0] = '\0';
    load_attrs.log_buf = log_buf;
    load_attrs.log_size = buf_size;
    prog_fd = oo_bpf_elf_load_prog(drv, elf, section, BPF_PROG_TYPE_XDP,
                                   &load_attrs);
    saved_errno = errno;
    free(log_buf);
    if( prog_fd >= 0 || saved_errno != ENOSPC )
      break;
    buf_size *= 2;
  }

  if( prog_fd >= 0 )
    fprintf(stderr, "Prog section '%s' loaded\n", section);
  else {
    fprintf(stderr, "Prog section '%s' rejected: %s (%d)\n",
            section, strerror(saved_errno), saved_errno);
  }
  if( log_buf[0] ) {
    fputs("Verifier analysis:\n", stderr);
    fputs(log_buf, stderr);
  }
  errno = saved_errno;
  return prog_fd;
}


#define PROG_LOAD_ATTACH_ARGUMENTS \
     "object FILE " \
     "[ section NAME ] " \
     "[ verbose ] " \
     "attach ATTACHMENT [attach ATTACHMENT]..."

static int cmd_prog_load_attach(int argc, char** argv)
{
  int rc;
  int drv_fd;
  int prog_fd;
  int i;

  struct oo_bpf_prog_attach_arg* attaches;
  int attach_cnt;
  bool attach_failed = false;

  const char* filename;
  const char* section = "prog";   /* default from iproute2 */
  bool verbose = false;
  struct oo_bpf_elf* elf;

  /* Parse file path and attachment */
  if( argc < 2 ) {
    fprintf(stderr, "Expected \"load-type FILE\"\n");
    return 1;
  }

  /* The word "object" is mandatory for iproute2 compatibility - we might
   * later add "object-pinned" or other features, like they have. */
  if( ! matches(argv[0], "object-file") ) {
    fprintf(stderr, "Expected \"object FILE\"\n");
    return 1;
  }
  filename = argv[1];
  argc -= 2;
  argv += 2;

  if( argc && matches(argv[0], "section") ) {
    if( argc < 2 ) {
      fprintf(stderr, "Expected \"section NAME\"\n");
      return 1;
    }
    section = argv[1];
    argc -= 2;
    argv += 2;
  }

  if( argc && matches(argv[0], "verbose") ) {
    verbose = true;
    --argc;
    ++argv;
  }

  rc = parse_attachments(argc, argv, "attach", &attaches, &attach_cnt);
  if( rc < 0 )
    return 1;
  if( rc < argc || attach_cnt == 0 ) {
    rc = 1;
    fprintf(stderr, "Expected attach " ATTACHMENT_SYNTAX "\n");
    goto fail_attachments;
  }
  argc -= rc; argv += rc;

  rc = oo_bpf_open_elf(filename, &elf);
  if( rc < 0 ) {
    if( errno == ENOSYS ) {
      fprintf(stderr,
        "onload_bpftool was compiled without the libelf development package. "
        "You need to install the elfutils-devel or libelf-dev package to use "
        "the 'load' subcommand.\n");
    }
    fprintf(stderr, "Cannot open '%s': %s\n", filename, strerror(errno));
    goto fail_attachments;
  }

  /* Attach */
  TRY(drv_fd = open(OO_BPF_DEVICE, O_RDWR));
  TRY(oo_bpf_check_version(drv_fd));

  if( verbose )
    prog_fd = load_prog_verbose(drv_fd, elf, section);
  else
    prog_fd = oo_bpf_elf_load_prog(drv_fd, elf, section, BPF_PROG_TYPE_XDP,
                                   NULL);
  if( prog_fd < 0 ) {
    fprintf(stderr, "Cannot use object '%s' section '%s': %s\n",
            filename, section, strerror(errno));
    goto fail_prog;
  }

  for( i = 0; i < attach_cnt; ++i ) {
    attaches[i].prog_fd = prog_fd;
    rc = oo_bpf_prog_attach(drv_fd, &attaches[i]);
    if( rc < 0 ) {
      attach_failed = true;
      if( errno == EEXIST ) {
        fprintf(stderr, "Error: a program is already attached at ");
        print_attachment(stderr, &attaches[i]);
        fprintf(stderr, "\n");
      }
      else {
        fprintf(stderr, "Error: could not attach at ");
        print_attachment(stderr, &attaches[i]);
        fprintf(stderr, ": %s\n", strerror(errno));
      }
    }
  }
  rc = attach_failed ? 1 : 0;

  close(drv_fd);

fail_prog:
  oo_bpf_close_elf(elf);
fail_attachments:
  free(attaches);

  return rc != 0;
}


#define PROG_DETACH_ARGUMENTS "ATTACHMENT"
static int cmd_prog_detach(int argc, char** argv)
{
  int rc;
  int fd;

  struct oo_bpf_prog_attach_arg attach;
  rc = parse_attachment(argc, argv, &attach);
  if( rc < 0 )
    return 1;
  if( rc < argc ) {
    parse_attachment_error();
    return 1;
  }
  argc -= rc; argv += rc;

  TRY(fd = open(OO_BPF_DEVICE, O_RDWR));
  TRY(oo_bpf_check_version(fd));

  attach.prog_fd = -1;
  rc = oo_bpf_prog_detach(fd, &attach);
  if( rc < 0 ) {
    rc = 1;
    if( errno == ENOENT )
      fprintf(stderr, "Error: no program is attached here\n");
    else
      fprintf(stderr, "Error: could not detach: %s\n", strerror(errno));
  }

  close(fd);

  return rc;
}


static void print_prog_usage(const char* name)
{
  fprintf(stdout, "    %s prog { show | list } " PROG_LIST_ARGUMENTS        "\n", name);
  fprintf(stdout, "    %s prog dump "            PROG_DUMP_ARGUMENTS        "\n", name);
  fprintf(stdout, "    %s prog load "            PROG_LOAD_ATTACH_ARGUMENTS "\n", name);
  fprintf(stdout, "    %s prog detach "          PROG_DETACH_ARGUMENTS      "\n", name);
}


static int cmd_prog_help(const char* name)
{
  fprintf(stdout, "Usage:\n");
  print_prog_usage(name);
  fprintf(stdout, "    \n");
  fprintf(stdout, "    " ATTACH_POINT_DEFINITION "\n");
  fprintf(stdout, "    " ATTACHMENT_DEFINITION   "\n");
  return 0;
}


static int cmd_prog(const char* name, int argc, char** argv)
{
  if( argc < 1 )
    return cmd_prog_list(argc, argv);

  const char* cmd = argv[0];
  if( !strcmp(cmd, "help") )
    return cmd_prog_help(name);
  else if( !strcmp(cmd, "show") ||
           !strcmp(cmd, "list") )
    return cmd_prog_list(argc - 1, argv + 1);
  else if( !strcmp(cmd, "dump") )
    return cmd_prog_dump(argc - 1, argv + 1);
  else if( !strcmp(cmd, "load") )
    return cmd_prog_load_attach(argc - 1, argv + 1);
  else if( !strcmp(cmd, "detach") )
    return cmd_prog_detach(argc - 1, argv + 1);

  return cmd_prog_help(name);
}


static int cmd_help(const char* name)
{
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "    %s help\n", name);
  print_prog_usage(name);
  fprintf(stdout, "    \n");
  fprintf(stdout, "    " ATTACH_POINT_DEFINITION "\n");
  fprintf(stdout, "    " ATTACHMENT_DEFINITION   "\n");
  return 0;
}


int main(int argc, char** argv)
{
  if( argc < 2 )
    return cmd_help(argv[0]);

  const char* cmd = argv[1];
  if( !strcmp(cmd, "help") )
    return cmd_help(argv[0]);
  else if( !strcmp(cmd, "prog") )
    return cmd_prog(argv[0], argc - 2, argv + 2);

  return cmd_help(argv[0]);
}
