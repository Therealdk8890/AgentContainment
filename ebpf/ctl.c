#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s attach <object> <cgroup> <pin-dir> | detach <pin-dir> <cgroup> | verify <pin-dir> <cgroup>\n", prog);
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    perror("mkdir");
    return -1;
}

static int query_has_program(int cgroup_fd, __u32 prog_id)
{
    __u32 prog_ids[64] = {};
    __u32 prog_cnt = 64;
    __u32 attach_flags = 0;

    if (bpf_prog_query(cgroup_fd, BPF_CGROUP_INET_EGRESS, 0,
                       &attach_flags, prog_ids, &prog_cnt) < 0) {
        return -1;
    }

    for (__u32 i = 0; i < prog_cnt; ++i) {
        if (prog_ids[i] == prog_id) return 1;
    }
    return 0;
}

static int attach_program(const char *obj_path, const char *cgroup_path, const char *pin_dir)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int cgroup_fd = -1;
    char link_path[PATH_MAX];
    int rc = -1;

    if (ensure_dir(pin_dir) < 0) return -1;
    snprintf(link_path, sizeof(link_path), "%s/egress_link", pin_dir);
    unlink(link_path);

    cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "open cgroup %s failed: %s\n", cgroup_path, strerror(errno));
        goto out;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_file failed for %s\n", obj_path);
        goto out;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
        goto out;
    }

    prog = bpf_object__find_program_by_name(obj, "agent_containment_egress");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        goto out;
    }

    link = bpf_program__attach_cgroup(prog, cgroup_fd);
    if (!link) {
        int err = -libbpf_get_error(link);
        fprintf(stderr, "bpf_program__attach_cgroup failed: %s (errno=%d)\n",
                strerror(err > 0 ? err : errno), err > 0 ? err : errno);
        goto out;
    }
    if (bpf_link__pin(link, link_path)) {
        fprintf(stderr, "bpf_link__pin failed: %s\n", strerror(errno));
        goto out;
    }

    printf("attached egress blocker to %s\n", cgroup_path);
    rc = 0;

out:
    if (rc != 0) unlink(link_path);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    if (cgroup_fd >= 0) close(cgroup_fd);
    return rc;
}

static int detach_program(const char *pin_dir, const char *cgroup_path)
{
    char link_path[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "%s/egress_link", pin_dir);

    int link_fd = bpf_obj_get(link_path);
    if (link_fd < 0) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "open pinned egress link failed: %s\n", strerror(errno));
        return -1;
    }

    struct bpf_link_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(link_fd, &info, &info_len) < 0 ||
        info.type != BPF_LINK_TYPE_CGROUP ||
        info.cgroup.attach_type != BPF_CGROUP_INET_EGRESS) {
        fprintf(stderr, "pinned object is not a cgroup egress link\n");
        close(link_fd);
        return -1;
    }

    int cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "open target cgroup %s failed: %s\n",
                cgroup_path, strerror(errno));
        close(link_fd);
        return -1;
    }

    int found = query_has_program(cgroup_fd, info.prog_id);
    if (found != 1) {
        fprintf(stderr, "pinned egress link is not attached to target cgroup\n");
        close(cgroup_fd);
        close(link_fd);
        return -1;
    }

    if (unlink(link_path) < 0) {
        fprintf(stderr, "unlink egress_link failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(link_fd);
        return -1;
    }

    close(link_fd);

    int still_attached = query_has_program(cgroup_fd, info.prog_id);
    close(cgroup_fd);

    if (still_attached < 0) {
        fprintf(stderr, "unable to verify target cgroup egress programs after detach: %s\n",
                strerror(errno));
        return -1;
    }
    if (still_attached) {
        fprintf(stderr, "containment egress program remains attached after detach\n");
        return -1;
    }

    return 0;
}

static int verify_program(const char *pin_dir, const char *cgroup_path)
{
    char link_path[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "%s/egress_link", pin_dir);

    int link_fd = bpf_obj_get(link_path);
    if (link_fd < 0) {
        fprintf(stderr, "pinned egress link is not available: %s\n", strerror(errno));
        return -1;
    }

    struct bpf_link_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(link_fd, &info, &info_len) < 0) {
        fprintf(stderr, "unable to inspect pinned egress link: %s\n", strerror(errno));
        close(link_fd);
        return -1;
    }

    if (info.type != BPF_LINK_TYPE_CGROUP ||
        info.cgroup.attach_type != BPF_CGROUP_INET_EGRESS) {
        fprintf(stderr, "pinned object is not a cgroup egress link\n");
        close(link_fd);
        return -1;
    }

    int cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "open target cgroup %s failed: %s\n",
                cgroup_path, strerror(errno));
        close(link_fd);
        return -1;
    }

    int found = query_has_program(cgroup_fd, info.prog_id);
    close(cgroup_fd);
    close(link_fd);

    if (found < 0) {
        fprintf(stderr, "unable to query target cgroup egress programs: %s\n",
                strerror(errno));
        return -1;
    }
    if (!found) {
        fprintf(stderr, "pinned egress link is not attached to target cgroup\n");
        return -1;
    }

    printf("verified pinned egress link at %s for %s\n", link_path, cgroup_path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 2; }

    if (strcmp(argv[1], "attach") == 0) {
        if (argc != 5) { usage(argv[0]); return 2; }
        return attach_program(argv[2], argv[3], argv[4]) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "detach") == 0) {
        if (argc != 4) { usage(argv[0]); return 2; }
        return detach_program(argv[2], argv[3]) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 4) { usage(argv[0]); return 2; }
        return verify_program(argv[2], argv[3]) == 0 ? 0 : 1;
    }

    usage(argv[0]);
    return 2;
}
