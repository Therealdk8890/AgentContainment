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
    fprintf(stderr, "usage: %s attach <object> <cgroup> <pin-dir> | detach <pin-dir>\n", prog);
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    perror("mkdir");
    return -1;
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

static int detach_program(const char *pin_dir)
{
    char link_path[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "%s/egress_link", pin_dir);
    if (unlink(link_path) < 0 && errno != ENOENT) {
        perror("unlink egress_link");
        return -1;
    }
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
        if (argc != 3) { usage(argv[0]); return 2; }
        return detach_program(argv[2]) == 0 ? 0 : 1;
    }
    usage(argv[0]);
    return 2;
}