## Notes of studying the tutorial code


### testenv script


### data structures
#### bpf_object
bpf_prog_load_xattr in libbpf.c populates it by reading an object file
```
struct bpf_object {
	char name[BPF_OBJ_NAME_LEN];
	char license[64];
	__u32 kern_version;

	struct bpf_program *programs;
	size_t nr_programs;
	struct bpf_map *maps;
	size_t nr_maps;
	size_t maps_cap;
	struct bpf_secdata sections;

	bool loaded;
	bool has_pseudo_calls;
	bool relaxed_core_relocs;

	/*
	 * Information when doing elf related work. Only valid if fd
	 * is valid.
	 */
	struct {
		int fd;
		const void *obj_buf;
		size_t obj_buf_sz;
		Elf *elf;
		GElf_Ehdr ehdr;
		Elf_Data *sym bols;
		Elf_Data *data;
		Elf_Data *rodata;
		Elf_Data *bss;
		size_t strtabidx;
		struct {
			GElf_Shdr shdr;
			Elf_Data *data;
		} *reloc_sects;
		int nr_reloc_sects;
		int maps_shndx;
		int btf_maps_shndx;
		int text_shndx;
		int data_shndx;
		int rodata_shndx;
		int bss_shndx;
	} efile;
	/*
	 * All loaded bpf_object is linked in a list, which is
	 * hidden to caller. bpf_objects__<func> handlers deal with
	 * all objects.
	 */
	struct list_head list;

	struct btf *btf;
	struct btf_ext *btf_ext;

	void *priv;
	bpf_object_clear_priv_t clear_priv;

	struct bpf_capabilities caps;

	char path[];
};
```
- bpf_program
One way of reading bpf_programs is through bpf_object__for_each_program defined in libbpf.h
```
struct bpf_program {
	/* Index in elf obj file, for relocation use. */
	int idx;
	char *name;
	int prog_ifindex;
	char *section_name;
	char *pin_name;

	struct bpf_insn *insns;

	size_t insns_cnt, main_prog_cnt;
	enum bpf_prog_type type;

	struct reloc_desc {} *reloc_desc;
	int nr_reloc;
	int log_level;

	struct {
		int nr;
		int *fds;
	} instances;
	bpf_program_prep_t preprocessor;

	struct bpf_object *obj;
	void *priv;
	bpf_program_clear_priv_t clear_priv;

	enum bpf_attach_type expected_attach_type;
	__u32 attach_btf_id;
	__u32 attach_prog_fd;
	void *func_info;
	__u32 func_info_rec_size;
	__u32 func_info_cnt;

	struct bpf_capabilities *caps;

	void *line_info;
	__u32 line_info_rec_size;
	__u32 line_info_cnt;
	__u32 prog_flags;
};
```
- bpf_map
```
struct bpf_map {
	int fd;
	char *name;
	int sec_idx;
	size_t sec_offset;
	int map_ifindex;
	int inner_map_fd;
	struct bpf_map_def def;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	void *priv;
	bpf_map_clear_priv_t clear_priv;
	enum libbpf_map_type libbpf_type;
	char *pin_path;
	bool pinned;
	bool reused;
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 :32;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
}
```
### common code


### Lesson 1
```
// Read the bpf object file and program fd with the given file name
bpf_prog_load() ==> bpf_prog_load_xattr() ==> bpf_object__open_xattr ==> __bpf_object__open ==> bpf_object__new // create a new bpf_object and fit it in

xdp_link_attach ==> bpf_set_link_xdp_fd (tools/lib/bpf/netlink.c)) ==> libbpf_netlink_open (in nlmsghdr, RTM_SETLINK ifinfomsg AF_UNSPEC, if_index, send() the nlmsghdr ifinfomsg nlattr with xdp) ;


```

### Lesson 2

```
__load_bpf_and_xdp_attach ==> __load_bpf_object_file; bpf_object__find_program_by_title; bpf_program__fd; xdp_link_attach

```
### Lesson 3
Note about the userspace stats program handles map-reloading.
> when userspace reads the map by syscall, it checks if the id in the bpf_map_info is different from the one previously read from kernel. If changed, use the new fd to read the map.

### Lesson 4
Note about reusing an existing map when reloading an ELF with map definition inside (keep the existing map with the same path and settings and only reload the BPF program):
> * tools/lib/bpf/bpf.c provides a wrapper function for bpf syscall with BPF_OBJ_GET, which get the fd of the pinned map from kernel.
> * tools/lib/bpf/bpf_object__reuse_map.c:bpf_object__reuse_map() first tries to get the fd of the specified pinned map (using the path) by querying kernel, and check the compatibility. Then calls bpf_map__reuse_fd() that makes a syscall with BPF_OBJ_GET_INFO_BY_FD to get bpf_map_info. Open a new fd, and dup the fd of the existing map to the new fd, finally, sets the bpf_map_info of the existing map from kernel to the bpf_map loaded from ELF file.
