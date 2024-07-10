#include <cstdlib>
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <algorithm>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <linux/landlock.h>
#include <linux/limits.h>
#include <linux/prctl.h>

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>


#ifndef landlock_create_ruleset
/*
 * internal wrapper for the landlock_create_ruleset syscall
 */
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags) {
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
/*
 * internal wrapper for the landlock_add_rule syscall
 */
static inline int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type, const void *const rule_attr, const __u32 flags) {
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
/*
 * internal wrapper for the landlock_restrict_self syscall
 */
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags) {
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif


#define EVERY_FS_FLAG (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE)

#define READ_DIR LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
#define READ_EXECUTE_DIR LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
#define READ_EXECUTE_FILE LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE

#define EXIT_ON_ERROR

using namespace std;

/*
 * Returns the current landlock abi version or a negative value if landlock is not active on the current system
 */
int get_landlock_abi_version() {
	return landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}


/**
 * Create a ruleset
 * By default the new ruleset will handle all permission and deny everything that is not explicitly allowed.
 * The permissions this ruleset should handle can be reduced with the arguments allowed_fs_flags and allowed_net_flags
 * @return a file descriptor for the ruleset that is used to add new rules and restrict the process
 *
 * WARNING: Make sure that 
 */
int create_rule_set(long allowed_fs_flags, long allowed_net_flags) {
	// by default deny everything except the specified flags
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs =
			LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
			LANDLOCK_ACCESS_FS_TRUNCATE,
		.handled_access_net =
			LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
	};
	ruleset_attr.handled_access_fs &= ~allowed_fs_flags;
	ruleset_attr.handled_access_net &= ~allowed_net_flags;

	cout << "landlock_ruleset_attr created" << endl;

	// Remove flags that are not supported by this version of the linux kernel
	int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        throw runtime_error{"Landlock is not active on this system"};
    }
	switch (abi) {
	case 1:
		/* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
		__attribute__((fallthrough));

	case 2:
		/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
		__attribute__((fallthrough));

	case 3:
		/* Removes network support for ABI < 4 */
		ruleset_attr.handled_access_net &=
				~(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);
		__attribute__((fallthrough));

    case 4:
		/* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;

    default:
        cerr << "There is a newer version of landlock available. Make sure to add the new permissions to the default list" << endl;
	}

	int fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	cout << "Successfully created ruleset" << endl;
	cout << "fd: " << to_string(fd)  << endl;
	return fd;
}

/**
 * Add a filesystem rule to the given ruleset
 */
int add_fs_rule(long ruleset_fd, unsigned long long allowed_fs_flags, string path) {
	int err;
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = allowed_fs_flags
	};
	const char *current_path = path.c_str();
	cout << "Trying to open path: " << current_path << endl;
	path_beneath.parent_fd = open(current_path, __O_PATH | O_CLOEXEC);

	if (path_beneath.parent_fd < 0) {
		cerr << "Failed to open file" << endl;
		close(ruleset_fd);
#ifdef EXIT_ON_ERROR
		exit(path_beneath.parent_fd);
#else
		return path_beneath.parent_fd;
#endif
	}

	struct stat statbuf;
	err = fstat(path_beneath.parent_fd, &statbuf);
	if (err) {
		cerr << "Failed to stat \"" << current_path << "\": " << strerror(errno) << endl;
		close(path_beneath.parent_fd);
#ifdef EXIT_ON_ERROR
		exit(path_beneath.parent_fd);
#else
		return path_beneath.parent_fd;
#endif
	}
	cout << "File successfully opened" << endl;

	cout << "Trying to add rule for path " << to_string(path_beneath.parent_fd) << endl;
	err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
	close(path_beneath.parent_fd);

	if (err) {
		cerr << "Failed to update ruleset: " << strerror(err) << endl;
		close(ruleset_fd);
#ifdef EXIT_ON_ERROR
		exit(err);
#else
		return err;
#endif
	}
	cout << "Successfully added a new file system rule" << endl << endl;
	return 0;
}

/**
 * Add a network rule to the given ruleset
 */
int add_net_rule(long ruleset_fd, unsigned long long allowed_flags, unsigned long long port) {
	struct landlock_net_port_attr net_port = {
		.allowed_access = allowed_flags,
		.port = port,
	};

	int err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_port, 0);
	if (err) {
		cerr << "There was an error when trying to add net rule for port " << to_string(port) << ": " << endl;
		if (allowed_flags & LANDLOCK_ACCESS_NET_BIND_TCP) {
			cerr << "BIND_TCP" << endl;
		}
		if (allowed_flags & LANDLOCK_ACCESS_NET_CONNECT_TCP) {
			cerr << "CONNECT_TCP" << endl;
		}
		cerr << endl;

#ifdef EXIT_ON_ERROR
		exit(err);
#else
		return err;
#endif
	} else {
		cout << "Successfully allowed ";
		if (allowed_flags & LANDLOCK_ACCESS_NET_BIND_TCP) {
			cout << "BIND_TCP ";
		}
		if (allowed_flags & LANDLOCK_ACCESS_NET_CONNECT_TCP) {
			cout << "CONNECT_TCP ";
		}
		cout << "on port " << to_string(port) << endl;
	}
	return err;
}


int restrict_self(long ruleset_fd) {
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		cerr << "Failed to restrict privileges" << endl;
		close(ruleset_fd);
		return 1;
	}

	int err = landlock_restrict_self(ruleset_fd, 0);
	if (err) {
		cerr << "Failed to enforce ruleset" << endl;
		close(ruleset_fd);
		return 2;
	}
	cout << "Successfully restricted self" << endl;
	close(ruleset_fd);
	return err;
}



int main(int argc, char ** argv) {
	
	cout << "i: " << to_string(argc) << endl;
	if (argc <= 1) {
		cout << "Usage " << argv[0] << " <jar file>" << endl;
		return 1;
	}

	vector<char*> java_args{
		"/usr/bin/java",
		"-jar"
	};
	for (size_t i = 1; i < argc; i++) {
		java_args.push_back(argv[i]);
	}
	
    // java/spring needs a temp dir. Normally this is /tmp. To avoid having to allow read/write access to /tmp (which could be a bad idea), we create a new directory and specify it via _JAVA_OPTIONS
	if (filesystem::is_directory("/tmp/java_tmp_dir")) {
		filesystem::remove_all("/tmp/java_tmp_dir");
	}
	filesystem::create_directory("/tmp/java_tmp_dir");


	auto rulesetFd = create_rule_set(0, 0);
	int err = 0;
	err |= add_fs_rule(rulesetFd, READ_EXECUTE_FILE, "/usr/bin/java");
	err |= add_fs_rule(rulesetFd, READ_EXECUTE_FILE, argv[1]);

    // TODO: this folder depends on the specific java version and the linux distribution and there is a high probability that this needs to be adjusted
	err |= add_fs_rule(rulesetFd, READ_DIR, "/etc/java17-openjdk");

    // TODO: restrict further to just use the files/folders that java really needs
    err |= add_fs_rule(rulesetFd, READ_EXECUTE_DIR, "/usr/lib");
	err |= add_fs_rule(rulesetFd, EVERY_FS_FLAG, "/tmp/java_tmp_dir");

    // TODO: change to match the port used by your application
	err |= add_net_rule(rulesetFd, LANDLOCK_ACCESS_NET_BIND_TCP, 8080);


    // TODO: if your service connects to other apis/http enpoints add these (in the best case just 443)
	// err |= add_net_rule(rulesetFd, LANDLOCK_ACCESS_NET_CONNECT_TCP, 80);
	// err |= add_net_rule(rulesetFd, LANDLOCK_ACCESS_NET_CONNECT_TCP, 443);
	
    if (err) {
		cerr << "There was an error: " << to_string(err) << endl;
		return err;
	}
	restrict_self(rulesetFd);
	cout << "Starting java command: ";
	for_each(java_args.cbegin(), java_args.cend(), [](const auto & s) {
		cout << s << " ";
	});
	cout << endl;



	// std::system starts /bin/sh internally, so we use execve directly to avoid allowing /bin/sh unnecessarily
    // If you still want to use std::system() you can do so
	// auto ret = system(command.c_str());

	char * c_java_args[java_args.size() + 1];
	copy(java_args.cbegin(), java_args.cend(), c_java_args);
	c_java_args[java_args.size()] = nullptr;

	char * const env[] = {"_JAVA_OPTIONS=-Djava.io.tmpdir=/tmp/java_tmp_dir", nullptr};
	auto ret = execve("/usr/bin/java", c_java_args, env);

	cout << "Ret value: " << strerror(ret) << endl;
	return ret;
}