"""Set output limits before exec, without preexec_fn in a threaded server."""
import os
import resource
import sys


def main():
    limit = int(sys.argv[1])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == '__main__':
    main()
