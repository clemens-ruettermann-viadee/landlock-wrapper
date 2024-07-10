# Landlock-Wrapper

This project is a template to create wrappers for programs to add [landlock] (https://docs.kernel.org/userspace-api/landlock.html) rules.

If `EXIT_ON_ERROR` is defined, the program will terminate/not start when there is an error like it is not possible to add a filesystem rule.
There are a few TODOs that you should at least have a look at them.

## Compilation
To compile execute the following command:
```
g++ -o landlock-wrapper landlock_wrapper.cpp
```