# inMemoryMockingJay
Process Mockingjay: Echoing RWX In Userland To Achieve Code Execution

The motivation came from the following article and github projects:

https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution

https://github.com/pwnsauc3/RWXfinder/blob/main/rwxfinder.c

Instead of looking for dlls with RWX perms on disk, inMemoryMockingjay checks for the loaded dlls in process memory and if rwx perms are found it injects our shellcode in there.

Ideally CreateRemoteThread should not be called but that doesn't guarantee that our shellcode will run.

To run the code simply provide the PID of the remote process as shown below.
```
int main()
{
    inMemoryMockingjay(21196); 
    return 1;

}
```
