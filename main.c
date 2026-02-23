/* @file cdbg main.c
 * @todo CLI UI like GDB
 * 	 Step-into vs. Step-over
 * 	 Reset 	
 * */

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
// #include <capstone/capstone.h> // sudo apt install libcapstone-dev
#include <sys/uio.h>
#include <elf.h>
#include <errno.h>

#define VERSION "0.1"
#define MAX_BREAKPOINTS 128
#define BRK0 0xd4200000 // breakpoint encoding in AArch64
#define higher32 0x00000000FFFFFFFF
#define lower32 0xFFFFFFFF00000000

#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_RESET   "\033[0m"

char command[256];
int status;
struct user_regs_struct regs; // from user.h, used to store gp cpu regs of user-space process
struct iovec iov; // for PTRACE_GETREGSET

typedef struct {
	unsigned long addr; // address to set brkpt
	unsigned long orig_word;
	int active;
} breakpoint_t;
breakpoint_t breakpoints[MAX_BREAKPOINTS];
int bp_count = 0;

void die (const char* s) {
	perror(s); 
	exit(1);
}

void print_source(unsigned long pc, const char *prog_path) {
	snprintf(command, sizeof(command),"addr2line -e %s 0x%lx", prog_path, pc); // writes formatted output to buffer in memory, addr2line = address to line
	system(command);
}

int set_breakpoint(pid_t pid, unsigned long addr) {
	if (bp_count >= MAX_BREAKPOINTS) die("set_breakpoint: Max breakpoints reached!"); 
	
	unsigned long aligned_addr = addr & ~0x7; // align to 8 bytes
	unsigned long word = ptrace(PTRACE_PEEKDATA, pid, aligned_addr, NULL); // current word at addr
	unsigned long new_word;

	if ((addr & 0x4) == 0) { // [ upper 32 bits | lower 32 bits ]
				 // addr 0x1000  -> lower instruction at 0x1000, upper at 0x1004
		new_word = (word & lower32) | BRK0; 
	} else {
		new_word = (word & higher32) | ((unsigned long)BRK0 << 32);
	}

	ptrace(PTRACE_POKEDATA, pid, aligned_addr, new_word); // insert brk
	
	breakpoints[bp_count].addr = addr;
	breakpoints[bp_count].orig_word = word;
	breakpoints[bp_count].active = 1;
	bp_count++;

	printf("Breakpoint set @ "COLOR_BLUE" 0x%lx\n" COLOR_RESET, addr);
	return 0;
}

int remove_breakpoint(pid_t pid, unsigned long addr) {
	for (int i = 0; i < bp_count; i++) {
		if (breakpoints[i].active && breakpoints[i].addr == addr) {
			unsigned long aligned_addr = addr & ~0x7;
            		ptrace(PTRACE_POKEDATA, pid, aligned_addr, breakpoints[i].orig_word);
            		breakpoints[i].active = 0;
			printf(COLOR_RESET COLOR_BLUE "Breakpoint removed @ 0x%lx\n" COLOR_RESET, addr);
			return 0;
		}
	}
	die("remove_breakpoint: Breakpoint not found!");
}

void handle_breakpoint(pid_t pid, int quit_proc, char *prog_path) {
	iov.iov_base = &regs; iov.iov_len = sizeof(regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	unsigned long pc = regs.pc;

	for (int i = 0; i < bp_count; i++) {
		if (breakpoints[i].active && pc/* - 4 */== breakpoints[i].addr) { // instr are 4 bytes. 
			printf(COLOR_BLUE "Hit breakpoint @ 0x%lx\n" COLOR_RESET, breakpoints[i].addr);
			print_source(breakpoints[i].addr, prog_path);
			remove_breakpoint(pid, breakpoints[i].addr); // temp, restore orig instr
			regs.pc = breakpoints[i].addr; // move pc back to orig instr addr
			iov.iov_base = &regs; iov.iov_len = sizeof(regs);
			ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL); // execute orig instr
			waitpid(pid, &status, 0);
			if (quit_proc) set_breakpoint(pid, breakpoints[i].addr); // re-set brkpt
		}
	}
}

void print_instr(pid_t pid) {
	iov.iov_base = &regs; iov.iov_len = sizeof(regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, (void*)regs.pc, NULL);
	printf(COLOR_GREEN "Instruction @ PC: 0x%lx\n" COLOR_RESET, instr);
}

void print_stack(pid_t pid) {
	iov.iov_base = &regs; iov.iov_len = sizeof(regs);

	ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
	
	for (int i = 0; i < 5; i++) {
		unsigned long addr = regs.sp + 8 * i;
		unsigned long val = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	printf(COLOR_YELLOW"0x%lx: 0x%lx\n"COLOR_RESET, addr, val); // long uint lx
	}
}

void print_registers(pid_t pid) {
	iov.iov_base = &regs; iov.iov_len = sizeof(regs); // get register state

	ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov); //  data points to a struct iovec, in man pages

	// %llx = 64 bit uint hex
	printf(COLOR_YELLOW "PC: 0x%llx\n" COLOR_RESET, regs.pc);
	printf(COLOR_YELLOW "SP: 0x%llx\n" COLOR_RESET, regs.sp);
	for (int i = 0; i <= 30; i++) { // x0-x30 - aarch64 registers
		printf(COLOR_YELLOW "X%d: 0x%llx\n" COLOR_RESET, i, regs.regs[i]);	
	}
}

void read_command(char *command, size_t size) {
	if (fgets(command, size, stdin) == NULL) { // returns s on success
		command[0] = '\0';
		return;
	}

	command[strcspn(command, "\n")] = '\0'; // remove \n for strcmp
}

int main(int argc, char *argv[]) {
	printf(COLOR_MAGENTA "Custom Debugger (cdbg) v%s\n" COLOR_RESET, VERSION);
	if (argc < 2) {
		printf("Usage: %s <program>\n", argv[0]);
	}
	char* prog_path = argv[1];
	pid_t pid = fork(); // create child process, posix cmd

	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL); // child process traced by parent, ptrace(op, pid, addr, data) -- TRACEME ignores addr + data, allows parent to trace 
		execl(argv[1], argv[1], NULL); // child calls to create new process image, execl(path, arg, ..), triggers SIGTRAP for waitpid()
	} else {
		waitpid(pid, &status, 0); // waits for child to hlt at start
		printf("Debugger attached.\n");

		while(!WIFEXITED(status)) { // status macro decoder
			printf("(cdbg) ");
			read_command(command, sizeof(command));
			unsigned long instr;
			if (strcmp(command, "continue") == 0 || strcmp(command, "c") == 0) {
				printf("Continuing.\n");
				ptrace(PTRACE_CONT, pid, NULL, NULL);
				waitpid(pid, &status, 0);
				if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { // brkpt sends SIGTRAP
    					handle_breakpoint(pid, 0, prog_path);
				}
			} else if (strcmp(command, "step_over") == 0 || strcmp(command, "s") == 0 || strcmp(command, "so") == 0 || strcmp(command, "step") == 0) {
				printf("Stepping.\n");
				ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
				waitpid(pid, &status, 0);
				print_instr(pid);
				if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    					handle_breakpoint(pid, 0, prog_path);
				}

			} else if (strcmp(command, "step_into") == 0 || strcmp(command, "si") == 0) {
				printf("Stepping into.\n");
				ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
				waitpid(pid, &status, 0);
				print_instr(pid);
				if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    					handle_breakpoint(pid, 0, prog_path);
				}

			} else if (strcmp(command, "stop") == 0 || strcmp(command, "q") == 0) {
				printf("Quitting.\n");
				ptrace(PTRACE_KILL, pid, NULL, NULL);
				waitpid(pid, &status, 0);
				handle_breakpoint(pid, 1, prog_path);
				return 0; 
			} else if (strcmp(command, "registers") == 0 || strcmp(command, "regs") == 0)  {
				print_registers(pid);
				continue;
			} else if (strcmp(command, "stack") == 0)  {
				print_stack(pid);
				continue;		
			} else if (strcmp(command, "b set") == 0) {
				printf("Set breakpoint @ address?: "); read_command(command, sizeof(command));
				unsigned long input_addr = strtoul(command, NULL, 0); // strtoul(const char *nptr, char **endptr, int base);
				set_breakpoint(pid, input_addr);
			} else if (strcmp(command, "b del") == 0) {
				printf("Remove breakpoint @ address?: "); read_command(command, sizeof(command));
				unsigned long input_addr = strtoul(command, NULL, 0);
				remove_breakpoint(pid, input_addr);
			} else if (strcmp(command, "b info") == 0) {
				printf("%d breakpoints found\n", bp_count);
				if (bp_count) {
					printf(COLOR_YELLOW "Number | Address | Active | Location\n"COLOR_RESET);
				}
				for (int i = 0; i < bp_count; i++) {
					printf(COLOR_YELLOW "%d | 0x%lx | %d | " COLOR_RESET, i + 1, breakpoints[i].addr, breakpoints[i].active);
				print_source(breakpoints[i].addr, prog_path); printf("\n");
				}
				continue;
			} else {
				printf(COLOR_RED "Unknown command.\n" COLOR_RESET);
				continue;
			 }	
			
			if(WIFEXITED(status)) { printf("Program exited.\n"); break; }
			if(WIFSTOPPED(status)) printf("Program stopped by signal %d.\n", WSTOPSIG(status));
		}
	}
}
