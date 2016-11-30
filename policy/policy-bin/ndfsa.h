#define t_PATH 0
#define ARGU_VALUE 1
#define ARGU_FILE 2
#define TRAN_EXEC 0
#define TRAN_PIPE 1
#define TRAN_SOCKET_READ 2
#define TRAN_SOCKET_WRITE 3

typedef struct argument{
	int index;
	int type;
	char value[100];
}argument;

typedef struct transition{
	char event[41];		// event value
	int snum;		// next state
	int transition_type;	// exec or pipe or socket
	int arg_count;		// if exec, how many arguments to check
	int args[10];		// location in the arguments pool
}transition;

typedef struct state{
	int snum;
	int tran_count;
    	transition trans[10];	
}state;

