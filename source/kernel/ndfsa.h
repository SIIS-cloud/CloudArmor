/*
# The CloudArmor additions are ...
#
#  Copyright (c) 2016 The Pennsylvania State University
#  Systems and Internet Infrastructure Security Laboratory
#
# they were developed by:
#
#  Yuqiong Sun          <yus138@cse.psu.edu>
#  Giuseppe Petracca    <gxp18@cse.psu.edu>
#  Trent Jaeger         <tjaeger@cse.psu.edu>
#
# Unless otherwise noted, all code additions are ...
#
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  * http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
*/


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

