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



import sys
import os

# Globals
num_states = 0
num_trans = 0
terminal = 0
commands = [[0 for i in range(2)] for j in range(100)]

# Step 0 - Clean Graph File
# Remove white spaces from before data

graph = open('graph', "r")
graph_new = open('graph_new', "w")
for line in graph.readlines():
	graph_new.write(line.lstrip()) 
graph.close()
graph_new.close()
os.remove('graph')
os.rename('graph_new', 'graph')

# Step 1 - Graph Splitting
# Starting from the graph creates nodes and edges files

def graphSplitting():
	graph = open('graph', "r")	
	edges = open('edges', "w")
	nodes = open('nodes', "w")
	file = nodes

	for line in graph.readlines():
		if "->" in line:
			file = edges
     		file.write(line) 
	edges.close()
	nodes.close()
	graph.close()

graphSplitting()

# Step 2 - Graph Adjusting
# Remove Terminal and set Initial State to be State 0

def graphAdjusting():

        # Identify INITIAL current index
        initial_index = 0
        terminal_index = 0
        nodes = open('nodes', "r")
        for lineN in nodes.readlines():
                if "INITIAL" in lineN:
                        break
                else:
                        initial_index += 1
        nodes.close()

        # Make INITIAL as State 0 and change index for command with index 0
        nodes = open('nodes', "r")
        nodes_bk = open('nodes_bk', "w")
        for lineN in nodes.readlines():
                if int(lineN.rsplit(None,1)[0]) == 0:
                        nodes_bk.write(repr(initial_index-1) + " " + lineN.rsplit(None,1)[1] + "\n")
                elif int(lineN.rsplit(None,1)[0]) == initial_index:
                        nodes_bk.write(repr(0)+ " " + lineN.rsplit(None,1)[1]+ "\n")
                elif "TERMINAL" in lineN:
                        terminal_index = int(lineN.rsplit(None,1)[0])
                else:
                        nodes_bk.write(lineN)
        terminal_index = initial_index - 1
        nodes.close()
        os.remove('nodes')
        nodes_bk.close()
        os.rename('nodes_bk', 'nodes')

 	# Update edges and remove edges to terminal
        edges_bk = open('edges_bk', "w")
        edges = open('edges', "r")
        global terminal
        for lineE in edges.readlines():
                str = lineE
                flag6 = 0
                source = ""
                dest = ""
                for i in range(0, len(str)):
                        if (str[i] == "-") | (str[i] == ">"):
                                flag6 = 1
                                continue
                        if (str[i].isdigit()) & (flag6 == 0):
                                source = source + str[i]
                        if (str[i].isdigit()) & (flag6 == 1):
                                dest = dest + str[i]
                        if (str[i] == " "):
                                break
                if source == repr(0):
                        edges_bk.write(repr(initial_index-1) + "->"+ dest + "\n")
                elif (source == repr(initial_index)) & (dest == repr(0)):
                        edges_bk.write("0->"+ repr(initial_index-1)+ "\n")
                elif source == repr(initial_index):
                        edges_bk.write("0->"+ dest + "\n")
                elif dest == repr(0):
                        edges_bk.write(source + "->"+ repr(initial_index-1) + "\n")
                else:
                        if dest == repr(terminal_index):
                                terminal = int(source)
                        else:
                                edges_bk.write(lineE)
        edges.close()
        os.remove('edges')
        edges_bk.close()
        os.rename('edges_bk', 'edges')

graphAdjusting()

                       
# Step 3 - Graph Enhancing
# Add PIPE node right after tee or iptables commands
# Add needed edges

def graphEnhancing():
	global terminal
	# Count current number of states (nodes)
	with open('nodes') as f:
        	for i, l in enumerate(f):
                	pass
        	states = i + 1

	# Add PIPE node and relative edges
	nodes = open('nodes', "r")
	#edges = open('edges', "r")
	nodes_en = open('nodes_enhanced', "w")
	for lineN in nodes.readlines():
        	if ("/tee" in lineN) | ("/iptables-" in lineN):
                	state = lineN.rsplit(None,1)[0]
			nodes_en.write(repr(states) + " [label=\"ANYTHING\"]; \n");
                	edges = open('edges', "r")
			edges_en = open('edges_enhanced', "w")
			flag2 = 0
                	for lineE in edges.readlines():
                        	str = lineE
                        	flag = 0
                		source = ""
                		dest = ""
                		for i in range(0, len(str)):
                			if (str[i] == "-") | (str[i] == ">"):
                        			flag = 1
                        			continue
                        		if (str[i].isdigit()) & (flag == 0):
                                		source = source + str[i]
                        		if (str[i].isdigit()) & (flag == 1):
                                		dest = dest + str[i]
                        		if (str[i] == " "):
                                		break
                		if state == source:
					if flag2 == 0:
                        			edges_en.write(source + "->" + repr(states) + "\n")
						flag2 = 1
                        		edges_en.write(repr(states) + "->" + dest + "\n")
                        	else:
					edges_en.write(source + "->" + dest + "\n")
                	if flag2 == 0:
				edges_en.write(state + "->" + repr(states) + "\n")
			if int(state) == terminal:
				terminal = states 
			states += 1
			edges.close()
			edges_en.close()
			os.remove('edges')
        		os.rename('edges_enhanced', 'edges')
	nodes.close()
	nodes_en.close()
	nodes_en = open('nodes_enhanced', "r")
	nodes = open('nodes', "a")
	for lineN in nodes_en.readlines():
        	nodes.write(lineN)
	nodes_en.close()
	nodes.close()
	os.remove('nodes_enhanced')

graphEnhancing()


# Step 4 - Graph Ordering
# Order nodes and edges files

def graphOrdering():
	# Count num states and transitions
	i = 0
	edges = open('edges', "r")
	for line in edges.readlines():
		i += 1
	edges.close()
	global num_trans 
	num_trans = i
	i = 0
	nodes = open('nodes', "r")
	for line in nodes.readlines():
		i += 1
	nodes.close()
	global num_states 
	num_states = i

	# Order nodes file
	nodes_bk = open('nodes_bk', "a")
	index = 0
	for index in range(0, num_states):
    		nodes = open('nodes', "r")
    		for lineN in nodes.readlines():
			if int(lineN.rsplit(None,1)[0]) == index:
            			nodes_bk.write(lineN)
    		index +=1
    		nodes.close()
	os.remove('nodes')
	nodes_bk.close()
	os.rename('nodes_bk', 'nodes')

	# Order edges file
	edges_bk = open('edges_bk', "a")
	index = 0
	for index in range(0, num_trans):
    		edges = open('edges', "r")
    		for lineE in edges.readlines():
			if int(lineE.rsplit('->',1)[0]) == index:
            			edges_bk.write(lineE)
    		index +=1
    		edges.close()
	os.remove('edges')
	edges_bk.close()
	os.rename('edges_bk', 'edges')

graphOrdering()


# Step 5 - Command Struct Population

def populateCommandStruct():
	nodes = open('nodes', "r")
	global commands
	commands = [[0 for i in range(2)] for j in range(100)]
	i = 0
	for line in nodes.readlines():
        	commands[i][0] = line.rsplit(None, 1)[0]
		tmp = line.rsplit(None, 1)[1][7:-2]
		if "INITIAL" in tmp:
        		commands[i][1] = "\"INITIAL\""
		else:
			commands[i][1] = tmp
        	i += 1
	nodes.close()

populateCommandStruct()


# Step 6 - Write policy.c header

policy = open('policy.c', "w")
policy.write("\n#include \"ndfsa.h\"")
policy.write("\n#include <string.h>")
policy.write("\n#include <stdio.h>")
policy.write("\n#include <stdlib.h>")
policy.write("\nint main()")
policy.write("\n{")
policy.write("\n    char *fname = \"policy_structs\";")
policy.write("\n    int snum = " + repr(num_states) + ";")
policy.write("\n    state s[snum];")
policy.write("\n    transition t["+ repr(num_trans) +"];")
policy.write("\n    int arg_count = 0;")
policy.write("\n    argument args[arg_count];")
policy.write("\n    FILE *f;")


# Step 7 - Populate Transition Structs

num_tran = 0

edges = open('edges', "r")
for lineE in edges.readlines():
                str = lineE
                flag3 = 0
                source = ""
                dest = ""
		
		policy.write("\n \n    // trans "+ repr(num_tran))
		policy.write("\n    memset(t["+ repr(num_tran)+"].event, \'\\0\', 41);")
                for i in range(0, len(str)):
                        if (str[i] == "-") | (str[i] == ">"):
                                flag3 = 1
                                continue
                        if (str[i].isdigit()) & (flag3 == 0):
                                source = source + str[i]
                        if (str[i].isdigit()) & (flag3 == 1):
                                dest = dest + str[i]
                        if (str[i] == " "):
                                break
		policy.write("\n    memcpy(t["+ repr(num_tran) +"].event, "+ commands[int(dest)][1] +", sizeof(" + commands[int(dest)][1] +"));")
		policy.write("\n    t["+repr(num_tran)+"].snum = "+ dest + ";")
		if commands[int(dest)][1][1:-1] == "/usr/bin/tee":
			policy.write("\n    t["+repr(num_tran)+"].transition_type = TRAN_EXEC;")
			policy.write("\n    t["+repr(num_tran)+"].arg_count = 0;")
			
		elif commands[int(dest)][1][1:-1] == "ANYTHING":
                        policy.write("\n    t["+repr(num_tran)+"].transition_type = TRAN_PIPE;")
                        policy.write("\n    t["+repr(num_tran)+"].arg_count = 0;")
		else:
                        policy.write("\n    t["+repr(num_tran)+"].transition_type = TRAN_EXEC;")
                        policy.write("\n    t["+repr(num_tran)+"].arg_count = 0;")
		num_tran += 1
edges.close()


# Step 8 - Populate State Structs

num_states = 0
global_num_edges = 0

nodes = open('nodes', "r")

for lineN in nodes.readlines():
	local_num_edges = 0
	policy.write("\n \n    // state "+ repr(num_states))
	policy.write("\n    s["+ repr(num_states) +"].snum = "+ repr(num_states) +";")
	edges = open('edges', "r")
	for lineE in edges.readlines():
		str = lineE
		flag4 = 0
        	source = ""
        	dest = ""
		for i in range(0, len(str)):
			if (str[i] == "-") | (str[i] == ">"):
				flag4 = 1
				continue
			if (str[i].isdigit()) & (flag4 == 0):
				source = source + str[i]
			if (str[i].isdigit()) & (flag4 == 1):
				dest = dest + str[i]
			if (str[i] == " "):
				break
		
		if int(source) == num_states:
			policy.write("\n    s["+ repr(num_states) +"].trans["+ repr(local_num_edges) +"] = t["+ repr(global_num_edges) +"];")
                	local_num_edges += 1
                    	global_num_edges += 1
	policy.write("\n    s["+ repr(num_states) +"].tran_count = "+ repr(local_num_edges) +";")
	if num_states == terminal:
		policy.write("\n    s["+ repr(num_states) +"].terminal_flag = 1;")
	else:
		policy.write("\n    s["+ repr(num_states) +"].terminal_flag = 0;")
	edges.close()			
	num_states += 1
nodes.close()


# Step 9 -  Write policy.c footer

policy.write("\n\n    f = fopen(fname, \"w\");");
policy.write("\n    if(f == NULL)");
policy.write("\n    {");
policy.write("\n         printf(\"error opening securityfs\\n\");");
policy.write("\n         exit(1);");
policy.write("\n    }");
policy.write("\n    fwrite(&snum, sizeof(int), 1, f);");       
policy.write("\n    printf(\"%d\",sizeof(state)*snum);");
policy.write("\n    fwrite(&s, sizeof(state)*snum, 1, f);");
policy.write("\n    fwrite(&arg_count, sizeof(int), 1, f);");
policy.write("\n    if(arg_count > 0)");
policy.write("\n    {");
policy.write("\n        fwrite(&args, sizeof(argument)*arg_count, 1, f);");
policy.write("\n    }");
policy.write("\n    fclose(f);");
policy.write("\n}");

os.remove('nodes')
os.remove('edges')
sys.exit()
