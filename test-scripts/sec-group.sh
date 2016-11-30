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



source ../novarc

nova boot --flavor 1 --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "mykey" --availability-zone nova:peta-VM1 test1
sleep 10
nova secgroup-list
nova secgroup-create group1 desc
nova secgroup-create group2 desc
nova secgroup-create group3 desc
nova secgroup-create group4 desc
nova secgroup-create group5 desc
nova secgroup-list
#nova secgroup-list-rules default
nova add-secgroup test1 group1
nova add-secgroup test1 group2
nova add-secgroup test1 group3
nova add-secgroup test1 group4
nova add-secgroup test1 group5
nova secgroup-list 

sleep 10
nova secgroup-add-rule group1 udp 23 24 192.168.0.1/16
nova secgroup-add-group-rule group2 default tcp 23 24 
nova secgroup-list-rules group2
nova secgroup-delete-group-rule group2 default tcp 23 24
nova secgroup-delete-rule group2 udp 23 24 192.168.0.1/16
nova secgroup-list-rules group2

nova secgroup-add-rule group3 udp 44 45 192.168.0.1/16
nova secgroup-add-group-rule group3 default tcp 23 24 
nova secgroup-list-rules group3
nova secgroup-delete-group-rule group3 default tcp 23 24
nova secgroup-delete-rule group3 udp 44 45 192.168.0.1/16
nova secgroup-list-rules group3
sleep 5
nova secgroup-add-rule group5 udp 23 24 192.168.0.1/16
nova secgroup-add-group-rule group5 default tcp 23 24 
nova secgroup-list-rules group5
nova secgroup-delete-group-rule group5 default tcp 23 24
nova secgroup-delete-rule group5 udp 23 24 192.168.0.1/16
nova secgroup-list-rules group5
sleep 5
nova secgroup-add-rule group4 udp 44 45 192.168.0.1/16
nova secgroup-add-group-rule group4 default tcp 44 45 
nova secgroup-list-rules group4
nova secgroup-delete-group-rule group4 default tcp 44 45
nova secgroup-delete-rule group4 udp 44 45 192.168.0.1/16
nova secgroup-list-rules group4
sleep 5
nova secgroup-add-rule group1 udp 23 24 192.168.0.1/16
nova secgroup-add-group-rule group1 default tcp 23 24 
nova secgroup-list-rules group1
nova secgroup-delete-group-rule group1 default tcp 23 24
nova secgroup-delete-rule group1 udp 23 24 192.168.0.1/16
nova secgroup-list-rules group1
sleep 5
nova secgroup-add-rule group1 udp 44 45 192.168.0.1/16
nova secgroup-add-group-rule group1 default tcp 44 45 
nova secgroup-list-rules group1
nova secgroup-delete-group-rule group1 default tcp 44 45
nova secgroup-delete-rule group1 udp 44 45 192.168.0.1/16
nova secgroup-list-rules group1

sleep 10

nova remove-secgroup test1 group1
nova remove-secgroup test1 group2
nova remove-secgroup test1 group3
nova remove-secgroup test1 group4
nova remove-secgroup test1 group5

sleep 10
#nova secgroup-list
#nova secgroup-list-rules

nova secgroup-delete group1 
nova secgroup-delete group2 
nova secgroup-delete group3
nova secgroup-delete group4
nova secgroup-delete group5
nova secgroup-list

nova delete test1
