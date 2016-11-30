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

nova boot --flavor "m1.large" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test1.1
sleep 10
nova list
nova add-fixed-ip test1.1 130.203.47.228
nova add-fixed-ip test1.1 130.203.47.229
nova add-fixed-ip test1.1 130.203.47.230
nova add-fixed-ip test1.1 130.203.47.231
nova add-fixed-ip test1.1 130.203.47.232
nova remove-fixed-ip test1.1 130.203.47.228
nova remove-fixed-ip test1.1 130.203.47.229
nova remove-fixed-ip test1.1 130.203.47.230
nova remove-fixed-ip test1.1 130.203.47.231
nova remove-fixed-ip test1.1 130.203.47.232
nova delete test1.1
nova boot --flavor "m1.large" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test1.2
sleep 10
nova list
nova add-fixed-ip test1.2 130.203.47.228
nova add-fixed-ip test1.2 130.203.47.229
nova add-fixed-ip test1.2 130.203.47.230
nova add-fixed-ip test1.2 130.203.47.231
nova add-fixed-ip test1.2 130.203.47.232
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test1.2
nova boot --flavor "m1.large" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test1.3
sleep 10
nova list
nova add-fixed-ip test1.3 130.203.47.240
nova add-fixed-ip test1.3 130.203.47.241
nova add-fixed-ip test1.3 130.203.47.242
nova add-fixed-ip test1.3 130.203.47.242
nova add-fixed-ip test1.3 130.203.47.244
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test1.3
nova boot --flavor "m1.tiny" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test2.1
sleep 10
nova list
nova add-fixed-ip test2.1 130.203.47.228
nova add-fixed-ip test2.1 130.203.47.229
nova add-fixed-ip test2.1 130.203.47.230
nova add-fixed-ip test2.1 130.203.47.231
nova add-fixed-ip test2.1 130.203.47.232
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test2.1
nova boot --flavor "m1.tiny" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test2.2
sleep 10
nova list
nova add-fixed-ip test2.2 130.203.47.228
nova add-fixed-ip test2.2 130.203.47.229
nova add-fixed-ip test2.2 130.203.47.230
nova add-fixed-ip test2.2 130.203.47.231
nova add-fixed-ip test2.2 130.203.47.232
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test2.2
nova boot --flavor "m1.tiny" --image "47ec5f2c-2608-4d4a-af78-f683bd5cfdd5" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test2.3
sleep 10
nova list
nova add-fixed-ip test2.3 130.203.47.228
nova add-fixed-ip test2.3 130.203.47.229
nova add-fixed-ip test2.3 130.203.47.230
nova add-fixed-ip test2.3 130.203.47.231
nova add-fixed-ip test2.3 130.203.47.232
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test2.3
nova boot --flavor "m1.large" --image "29781e88-98b3-4e3c-90fa-973822e0ed5d" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test3.1
sleep 15
nova list
nova add-fixed-ip test3.1 130.203.47.228
nova add-fixed-ip test3.1 130.203.47.229
nova add-fixed-ip test3.1 130.203.47.230
nova add-fixed-ip test3.1 130.203.47.242
nova add-fixed-ip test3.1 130.203.47.244
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test3.1
nova boot --flavor "m1.large" --image "29781e88-98b3-4e3c-90fa-973822e0ed5d" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test3.2
sleep 15
nova list
nova add-fixed-ip test3.2 130.203.47.245
nova add-fixed-ip test3.2 130.203.47.246
nova add-fixed-ip test3.2 130.203.47.246
nova add-fixed-ip test3.2 130.203.47.247
nova add-fixed-ip test3.2 130.203.47.248
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test3.2
nova boot --flavor "m1.large" --image "29781e88-98b3-4e3c-90fa-973822e0ed5d" --key_name "testkey" --security_groups "default" --availability-zone nova:peta-VM1 test3.3
sleep 15
nova list
nova add-fixed-ip test3.3 130.203.47.228
nova add-fixed-ip test3.3 130.203.47.229
nova add-fixed-ip test3.3 130.203.47.230
nova add-fixed-ip test3.3 130.203.47.231
nova add-fixed-ip test3.3 130.203.47.232
nova remove-fixed-ip test1.2 130.203.47.228
nova remove-fixed-ip test1.2 130.203.47.229
nova remove-fixed-ip test1.2 130.203.47.230
nova remove-fixed-ip test1.2 130.203.47.231
nova remove-fixed-ip test1.2 130.203.47.232
nova delete test3.3
