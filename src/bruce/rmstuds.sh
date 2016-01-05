#!/bin/bash
echo "#!/bin/bash" > /tmp/rmstud.sh
ps -ef | grep stud | awk '{if ($8=="stud") print "kill -9 " $2}' >> /tmp/rmstud.sh
bash /tmp/rmstud.sh
rm /tmp/rmstud.sh
