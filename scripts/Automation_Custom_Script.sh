cd ~
sudo echo -e "cd ~\nsudo git clone https://github.com/dazzaXx/ModernJVS\ncd ModernJVS\nsudo make install\ncd ..\nsudo rm -r ModernJVS" >> ./ModernJVS_Automation_Script.sh
sudo chmod +x ModernJVS_Automation_Script.sh
sudo echo -e "sudo systemctl stop modernjvs\nsudo systemctl stop modernjvs-webui\nsudo systemctl disable modernjvs\nsudo systemctl disable modernjvs-webui\nsudo apt remove -y modernjvs" >> ./Uninstall_ModernJVS.sh
sudo chmod +x Uninstall_ModernJVS.sh
sudo ./ModernJVS_Automation_Script.sh
sudo rm ModernJVS_Automation_Script.sh